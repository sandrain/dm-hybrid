/****************************************************************************
 *  dm-hybrid.c
 *  Device mapper target for hybrid device using SSD + HDD.
 *
 *  Author: Hyogi Sim (sandrain@gmail.com)
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; under version 2 of the License.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 ****************************************************************************/
#include <linux/blk_types.h>
#include <asm/atomic.h>
#include <asm/checksum.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/blkdev.h>
#include <linux/bio.h>
#include <linux/slab.h>
#include <linux/hash.h>
#include <linux/spinlock.h>
#include <linux/workqueue.h>
#include <linux/pagemap.h>
#include <linux/log2.h>
#include "dm.h"
#include <linux/dm-io.h>
#include <linux/dm-kcopyd.h>

#define	DMH_DEBUG	1

#define DM_MSG_PREFIX "hybrid"
#define DMH_PREFIX "dm-hybrid: "

#if DMH_DEBUG
#define DPRINTK( s, arg... ) printk(DMH_PREFIX s "\n", ##arg)
#else
#define DPRINTK( s, arg... )
#endif

#define	get_hybrid(ti)		((struct hybrid_c *) (ti)->private)
#define	DMH_META_BLOCK_SIZE		1024
#define DMH_COPY_PAGES			1024

#ifndef	TRUE
#  define	TURE		1
#endif
#ifndef	FALSE
#  define	FALSE		0
#endif

/* Default params */
#define	DMH_DEFAULT_BLOCK_SHIFT		2

struct hybrid_c {
	struct dm_dev	*src;
	struct dm_dev	*cache;
	struct dm_io_client *io_client;

	sector_t	src_dev_size;		/* Device size in sectors */
	sector_t	cache_dev_size;

	/* TODO: change the unit of block_size to number of sectors */
	__u16		block_size;		/* in KB */
	__u16		block_shift;

	__u32		cache_blocks;		/* Units are in blocks */
	__u32		writeback_offset;
	__u32		trigger_blocks;

	atomic_t	meta_block_dirty;
	spinlock_t	meta_block_lock;
	struct hybrid_meta_block *meta_block;
};

#define	DMH_MAGIC_1	0x20090927U
#define	DMH_MAGIC_2	0x20110117U

struct hybrid_meta_block {
	__le32		magic1;

	__le32		src_major;
	__le32		src_minor;
	__le64		src_dev_size;		/* number of sectors */

	__le16		block_size;
	__le16		block_shift;

	__le32		magic2;

	__le32		cache_blocks;
	__le32		writeback_offset;
	__le32		trigger_blocks;
} __attribute__((packed));

/****************************************************************************
 *  Wrapper functions for using the new dm_io API
 ****************************************************************************/
static int dm_io_sync_vm(unsigned int num_regions,struct dm_io_region *where,
		int rw, void *data, unsigned long *error_bits, struct hybrid_c *dmh)
{
	struct dm_io_request iorq;

	iorq.bi_rw= rw;
	iorq.mem.type = DM_IO_VMA;
	iorq.mem.ptr.vma = data;
	iorq.notify.fn = NULL;
	iorq.client = dmh->io_client;

	return dm_io(&iorq, num_regions, where, error_bits);
}

#if 0
static int dm_io_async_bvec(unsigned int num_regions, struct dm_io_region *where,
		int rw, struct bio_vec *bvec, io_notify_fn fn, void *context)
{
	struct kcached_job *job = (struct kcached_job *)context;
	struct cache_c *dmc = job->dmc;
	struct dm_io_request iorq;

	iorq.bi_rw = (rw | (1 << REQ_SYNC));
	iorq.mem.type = DM_IO_BVEC;
	iorq.mem.ptr.bvec = bvec;
	iorq.notify.fn = fn;
	iorq.notify.context = context;
	iorq.client = dmc->io_client;

	return dm_io(&iorq, num_regions, where, NULL);
}
#endif

static inline int __is_valid_meta_block(struct hybrid_c *dmh,
					struct hybrid_meta_block *meta)
{
	if (!(le32_to_cpu(meta->magic1) == DMH_MAGIC_1
		&& le32_to_cpu(meta->magic2) == DMH_MAGIC_2))
		return FALSE;

	if (!(le32_to_cpu(meta->src_major) == MAJOR(dmh->src->bdev->bd_dev)
		&& le32_to_cpu(meta->src_minor) == MINOR(dmh->src->bdev->bd_dev)))
		return FALSE;

	return le32_to_cpu(meta->src_dev_size) == dmh->src_dev_size;
}

static inline void __extract_meta_block(struct hybrid_c *dmh,
				struct hybrid_meta_block *meta)
{
	dmh->block_size = le32_to_cpu(meta->block_size);
	dmh->block_shift = le32_to_cpu(meta->block_shift);
	dmh->cache_blocks = le32_to_cpu(meta->cache_blocks);
	dmh->writeback_offset = le32_to_cpu(meta->writeback_offset);
	dmh->trigger_blocks = le32_to_cpu(meta->trigger_blocks);
}

static inline void __fill_meta_block(struct hybrid_c *dmh,
				struct hybrid_meta_block *meta)
{
	meta->magic1 = cpu_to_le32(DMH_MAGIC_1);
	meta->magic2 = cpu_to_le32(DMH_MAGIC_2);

	meta->src_major = cpu_to_le32(MAJOR(dmh->src->bdev->bd_dev));
	meta->src_minor = cpu_to_le32(MINOR(dmh->src->bdev->bd_dev));
	meta->src_dev_size = cpu_to_le64(dmh->src_dev_size);
	meta->block_size = cpu_to_le16(dmh->block_size);
	meta->block_shift = cpu_to_le16(dmh->block_shift);
	meta->cache_blocks = cpu_to_le32(dmh->cache_blocks);
	meta->writeback_offset = cpu_to_le32(dmh->writeback_offset);
	meta->trigger_blocks = cpu_to_le32(dmh->trigger_blocks);
}

static void extract_meta_block(struct hybrid_c *dmh,
				struct hybrid_meta_block *meta)
{
	spin_lock(&dmh->meta_block_lock);
	__extract_meta_block(dmh, meta);
	spin_unlock(&dmh->meta_block_lock);
}

static void fill_meta_block(struct hybrid_c *dmh,
				struct hybrid_meta_block *meta)
{
	spin_lock(&dmh->meta_block_lock);
	__fill_meta_block(dmh, meta);
	spin_unlock(&dmh->meta_block_lock);
}

/*
 * Target constructor.
 *
 * Here are things that this function should do
 * - Parse/validate the arguments.
 * - Read the metablock and check whether old session is available to go on.
 * - Read the metadata and construct in-memory data structures.
 * - Register workqueue for asynchronous I/O.
 *
 * List of arguments, (o) means optional.
 *
 * argv[0]: path to hdd, the source device
 * argv[1]: path to ssd, the cache device
 * argv[2]: (o) block shift (>=2), e.g. 2=4KB block, 3=8KB, 4=16KB, ...
 * argv[3]: (o) ssd space to be used in number of blocks
 * argv[4]: (o) writeback cache size in number of blocks
 * argv[5]: (o) re-organization threshold in number of blocks
 * TODO
 * argv[4]: (o) dynamically divide area, using on-line access patterns.
 * argv[6]: (o) cache policy (consider dirty flag)
 */
static int hybrid_ctr(struct dm_target *ti, unsigned int argc, char **argv)
{
	int ret = 0;
	struct hybrid_c *dmh;
	struct dm_dev *hdd;
	struct dm_dev *ssd;
	struct hybrid_meta_block *meta_block = NULL;
	__u16 block_shift = 0;
	__u32 cache_blocks = 0;
	__u32 writeback_offset = 0;
	__u32 trigger_blocks = 0;
	sector_t src_dev_size;
	sector_t cache_dev_size;

	ret = dm_get_device(ti, argv[0], dm_table_get_mode(ti->table), &hdd);
	if (ret < 0) {
		ti->error = DMH_PREFIX "SSD device lookup failed";
		return ret;
	}

	ret = dm_get_device(ti, argv[1], dm_table_get_mode(ti->table), &ssd);
	if (ret < 0) {
		ti->error = DMH_PREFIX "HDD device lookup failed";
		goto put_hdd;
	}

	meta_block = (struct hybrid_meta_block *) vmalloc(DMH_META_BLOCK_SIZE);
	if (!meta_block) {
		ret = -ENOMEM;
		goto put_ssd;
	}

	if (argc == 2) {
		/* TODO:
		 * In this case, we must check whether old session should continue. */

		block_shift = DMH_DEFAULT_BLOCK_SHIFT;
	}
	else {
		/* Now, rest of the arguments are optional, read them. */
		switch (argc) {
		case 6: if (sscanf(argv[5], "%u", &trigger_blocks) != 1)
				goto arg_invalid;
		case 5: if (sscanf(argv[4], "%u", &writeback_offset) != 1)
				goto arg_invalid;
		case 4: if (sscanf(argv[3], "%u", &cache_blocks) != 1)
				goto arg_invalid;
		case 3: if (sscanf(argv[2], "%hu", &block_shift) != 1)
				goto arg_invalid;
			if (unlikely(block_shift == 0)) {
				ti->error = DMH_PREFIX "Block size cannot be 0";
				ret = -EINVAL;
				goto put_ssd;
			}
			break;

		default:
arg_invalid:
			ti->error = DMH_PREFIX "Cannot parse the arguments";
			ret = -EINVAL;
			goto put_ssd;
		}
	}

	/* Check params. */
	src_dev_size = hdd->bdev->bd_inode->i_size;
	cache_dev_size = ssd->bdev->bd_inode->i_size;
	block_shift += 10;	/* we use KB */

	if (cache_blocks == 0)
		cache_blocks = src_dev_size >> block_shift;
	if (writeback_offset == 0)
		writeback_offset = cache_blocks >> 3;
	if (trigger_blocks == 0)
		trigger_blocks = cache_blocks >> 4;

	if (cache_blocks << block_shift > cache_dev_size) {
		ti->error = DMH_PREFIX "Cache size exceeds the device size";
		ret = -EINVAL;
		goto free_meta_block;
	}
	if (writeback_offset << block_shift > cache_dev_size) {
		ti->error = DMH_PREFIX "Writeback blocks exceeds the device size";
		ret = -EINVAL;
		goto free_meta_block;
	}
	if (unlikely(trigger_blocks << block_shift > cache_dev_size)) {
		ti->error = DMH_PREFIX "Trigger blocks exceeds the device size";
		ret = -EINVAL;
		goto free_meta_block;
	}

	/* Prepare our context. */
	if (unlikely((dmh = kmalloc(sizeof(*dmh), GFP_KERNEL)) == NULL)) {
		ti->error = DMH_PREFIX "kamlloc failed";
		ret = -ENOMEM;
		goto free_meta_block;
	}

	dmh->src = hdd;
	dmh->cache = ssd;
	dmh->cache_blocks = cache_blocks;
	dmh->block_shift = block_shift;
	dmh->block_size = 1 << block_shift;
	dmh->writeback_offset = writeback_offset;
	dmh->trigger_blocks = trigger_blocks;
	dmh->src_dev_size = src_dev_size >> 9;
	dmh->cache_dev_size = cache_dev_size >> 9;
	dmh->meta_block = meta_block;

	dmh->io_client = dm_io_client_create(DMH_COPY_PAGES);

	if (IS_ERR(dmh->io_client)) {
		ti->error = "Failed to create io client";
		ret = PTR_ERR(dmh->io_client);
		goto free_dmh;
	}

	/* TODO:
	 * Here we read the superblock to check whether old session is
	 * still available.
	 * Move this part somewhere above!
	 */
	if (argc == 2) {
		struct dm_io_region where;
		unsigned long bits;

		where.bdev = ssd->bdev;
		where.sector = 0;
		where.count = 2;

		DPRINTK("Try to read the old meta-block");

		/* TODO: check the return value! */
		dm_io_sync_vm(1, &where, READ, meta_block, &bits, dmh);

		if (__is_valid_meta_block(dmh, meta_block)) {
			DPRINTK("Valid meta-block found, continue the old session");
			extract_meta_block(dmh, meta_block);
		}
		else {
			DPRINTK("No meta-block found, start a new session");
		}
	}

	/*ti->split_io = dmh->block_size << 1;*/
	ti->private = dmh;

	DPRINTK("hybrid_ctr");

	return ret;

free_dmh:
	kfree(dmh);
free_meta_block:
	if (meta_block)
		vfree(meta_block);
put_ssd:
	dm_put_device(ti, ssd);
put_hdd:
	dm_put_device(ti, hdd);
	return ret;
}

static void hybrid_dtr(struct dm_target *ti)
{
	struct hybrid_c *dmh = get_hybrid(ti);
	struct dm_io_region region;
#if 0
	struct dm_io_request req;
	struct hybrid_meta_block *meta;
#endif
	unsigned long bits;

	fill_meta_block(dmh, dmh->meta_block);

	region.bdev = dmh->cache->bdev;
	region.sector = 0;
	region.count = 2;	/* 1KB */

	/* TODO: check the return value! */
	dm_io_sync_vm(1, &region, WRITE, dmh->meta_block, &bits, dmh);

#if 0
	meta = (struct hybrid_meta_block *) vmalloc(1024);
	if (!meta) {
		DMERR("Unable to allocate memory for metablock");
	}
	else {
		unsigned long errbits;
		/* Sync metadata */
		memset((void *) meta, 0, 1024);
		__fill_meta_block(dmh, meta);

		region.bdev = dmh->cache->bdev;
		region.sector = 0;
		region.count = 2;	/* 1KB */

		req.bi_rw = WRITE;
		req.mem.type = DM_IO_VMA;
		req.mem.ptr.vma = meta;
		req.notify.fn = NULL;
		req.client = dmh->io_client;

		/* TODO: check the return value! */
		dm_io(&req, 1, &region, &errbits);
	}
#endif

	dm_io_client_destroy(dmh->io_client);

	dm_put_device(ti, dmh->src);
	dm_put_device(ti, dmh->cache);

	/* vfree(meta); */
	vfree(dmh->meta_block);
	kfree(dmh);

	DPRINTK("hybrid_dtr");
}

static inline void dump_bio(struct bio *bio)
{
	DPRINTK("%s %llu %u", bio_rw(bio) == READ ? "READ" :
			(bio_rw(bio) == READA ? "READA" : "WRITE"),
			(u64) bio->bi_sector, bio_sectors(bio));
}

static int hybrid_map(struct dm_target *ti, struct bio *bio,
		      union map_info *map_context)
{
	struct hybrid_c *dmh = get_hybrid(ti);

	dump_bio(bio);
	bio->bi_bdev = dmh->src->bdev;

	return DM_MAPIO_REMAPPED;
}

static int hybrid_status(struct dm_target *ti, status_type_t type,
			 char *result, unsigned int maxlen)
{
	struct hybrid_c *dmh = get_hybrid(ti);
	int sz = 0;

	switch (type) {
	case STATUSTYPE_INFO:	/* pass the statistics */
		DMEMIT("stats are not available, yet");
		break;
	case STATUSTYPE_TABLE:	/* pass the configuration info */
		DMEMIT("source dev = %s, cache dev = %s, "
			"block size = %d KB, cache blocks = %u, "
			"writeback offset = %u, Trigger blocks = %u",
			dmh->src->name, dmh->cache->name,
			dmh->block_size >> 10, dmh->cache_blocks,
			dmh->writeback_offset, dmh->trigger_blocks);
		break;

	default: break;
	}

	return 0;
}

static struct target_type hybrid_target = {
	.name   = "hybrid",
	.version= {1, 0, 1},
	.module = THIS_MODULE,
	.ctr    = hybrid_ctr,
	.dtr    = hybrid_dtr,
	.map    = hybrid_map,
	.status = hybrid_status,
};


static int __init dm_hybrid_init(void)
{
	int ret = 0;

	if ((ret = dm_register_target(&hybrid_target)) < 0) {
		DMERR(DMH_PREFIX "register failed: %d", ret);
		return ret;
	}
	DPRINTK("target registered");

	return ret;
}

static void __exit dm_hybrid_exit(void)
{
	dm_unregister_target(&hybrid_target);
	DPRINTK("target unregistered");
}

module_init(dm_hybrid_init);
module_exit(dm_hybrid_exit);

MODULE_DESCRIPTION(DM_NAME " hybrid target (ssd + hdd)");
MODULE_AUTHOR("Hyogi Sim <sandrain@gmail.com>");
MODULE_LICENSE("GPL");

