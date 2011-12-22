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
#define DMH_COPY_PAGES 1024

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
};

struct hybrid_meta_block {
	__le32		magic1;

	__le32		src_major;
	__le32		src_minor;

	__le64		src_dev_size;		/* number of sectors */
	__le64		cache_dev_size;

	__le16		block_size;
	__le16		block_shift;

	__le32		cache_blocks;
	__le32		writeback_offset;
	__le32		trigger_blocks;
};

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
		return ret;
	}

	if (argc == 2) {
		/* In this case, we check whether old session should continue. */
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
				return -EINVAL;
			}
			break;

		default:
arg_invalid:
			ti->error = DMH_PREFIX "Cannot parse the arguments";
			return -EINVAL;
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
		return -EINVAL;
	}
	if (writeback_offset << block_shift > cache_dev_size) {
		ti->error = DMH_PREFIX "Writeback blocks exceeds the device size";
		return -EINVAL;
	}
	if (unlikely(trigger_blocks << block_shift > cache_dev_size)) {
		ti->error = DMH_PREFIX "Trigger blocks exceeds the device size";
		return -EINVAL;
	}

	/* Prepare our context. */
	if (unlikely((dmh = kmalloc(sizeof(*dmh), GFP_KERNEL)) == NULL)) {
		ti->error = DMH_PREFIX "kamlloc failed";
		return -ENOMEM;
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
	dmh->io_client = dm_io_client_create(DMH_COPY_PAGES);

	if (IS_ERR(dmh->io_client)) {
		kfree(dmh);
		ti->error = "Failed to create io client";
		return PTR_ERR(dmh->io_client);
	}

	//ti->split_io = dmh->block_size << 1;
	ti->private = dmh;

	DPRINTK("hybrid_ctr");

	return ret;
}

static void hybrid_dtr(struct dm_target *ti)
{
	struct hybrid_c *dmh = get_hybrid(ti);
	struct dm_io_region region;
	struct dm_io_request req;
	struct hybrid_meta_block *meta;

	meta = (struct hybrid_meta_block *) vmalloc(1024);
	if (!meta) {
		DMERR("Unable to allocate memory for metablock");
	}
	else {
		unsigned long errbits;
		/* Sync metadata */
		memset((void *) meta, 0, 1024);

		region.bdev = dmh->cache->bdev;
		region.sector = 0;
		region.count = 2;	/* 1KB */

		req.bi_rw = WRITE;
		req.mem.type = DM_IO_VMA;
		req.mem.ptr.vma = meta;
		req.notify.fn = NULL;
		req.client = dmh->io_client;

		dm_io(&req, 1, &region, &errbits);
	}

	dm_io_client_destroy(dmh->io_client);

	dm_put_device(ti, dmh->src);
	dm_put_device(ti, dmh->cache);

	kfree(meta);
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

