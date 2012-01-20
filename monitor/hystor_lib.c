/*
 * hystor_lib.c
 *
 * Author(s): Hyogi Sim <sandrain@gmail.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <math.h>	/* log2() */
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>

#include "hystor.h"
#include "hash_table.h"

#ifdef	__DEBUG__
#  define	BUG(s, arg...)		\
			do { fprintf(stderr, s, ##arg); exit(-1); } while (0)
#else
#  define	BUG(s, arg...)
#endif

#if 0
/* TODO:
 * implement getting device information using ioctl
 */

struct hystor_info {
	dev_t	source;
	dev_t	cache;
	int	blocksize;
};

static char *hystor_dm;
#endif

struct cacheblock {
	__u64	block;
	unsigned short state;
	unsigned long counter;
	char *pad;
};

static int mapfd;
static struct cacheblock *cacheblock;

static char *hystor_mapper;
static int hystor_block_shift;
static unsigned int hystor_block_mask;

#if 0
static inline u64 hash_64(u64 val, unsigned int bits)
{
	u64 hash = val;

	/*  Sigh, gcc can't optimise this alone like it does for 32 bits. */
	u64 n = hash;
	n <<= 18;
	hash -= n;
	n <<= 33;
	hash -= n;
	n <<= 3;
	hash += n;
	n <<= 3;
	hash -= n;
	n <<= 4;
	hash += n;
	n <<= 2;
	hash += n;

	/* High bits are more random, so use them. */
	return hash >> (64 - bits);
}

static unsigned long hash_block(sector_t block)
{
	unsigned long set_number, value;

	value = (unsigned long)(block >> (dmc->block_shift +
	        dmc->consecutive_shift));
	set_number = hash_64(value, dmc->bits) / ;

 	return set_number;
}
#endif


/**************************************************************************
 * Remap list.
 *************************************************************************/

#define	REMAP_LIST_DEFAULT_SIZE		1024

static int remap_list_size;
static __u32 *remap_list;


/**************************************************************************
 * In-memory block table structure.
 *************************************************************************/

/* The __u32 lbn (Logical Block Address) is split as follows:
 *	lbn { bgd:13; bmd:9; bte:10 };
 *
 * And our metadata blocks are always 4KB. 16 BGD blocks are statically
 * allocated. Other blocks (BMD, BTE) are alocated dynamically and we keep
 * them using a hash table.
 *
 * TODO:
 * In the Hystor paper, the block table is stored in a ssd and entries are
 * fetched on demand.
 */

#define	BT_HASH_SIZE		256

static hash_table_t *bt_hash;
/* BGD blocks are not inserted to hash table */
static bt_block_t bgd_blocks[HYSTOR_BGD_BLOCKS];

/**************************************************************************
 * Block allocation/de-allocation for block table.
 *************************************************************************/

/* Index of most recently allocated block, this value is stored in
 * bt_block_t structure (bid field).
 */
static __u32 alloc_sequence = 1;

static bt_block_t *allocate_bt_blocks(int count)
{
	int i;
	bt_block_t *blocks;

	blocks = (bt_block_t *) malloc(sizeof(*blocks) * count);
	if (!blocks)
		return NULL;

	memset(blocks, 0, sizeof(*blocks) * count);

	for (i = 0; i < count; i++) {
		__u32 key;
		blocks[i].bid = ++alloc_sequence;
		key = blocks[i].bid;
		if (!hash_insert(bt_hash, &key, sizeof(key), &blocks[i])) {
			free(blocks);
			alloc_sequence -= (i + 1);
			return NULL;
		}
	}

	return blocks;
}

static inline bt_block_t *allocate_bt_block(block_type_t type)
{
	bt_block_t *block = allocate_bt_blocks(1);

	block->type = type;
	return block;
}

/**************************************************************************
 * Access/manipulate block table entries.
 *************************************************************************/

/* TODO: should we rewrite these functions using macro?? */

static inline __u32 sector_to_lbn(__u64 sector)
{
	return sector >> hystor_block_shift;
}

/* BGD blocks are an array of 4KB blocks. And each entry is 8 bytes.
 * (one block can hold 512 entries.)
 * High 13 bits of lbn denotes the corresponding index of the block array.
 * So the calculation is:
 *	index = lbn >> 19;
 *	block = bgd_blocks[index / 512]; // bgd_blocks[index >> 9]
 *
 * And the index inside the bgd block is:
 *	block->data[index % 512];	// block->data[index & 1ff]
 */
static inline bt_block_t *find_bgd_block(__u32 lbn)
{
	return &bgd_blocks[lbn >> 28];
}

static inline __u64 *find_bgd_entry(bt_block_t *block, __u32 lbn)
{
	return &(((__u64 *) block->data)[(lbn >> 19) & 0x1ff]);
}

static inline __u64 *find_bmd_entry(bt_block_t *block, __u32 lbn)
{
	return &(((__u64 *) block->data)[(lbn >> 10) & 0x1ff]);
}

static inline __u32 *find_bte_entry(bt_block_t *block, __u32 lbn)
{
	return &(((__u32 *) block->data)[lbn & 0x3ff]);
}

static inline bt_block_t *find_bt_block(__u32 sequence)
{
	if (sequence)
		return (bt_block_t *)
			hash_find(bt_hash, &sequence, sizeof(sequence));
	return NULL;
}

static inline __u16 get_bgd_counter(__u64 *entry)
{
	return ((*entry) >> 16) & 0xffff;
}

static inline void set_bgd_counter(__u64 *entry, __u16 counter)
{
	__u64 tmp = *entry;
	tmp &= 0xffffffff0000ffff;
	tmp |= ((__u64) counter << 16);
	*entry = tmp;
}

static inline void update_bgd_counter(__u64 *entry, __u16 ib)
{
	__u16 counter = get_bgd_counter(entry);
	set_bgd_counter(entry, counter + ib);
}
#define	update_bmd_counter	update_bgd_counter

/* BTE { counter:16; flags:16 } */
static inline __u16 get_bte_counter(__u32 *entry)
{
	return (*entry) >> 16;
}

static inline void set_bte_counter(__u32 *entry, __u16 counter)
{
	__u32 tmp = *entry;
	tmp &= 0xffff0000;
	tmp |= ((__u32) counter << 16);
	*entry = tmp;
}

static inline void update_bte_counter(__u32 *entry, __u16 ib)
{
	__u16 counter = get_bte_counter(entry);
	set_bte_counter(entry, counter + ib);
}

/**************************************************************************
 * Calculation of inverse bitmap.
 *************************************************************************/

/* The calculation of ib(inverse bitmap):
 *	N = (number of sectors requested)
 *	m = max(0, 7 - floor(log2(N)))
 *	ib = 1 << m; // pow(2, m)
 *
 * In fact, the result of inverse bitmap is always fits with
 * __u8.
 */
static inline __u16 inverse_bitmap(__u32 nsectors)
{
	int order = 7 - (int) floor(log2((double) nsectors));

	return order < 0 ? 1 : (__u16) (1 << order);
}

/**************************************************************************
 * Read information from debugfs entry.
 *************************************************************************/

static char free_block_namebuf[64];

static __u32 get_number_of_free_blocks(char *hid)
{
	FILE *fp;
	__u32 res;

	memset(free_block_namebuf, 0, sizeof(free_block_namebuf));
	sprintf(free_block_namebuf, "/sys/kernel/debug/hystor/%s/info", hid);

	fp = fopen(free_block_namebuf, "r");
	if (fp == NULL)
		return 0xffffffff;

	if (fscanf(fp, "%u", &res) != 1)
		res = 0xffffffff;

	fclose(fp);

	return res;
}

/**************************************************************************
 * External interfaces.
 *************************************************************************/

int hystor_init(char *mapper)
{
	int i;
	char *address;

	hystor_mapper = mapper;

	/* Read mapping table from debugfs/mapping */
	mapfd = open("/sys/kernel/debug/hystor/8388624/mapping", O_RDWR);
	if (mapfd < 0) {
		perror("open");
		return -1;
	}

	address = mmap(NULL, 2097152, PROT_READ|PROT_WRITE, MAP_SHARED, mapfd, 0);
	if (address == MAP_FAILED) {
		perror("mmap");
		return -1;
	}
	cacheblock = (struct cacheblock *) address;

	/* create a hash table for block table lookup */
	bt_hash = create_hash_table(BT_HASH_SIZE);
	if (!bt_hash)
		return -ENOMEM;

	/* initialize block global table */
	for (i = 0; i < HYSTOR_BGD_BLOCKS; i++) {
		bt_block_t *current = &bgd_blocks[i];
		current->type = BLOCK_META_BGD;
		current->bid = i + 1;
	}

	/* Create remap list */
	remap_list_size = REMAP_LIST_DEFAULT_SIZE;
	remap_list = (__u32 *) malloc(sizeof(__u32) * remap_list_size);
	if (!remap_list) {
		destroy_hash_table(bt_hash);
		return -ENOMEM;
	}

	/* TODO: read this value using ioctl(dm-hystor) */
	hystor_block_shift = 3;
	hystor_block_mask = 7;

	return 0;
}

void hystor_exit(void)
{
	munmap((char *) cacheblock, 2097152);
	close(mapfd);
}


#if 0
int hystor_dev_init(/* dev_t */ __u32 device)
{
	dev_t dev = (dev_t) device;

	return 0;
}
#endif

int hystor_update_block_table(struct blk_io_trace *bit)
{
	bt_block_t *bgd, *bmd, *bte;
	__u64 sequence;
	__u64 *entry64;
	__u32 *entry32;
	__u32 lbn = sector_to_lbn(bit->sector);
	__u16 ib = inverse_bitmap(bit->bytes >> SECTOR_SHIFT);

	if (!bit)
		return -1;

	/* BGD */
	bgd = find_bgd_block(lbn);
	entry64 = find_bgd_entry(bgd, lbn);
	update_bgd_counter(entry64, ib);
	bgd->total += ib;
	sequence = *entry64 >> 32;

	/* find or allocate bgd block */
	if (sequence == HYSTOR_SEQUENCE_NULL) {
		bmd = allocate_bt_block(BLOCK_META_BMD);
		if (bmd == NULL)
			return -ENOMEM;
		*entry64 |= ((__u64) bmd->bid) << 32;
		(*entry64)++;	/* increment the unique */
	}
	else {
		bmd = find_bt_block(sequence);
		if (bmd == NULL)
			BUG("failed to find the bmd block! (seq=%llu)\n", sequence);
	}

	/* BMD */
	entry64 = find_bmd_entry(bmd, lbn);
	update_bmd_counter(entry64, ib);
	bmd->total += ib;
	sequence = *entry64 >> 32;

	/* find or allocate bte block */
	if (sequence == HYSTOR_SEQUENCE_NULL) {
		bte = allocate_bt_block(BLOCK_META_BTE);
		if (bte == NULL)
			return -ENOMEM;
		*entry64 |= ((__u64) bte->bid) << 32;
		(*entry64)++;
	}
	else {
		bte = find_bt_block(sequence);
		if (bte == NULL)
			BUG("failed to find the bte block! (seq=%llu)\n", sequence);
	}

	/* BTE */
	entry32 = find_bte_entry(bte, lbn);
	update_bte_counter(entry32, ib);
	bte->total += ib;

	return 0;
}

/* TODO: This function should work as program 1 of the Hystor paper (5.4).
 * And to do that, we should be able to access the number of availble
 * blocks in SSD.
 */
__u32 *hystor_generate_remap_list(struct trace *tlist, int *remap_size)
{
	int i = 0;
	int count = 0;
	struct trace *tmp;
	__u32 free_blocks;

	if (tlist == NULL)
		return NULL;

	/* TODO: the parameter should be generated dynamically. */
	free_blocks = get_number_of_free_blocks("8388624");

	if (free_blocks == 0xffffffff)
		return NULL;

	fprintf(stderr, "Free blocks = %u\n", free_blocks);

	memset(remap_list, 0, sizeof(__u32) * remap_list_size);

	for (tmp = tlist; tmp; tmp = tmp->next) {
		remap_list[i++] = tmp->bit.sector & ~hystor_block_mask;
		if (++count == remap_list_size)
			break;
	}

	*remap_size = count;
	return remap_list;
}

void hystor_destory_remap_list(__u32 *list)
{
	if (list == NULL)
		BUG("remap list is gone!!\n");
}

/* TODO: how should we access the resident-list??
 * returns number of blocks requested to be moved.
 */
int hystor_request_remap(__u32 *list, int size)
{
	int i = 0;
	int fd;
	char *address;
	__u32 *blks;

	fd = open("/sys/kernel/debug/hystor/8388624/remap", O_RDWR);
	if (fd < 0) {
		perror("open");
		return -1;
	}

	address = mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
	if (address == MAP_FAILED) {
		perror("mmap");
		return -1;
	}

	blks = (__u32 *) address;

	fprintf(stderr, "request remap (%d blocks): \n", size);

	for (i = 0; i < size; i++) {
		fprintf(stderr, "%u\n", list[i]);
		blks[i] = list[i];
	}

	blks[i] = 0xffffffff;

	munmap(address, 4096);
	close(fd);	/* Actual request happens here */

	return size;
}

