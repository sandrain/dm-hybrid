#ifndef	__HYSTOR_H__
#define	__HYSTOR_H__

#include <linux/types.h>
#include <sys/types.h>
#include <sys/ioctl.h>

#include "blktrace.h"

typedef enum {
	BLOCK_FREE = 0,			/* free blocks */
	BLOCK_META_SUPER,		/* hystor's superblock */
	BLOCK_META_BGD,			/* bgd of block table */
	BLOCK_META_BMD,			/* bmd of block table */
	BLOCK_META_BTE,			/* bte of block table */
	BLOCK_META_MAPPING,		/* mapping table */
	BLOCK_META_RESIDENTLIST,	/* resident list */
	BLOCK_DATA_REMAP,		/* remap area blocks */
	BLOCK_DATA_WRITEBACK,		/* write-back area blocks */
	BLOCK_RESERVED,			/* reserved or unused */

	N_BLOCK_TYPES
} block_type_t;

/*
 * The block table interface
 */

#define	SECTOR_SHIFT			9

/* We use 4KB blocks for our metadata. */
#define	HYSTOR_META_BLOCK_SIZE		4096
#define	HYSTOR_BGD_BLOCKS		16
#define	HYSTOR_BLOCK_NULL		0xffffffff
#define	HYSTOR_SEQUENCE_NULL		0	/* sequence starts from 1 */

/* BGD (Block Global Directory), BMD (Block Middle Directory):
 * - 32bit:	block pointer
 * - 16bit:	counter
 * - 16bit:	unique
 *
 * BTE (Block Table Entry):
 * - 16bit:	counter
 * - 16bit:	flag
 */
typedef	__u64		hy_bgd_t;
typedef __u64		hy_bmd_t;
typedef	__u32		hy_bte_t;

struct hystor_bt_block {
	block_type_t	type;		/* BGD/BMD/BTE ? */
	__u32		bid;		/* LBN/ID of the block */
	__u32		total;		/* sum of each counter values */
	__u8		data[HYSTOR_META_BLOCK_SIZE];	/* actual data */
};

typedef	struct hystor_bt_block	bt_block_t;

/* initialize the hystor monitor */
extern int hystor_init(char *mapper);

/* initialize the device information.
 * __u32 since the blk_io_trace encodes dev_t using __u32 */
extern int hystor_dev_init(/* dev_t */ __u32 dev);

/* update the block table for the request */
extern int hystor_update_block_table(struct blk_io_trace *bit);

/* generate and destory remap-list */
extern __u32 *hystor_generate_remap_list(struct trace *tlist, int tsize, int *remap_size);
extern void hystor_destory_remap_list(__u32 *list);

/* request to remap blocks */
extern int hystor_request_remap(__u32 *list, int size);


/***************************************************************************/
#if 0
/*
 * TODO:
 * Our current implementation doesn't support multiple instances.
 * Supporting such feature requires modification of blktrace.
 */

struct hystor_dev {
	char	*path;
	dev_t	dev;
};

/*
 * Hystor monitor
 */
struct hystor {
	struct hystor_dev *mapper;
	struct hystor_dev *source;
	struct hystor_dev *cache;

	int block_size;

	/* in-memory block table */
	struct hystor_bt_block *bgd;
	struct hystor_bt_block *bt_blocks;
	__u32 sequence;
};

struct hystor *hystor_init(char *path_mapper);
struct hystor *hystor_exit(struct hystor *hystor);

struct hystor_bt_block *allocate_bt_block(struct hystor *hystor);
#endif

#endif	/* __HYSTOR_H__ */

