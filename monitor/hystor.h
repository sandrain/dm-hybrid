#ifndef	__HYSTOR_H__
#define	__HYSTOR_H__

#include <linux/types.h>
#include <sys/types.h>
#include <sys/ioctl.h>

#include "blktrace.h"

typedef enum {
	BLOCK_FREE = 0,			/* free blocks */
	BLOCK_DATA_REMAP,		/* remap area blocks */
	BLOCK_DATA_WRITEBACK,		/* write-back area blocks */
	BLOCK_META_SUPER,		/* hystor's superblock */
	BLOCK_META_BGD,			/* bgd of block table */
	BLOCK_META_BMD,			/* bmd of block table */
	BLOCK_META_BTE,			/* bte of block table */
	BLOCK_META_MAPPING,		/* mapping table */
	BLOCK_META_RESIDENTLIST,	/* resident list */
	BLOCK_RESERVED,			/* reserved or unused */

	N_BLOCK_TYPES
} block_type_t;

extern int hystor_block_size;	/* defined in hystor_lib.c */

static inline void hystor_set_block_size(int size)
{
	hystor_block_size = size;
}

/*
 * The block table interface
 */

/* We use 4KB blocks for our metadata. */
#define	HYSTOR_META_BLOCK_SIZE		4096


typedef	__u32		hy_block_t;

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

#define	bgd_pointer(entry)		((entry) >> 32)
#define	bgd_counter(entry)		(((entry) >> 16) & 0xffff)
#define	bgd_unique(entry)		((entry) & 0xffff)

#define bmd_pointer			bgd_pointer
#define	bmd_counter			bgd_counter
#define	bmd_unique			bgd_unique

#define	bte_counter(entry)		((entry) >> 16)
#define	bte_flag(entry)			((entry) & 0xffff)

struct hystor_bt_block {
	block_type_t	type;		/* BGD/BMD/BTE ? */
	__u32		bid;		/* LBN/ID of the block */
	__u8		data[HYSTOR_META_BLOCK_SIZE];	/* actual data */
};

#define	bgd_entry(bt_block, idx)	(((__u64 *)(bt_block)->data)[(idx)])
#define	bmd_entry bgd_entry
#define	bte_entry(bt_block, idx)	(((__u32 *)(bt_block)->data)[(idx)])

/* initialize the hystor monitor */
extern int hystor_init(void);

/* update the block table for the request */
extern int hystor_update_block_table(struct blk_io_trace *bit);

/* request to remap blocks */
extern int hystor_request_remap(hy_block_t *list, int size);



/***************************************************************************/
/*
 * TODO:
 * Our current implementation doesn't support multiple instances.
 * Supporting such feature requires modification of blktrace.
 */
#if 0
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

