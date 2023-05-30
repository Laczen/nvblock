/*
 * A virtual block system for non volatile (nor-flash, nand-flash, eeprom)
 * memory.
 *
 * The system creates a block IO device. The block size is configurable. The
 * system handles all translations to memory. Wear levelling is provided. Bad
 * blocks are also supported.
 *
 * The system stores data and meta data in separate blocks. The meta data
 * storage is inspired by the dhara nand-flash wear levelling library. The radix
 * tree idea with alternate pointers in the meta data is taken from the dhara
 * library but has been altered slightly to allow storing multiple physical
 * block locations in one meta page.
 *
 * Terminology:
 * a. write-block: smallest writeable unit on memory,
 * b. erase-block: smallest eraseable unit on memory (unused for eeprom),
 * c. virtual block: base area used as block. The smallest virtual block size
 *    that is supported is determined by the write-block-size or the number of
 *    blocks: 64 byte for a maximum of 2^8-1 blocks, 128 byte for a maximum of
 *    2^16-1 blocks, 512 byte for a maximum of 2^32-1 blocks.
 * d. virtual block group: multiple virtual blocks are taken together in a
 *    group and at least the last block in this group is a meta block, this is
 *    used as a unit to ensure no valid data is lost when doing garbage
 *    collection. On systems where erase is required the erase-block size should
 *    be a multiple of the virtual block group size.
 *
 * Copyright (c) 2021 Laczen
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef NVBLOCK_H
#define NVBLOCK_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>

#ifdef __cplusplus
extern "C"
{
#endif

enum {
	NVB_VERSION_MAJOR = 0,
	NVB_VERSION_MINOR = 0,
	NVB_VERSION_REVISION = 1,
	NVB_VERSION = ((NVB_VERSION_MAJOR & 0xff) << 24) |
		      ((NVB_VERSION_MINOR & 0xff) << 16) |
		      (NVB_VERSION_REVISION & 0xffff),
	NVB_BLOCK_NONE = 0xffff,
	NVB_MIN_BLOCK_SIZE = 64,
	NVB_META_ADDRESS_SIZE = 2,
	NVB_META_MAGIC_START = 0,
	NVB_META_MAGIC_SIZE = 4,
	NVB_META_VERSION_START = NVB_META_MAGIC_START + NVB_META_MAGIC_SIZE,
	NVB_META_VERSION_SIZE = 4,
	NVB_META_EPOCH_START = NVB_META_VERSION_START + NVB_META_VERSION_SIZE,
	NVB_META_EPOCH_SIZE = 4,
	NVB_META_CRC_START = NVB_META_EPOCH_START + NVB_META_EPOCH_SIZE,
	NVB_META_CRC_SIZE = 4,
	NVB_META_TGT_START = NVB_META_CRC_START + NVB_META_CRC_SIZE,
	NVB_META_TGT_SIZE = NVB_META_ADDRESS_SIZE,
	NVB_META_ALT_START = NVB_META_TGT_START + NVB_META_TGT_SIZE,
	NVB_META_ALT_CNT = 15,
	NVB_META_ALT_SIZE = NVB_META_ALT_CNT * NVB_META_ADDRESS_SIZE,
	NVB_META_DMP_START = NVB_META_ALT_START + NVB_META_ALT_SIZE,
};

enum nvb_error {
	NVB_ENOENT = 2,	 /**< No such file or directory */
	NVB_EFAULT = 14, /**< Bad address */
	NVB_EINVAL = 22, /**< Invalid argument */
	NVB_ENOSPC = 28, /**< No space left on device */
	NVB_EROFS = 30,	/**< Read-only file system */
	NVB_EAGAIN = 11, /**< No more contexts */
};

/* IOCTL status return codes */
enum nvb_status {
	NVB_STATUS_OK = 0x00,
	NVB_STATUS_UNINIT = 0x01, /* uninitialized */
	NVB_STATUS_NOMEDIA = 0x02, /* media unavailable */
	NVB_STATUS_WR_PROTECT =	0x04, /* media write protected */
};

/* IOCTL commands codes*/
enum nvb_cmd {
	NVB_CMD_GET_BLK_COUNT = 0x01,
	NVB_CMD_GET_BLK_SIZE = 0x02,
	NVB_CMD_CTRL_SYNC = 0x05,
};

/** @brief Configuration info structure for the virtual block system */
struct nvb_config {
	/* Opaque user provided context */
	void *context;

	/* Pointer to ram buffer for meta storage */
	uint8_t *meta;

	/* Initialize routine (optional). For systems that provide thread safety
	 * using a lock mechanism the lock should be initialized in the routine.
	 *
	 * Should return 0 on success, -ERRNO on failure.
	 */
	int (*init)(const struct nvb_config *cfg);

	/* lock (optional): blocks execution for other threads */
	int (*lock)(const struct nvb_config *cfg);

	/* unlock (optional): unblocks execution for other threads */
	int (*unlock)(const struct nvb_config *cfg);

	/* Read a virtual block at location p (the virtual block size can
	 * be retrieved from cfg).
	 *
	 * Should return 0 on success, -ERRNO on failure.
	 */
	int (*read)(const struct nvb_config *cfg, uint32_t p, void *buffer);

	/* Program a virtual block at location p (the virtual block size can
	 * be retrieved from cfg). When working on memory that needs to be
	 * erased before programming the function needs to erase a block when
	 * a write is performed to the first block of an eraseblock.
	 *
	 * Should return 0 on success, -ERRNO on failure (-NVB_EFAULT on bad
	 * block detection).
	 */
	int (*prog)(const struct nvb_config *cfg, uint32_t p,
		    const void *buffer);

	/* Move a virtual block from location pf to location pt (the virtual
	 * block size can be retrieved from cfg). When working on memory that
	 * needs to be erased before programming the function needs to erase a
	 * block when a copy is performed to the first block of an eraseblock.
	 *
	 * Should return 0 on success, -ERRCODE on failure (-NVB_EFAULT on bad
	 * block detection).
	 */
	int (*move)(const struct nvb_config *cfg, uint32_t pf, uint32_t pt);

	/* Compare a virtual block at location p (the virtual block size can
	 * be retrieved from cfg) with data in buffer, return 0 if equal. This
	 * is used to avoid rewriting the same data when chunks of data larger
	 * than the virtual block size are written. If not provided the system
	 * writes the data to a new location.
	 *
	 * Should return 0 on equal, non-zero if not equal.
	 */
	int (*comp)(const struct nvb_config *cfg, uint32_t p,
		    const void *buffer);

    	/* Detect if a virtual block at p belongs to a bad area.
	 *
	 * Should return true if bad.
	 */
	bool (*is_bad)(const struct nvb_config *cfg, uint32_t p);

	/* Detect if a virtual block is erased. In case a erase is not required
	 * e.g. on eeprom, this should always return true.
	 *
	 * Should return true if free, false if not free.
	 */
	bool (*is_free)(const struct nvb_config *cfg, uint32_t p);

	/* Mark the area (block) that p belongs to as bad. */
	void (*mark_bad)(const struct nvb_config *cfg, uint32_t p);

	/* Sync to memory
	 *
	 * Should return 0 on success, -ERRCODE on failure.
	 */
    	int (*sync)(const struct nvb_config *cfg);

	uint32_t bsize; /* virtual block size */
	uint32_t bpg; /* blocks per group */
	uint32_t gcnt; /* total count of groups available in backend */
		       /* gcnt = backend size / (bsize * bpg) */
	uint32_t spgcnt; /* spare group count for wear levelling + bad regions*/
};

/** @brief Info structure for the virtual block system */
struct nvb_info {
	const struct nvb_config *cfg;

	uint32_t head; /* Next write block */
	uint32_t gc_head; /* Start of the next erase block that needs gc */
	uint32_t epoch; /* Wrap around counter (erase counter) */

	uint32_t root; /* Last written meta block */
	uint32_t meta_dmmsk; /* Direct map mask */

	enum nvb_status status;
};

/**
 * @brief Initialize the virtual block system object
 *
 * Initializes the nvb_info object; the function needs to be invoked
 * on object before first use. A configuration structure needs to be passed to
 * the initialize routine.
 *
 * @param info Pointer to virtual block object
 * @param cfg Pointer to virtual block configuration object
 *
 * @retval 0 on success, -ERRNO otherwise.
 *
 */
int nvb_init(struct nvb_info *info, const struct nvb_config *cfg);

/**
 * @brief Get the status of the virtual block system object
 *
 * @param info Pointer to virtual block object
 *
 * @retval 0 on success, -ERRNO otherwise.
 *
 */
int nvb_status(struct nvb_info *info);

/**
 * @brief Read data from a virtual block object
 *
 * @param info Pointer to virtual block object
 * @param data Pointer to read result buffer
 * @param sblock Start block to read
 * @param bcnt Number of blocks to read
 *
 * @retval 0 on success, -ERRNO otherwise.
 */
int nvb_read(struct nvb_info *info, void *data, uint32_t sblock, uint32_t bcnt);

/**
 * @brief Write data to a virtual block object
 *
 * Write data to a virtual block object. This can also be used to delete blocks
 * from the virtual block object by writing with data = NULL.
 *
 * @param info Pointer to virtual block object
 * @param data Pointer to data
 * @param sblock Start block to write
 * @param bcnt Number of blocks to write
 *
 * @retval 0 on success, -ERRNO otherwise.
 */
int nvb_write(struct nvb_info *info, const void *data, uint32_t sblock,
	      uint32_t bcnt);

/**
 * @brief IOCTL interface for a virtual block object
 *
 * @param info Pointer to virtual block object
 * @param cmd command number
 * @param buff Pointer to command info/command result
 *
 * @retval 0 on success, -ERRNO otherwise.
 */
int nvb_ioctl(struct nvb_info *info, uint8_t cmd, void *buff);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* NVBLOCK_H */