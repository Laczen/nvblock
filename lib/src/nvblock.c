/*
 * Copyright (c) 2021 Laczen
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "nvblock/nvblock.h"
#include <stdlib.h>

/* Flash routines for virtual blocks */
/* read from physical block */
static int pb_read(const struct nvb_config *cfg, uint8_t *buf, uint32_t p)
{
	const uint32_t bsize = cfg->bsize;
	int rc;

	if (p == NVB_BLOCK_NONE) {
		memset(buf, 0xff, bsize);
		rc = 0;
	} else {
		rc = cfg->read(cfg, p, (void *)buf);
	}

	return rc;
}

/* write to physical block */
static int pb_write(const struct nvb_config *cfg, const uint8_t *buf,
		    uint32_t p)
{
	int rc;

	rc = cfg->prog(cfg, p, (const void *)buf);
	if ((rc == -NVB_EFAULT) && (cfg->mark_bad != NULL)) {
		cfg->mark_bad(cfg, p);
	}

	return rc;
}

/* Compare data in buf with data at location p */
static int pb_compare(const struct nvb_config *cfg, const uint8_t *buf,
		   uint32_t p)
{
	return cfg->comp(cfg, p, (const void *)buf);
}

/* move from physical block to physical block */
static int pb_move(const struct nvb_config *cfg, uint32_t fp, uint32_t tp)
{
	int rc;

	rc = cfg->move(cfg, fp, tp);
	if ((rc == -NVB_EFAULT) && (cfg->mark_bad != NULL)) {
		cfg->mark_bad(cfg, tp);
	}

	return rc;
}

/* check if virtual block belongs to a bad area */
static bool pb_is_bad(const struct nvb_config *cfg, uint32_t p)
{
	bool rv = false;

	if (cfg->is_bad != NULL) {
		rv = cfg->is_bad(cfg, p);
	}

	return rv;
}

/* check if virtual block is unused */
static bool pb_is_free(const struct nvb_config *cfg, uint32_t p)
{
	return cfg->is_free(cfg, p);
}

static int lock(const struct nvb_config *cfg)
{
	if (cfg->lock == NULL) {
		return 0;
	}

	return cfg->lock(cfg);

}

static int unlock(const struct nvb_config *cfg)
{
	if (cfg->unlock != NULL) {
		return 0;
	}

	return cfg->unlock(cfg);
}

static uint32_t crc32(uint32_t crc, const void *buffer, size_t size);

/* Start Meta (or map) routines */
static uint32_t nvb_get32(const uint8_t *buf)
{
	return ((uint32_t)buf[0] | (((uint32_t)buf[1]) << 8) |
	        (((uint32_t)buf[2]) << 16) | (((uint32_t)buf[3]) << 24));
}

static inline void nvb_set32(uint8_t *buf, uint32_t val)
{
	buf[0] = (uint8_t)val;
	buf[1] = (uint8_t)(val >> 8);
	buf[2] = (uint8_t)(val >> 16);
	buf[3] = (uint8_t)(val >> 24);
}

static uint16_t nvb_get16(const uint8_t *buf)
{
	return ((uint16_t)buf[0] | (((uint16_t)buf[1]) << 8));
}

static inline void nvb_set16(uint8_t *buf, uint16_t val)
{
	buf[0] = (uint8_t)val;
	buf[1] = (uint8_t)(val >> 8);
}

/* Meta verify magic */
static bool meta_vrf_magic(const uint8_t *meta)
{
	return ((meta[0] == '!') && (meta[1] == 'N') && (meta[2] == 'V') &&
		(meta[3] == 'B'));
}

/* Meta set magic */
static void meta_set_magic(uint8_t *meta)
{
	meta[0] = '!';
	meta[1] = 'N';
	meta[2] = 'V';
	meta[3] = 'B';
}

/* Meta get version */
static uint32_t meta_get_version(const uint8_t *meta)
{
	return nvb_get32(meta + NVB_META_VERSION_START);
}

/* Meta set version */
static void meta_set_version(uint8_t *meta, uint32_t version)
{
	nvb_set32(meta + NVB_META_VERSION_START, version);
}

/* Meta get counter */
static uint32_t meta_get_epoch(const uint8_t *meta)
{
	return nvb_get32(meta + NVB_META_EPOCH_START);
}

/* Meta set counter */
static void meta_set_epoch(uint8_t *meta, uint32_t mcnt)
{
	nvb_set32(meta + NVB_META_EPOCH_START, mcnt);
}

static void meta_set_target(uint8_t *meta, uint32_t target)
{
	nvb_set16(meta + NVB_META_TGT_START, (uint16_t)target);
}

static void meta_reset_target(uint8_t *meta)
{
	nvb_set16(meta + NVB_META_TGT_START, NVB_BLOCK_NONE);
}

static uint32_t meta_get_target(const uint8_t *meta)
{
	return (uint32_t)nvb_get16(meta + NVB_META_TGT_START);
}

/* Meta set alt pointer at depth */
static void meta_set_alt(uint8_t *meta, uint32_t d, uint32_t alt)
{
	const uint32_t off = NVB_META_ALT_START + (d * NVB_META_ADDRESS_SIZE);

	nvb_set16(meta + off, (uint16_t)alt);
}

/* Meta get alt pointer at depth */
static uint32_t meta_get_alt(const uint8_t *meta, uint32_t d)
{
	const uint32_t off = NVB_META_ALT_START + (d * NVB_META_ADDRESS_SIZE);

	return (uint32_t)nvb_get16(meta + off);
}

/* Meta set loc at position */
static void meta_set_loc(uint8_t *meta, uint32_t p, uint32_t loc)
{
	const uint32_t off = NVB_META_DMP_START + (p * NVB_META_ADDRESS_SIZE);

	nvb_set16(meta + off, (uint16_t)loc);
}

/* Meta get loc at position */
static uint32_t meta_get_loc(uint8_t *meta, uint32_t p)
{
	const uint32_t off = NVB_META_DMP_START + (p * NVB_META_ADDRESS_SIZE);

	return (uint32_t)nvb_get16(meta + off);
}

/* Meta get crc */
static uint32_t meta_get_crc(const uint8_t *meta)
{
	return nvb_get32(meta + NVB_META_CRC_START);
}

/* Meta calculate crc */
static uint32_t meta_clc_crc(const uint8_t *meta, uint32_t blksize)
{
	const uint32_t off = NVB_META_TGT_START;
	const uint32_t size = blksize - NVB_META_TGT_START;
	uint32_t crc32val = 0xffff;

	return crc32(crc32val, meta + off, size);
}

/* Meta set crc */
static void meta_set_crc(uint8_t *meta, uint32_t blksize)
{
	uint32_t crc32val = meta_clc_crc(meta, blksize);

	nvb_set32(meta + NVB_META_CRC_START, crc32val);
}

/* Meta verify crc */
static bool meta_vrf_crc(const uint8_t *meta, uint32_t blksize)
{
	return (meta_get_crc(meta) == meta_clc_crc(meta, blksize));
}

static void nvb_meta_reset(struct nvb_info *info)
{
	uint8_t *meta = info->cfg->meta;

	meta_reset_target(meta);
}

static bool nvb_meta_valid(struct nvb_info *info)
{
	uint8_t *meta = info->cfg->meta;
	const uint32_t bsize = info->cfg->bsize;

	return (meta_vrf_magic(meta) && meta_vrf_crc(meta, bsize));
}

static void nvb_meta_close(struct nvb_info *info)
{
	uint8_t *meta = info->cfg->meta;

	meta_set_magic(meta);
	meta_set_version(meta, NVB_VERSION);
	meta_set_epoch(meta, info->epoch);
	meta_set_crc(meta, info->cfg->bsize);
}

static inline uint32_t d_bit(int depth)
{
	return ((uint32_t)1) << (NVB_META_ALT_CNT - depth - 1);
}

static int nvb_meta_trace(struct nvb_info *info, uint32_t t, uint32_t *p)
{
	const struct nvb_config *cfg = info->cfg;
	const uint32_t dmmsk = info->meta_dmmsk;
	const uint32_t t_ap = (t & ~dmmsk);
	const uint32_t t_mp = (t & dmmsk);
	uint8_t *meta = cfg->meta;
	uint32_t t_meta = meta_get_target(meta);
	int rc = 0;

	if (t_meta == t_ap) {
		goto done;
	}

	uint32_t trace_p = info->root;
	uint32_t alt[NVB_META_ALT_CNT];

	rc = pb_read(cfg, meta, trace_p);
	if (rc != 0) {
		goto end;
	}

	for (uint32_t depth = 0U; ((~dmmsk) & d_bit(depth)) != 0U; depth++) {
		if (trace_p == NVB_BLOCK_NONE) {
			alt[depth] = NVB_BLOCK_NONE;
			continue;
		}

		t_meta = meta_get_target(meta);
		if (((t_meta ^ t_ap) & d_bit(depth)) != 0U) {
			alt[depth] = trace_p;
			trace_p = meta_get_alt(meta, depth);
			rc = pb_read(cfg, meta, trace_p);
			if (rc != 0) {
				goto end;
			}

		} else {
			alt[depth] = meta_get_alt(meta, depth);
		}

	}

	meta_set_target(meta, t_ap);

	for (uint32_t depth = 0U; ((~dmmsk) & d_bit(depth)) != 0U; depth++) {
		meta_set_alt(meta, depth, alt[depth]);
	}

done:
	if (p != NULL) {
		*p = meta_get_loc(meta, t_mp);
	}
end:
	return rc;
}

static void nvb_advance(struct nvb_info *info, uint32_t *head, uint32_t step)
{
	const uint32_t bcnt = info->cfg->bpg * info->cfg->gcnt;

	*head += step;
	while (*head >= bcnt) {
		*head -= bcnt;
	}
}

static void nvb_head_advance(struct nvb_info *info)
{
	nvb_advance(info, &info->head, 1U);
	if (info->head == 0U) {
		info->epoch++;
	}
}

static void nvb_gchead_advance(struct nvb_info *info)
{
	nvb_advance(info, &info->gc_head, info->cfg->bpg);
}

static uint32_t nvb_grp_rem(struct nvb_info *info, uint32_t p)
{
	return p % info->cfg->bpg;
}

static bool nvb_need_gc(struct nvb_info *info)
{
	const struct nvb_config *cfg = info->cfg;
	uint32_t head = info->head;
	bool rv = false;

	head -= nvb_grp_rem(info, head);

	for (uint32_t i = cfg->spgcnt; i != 0U; i--) {
		nvb_advance(info, &head, cfg->bpg);
		if (head == info->gc_head) {
			rv = true;
		}

	}

	return rv;
}

static int nvb_gc_grp(struct nvb_info *info)
{
	const struct nvb_config *cfg = info->cfg;
	int rc = 0;

	if (pb_is_bad(cfg, info->gc_head)) {
		nvb_gchead_advance(info);
		goto end;
	}

	uint8_t *meta = cfg->meta;
	const uint32_t dmcnt = info->meta_dmmsk + 1;

	for (uint32_t i = cfg->bpg; i != 0U; i--) {
		uint32_t wr_head, p_meta, l;

		wr_head = info->head;
		if (pb_read(cfg, meta, info->gc_head + i - 1) < 0) {
			continue;
		}

		if (!nvb_meta_valid(info)) {
			continue;
		}

		l = meta_get_target(meta);
		meta_reset_target(meta);
		if (nvb_meta_trace(info, l, &p_meta) < 0) {
			continue;
		}

		for (uint32_t k = dmcnt; k != 0U; k--) {
			uint32_t p = meta_get_loc(meta, k - 1);

			if (p == NVB_BLOCK_NONE) {
				continue;
			}

			if ((p < info->gc_head) ||
			    (p >= (info->gc_head + cfg->bpg)))  {
				continue;
			}

			rc = pb_move(info->cfg, p, info->head);
			if (rc != 0) {
				goto reset_meta;
			}

			meta_set_loc(meta, k - 1, info->head);
			nvb_head_advance(info);
		}

		if ((wr_head != info->head) ||
		    (p_meta == (info->gc_head + i - 1))) {
			nvb_meta_close(info);
			rc = pb_write(cfg, meta, info->head);
			if (rc != 0) {
				goto reset_meta;
			}

			info->root = info->head;
			nvb_head_advance(info);
		}
	}

	nvb_gchead_advance(info);
reset_meta:
	meta_reset_target(meta);
end:
	return rc;
}

static int nvb_gc(struct nvb_info *info, uint8_t *data)
{
	const struct nvb_config *cfg = info->cfg;
	uint32_t retries = cfg->gcnt;
	int rc = 0;

	while (true) {
		if (retries == 0U) {
			info->status = NVB_STATUS_WR_PROTECT;
			rc = -NVB_ENOSPC;
			break;
		}

		if ((nvb_grp_rem(info, info->head + 1) == 0) &&
		    (data != NULL)) {
			nvb_head_advance(info);
		}

		while (pb_is_bad(cfg, info->head)) {
			nvb_head_advance(info);
			if (info->head == info->gc_head) {
				break;
			}
		}

		if (info->head == info->gc_head) {
			break;
		}

		if (!nvb_need_gc(info)) {
			break;
		}

		rc = nvb_gc_grp(info);

		/* Only in the case that there is a error and it is not caused
		 * by a write to a bad erase block stop the loop. For other
		 * cases restart the loop (the loop will stop automatically if
		 * there is no more gc needed).
		 */
		if ((rc != 0) && (rc != -NVB_EFAULT)) {
			break;
		}

		retries--;
	}
	return rc;
}

static int nvb_block_data_write(struct nvb_info *info, uint32_t l,
				uint32_t b, uint8_t *data)
{
	const struct nvb_config *cfg = info->cfg;
	const uint32_t dmmsk = info->meta_dmmsk;
	const uint32_t t_ap = (l & ~dmmsk);
	const uint32_t t_mp = (l & dmmsk);
	uint8_t *meta = cfg->meta;
	uint32_t data_pb;
	int rc = 0;

	rc = nvb_meta_trace(info, l, NULL);
	if (rc != 0) {
		goto end;
	}

	data_pb = meta_get_loc(meta, t_mp);

	/* Avoid rewriting the same data */
	if ((data_pb != NVB_BLOCK_NONE) && (data != NULL) &&
	    (cfg->comp != NULL)) {
		rc = pb_compare(cfg, data, data_pb);
		if (rc == 0) {
			goto end;
		}

	}

	/* Proceed with normal write */
	if (data != NULL) {
		rc = pb_write(cfg, data, info->head);
		if (rc != 0) {
			goto end;
		}

		meta_set_loc(meta, t_mp, info->head);
		nvb_head_advance(info);
	} else {
		meta_set_loc(meta, t_mp, NVB_BLOCK_NONE);
	}

	meta_set_target(meta, t_ap);

	/* Add meta information at end of each erase-block, if the end of a map
	 * region is reached or if the last data block is written.
	 */

	if ((nvb_grp_rem(info, info->head + 1) == 0U) || (t_mp == dmmsk) ||
	    (b == 1U)) {
		nvb_meta_close(info);
		rc = pb_write(cfg, meta, info->head);
		if (rc != 0) {
			goto end;
		}

		info->root = info->head;
		nvb_head_advance(info);
	}

end:
	return rc;
}

static int nvb_write_vblock(struct nvb_info *info, uint8_t *data, uint32_t l,
			    uint32_t b)
{
	int rc;

	while (true) {
		rc = nvb_gc(info, data);
		if (rc != 0) {
			goto end;
		}

		rc = nvb_block_data_write(info, l, b, data);
		if (rc == 0) {
			break;
		}
	}
end:
	return rc;
}

static int nvb_raw_init(struct nvb_info *info)
{
	const struct nvb_config *cfg = info->cfg;
	uint8_t *meta = cfg->meta;
	uint32_t rd;

	info->meta_dmmsk = 1;
	while ((cfg->bsize - NVB_META_DMP_START) >=
	       (2 * (info->meta_dmmsk + 1U) * NVB_META_ADDRESS_SIZE)) {
		info->meta_dmmsk <<= 1U;
		info->meta_dmmsk += 1U;
	}

	info->root = NVB_BLOCK_NONE;
	info->epoch = 0U;


	for (uint32_t i = cfg->gcnt; i != 0U; i--) {
		bool bad_grp = false;
		bool end_found = false;

		if (pb_is_bad(cfg, (i - 1) * cfg->bpg)) {
			bad_grp = true;
		}

		for (uint32_t j = cfg->bpg; j != 0U; j--) {
			rd = (i - 1) * cfg->bpg + j - 1;

			if (pb_read(cfg, meta, rd) < 0) {
				continue;
			}

			if (!nvb_meta_valid(info)) {
				continue;
			}

			if (meta_get_version(meta) > NVB_VERSION) {
				goto end;
			}

			uint32_t epoch = meta_get_epoch(meta);
			if (info->root == NVB_BLOCK_NONE) {
				info->epoch = epoch;
				info->root = rd;
			}

			if (info->epoch < epoch) {
				info->epoch = epoch;
				info->root = rd;
				if (!bad_grp) {
					end_found = true;
				}
			}

		}

		if (end_found) {
			break;
		}
	}

	if (info->root == NVB_BLOCK_NONE) {
		info->head = 0U;
	} else {
		info->head = info->root;
		nvb_head_advance(info);
	}

	info->gc_head = info->head - nvb_grp_rem(info, info->head);
	for (uint32_t i = cfg->spgcnt + 1; i != 0U; i--) {
		nvb_gchead_advance(info);
	}

	while (pb_is_bad(cfg, info->head) || (!pb_is_free(cfg, info->head))) {
		nvb_head_advance(info);
	}

	return 0;
end:
	return -NVB_EINVAL;
}

int nvb_read(struct nvb_info *info, void *data, uint32_t sblock, uint32_t bcnt)
{
	if ((info == NULL) || (info->cfg == NULL) || (data == NULL)) {
		return -NVB_EINVAL;
	}

	const struct nvb_config *cfg = info->cfg;
	const uint32_t gav = cfg->gcnt - cfg->spgcnt;
	const uint32_t end = gav * (cfg->bpg >> 1U);

	if (((sblock + bcnt) < sblock) || ((sblock + bcnt) > end)) {
		return -NVB_EINVAL;
	}

	uint8_t *data8 = (uint8_t *)data;
	int rc = 0;

	rc = lock(cfg);
	if (rc != 0) {
		return rc;
	}

	nvb_meta_reset(info);
	while (bcnt != 0U) {
		uint32_t p;

		rc = nvb_meta_trace(info, sblock, &p);
		if (rc != 0) {
			goto end;
		}

		rc = pb_read(cfg, data8, p);
		if (rc != 0) {
			goto end;
		}

		sblock++;
		data8 += cfg->bsize;
		bcnt--;
	}

end:
	(void)unlock(cfg);
	return rc;
}

/* write to (multiple) virtual blocks */
int nvb_write(struct nvb_info *info, const void *data, uint32_t sblock,
	      uint32_t bcnt)
{
	if ((info == NULL) || (info->cfg == NULL)) {
		return -NVB_EINVAL;
	}

	if (info->status == NVB_STATUS_WR_PROTECT) {
		return -NVB_EROFS;
	}

	const struct nvb_config *cfg = info->cfg;
	const uint32_t gav = cfg->gcnt - cfg->spgcnt;
	const uint32_t end = gav * (cfg->bpg >> 1U);

	if (((sblock + bcnt) < sblock) || ((sblock + bcnt) > end)) {
		return -NVB_EINVAL;
	}

	uint8_t *data8 = (uint8_t *)data;
	int rc = 0;

	rc = lock(cfg);
	if (rc != 0) {
		return rc;
	}

	nvb_meta_reset(info);
	while (bcnt != 0U) {
		rc = nvb_write_vblock(info, data8, sblock, bcnt);
		if (rc != 0) {
			goto end;
		}

		sblock++;
		if (data != NULL) {
			data8 += cfg->bsize;
		}
		bcnt--;
	}

	if (cfg->sync != NULL) {
		rc = cfg->sync(cfg);
	}

end:
	(void)unlock(cfg);
	return rc;
}

int nvb_init(struct nvb_info *info, const struct nvb_config *cfg)
{
	if ((info == NULL) || (cfg == NULL)) {
		return -NVB_EINVAL;
	}

	if (info->cfg != NULL) {
		return -NVB_EAGAIN;
	}

	info->status = NVB_STATUS_UNINIT;

	if ((cfg->read == NULL) || (cfg->prog == NULL) || (cfg->move == NULL) ||
	    (cfg->is_free == NULL) || (cfg->meta == NULL)) {
		return -NVB_EINVAL;
	}

	if ((cfg->bsize < NVB_MIN_BLOCK_SIZE) || (cfg->bpg < 3U) ||
	    (cfg->gcnt < 2U) || (cfg->spgcnt == 0U)) {
		return -NVB_EINVAL;
	}

	/* Is virtual block size a power of 2 */
	if ((cfg->bsize & (cfg->bsize - 1)) != 0U) {
		return -NVB_EINVAL;
	}

	/* Is block per group a power of 2 */
	if ((cfg->bpg & (cfg->bpg - 1)) != 0U) {
		return -NVB_EINVAL;
	}

	int rc;

	if (cfg->init != NULL) {
		rc = cfg->init(cfg);
		if (rc != 0) {
			return rc;
		}
	}

	rc = lock(cfg);
	if (rc != 0) {
		return rc;
	}

	info->cfg = cfg;
	rc = nvb_raw_init(info);
	if (rc != 0) {
		info->cfg = NULL;
		goto end;
	}

	info->status = NVB_STATUS_OK;
end:
	(void)unlock(cfg);
	return rc;
}

int nvb_status(struct nvb_info *info)
{
	if (info == NULL) {
		return -NVB_EINVAL;
	}

	if (info->cfg == NULL) {
		info->status = NVB_STATUS_UNINIT;
	}

	return (int)info->status;
}

int nvb_ioctl(struct nvb_info *info, uint8_t cmd, void *buffer)
{
	if ((info == NULL) || (info->cfg == NULL)) {
		return -NVB_EINVAL;
	}

	const struct nvb_config *cfg = info->cfg;
	const uint32_t gav = cfg->gcnt - cfg->spgcnt;
	const uint32_t cnt = gav * (cfg->bpg >> 1U);

	switch(cmd) {
	case NVB_CMD_GET_BLK_COUNT:
	 	*(uint32_t *)buffer = cnt;
		break;
	case NVB_CMD_GET_BLK_SIZE:
		*(uint32_t *)buffer = cfg->bsize;
		break;
	case NVB_CMD_CTRL_SYNC:
		/* All is synced already */
		return 0;
	default:
		return -NVB_EINVAL;
	}

	return 0;
}

/* Software CRC implementation with small lookup table */
static uint32_t crc32(uint32_t crc, const void *buffer, size_t size) {
	const uint8_t *data = buffer;
	static const uint32_t rtable[16] = {
		0x00000000, 0x1db71064, 0x3b6e20c8, 0x26d930ac,
		0x76dc4190, 0x6b6b51f4, 0x4db26158, 0x5005713c,
		0xedb88320, 0xf00f9344, 0xd6d6a3e8, 0xcb61b38c,
		0x9b64c2b0, 0x86d3d2d4, 0xa00ae278, 0xbdbdf21c,
	};

	for (size_t i = 0; i < size; i++) {
		crc = (crc >> 4) ^ rtable[(crc ^ (data[i] >> 0)) & 0xf];
		crc = (crc >> 4) ^ rtable[(crc ^ (data[i] >> 4)) & 0xf];
	}

	return crc;
}