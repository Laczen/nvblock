/*
 * Copyright (c) 2023 Laczen
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>
#include <zephyr/types.h>
#include <zephyr/sys/__assert.h>
#include <zephyr/sys/util.h>
#include <zephyr/drivers/disk.h>
#include <errno.h>
#include <zephyr/init.h>
#include <zephyr/device.h>
#include <zephyr/drivers/flash.h>
#include "nvblock/nvblock.h"

#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(nvblockdisk, CONFIG_NVBLOCKDISK_LOG_LEVEL);

struct nvblock_data {
        struct disk_info info;
        struct nvb_info *nvbi;
        struct nvb_config *nvbc; 
};

struct nvblock_ctx {
        struct k_mutex *lock;
        const struct device *fldev;
        const off_t region_offset;
        const size_t region_size;
        const size_t erase_block_size;
};

static int nvblock_init(const struct nvb_config *cfg)
{
        struct nvblock_ctx *ctx = (struct nvblock_ctx *)cfg->context;
        
        return k_mutex_init(ctx->lock);
}

static int nvblock_lock(const struct nvb_config *cfg)
{
        struct nvblock_ctx *ctx = (struct nvblock_ctx *)cfg->context;
        
        return k_mutex_lock(ctx->lock, K_FOREVER);
}

static int nvblock_unlock(const struct nvb_config *cfg)
{
        struct nvblock_ctx *ctx = (struct nvblock_ctx *)cfg->context;
        
        return k_mutex_unlock(ctx->lock);
}

static int nvblock_read(const struct nvb_config *cfg, uint32_t p, void *buffer)
{
        struct nvblock_ctx *ctx = (struct nvblock_ctx *)cfg->context;
        const uint32_t bsize = cfg->bsize;
	const uint32_t off = ctx->region_offset + p * bsize;
	uint8_t *buf = (uint8_t *)buffer;

        return flash_read(ctx->fldev, (off_t)off, buf, bsize);
}

static int nvblock_prog(const struct nvb_config *cfg, uint32_t p, 
                        const void *buffer)
{
        struct nvblock_ctx *ctx = (struct nvblock_ctx *)cfg->context;
        const uint32_t bsize = cfg->bsize;
	const uint32_t off = ctx->region_offset + p * bsize;
	const uint8_t *buf = (const uint8_t *)buffer;
        int rc;

        if (((p * bsize) % ctx->erase_block_size) == 0U) {
                rc = flash_erase(ctx->fldev, (off_t)off, ctx->erase_block_size);
                if (rc != 0) {
                        goto end;
                }
        }

        rc = flash_write(ctx->fldev, (off_t)off, buf, bsize);
end:
        return rc;
}

static int nvblock_move(const struct nvb_config *cfg, uint32_t pf, uint32_t pt)
{
        uint8_t tmp[cfg->bsize];
        int rc;

        rc = nvblock_read(cfg, pf, tmp);
        if (rc != 0) {
                return rc;
        }

        return nvblock_prog(cfg, pt, tmp);
}

static int nvblock_comp(const struct nvb_config *cfg, uint32_t p,
		        const void *buffer)
{
        uint8_t tmp[cfg->bsize];
        int rc;

        rc = nvblock_read(cfg, p, tmp);
        if (rc != 0) {
                return rc;
        }

        return memcmp(tmp, buffer, cfg->bsize);
}

bool nvblock_is_bad(const struct nvb_config *cfg, uint32_t p)
{
        return false;
}

bool nvblock_is_free(const struct nvb_config *cfg, uint32_t p)
{
        struct nvblock_ctx *ctx = (struct nvblock_ctx *)cfg->context;
        uint8_t tmp[cfg->bsize];
        const struct flash_parameters *fp = flash_get_parameters(ctx->fldev);

        memset(tmp, fp->erase_value, cfg->bsize);
        return nvblock_comp(cfg, p, tmp) == 0 ? true : false;
}

static void nvblock_mark_bad(const struct nvb_config *cfg, uint32_t p)
{
        return;
}

static int nvblock_sync(const struct nvb_config *cfg)
{
        return 0;
}


static int nvblockdisk_status(struct disk_info *disk)
{
        LOG_DBG("status : %s", disk->dev ? "okay" : "no media");
	if (!disk->dev) {
		return DISK_STATUS_NOMEDIA;
	}

	return DISK_STATUS_OK;
}

static int nvblockdisk_init(struct disk_info *disk)
{
	struct nvblock_data *nvbd = CONTAINER_OF(disk, struct nvblock_data, info);
        struct nvb_info *nvbi = nvbd->nvbi;
        struct nvb_config *nvbc = nvbd->nvbc;
        struct nvblock_ctx *ctx = (struct nvblock_ctx *)nvbc->context;

	
        LOG_DBG("Initializing nvblock disk");
        if (!device_is_ready(ctx->fldev)) {
                return -ENODEV;
        }

        disk->dev = ctx->fldev;

        return nvb_init(nvbi, nvbc);
}

static int nvblockdisk_read(struct disk_info *disk, uint8_t *buff,
			    uint32_t start_sector, uint32_t sector_count)
{
        struct nvblock_data *nvbd = CONTAINER_OF(disk, struct nvblock_data, info);
        struct nvb_info *nvbi = nvbd->nvbi;

        return nvb_read(nvbi, buff, start_sector, sector_count);
}


static int nvblockdisk_write(struct disk_info *disk, const uint8_t *buff,
				 uint32_t start_sector, uint32_t sector_count)
{
        struct nvblock_data *nvbd = CONTAINER_OF(disk, struct nvblock_data, info);
        struct nvb_info *nvbi = nvbd->nvbi;

        return nvb_write(nvbi, buff, start_sector, sector_count);
}

static int nvblockdisk_ioctl(struct disk_info *disk, uint8_t cmd, void *buff)
{
        struct nvblock_data *nvbd = CONTAINER_OF(disk, struct nvblock_data, info);
        struct nvb_info *nvbi = nvbd->nvbi;

        return nvb_ioctl(nvbi, cmd, buff);
}

static const struct disk_operations nvblockdisk_ops = {
	.init = nvblockdisk_init,
	.status = nvblockdisk_status,
	.read = nvblockdisk_read,
	.write = nvblockdisk_write,
	.ioctl = nvblockdisk_ioctl,
};

#define DT_DRV_COMPAT zephyr_nvblock_disk

#define PARTITION_PHANDLE(n) DT_PHANDLE_BY_IDX(DT_DRV_INST(n), partition, 0)
#define NVBLOCK_FLDEV(n)                                                        \
        DEVICE_DT_GET_OR_NULL(DT_MTD_FROM_FIXED_PARTITION(PARTITION_PHANDLE(n)))
#define NVBLOCK_REG_OFF(n) (DT_REG_ADDR(PARTITION_PHANDLE(n)))
#define NVBLOCK_REG_SIZE(n) (DT_REG_SIZE(PARTITION_PHANDLE(n)))
#define NVBLOCK_ERASEBLOCK_SIZE(n) (DT_INST_PROP(n, erase_block_size))
#define NVBLOCK_BSIZE(n) (DT_INST_PROP(n, sector_size))
#define NVBLOCK_BPG(n) (DT_INST_PROP(n, blocks_per_group))
#define NVBLOCK_GSIZE(n) (NVBLOCK_BSIZE(n) * NVBLOCK_BPG(n))
#define NVBLOCK_GCNT(n) (NVBLOCK_REG_SIZE(n) / NVBLOCK_GSIZE(n))
#define NVBLOCK_SPARE_SIZE(n) (DT_INST_PROP(n, spare_size))
#define NVBLOCK_SPGCNT(n) (NVBLOCK_SPARE_SIZE(n) / NVBLOCK_GSIZE(n))

#define DEFINE_NVBLOCK_DISK(n)                                                  \
        uint8_t nvblockdisk##n##meta[DT_INST_PROP(n, sector_size)];             \
        struct k_mutex nvblockdisk##n##mutex;                                   \
        struct nvblock_ctx nvblockdisk##n##ctx = {                              \
                .lock = &nvblockdisk##n##mutex,                                 \
                .fldev = NVBLOCK_FLDEV(n),                                      \
                .region_offset = NVBLOCK_REG_OFF(n),                            \
                .region_size = NVBLOCK_REG_SIZE(n),                             \
                .erase_block_size = NVBLOCK_ERASEBLOCK_SIZE(n),                 \
        };                                                                      \
        struct nvb_config nvblockdisk##n##config = {                            \
                .context = (void *)&nvblockdisk##n##ctx,                        \
                .meta = &nvblockdisk##n##meta[0],                                   \
                .init = nvblock_init,                                           \
                .lock = nvblock_lock,                                           \
                .unlock = nvblock_unlock,                                       \
                .read = nvblock_read,                                           \
                .prog = nvblock_prog,                                           \
                .move = nvblock_move,                                           \
                .comp = nvblock_comp,                                           \
                .is_bad = nvblock_is_bad,                                       \
                .is_free = nvblock_is_free,                                     \
                .mark_bad = nvblock_mark_bad,                                   \
                .sync = nvblock_sync,                                           \
                .bsize = NVBLOCK_BSIZE(n),                                      \
                .bpg = NVBLOCK_BPG(n),                                          \
                .gcnt = NVBLOCK_GCNT(n),                                        \
                .spgcnt = NVBLOCK_SPGCNT(n),                                     \
        };                                                                      \
        struct nvb_info nvblockdisk##n##info;

DT_INST_FOREACH_STATUS_OKAY(DEFINE_NVBLOCK_DISK)

#define DEFINE_NVBLOCK_DISK_DEVICE(n)						\
{										\
	.info = {								\
		.ops = &nvblockdisk_ops,					\
		.name = DT_INST_PROP(n, disk_name),				\
	},									\
        .nvbi = &nvblockdisk##n##info,                                          \
        .nvbc = &nvblockdisk##n##config                                         \
},

static struct nvblock_data nvblock_disks[] = {
	DT_INST_FOREACH_STATUS_OKAY(DEFINE_NVBLOCK_DISK_DEVICE)
};

static int nvblockdisks_init(void)
{
	int err = 0;

	for (int i = 0; i < ARRAY_SIZE(nvblock_disks); i++) {
		int rc;

		rc = disk_access_register(&nvblock_disks[i].info);
		if (rc < 0) {
			LOG_ERR("Failed to register disk %s error %d",
				nvblock_disks[i].info.name, rc);
			err = rc;
		}
	}

	return err;
}

SYS_INIT(nvblockdisks_init, APPLICATION, CONFIG_KERNEL_INIT_PRIORITY_DEFAULT);