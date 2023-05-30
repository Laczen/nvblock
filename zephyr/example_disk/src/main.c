/*
 * Copyright (c) 2023 Laczen.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/kernel.h>
#include <zephyr/storage/disk_access.h>
#include <string.h>
#include "nvblock/nvblock.h"

static const char *disk_pdrv = "NVBL";
static uint32_t disk_sector_count;
static uint32_t disk_sector_size;
extern struct nvb_info nvblockdisk0info;
struct nvb_info *inf = &nvblockdisk0info;

void main(void)
{
        int rc;

	printk("Hello World! %s\n", CONFIG_BOARD);
        rc = disk_access_init(disk_pdrv);
        printk("Init returned %d\n", rc);
        rc = disk_access_ioctl(disk_pdrv, 0x01, &disk_sector_count);
        printk("Disk has %d sectors\n", disk_sector_count);
        rc = disk_access_ioctl(disk_pdrv, 0x02, &disk_sector_size);
        printk("Disk has sectors of %d byte\n", disk_sector_size);
        rc = disk_access_status(disk_pdrv);
        printk("Disk access status [%d]\n", rc);

        uint8_t wrdata[disk_sector_size];
        uint8_t rddata[disk_sector_size];
        uint8_t mod = 0U;

        for (int i = 0; i < 8 * disk_sector_count; i++) {
                uint32_t wr_sector = i % disk_sector_count;

                if (wr_sector == 0U) {
                        mod++;
                        printk("Disk info epoch [%d] head [%d]\n", inf->epoch,
                               inf->head);
                }
                
                memset(wrdata, (uint8_t)(mod + i), sizeof(wrdata));
                rc = disk_access_write(disk_pdrv, wrdata, wr_sector, 1);
                rc = disk_access_read(disk_pdrv, rddata, wr_sector, 1);
                if (memcmp(rddata, wrdata, sizeof(wrdata)) != 0) {
                        printk("Compare failed at %d\n", i);
                        break;
                }
        }

        printk("Finished writing and reading\n");
        printk("Disk info epoch [%d] head [%d]\n", inf->epoch, inf->head);
}
