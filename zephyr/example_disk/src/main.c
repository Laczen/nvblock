/*
 * Copyright (c) 2012-2014 Wind River Systems, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/kernel.h>
#include <zephyr/storage/disk_access.h>
#include <string.h>

static const char *disk_pdrv = "NVBL";
static uint32_t disk_sector_count;
static uint32_t disk_sector_size;

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

        uint8_t wrdata[disk_sector_size];
        uint8_t rddata[disk_sector_size];

        memset(wrdata, 0xa5, sizeof(wrdata));
        rc = disk_access_write(disk_pdrv, wrdata, 0, 1);
        printk("Disk write first sector returned %d\n", rc);
        rc = disk_access_read(disk_pdrv, rddata, 0, 1);
        printk("Disk read first sector returned %d\n", rc);
        printk("Data comparison: %s\n", 
               memcmp(rddata, wrdata, sizeof(wrdata)) == 0 ? "Success": "Fail");

        rc = disk_access_write(disk_pdrv, wrdata, disk_sector_count - 1, 1);
        printk("Disk write last sector returned %d\n", rc);
        rc = disk_access_read(disk_pdrv, rddata, disk_sector_count - 1, 1);
        printk("Disk read last sector returned %d\n", rc);
        printk("Data comparison: %s\n", 
               memcmp(rddata, wrdata, sizeof(wrdata)) == 0 ? "Success": "Fail");
}
