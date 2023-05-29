/*
 * Copyright (c) 2012-2014 Wind River Systems, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/kernel.h>
#include <zephyr/storage/disk_access.h>

static const char *disk_pdrv = "NAND";
static uint32_t disk_sector_count;
static uint32_t disk_sector_size;

void main(void)
{
        int rc;

	printk("Hello World! %s\n", CONFIG_BOARD);
        rc = disk_access_init(disk_pdrv);
        printk("Init returned %d\n", rc);
}
