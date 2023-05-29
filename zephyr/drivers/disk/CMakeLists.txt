# Copyright (c) 2023 Laczen
# SPDX-License-Identifier: Apache-2.0

zephyr_library()
zephyr_library_sources_ifdef(CONFIG_DISK_DRIVER_NVBLOCK nvblockdisk.c)