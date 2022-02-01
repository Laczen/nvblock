# SPDX-License-Identifier: Apache-2.0
if(CONFIG_NVBLOCK)
add_library(nvblock INTERFACE)

target_include_directories(nvblock INTERFACE lib)

zephyr_library()
zephyr_library_sources(
    lib/nvblock.c
    )
zephyr_library_link_libraries(nvblock)
target_link_libraries(nvblock INTERFACE zephyr_interface)