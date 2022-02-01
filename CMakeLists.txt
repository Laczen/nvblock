# SPDX-License-Identifier: Apache-2.0
if(CONFIG_NVBLOCK)
add_library(nvblock INTERFACE)

zephyr_include_directories(lib)

zephyr_library()
zephyr_library_sources(
    lib/nvblock.c
    )
zephyr_library_link_libraries(nvblock)
endif()