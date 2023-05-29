# SPDX-License-Identifier: Apache-2.0
# find_package(Zephyr) in order to load application boilerplate:
# http://docs.zephyrproject.org/application/application.html
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})

# Path to repository root.
get_filename_component(ROOT_DIR ${CMAKE_CURRENT_LIST_DIR} DIRECTORY)

# Path to nvblock library
set(NVBLOCK_DIR "${ROOT_DIR}/lib")
assert_exists(NVBLOCK_DIR)

if(CONFIG_NVBLOCK)

zephyr_include_directories(
    ${ROOT_DIR}/lib/include
)

zephyr_library_sources(
    ${NVBLOCK_DIR}/src/nvblock.c
)

endif()

add_subdirectory(drivers)