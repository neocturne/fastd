cmake_minimum_required(VERSION 2.6)
project(FASTD C)

set(CMAKE_MODULE_PATH ${FASTD_SOURCE_DIR})

find_package(BISON 2.5 REQUIRED)
find_package(FLEX REQUIRED)

find_package(UECC REQUIRED)
find_package(NaCl REQUIRED)


set(WITH_METHOD_XSALSA20_POLY1305 TRUE CACHE BOOL "Include xsalsa20-poly1305 method")

set(MAX_CONFIG_DEPTH 10 CACHE STRING "Maximum config include depth")

# Ensure the value is numeric
math(EXPR MAX_CONFIG_DEPTH_NUM ${MAX_CONFIG_DEPTH})

configure_file(${FASTD_SOURCE_DIR}/config.h.in ${FASTD_BINARY_DIR}/config.h)

add_subdirectory(src)
