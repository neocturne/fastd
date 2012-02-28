cmake_minimum_required(VERSION 2.6)
project(FASTD C)

set(CMAKE_MODULE_PATH ${FASTD_SOURCE_DIR})

#configure_file(${FAST_SOURCE_DIR}/config.h.in ${FAST_BINARY_DIR}/config.h)

add_subdirectory(src)
