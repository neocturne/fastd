cmake_minimum_required(VERSION 2.8.3)
project(FASTD C ASM)

set(CMAKE_MODULE_PATH ${FASTD_SOURCE_DIR}/cmake)
set(FASTD_VERSION "v11+")

include(arch)
include(config)
include(deps)
include(checks)

add_subdirectory(src)
