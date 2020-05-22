cmake_minimum_required(VERSION 2.8.8)

list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake)

project(FASTD C ASM)
set(FASTD_VERSION "v19+")

include(arch)
include(config)
include(deps)
include(checks)

add_subdirectory(src)
