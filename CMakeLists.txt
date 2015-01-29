cmake_minimum_required(VERSION 2.8.3)

set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake)
cmake_policy(SET CMP0017 OLD) # Prefer modules in our module directory

project(FASTD C ASM)
set(FASTD_VERSION "v17+")

include(arch)
include(config)
include(deps)
include(checks)

set(DOXYFILE_SOURCE_DIR ${FASTD_SOURCE_DIR}/src)
include(UseDoxygen OPTIONAL)

add_subdirectory(src)
