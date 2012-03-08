cmake_minimum_required(VERSION 2.6)
project(FASTD C)

set(CMAKE_MODULE_PATH ${FASTD_SOURCE_DIR})

find_package(NaCl)

set(WITH_CFXP ${NACL_FOUND} CACHE BOOL "Include curve25519-fhmqvc-xsalsa20-poly1305 method")

if(WITH_CFXP AND NOT NACL_FOUND)
  MESSAGE(FATAL_ERROR "NaCl: Networking and Cryptography library is required for the curve25519-fhmqvc-xsalsa20-poly1305 method")
endif(WITH_CFXP AND NOT NACL_FOUND)

configure_file(${FASTD_SOURCE_DIR}/config.h.in ${FASTD_BINARY_DIR}/config.h)

add_subdirectory(src)
