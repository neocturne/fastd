cmake_minimum_required(VERSION 2.6)
project(FASTD C)

set(CMAKE_MODULE_PATH ${FASTD_SOURCE_DIR})

find_package(UECC)
find_package(NaCl)

if(UECC_FOUND AND NACL_FOUND)
  set(CRYPTO_FOUND TRUE)
endif(UECC_FOUND AND NACL_FOUND)

set(WITH_METHOD_ECFXP ${CRYPTO_FOUND} CACHE BOOL "Include ec25519-fhmqvc-xsalsa20-poly1305 method")

if(WITH_METHOD_ECFXP AND NOT CRYPTO_FOUND)
  MESSAGE(FATAL_ERROR "libuecc and NaCl are required for the ec25519-fhmqvc-xsalsa20-poly1305 method")
endif(WITH_METHOD_ECFXP AND NOT CRYPTO_FOUND)

configure_file(${FASTD_SOURCE_DIR}/config.h.in ${FASTD_BINARY_DIR}/config.h)

add_subdirectory(src)
