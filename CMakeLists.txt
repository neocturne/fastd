cmake_minimum_required(VERSION 2.8.3)
project(FASTD C)

set(CMAKE_MODULE_PATH ${FASTD_SOURCE_DIR})
set(FASTD_VERSION "v9")


if(${CMAKE_SYSTEM_NAME} MATCHES "Linux")
  set(LINUX TRUE)
else()
  set(LINUX FALSE)
endif()


set(USE_BINDTODEVICE ${LINUX})
set(USE_PMTU ${LINUX})
set(USE_PKTINFO ${LINUX})

if(${CMAKE_SYSTEM_NAME} MATCHES "OpenBSD")
  set(USE_MULTIAF_BIND FALSE)
else()
  set(USE_MULTIAF_BIND TRUE)
endif()


set(WITH_CAPABILITIES ${LINUX} CACHE BOOL "Include support for POSIX capabilities")
set(WITH_CMDLINE_USER TRUE CACHE BOOL "Include support for setting user/group related options on the command line")
set(WITH_CMDLINE_LOGGING TRUE CACHE BOOL "Include support for setting logging related options on the command line")
set(WITH_CMDLINE_OPERATION TRUE CACHE BOOL "Include support for setting options related to the VPN operation (like mode, interface, encryption method) on the command line")
set(WITH_CMDLINE_COMMANDS TRUE CACHE BOOL "Include support for setting handler scripts (e.g. --on-up) on the command line")


set(WITH_CRYPTO_AES128CTR_NACL TRUE CACHE BOOL "Include the AES128-CTR implementation from the NaCl library")
set(WITH_CRYPTO_GHASH_BUILTIN TRUE CACHE BOOL "Include the built-in GHASH implementation")

if(LINUX)
  set(WITH_CRYPTO_AES128CTR_LINUX TRUE CACHE BOOL "Support using the AES128-CTR implementation in the Linux kernel")
  set(WITH_CRYPTO_GHASH_LINUX TRUE CACHE BOOL "Support using the GHASH implementation in the Linux kernel")
endif(LINUX)

set(WITH_METHOD_XSALSA20_POLY1305 TRUE CACHE BOOL "Include xsalsa20-poly1305 method")
set(WITH_METHOD_AES128_GCM TRUE CACHE BOOL "Include aes128-gcm method")


set(MAX_CONFIG_DEPTH 10 CACHE STRING "Maximum config include depth")


if(WITH_CRYPTO_AES128CTR_NACL OR WITH_CRYPTO_AES128CTR_LINUX)
  set(WITH_CRYPTO_AES128CTR TRUE)
endif(WITH_CRYPTO_AES128CTR_NACL OR WITH_CRYPTO_AES128CTR_LINUX)

if(WITH_CRYPTO_GHASH_BUILTIN OR WITH_CRYPTO_GHASH_LINUX)
  set(WITH_CRYPTO_GHASH TRUE)
endif(WITH_CRYPTO_GHASH_BUILTIN OR WITH_CRYPTO_GHASH_LINUX)


# Ensure the value is numeric
math(EXPR MAX_CONFIG_DEPTH_NUM ${MAX_CONFIG_DEPTH})

set(USE_CRYPTO_AES128CTR FALSE)
set(USE_CRYPTO_GHASH FALSE)

if(WITH_METHOD_AES128_GCM)
  set(USE_CRYPTO_AES128CTR TRUE)
  set(USE_CRYPTO_GHASH TRUE)
endif(WITH_METHOD_AES128_GCM)


if(USE_CRYPTO_AES128CTR AND NOT WITH_CRYPTO_AES128CTR)
  MESSAGE(FATAL_ERROR "No AES128-CTR implementation was selected, but a selected method needs it.")
endif(USE_CRYPTO_AES128CTR AND NOT WITH_CRYPTO_AES128CTR)

if(USE_CRYPTO_GHASH AND NOT WITH_CRYPTO_GHASH)
  MESSAGE(FATAL_ERROR "No GHASH implementation was selected, but a selected method needs it.")
endif(USE_CRYPTO_GHASH AND NOT WITH_CRYPTO_GHASH)


find_package(BISON 2.5 REQUIRED)

set(CMAKE_THREAD_PREFER_PTHREAD TRUE)
find_package(Threads)
if(NOT CMAKE_USE_PTHREADS_INIT)
  MESSAGE(FATAL_ERROR "No pthread support found.")
endif(NOT CMAKE_USE_PTHREADS_INIT)

find_package(PkgConfig REQUIRED)
pkg_check_modules(UECC REQUIRED libuecc>=3)


if(WITH_METHOD_XSALSA20_POLY1305 OR WITH_CRYPTO_AES128CTR_NACL)
  find_package(NaCl REQUIRED)
else(WITH_METHOD_XSALSA20_POLY1305 OR WITH_CRYPTO_AES128CTR_NACL)
  set(NACL_INCLUDE_DIR "")
  set(NACL_LIBRARY "")
endif(WITH_METHOD_XSALSA20_POLY1305 OR WITH_CRYPTO_AES128CTR_NACL)


if(WITH_CAPABILITIES)
  find_package(CAP REQUIRED)
else(WITH_CAPABILITIES)
  set(CAP_INCLUDE_DIR "")
  set(CAP_LIBRARY "")
endif(WITH_CAPABILITIES)


include(CheckCSourceCompiles)
include(CheckPrototypeDefinition)
include(CheckSymbolExists)
include(CheckTypeSize)
set(CMAKE_REQUIRED_DEFINITIONS "-D_GNU_SOURCE")


check_c_source_compiles("
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

int main() {
	return AI_ADDRCONFIG;
}
" HAVE_AI_ADDRCONFIG)


check_prototype_definition("get_current_dir_name" "char *get_current_dir_name(void)" "NULL" "unistd.h" HAVE_GET_CURRENT_DIR_NAME)


set(RT_LIBRARY "")
check_symbol_exists("clock_gettime" "time.h" HAVE_CLOCK_GETTIME)

if(NOT HAVE_CLOCK_GETTIME)
  set(RT_LIBRARY "rt")
  list(APPEND CMAKE_REQUIRED_LIBRARIES "rt")

  check_symbol_exists("clock_gettime" "time.h" HAVE_CLOCK_GETTIME_RT)
  if(NOT HAVE_CLOCK_GETTIME_RT)
      message(FATAL_ERROR "clock_gettime() not found")
  endif(NOT HAVE_CLOCK_GETTIME_RT)
endif(NOT HAVE_CLOCK_GETTIME)


set(CMAKE_EXTRA_INCLUDE_FILES "netinet/if_ether.h")
check_type_size("struct ethhdr" SIZEOF_ETHHDR)
string(COMPARE NOTEQUAL "${SIZEOF_ETHHDR}" "" HAVE_ETHHDR)


configure_file(${FASTD_SOURCE_DIR}/config.h.in ${FASTD_BINARY_DIR}/config.h)

add_subdirectory(src)
