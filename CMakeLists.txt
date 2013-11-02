cmake_minimum_required(VERSION 2.8.3)
project(FASTD C)

set(CMAKE_MODULE_PATH ${FASTD_SOURCE_DIR})
set(FASTD_VERSION "v10+")


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


set(WITH_CIPHER_AES128_CTR TRUE CACHE BOOL "Include the AES128-CTR cipher algorithm")
set(WITH_CIPHER_AES128_CTR_NACL TRUE CACHE BOOL "Include the AES128-CTR implementation from the NaCl library")

set(WITH_CRYPTO_GHASH_BUILTIN TRUE CACHE BOOL "Include the built-in GHASH implementation")

set(WITH_METHOD_XSALSA20_POLY1305 TRUE CACHE BOOL "Include xsalsa20-poly1305 method")
set(WITH_METHOD_GENERIC_GCM TRUE CACHE BOOL "Include generic gcm method")

set(USE_LIBSODIUM FALSE CACHE BOOL "Use libsodium instead of NaCl")


set(MAX_CONFIG_DEPTH 10 CACHE STRING "Maximum config include depth")


if(WITH_CRYPTO_GHASH_BUILTIN)
  set(WITH_CRYPTO_GHASH TRUE)
endif(WITH_CRYPTO_GHASH_BUILTIN)


# Ensure the value is numeric
math(EXPR MAX_CONFIG_DEPTH_NUM ${MAX_CONFIG_DEPTH})

set(USE_CRYPTO_GHASH FALSE)

if(WITH_METHOD_AES128_GCM)
  set(USE_CRYPTO_GHASH TRUE)
endif(WITH_METHOD_AES128_GCM)


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


set(NACL_INCLUDE_DIRS "")
set(NACL_CFLAGS_OTHER "")
set(NACL_LIBRARY_DIRS "")
set(NACL_LIBRARIES "")
set(NACL_LDFLAGS_OTHER "")

if(WITH_METHOD_XSALSA20_POLY1305 OR WITH_CIPHER_AES128_CTR_NACL)
  if(USE_LIBSODIUM)
    pkg_check_modules(SODIUM REQUIRED libsodium)

    set(NACL_INCLUDE_DIRS "${SODIUM_INCLUDE_DIRS}")
    foreach(dir "${SODIUM_INCLUDEDIR}" ${SODIUM_INCLUDE_DIRS})
      list(APPEND NACL_INCLUDE_DIRS "${dir}/sodium")
    endforeach(dir)

    set(NACL_CFLAGS_OTHER "${SODIUM_CFLAGS_OTHER}")
    set(NACL_LIBRARY_DIRS "${SODIUM_LIBRARY_DIRS}")
    set(NACL_LIBRARIES "${SODIUM_LIBRARIES}")
    set(NACL_LDFLAGS_OTHER "${SODIUM_LDFLAGS_OTHER}")
  else(USE_LIBSODIUM)
    find_package(NaCl REQUIRED)

    set(NACL_INCLUDE_DIRS "${NACL_INCLUDE_DIR}")
    set(NACL_LIBRARIES "${NACL_LIBRARY}")
  endif(USE_LIBSODIUM)
endif()


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


configure_file(${FASTD_SOURCE_DIR}/fastd_config.h.in ${FASTD_BINARY_DIR}/fastd_config.h)

add_custom_target(
    version
    COMMAND echo "#ifndef _FASTD_VERSION_H_" > ${FASTD_BINARY_DIR}/fastd_version.h.new
    COMMAND echo "#define _FASTD_VERSION_H_" >> ${FASTD_BINARY_DIR}/fastd_version.h.new
    COMMAND sh -c "echo \"#define FASTD_VERSION \\\"$(git --git-dir=./.git describe --dirty 2>/dev/null || echo ${FASTD_VERSION})\\\"\"" >> ${FASTD_BINARY_DIR}/fastd_version.h.new
    COMMAND echo "#endif /* _FASTD_VERSION_H_ */" >> ${FASTD_BINARY_DIR}/fastd_version.h.new
    COMMAND cmp -s ${FASTD_BINARY_DIR}/fastd_version.h.new ${FASTD_BINARY_DIR}/fastd_version.h && rm ${FASTD_BINARY_DIR}/fastd_version.h.new || mv ${FASTD_BINARY_DIR}/fastd_version.h.new ${FASTD_BINARY_DIR}/fastd_version.h
    WORKING_DIRECTORY "${FASTD_SOURCE_DIR}"
    VERBATIM
)

add_subdirectory(src)
