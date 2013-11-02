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

set(USE_LIBSODIUM FALSE CACHE BOOL "Use libsodium instead of NaCl")

set(WITH_CMDLINE_USER TRUE CACHE BOOL "Include support for setting user/group related options on the command line")
set(WITH_CMDLINE_LOGGING TRUE CACHE BOOL "Include support for setting logging related options on the command line")
set(WITH_CMDLINE_OPERATION TRUE CACHE BOOL "Include support for setting options related to the VPN operation (like mode, interface, encryption method) on the command line")
set(WITH_CMDLINE_COMMANDS TRUE CACHE BOOL "Include support for setting handler scripts (e.g. --on-up) on the command line")

set(MAX_CONFIG_DEPTH 10 CACHE STRING "Maximum config include depth")

set(WITH_CIPHER_AES128_CTR TRUE CACHE BOOL "Include the AES128-CTR cipher algorithm")
set(WITH_CIPHER_AES128_CTR_NACL TRUE CACHE BOOL "Include the AES128-CTR implementation from the NaCl library")

set(WITH_MAC_GHASH TRUE CACHE BOOL "Include the GHASH MAC algorithm")
set(WITH_MAC_GHASH_BUILTIN TRUE CACHE BOOL "Include the built-in GHASH implementation")

set(WITH_METHOD_XSALSA20_POLY1305 TRUE CACHE BOOL "Include xsalsa20-poly1305 method")
set(WITH_METHOD_GENERIC_GCM TRUE CACHE BOOL "Include generic gcm method")


# Ensure the value is numeric
math(EXPR MAX_CONFIG_DEPTH_NUM ${MAX_CONFIG_DEPTH})
