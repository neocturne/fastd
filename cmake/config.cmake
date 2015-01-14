if(${CMAKE_SYSTEM_NAME} MATCHES "Linux")
  set(LINUX TRUE)
else()
  set(LINUX FALSE)
endif()

if(${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
  set(DARWIN TRUE)
else()
  set(DARWIN FALSE)
endif()


set(USE_BINDTODEVICE ${LINUX})
set(USE_EPOLL ${LINUX})
set(USE_FREEBIND ${LINUX})
set(USE_PMTU ${LINUX})
set(USE_PKTINFO ${LINUX})
set(USE_PACKET_MARK ${LINUX})

# OSX doesn't support poll on devices...
set(USE_SELECT ${DARWIN})

if(${CMAKE_SYSTEM_NAME} MATCHES "OpenBSD")
  set(USE_MULTIAF_BIND FALSE)
else()
  set(USE_MULTIAF_BIND TRUE)
endif()

set(WITH_CAPABILITIES ${LINUX} CACHE BOOL "Include support for POSIX capabilities")

set(ENABLE_LIBSODIUM TRUE CACHE BOOL "Use libsodium instead of NaCl")
set(ENABLE_OPENSSL FALSE CACHE BOOL "Enable crypto implementations using OpenSSL")

set(ENABLE_LTO FALSE CACHE BOOL "Enable link-time optimization")

if(LINUX AND NOT ANDROID)
  set(ENABLE_SYSTEMD TRUE CACHE BOOL "Enable systemd support")
endif(LINUX AND NOT ANDROID)

set(WITH_CMDLINE_USER TRUE CACHE BOOL "Include support for setting user/group related options on the command line")
set(WITH_CMDLINE_LOGGING TRUE CACHE BOOL "Include support for setting logging related options on the command line")
set(WITH_CMDLINE_OPERATION TRUE CACHE BOOL "Include support for setting options related to the VPN operation (like mode, interface, encryption method) on the command line")
set(WITH_CMDLINE_COMMANDS TRUE CACHE BOOL "Include support for setting handler scripts (e.g. --on-up) on the command line")

set(WITH_DYNAMIC_PEERS TRUE CACHE BOOL "Include support for dynamic peers (using on-verify handlers)")
set(WITH_STATUS_SOCKET TRUE CACHE BOOL "Include support for the status socket")

set(MAX_CONFIG_DEPTH 10 CACHE STRING "Maximum config include depth")


# Ensure the value is numeric
math(EXPR MAX_CONFIG_DEPTH_NUM ${MAX_CONFIG_DEPTH})
