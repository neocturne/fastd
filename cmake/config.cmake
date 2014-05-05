if(${CMAKE_SYSTEM_NAME} MATCHES "Linux")
  set(LINUX TRUE)
else()
  set(LINUX FALSE)
endif()


set(USE_BINDTODEVICE ${LINUX})
set(USE_EPOLL ${LINUX})
set(USE_FREEBIND ${LINUX})
set(USE_PMTU ${LINUX})
set(USE_PKTINFO ${LINUX})
set(USE_PACKET_MARK ${LINUX})

if(${CMAKE_SYSTEM_NAME} MATCHES "OpenBSD")
  set(USE_MULTIAF_BIND FALSE)
else()
  set(USE_MULTIAF_BIND TRUE)
endif()

set(WITH_CAPABILITIES ${LINUX} CACHE BOOL "Include support for POSIX capabilities")

set(ENABLE_LIBSODIUM FALSE CACHE BOOL "Use libsodium instead of NaCl")
set(ENABLE_OPENSSL FALSE CACHE BOOL "Enable crypto implementations using OpenSSL")

if(LINUX)
  set(ENABLE_SYSTEMD TRUE CACHE BOOL "Enable systemd support")
endif(LINUX)

set(WITH_CMDLINE_USER TRUE CACHE BOOL "Include support for setting user/group related options on the command line")
set(WITH_CMDLINE_LOGGING TRUE CACHE BOOL "Include support for setting logging related options on the command line")
set(WITH_CMDLINE_OPERATION TRUE CACHE BOOL "Include support for setting options related to the VPN operation (like mode, interface, encryption method) on the command line")
set(WITH_CMDLINE_COMMANDS TRUE CACHE BOOL "Include support for setting handler scripts (e.g. --on-up) on the command line")

set(WITH_VERIFY TRUE CACHE BOOL "Include support for on-verify handlers")

set(MAX_CONFIG_DEPTH 10 CACHE STRING "Maximum config include depth")


# Ensure the value is numeric
math(EXPR MAX_CONFIG_DEPTH_NUM ${MAX_CONFIG_DEPTH})
