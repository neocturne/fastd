set(METHODS method_null.c)
set(FASTD_INCLUDES ${FASTD_BINARY_DIR})
set(FASTD_LIBS "")

if(WITH_CFXP)
  set(METHODS ${METHODS} method_curve25519_fhmqvc_xsalsa20_poly1305.c)
  set(FASTD_INCLUDES ${FASTD_INCLUDES} ${NACL_INCLUDE_DIR})
  set(FASTD_LIBS ${FASTD_LIBS} ${NACL_LIBRARY})
endif(WITH_CFXP)

include_directories(${FASTD_INCLUDES})

add_executable(fastd fastd.c handshake.c peer.c printf.c queue.c task.c ${METHODS})
target_link_libraries(fastd rt ${FASTD_LIBS})
