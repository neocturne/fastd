set(METHODS method_null.c)
set(FASTD_INCLUDES ${FASTD_BINARY_DIR})
set(FASTD_LIBS "")

if(WITH_METHOD_ECFXP)
  set(METHODS ${METHODS} method_ec25519_fhmqvc_xsalsa20_poly1305.c)
  set(FASTD_INCLUDES ${FASTD_INCLUDES} ${UECC_INCLUDE_DIR} ${NACL_INCLUDE_DIR})
  set(FASTD_LIBS ${FASTD_LIBS} ${UECC_LIBRARY} ${NACL_LIBRARY})
endif(WITH_METHOD_ECFXP)

include_directories(${FASTD_INCLUDES})

add_executable(fastd fastd.c configure.c handshake.c peer.c printf.c queue.c task.c ${METHODS})
target_link_libraries(fastd rt ${FASTD_LIBS})
