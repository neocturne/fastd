set(METHODS method_null.c)

if(WITH_METHOD_XSALSA20_POLY1305)
  list(APPEND METHODS method_xsalsa20_poly1305.c)
endif(WITH_METHOD_XSALSA20_POLY1305)

if(WITH_METHOD_AES128_GCM)
  list(APPEND METHODS method_aes128_gcm.c)
endif(WITH_METHOD_AES128_GCM)

include_directories(${CMAKE_CURRENT_SOURCE_DIR} ${FASTD_BINARY_DIR} ${CMAKE_CURRENT_BINARY_DIR} ${UECC_INCLUDE_DIR} ${NACL_INCLUDE_DIR})

FLEX_TARGET(fastd_config_lex config.l ${CMAKE_CURRENT_BINARY_DIR}/config.ll.c)
BISON_TARGET(fastd_config_parse config.y ${CMAKE_CURRENT_BINARY_DIR}/config.yy.c)

add_executable(fastd
  fastd.c
  config.c
  crypto.c
  crypto_linux.c
  handshake.c
  peer.c
  printf.c
  queue.c
  random.c
  resolve.c
  task.c
  protocol_ec25519_fhmqvc.c
  ${FLEX_fastd_config_lex_OUTPUTS}
  ${BISON_fastd_config_parse_OUTPUTS}
  ${METHODS}
)
set_target_properties(fastd PROPERTIES COMPILE_FLAGS -pthread LINK_FLAGS -pthread)
target_link_libraries(fastd rt ${UECC_LIBRARY} ${NACL_LIBRARY})

install(TARGETS fastd RUNTIME DESTINATION sbin)
