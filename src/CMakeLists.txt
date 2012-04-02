set(PROTOCOLS protocol_null.c)
set(FASTD_INCLUDES ${CMAKE_CURRENT_SOURCE_DIR} ${FASTD_BINARY_DIR} ${CMAKE_CURRENT_BINARY_DIR})
set(FASTD_LIBS "")

if(WITH_PROTOCOL_ECFXP)
  list(APPEND PROTOCOLS protocol_ec25519_fhmqvc_xsalsa20_poly1305.c)
  list(APPEND FASTD_INCLUDES ${UECC_INCLUDE_DIR} ${NACL_INCLUDE_DIR})
  list(APPEND FASTD_LIBS ${UECC_LIBRARY} ${NACL_LIBRARY})
endif(WITH_PROTOCOL_ECFXP)

include_directories(${FASTD_INCLUDES})

FLEX_TARGET(fastd_config_lex config.l ${CMAKE_CURRENT_BINARY_DIR}/config.ll.c)
BISON_TARGET(fastd_config_parse config.y ${CMAKE_CURRENT_BINARY_DIR}/config.yy.c)

add_executable(fastd
  fastd.c
  config.c
  handshake.c
  peer.c
  printf.c
  queue.c
  random.c
  task.c
  ${FLEX_fastd_config_lex_OUTPUTS}
  ${BISON_fastd_config_parse_OUTPUTS}
  ${PROTOCOLS}
)
target_link_libraries(fastd rt ${FASTD_LIBS})

install(TARGETS fastd RUNTIME DESTINATION sbin)
