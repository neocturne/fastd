set(METHODS method_null.c)

if(WITH_METHOD_XSALSA20_POLY1305)
  list(APPEND METHODS method_xsalsa20_poly1305.c)
endif(WITH_METHOD_XSALSA20_POLY1305)

if(WITH_METHOD_AES128_GCM)
  list(APPEND METHODS method_aes128_gcm.c)
endif(WITH_METHOD_AES128_GCM)

include_directories(${CMAKE_CURRENT_SOURCE_DIR} ${FASTD_BINARY_DIR} ${CMAKE_CURRENT_BINARY_DIR} ${CAP_INCLUDE_DIR} ${UECC_INCLUDE_DIRS} ${NACL_INCLUDE_DIR})
link_directories(${UECC_LIBRARY_DIRS})

FLEX_TARGET(fastd_config_lex config.l ${CMAKE_CURRENT_BINARY_DIR}/config.ll.c)
BISON_TARGET(fastd_config_parse config.y ${CMAKE_CURRENT_BINARY_DIR}/config.yy.c)

add_executable(fastd
  fastd.c
  capabilities.c
  config.c
  crypto.c
  crypto_linux.c
  handshake.c
  peer.c
  printf.c
  queue.c
  random.c
  resolve.c
  shell.c
  task.c
  protocol_ec25519_fhmqvc.c
  ${FLEX_fastd_config_lex_OUTPUTS}
  ${BISON_fastd_config_parse_OUTPUTS}
  ${METHODS}
)
set_target_properties(fastd PROPERTIES COMPILE_FLAGS -pthread ${UECC_CFLAGS_OTHER} LINK_FLAGS -pthread ${UECC_LDFLAGS_OTHER})
target_link_libraries(fastd rt ${CAP_LIBRARY} ${UECC_LIBRARIES} ${NACL_LIBRARY})

add_custom_target(
    version
    COMMAND echo "#ifndef _FASTD_VERSION_H_" > ${CMAKE_CURRENT_BINARY_DIR}/version.h.new
    COMMAND echo "#define _FASTD_VERSION_H_" >> ${CMAKE_CURRENT_BINARY_DIR}/version.h.new
    COMMAND sh -c "echo \"#define FASTD_VERSION \\\"\$(git --git-dir=${FASTD_SOURCE_DIR}/.git --work-tree=${FASTD_SOURCE_DIR} describe --dirty 2>/dev/null || echo ${FASTD_VERSION})\\\"\"" >> ${CMAKE_CURRENT_BINARY_DIR}/version.h.new
    COMMAND echo "#endif /* _FASTD_VERSION_H_ */" >> ${CMAKE_CURRENT_BINARY_DIR}/version.h.new
    COMMAND cmp -s ${CMAKE_CURRENT_BINARY_DIR}/version.h.new ${CMAKE_CURRENT_BINARY_DIR}/version.h && rm ${CMAKE_CURRENT_BINARY_DIR}/version.h.new || mv ${CMAKE_CURRENT_BINARY_DIR}/version.h.new ${CMAKE_CURRENT_BINARY_DIR}/version.h
    WORKING_DIRECTORY "${FASTD_SOURCE_DIR}"
    VERBATIM
)

add_dependencies(fastd version)

install(TARGETS fastd RUNTIME DESTINATION bin)
