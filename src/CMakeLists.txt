set_directory_properties(PROPERTIES COMPILE_DEFINITIONS _GNU_SOURCE)
set(FASTD_CFLAGS "-Wall -pthread ${UECC_CFLAGS_OTHER}")

include_directories(BEFORE ${FASTD_BINARY_DIR} ${CMAKE_CURRENT_BINARY_DIR} ${CMAKE_CURRENT_SOURCE_DIR} ${CAP_INCLUDE_DIR} ${NACL_INCLUDE_DIR})
link_directories(${UECC_LIBRARY_DIRS})


add_subdirectory(protocols)
add_subdirectory(methods)


BISON_TARGET(fastd_config_parse config.y ${CMAKE_CURRENT_BINARY_DIR}/config.yy.c)

add_executable(fastd
  fastd.c
  capabilities.c
  config.c
  crypto.c
  crypto_linux.c
  handshake.c
  lex.c
  options.c
  peer.c
  printf.c
  random.c
  receive.c
  resolve.c
  send.c
  sha256.c
  shell.c
  socket.c
  tuntap.c
  ${BISON_fastd_config_parse_OUTPUTS}
  ${PROTOCOL_SOURCES}
  ${METHOD_SOURCES}
)
set_property(TARGET fastd PROPERTY COMPILE_FLAGS "${FASTD_CFLAGS}")
set_property(TARGET fastd PROPERTY LINK_FLAGS "-pthread ${UECC_LDFLAGS_OTHER}")
target_link_libraries(fastd ${RT_LIBRARY} ${CAP_LIBRARY} ${UECC_LIBRARIES} ${NACL_LIBRARY})

add_dependencies(fastd version)

install(TARGETS fastd RUNTIME DESTINATION bin)
