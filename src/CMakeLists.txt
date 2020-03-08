set_property(DIRECTORY PROPERTY COMPILE_DEFINITIONS _GNU_SOURCE __APPLE_USE_RFC_3542)
set(FASTD_CFLAGS "${PTHREAD_CFLAGS} -std=c99 ${LIBUECC_CFLAGS_OTHER} ${LIBNACL_CFLAGS_OTHER} ${JSON_C_CFLAGS_OTHER} ${CFLAGS_LTO} -Wall")

include_directories(${FASTD_SOURCE_DIR} ${FASTD_BINARY_DIR}/gen)


include(generate_version)

include(fastd_module)
add_subdirectory(protocols)
add_subdirectory(methods)
add_subdirectory(crypto)

include(check_reqs)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/build.h.in ${CMAKE_BINARY_DIR}/gen/generated/build.h)

BISON_TARGET(fastd_config_parse config.y ${CMAKE_BINARY_DIR}/gen/generated/config.yy.c)

add_executable(fastd
  android.c
  async.c
  capabilities.c
  config.c
  handshake.c
  hkdf_sha256.c
  fastd.c
  iface.c
  lex.c
  log.c
  options.c
  peer.c
  peer_hashtable.c
  poll.c
  pqueue.c
  random.c
  receive.c
  resolve.c
  send.c
  sha256.c
  shell.c
  socket.c
  status.c
  task.c
  time.c
  vector.c
  verify.c
  ${BISON_fastd_config_parse_OUTPUTS}
)
set_property(TARGET fastd PROPERTY COMPILE_FLAGS "${FASTD_CFLAGS}")
set_property(TARGET fastd PROPERTY LINK_FLAGS "${PTHREAD_LDFLAGS} ${LIBUECC_LDFLAGS_OTHER} ${NACL_LDFLAGS_OTHER} ${JSON_C_LDFLAGS_OTHER} ${LDFLAGS_LTO}")
set_property(TARGET fastd APPEND PROPERTY INCLUDE_DIRECTORIES ${LIBCAP_INCLUDE_DIR} ${NACL_INCLUDE_DIRS} ${JSON_C_INCLUDE_DIR})
target_link_libraries(fastd protocols methods ciphers macs ${RT_LIBRARY} ${LIBCAP_LIBRARY} ${LIBUECC_LIBRARIES} ${NACL_LIBRARIES} ${OPENSSL_CRYPTO_LIBRARY} ${JSON_C_LIBRARIES})

add_dependencies(fastd version)

install(TARGETS fastd RUNTIME DESTINATION bin)


add_custom_target(format
	find src -type f -name '*.[ch]' | xargs clang-format -i --style=file
	WORKING_DIRECTORY ${FASTD_SOURCE_DIR}
)
