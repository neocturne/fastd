set_directory_properties(PROPERTIES COMPILE_DEFINITIONS _GNU_SOURCE)
set(FASTD_CFLAGS "-Wall -pthread ${UECC_CFLAGS_OTHER} ${NACL_CFLAGS_OTHER}")

include_directories(${CMAKE_CURRENT_BINARY_DIR} ${CMAKE_CURRENT_SOURCE_DIR} ${CAP_INCLUDE_DIR} ${NACL_INCLUDE_DIRS})
link_directories(${UECC_LIBRARY_DIRS} ${NACL_LIBRARY_DIRS})


configure_file(${CMAKE_CURRENT_SOURCE_DIR}/fastd_config.h.in ${CMAKE_CURRENT_BINARY_DIR}/fastd_config.h)

add_subdirectory(protocols)
add_subdirectory(methods)
add_subdirectory(crypto)


add_custom_target(
    version
    COMMAND echo "#ifndef _FASTD_FASTD_VERSION_H_" > ${CMAKE_CURRENT_BINARY_DIR}/fastd_version.h.new
    COMMAND echo "#define _FASTD_FASTD_VERSION_H_" >> ${CMAKE_CURRENT_BINARY_DIR}/fastd_version.h.new
    COMMAND sh -c "echo \"#define FASTD_VERSION \\\"$(git --git-dir=./.git describe --dirty 2>/dev/null || echo ${FASTD_VERSION})\\\"\"" >> ${CMAKE_CURRENT_BINARY_DIR}/fastd_version.h.new
    COMMAND echo "#endif /* _FASTD_FASTD_VERSION_H_ */" >> ${CMAKE_CURRENT_BINARY_DIR}/fastd_version.h.new
    COMMAND cmp -s ${CMAKE_CURRENT_BINARY_DIR}/fastd_version.h.new ${CMAKE_CURRENT_BINARY_DIR}/fastd_version.h && rm ${CMAKE_CURRENT_BINARY_DIR}/fastd_version.h.new || mv ${CMAKE_CURRENT_BINARY_DIR}/fastd_version.h.new ${CMAKE_CURRENT_BINARY_DIR}/fastd_version.h
    WORKING_DIRECTORY "${FASTD_SOURCE_DIR}"
    VERBATIM
)

BISON_TARGET(fastd_config_parse config.y ${CMAKE_CURRENT_BINARY_DIR}/config.yy.c)

add_executable(fastd
  fastd.c
  capabilities.c
  config.c
  handshake.c
  hkdf_sha256.c
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
  ${CRYPTO_SOURCES}
)
set_property(TARGET fastd PROPERTY COMPILE_FLAGS "${FASTD_CFLAGS}")
set_property(TARGET fastd PROPERTY LINK_FLAGS "-pthread ${UECC_LDFLAGS_OTHER} ${NACL_LDFLAGS_OTHER}")
target_link_libraries(fastd ${RT_LIBRARY} ${CAP_LIBRARY} ${UECC_LIBRARIES} ${NACL_LIBRARIES})

add_dependencies(fastd version)

install(TARGETS fastd RUNTIME DESTINATION bin)
