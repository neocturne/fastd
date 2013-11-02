include_directories(${FASTD_SOURCE_DIR} ${FASTD_BINARY_DIR}/src ${UECC_INCLUDE_DIRS})

add_library(protocol_ec25519_fhmqvc OBJECT
  ec25519_fhmqvc.c
  handshake.c
  state.c
  util.c
)
set_property(TARGET protocol_ec25519_fhmqvc PROPERTY COMPILE_FLAGS "${FASTD_CFLAGS}")
