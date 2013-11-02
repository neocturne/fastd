add_library(protocol_ec25519_fhmqvc OBJECT
  ec25519_fhmqvc.c
  handshake.c
  state.c
  util.c
)
set_property(TARGET protocol_ec25519_fhmqvc PROPERTY COMPILE_FLAGS "${FASTD_CFLAGS}")
target_include_directories(protocol_ec25519_fhmqvc PRIVATE ${UECC_INCLUDE_DIRS})
