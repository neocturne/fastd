include_directories(${FASTD_SOURCE_DIR}/src ${FASTD_BINARY_DIR} ${UECC_INCLUDE_DIRS})

add_library(protocol_ec25519_fhmqvc OBJECT
  ec25519_fhmqvc.c
)
set_property(TARGET protocol_ec25519_fhmqvc PROPERTY COMPILE_FLAGS "${FASTD_CFLAGS}")
