include_directories(${FASTD_SOURCE_DIR} ${FASTD_BINARY_DIR}/src)

add_library(mac_ghash_builtin OBJECT
  ghash_builtin.c
)
set_property(TARGET mac_ghash_builtin PROPERTY COMPILE_FLAGS "${FASTD_CFLAGS}")
