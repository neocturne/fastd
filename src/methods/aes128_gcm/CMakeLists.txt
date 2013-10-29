include_directories(${FASTD_SOURCE_DIR}/src ${FASTD_BINARY_DIR} ${NACL_INCLUDE_DIRS})

add_library(method_aes128_gcm OBJECT
  aes128_gcm.c
)
set_property(TARGET method_aes128_gcm PROPERTY COMPILE_FLAGS "${FASTD_CFLAGS}")
