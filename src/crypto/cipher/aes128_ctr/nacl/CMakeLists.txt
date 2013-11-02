include_directories(${FASTD_SOURCE_DIR} ${FASTD_BINARY_DIR}/src ${NACL_INCLUDE_DIRS})

add_library(cipher_aes128_ctr_nacl OBJECT
  cipher_aes128_ctr_nacl.c
)
set_property(TARGET method_xsalsa20_poly1305 PROPERTY COMPILE_FLAGS "${FASTD_CFLAGS}")
