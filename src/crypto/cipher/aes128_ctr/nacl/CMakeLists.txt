add_library(cipher_aes128_ctr_nacl OBJECT
  cipher_aes128_ctr_nacl.c
)
set_property(TARGET cipher_aes128_ctr_nacl PROPERTY COMPILE_FLAGS "${FASTD_CFLAGS}")
target_include_directories(cipher_aes128_ctr_nacl PRIVATE ${NACL_INCLUDE_DIRS})
