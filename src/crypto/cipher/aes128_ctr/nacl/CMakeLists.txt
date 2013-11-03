fastd_cipher_impl(aes128-ctr nacl
  cipher_aes128_ctr_nacl.c
)
fastd_cipher_impl_include_directories(aes128-ctr nacl ${NACL_INCLUDE_DIRS})
fastd_cipher_impl_link_libraries(aes128-ctr nacl ${NACL_LIBRARIES})
fastd_cipher_impl_require(aes128-ctr nacl NACL)
