fastd_cipher_impl(salsa20 nacl
  salsa20_nacl.c
)
fastd_cipher_impl_include_directories(salsa20 nacl ${NACL_INCLUDE_DIRS})
fastd_cipher_impl_link_libraries(salsa20 nacl ${NACL_LIBRARIES})
fastd_cipher_impl_require(salsa20 nacl NACL)
