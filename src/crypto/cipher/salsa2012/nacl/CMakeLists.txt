fastd_cipher_impl(salsa2012 nacl
  salsa2012_nacl.c
)
fastd_cipher_impl_include_directories(salsa2012 nacl ${NACL_INCLUDE_DIRS})
fastd_cipher_impl_link_libraries(salsa2012 nacl ${NACL_LIBRARIES})
fastd_cipher_impl_require(salsa2012 nacl NACL)
