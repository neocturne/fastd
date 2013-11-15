if(USE_OPENSSL)
  fastd_cipher_impl(blowfish-ctr openssl
    blowfish_ctr.c
  )
  fastd_cipher_impl_include_directories(blowfish-ctr openssl ${OPENSSL_INCLUDE_DIRS})
  fastd_cipher_impl_link_libraries(blowfish-ctr openssl ${OPENSSL_CRYPTO_LIBRARIES})
endif(USE_OPENSSL)
