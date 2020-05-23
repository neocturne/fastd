if(ENABLE_OPENSSL)
  fastd_cipher_impl(aes128-ctr openssl
    aes128_ctr_openssl.c
  )
  fastd_cipher_impl_include_directories(aes128-ctr openssl ${OPENSSL_INCLUDE_DIR})
  fastd_cipher_impl_link_libraries(aes128-ctr openssl ${OPENSSL_CRYPTO_LIBRARY})
endif(ENABLE_OPENSSL)
