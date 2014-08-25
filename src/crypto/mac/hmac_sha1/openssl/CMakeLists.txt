if(ENABLE_OPENSSL)
  fastd_mac_impl(hmac-sha1 openssl
    hmac_sha1_openssl.c
  )
  fastd_cipher_impl_include_directories(hmac-sha1 openssl ${OPENSSL_INCLUDE_DIRS})
endif(ENABLE_OPENSSL)
