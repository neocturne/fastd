set(CIPHERS "")

if(WITH_CIPHER_AES128_CTR)
  list(APPEND CIPHERS aes128_ctr)
endif(WITH_CIPHER_AES128_CTR)

set(CIPHER_SOURCES "${CMAKE_CURRENT_BINARY_DIR}/ciphers.c")

set(CIPHER_DEFINITIONS "")
set(CIPHER_IMPLS "")
set(CIPHER_LIST "")

foreach(cipher ${CIPHERS})
  add_subdirectory(${cipher})

  list(APPEND CIPHER_SOURCES ${IMPL_SOURCES})

  set(CIPHER_LIST "${CIPHER_LIST}\n{\"${CIPHER_NAME}\", cipher_${cipher}_impls},")
  set(CIPHER_IMPLS "${CIPHER_IMPLS}\nstatic const fastd_cipher_t *const cipher_${cipher}_impls[] = {")

  foreach(impl ${IMPLS})
    set(CIPHER_DEFINITIONS "${CIPHER_DEFINITIONS}\nextern const fastd_cipher_t fastd_cipher_${cipher}_${impl};")
    set(CIPHER_IMPLS "${CIPHER_IMPLS}&fastd_cipher_${cipher}_${impl}, ")
  endforeach(impl)

  set(CIPHER_IMPLS "${CIPHER_IMPLS}NULL};")

endforeach(cipher)


configure_file(${CMAKE_CURRENT_SOURCE_DIR}/ciphers.c.in ${CMAKE_CURRENT_BINARY_DIR}/ciphers.c)


set(CIPHER_SOURCES "${CIPHER_SOURCES}" PARENT_SCOPE)
