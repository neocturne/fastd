set(IMPLS "")

if(WITH_CIPHER_AES128_CTR_NACL)
  list(APPEND IMPLS nacl)
endif(WITH_CIPHER_AES128_CTR_NACL)

set(IMPL_SOURCES "")

foreach(impl ${IMPLS})
  add_subdirectory(${impl})

  list(APPEND IMPL_SOURCES $<TARGET_OBJECTS:cipher_aes128_ctr_${impl}>)
endforeach(impl)


set(CIPHER_NAME "aes128-ctr" PARENT_SCOPE)
set(IMPLS "${IMPLS}" PARENT_SCOPE)
set(IMPL_SOURCES "${IMPL_SOURCES}" PARENT_SCOPE)
