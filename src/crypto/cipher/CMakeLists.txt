add_library(ciphers STATIC "${CMAKE_CURRENT_BINARY_DIR}/ciphers.c")

macro(fastd_cipher name)
  fastd_module(cipher enabled "cipher" ${name} ${ARGN})

  if(${enabled})
    set_property(GLOBAL APPEND PROPERTY FASTD_CIPHERS ${name})
  endif(${enabled})
endmacro(fastd_cipher)


macro(fastd_cipher_impl cipher name)
  string(REPLACE - _ cipher_ "${cipher}")
  string(TOUPPER "${cipher_}" CIPHER)

  if(WITH_CIPHER_${CIPHER})
    fastd_module(cipher enabled "cipher implementation" "${cipher} ${name}" ${ARGN})

    if(${enabled})
      set_property(TARGET "cipher_${cipher_}" APPEND PROPERTY FASTD_CIPHER_IMPLS ${name})
    endif(${enabled})
  endif(WITH_CIPHER_${CIPHER})
endmacro(fastd_cipher_impl)

macro(fastd_cipher_impl_include_directories cipher name)
  string(REPLACE - _ cipher_ "${cipher}")
  string(TOUPPER "${cipher_}" CIPHER)

  if(WITH_CIPHER_${CIPHER})
    fastd_module_include_directories(cipher "${cipher} ${name}" ${ARGN})
  endif(WITH_CIPHER_${CIPHER})
endmacro(fastd_cipher_impl_include_directories)

macro(fastd_cipher_impl_link_libraries cipher name)
  string(REPLACE - _ cipher_ "${cipher}")
  string(TOUPPER "${cipher_}" CIPHER)

  if(WITH_CIPHER_${CIPHER})
    fastd_module_link_libraries(cipher "${cipher} ${name}" ${ARGN})
  endif(WITH_CIPHER_${CIPHER})
endmacro(fastd_cipher_impl_link_libraries)

macro(fastd_cipher_impl_require cipher name)
  string(REPLACE - _ cipher_ "${cipher}")
  string(TOUPPER "${cipher_}" CIPHER)

  if(WITH_CIPHER_${CIPHER})
    fastd_module_require(cipher "${cipher} ${name}" ${ARGN})
  endif(WITH_CIPHER_${CIPHER})
endmacro(fastd_cipher_impl_require)


add_subdirectory(aes128_ctr)
add_subdirectory(null)
add_subdirectory(salsa2012)
add_subdirectory(salsa20)


set(CIPHER_DEFINITIONS "")
set(CIPHER_IMPLS "")
set(CIPHER_LIST "")

get_property(CIPHERS GLOBAL PROPERTY FASTD_CIPHERS)
foreach(cipher ${CIPHERS})
  string(REPLACE - _ cipher_ "${cipher}")
  string(TOUPPER "${cipher_}" CIPHER)

  set(CIPHER_DEFINITIONS "${CIPHER_DEFINITIONS}\nextern const fastd_cipher_info_t fastd_cipher_info_${cipher_};")
  set(CIPHER_LIST "${CIPHER_LIST}\n{\"${cipher}\", &fastd_cipher_info_${cipher_}, cipher_${cipher_}_impls},")
  set(CIPHER_IMPLS "${CIPHER_IMPLS}\nstatic const fastd_cipher_impl_t cipher_${cipher_}_impls[] = {")


  get_property(IMPLS TARGET "cipher_${cipher_}" PROPERTY FASTD_CIPHER_IMPLS)
  foreach(impl ${IMPLS})
    set(CIPHER_DEFINITIONS "${CIPHER_DEFINITIONS}\nextern const fastd_cipher_t fastd_cipher_${cipher_}_${impl};")
    set(CIPHER_IMPLS "${CIPHER_IMPLS}{\"${impl}\", &fastd_cipher_${cipher_}_${impl}}, ")
  endforeach(impl)

  set(CIPHER_IMPLS "${CIPHER_IMPLS}{NULL, NULL}};")
endforeach(cipher)

get_property(LIBS TARGET ciphers PROPERTY FASTD_LINK_LIBRARIES)
target_link_libraries(ciphers ${LIBS})

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/ciphers.c.in ${CMAKE_CURRENT_BINARY_DIR}/ciphers.c)
