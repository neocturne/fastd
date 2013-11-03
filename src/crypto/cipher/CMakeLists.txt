add_library(ciphers STATIC "${CMAKE_CURRENT_BINARY_DIR}/ciphers.c")

function(fastd_cipher name)
  string(REPLACE - _ name_ "${name}")
  string(TOUPPER "${name_}" NAME)

  set(WITH_CIPHER_${NAME} TRUE CACHE BOOL "Include the ${name} cipher")

  if(WITH_CIPHER_${NAME})
    set_property(GLOBAL APPEND PROPERTY FASTD_CIPHERS ${name})
  endif(WITH_CIPHER_${NAME})
endfunction(fastd_cipher)


macro(fastd_cipher_impl cipher name)
  string(REPLACE - _ cipher_ "${cipher}")
  string(TOUPPER "${cipher_}" CIPHER)

  fastd_module(cipher enabled "cipher implementation" "${cipher} ${name}" ${ARGN})

  if(${enabled})
    set_property(GLOBAL APPEND PROPERTY FASTD_CIPHER_${CIPHER}_IMPLS ${name})
  endif(${enabled})
endmacro(fastd_cipher_impl)

macro(fastd_cipher_impl_include_directories cipher name)
  fastd_module_include_directories(cipher "${cipher} ${name}" ${ARGN})
endmacro(fastd_cipher_impl_include_directories)

macro(fastd_cipher_impl_link_libraries cipher name)
  fastd_module_link_libraries(cipher "${cipher} ${name}" ${ARGN})
endmacro(fastd_cipher_impl_link_libraries)


add_subdirectory(aes128_ctr)


set(CIPHER_DEFINITIONS "")
set(CIPHER_IMPLS "")
set(CIPHER_LIST "")

get_property(CIPHERS GLOBAL PROPERTY FASTD_CIPHERS)
foreach(cipher ${CIPHERS})
  string(REPLACE - _ cipher_ "${cipher}")
  string(TOUPPER "${cipher_}" CIPHER)

  set(CIPHER_LIST "${CIPHER_LIST}\n{\"${cipher}\", cipher_${cipher_}_impls},")
  set(CIPHER_IMPLS "${CIPHER_IMPLS}\nstatic const fastd_cipher_t *const cipher_${cipher_}_impls[] = {")

  get_property(IMPLS GLOBAL PROPERTY FASTD_CIPHER_${CIPHER}_IMPLS)
  foreach(impl ${IMPLS})
    set(CIPHER_DEFINITIONS "${CIPHER_DEFINITIONS}\nextern const fastd_cipher_t fastd_cipher_${cipher_}_${impl};")
    set(CIPHER_IMPLS "${CIPHER_IMPLS}&fastd_cipher_${cipher_}_${impl}, ")
  endforeach(impl)

  set(CIPHER_IMPLS "${CIPHER_IMPLS}NULL};")

endforeach(cipher)

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/ciphers.c.in ${CMAKE_CURRENT_BINARY_DIR}/ciphers.c)
