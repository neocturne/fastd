set(HAVE_LIBSODIUM FALSE)

get_property(nacl_required GLOBAL PROPERTY NACL_REQUIRED)
if(${nacl_required})
  if("${NACL_LIBRARIES}" STREQUAL "")
    message(FATAL_ERROR "NaCl is not available, but a selected module needs it")
  endif()

  if(USE_LIBSODIUM)
    set(HAVE_LIBSODIUM TRUE)
  endif(USE_LIBSODIUM)
endif(${nacl_required})
