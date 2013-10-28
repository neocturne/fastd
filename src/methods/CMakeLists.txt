set(METHODS null)

if(WITH_METHOD_XSALSA20_POLY1305)
  list(APPEND METHODS xsalsa20_poly1305)
endif(WITH_METHOD_XSALSA20_POLY1305)

if(WITH_METHOD_AES128_GCM)
  list(APPEND METHODS aes128_gcm)
endif(WITH_METHOD_AES128_GCM)


set(METHOD_OBJECTS "")

foreach(method ${METHODS})
  add_subdirectory(${method})
  list(APPEND METHOD_OBJECTS $<TARGET_OBJECTS:method_${method}>)
endforeach(method)

set(METHOD_OBJECTS "${METHOD_OBJECTS}" PARENT_SCOPE)
