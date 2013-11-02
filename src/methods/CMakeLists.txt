set(METHODS null)
set(METHOD_COMMON FALSE)

if(WITH_METHOD_XSALSA20_POLY1305)
  list(APPEND METHODS xsalsa20_poly1305)
  set(METHOD_COMMON TRUE)
endif(WITH_METHOD_XSALSA20_POLY1305)

if(WITH_METHOD_GENERIC_GCM)
  list(APPEND METHODS generic_gcm)
  set(METHOD_COMMON TRUE)
endif(WITH_METHOD_GENERIC_GCM)


set(METHOD_SOURCES "${CMAKE_CURRENT_BINARY_DIR}/methods.c")

set(METHOD_DEFINITIONS "")
set(METHOD_LIST "")

foreach(method ${METHODS})
  add_subdirectory(${method})

  list(APPEND METHOD_SOURCES $<TARGET_OBJECTS:method_${method}>)

  set(METHOD_DEFINITIONS "${METHOD_DEFINITIONS}\nextern const fastd_method_t fastd_method_${method};")
  set(METHOD_LIST "${METHOD_LIST}\n&fastd_method_${method},")
endforeach(method)

if(METHOD_COMMON)
  list(APPEND METHOD_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/common.c)
endif(METHOD_COMMON)


configure_file(${CMAKE_CURRENT_SOURCE_DIR}/methods.c.in ${CMAKE_CURRENT_BINARY_DIR}/methods.c)


set(METHOD_SOURCES "${METHOD_SOURCES}" PARENT_SCOPE)
