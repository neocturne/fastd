set(METHODS "")
set(METHOD_COMMON FALSE)

macro(fastd_method name needs_common)
  string(REPLACE - _ name_ "${name}")
  string(TOUPPER "${name_}" NAME)

  set(WITH_METHOD_${NAME} TRUE CACHE BOOL "Include the ${name} method")

  if(WITH_METHOD_${NAME})
    add_library(method_${name_} OBJECT ${ARGN})
    set_property(TARGET method_${name_} PROPERTY COMPILE_FLAGS "${FASTD_CFLAGS}")

    list(APPEND METHODS ${name_})
    set(METHODS "${METHODS}" PARENT_SCOPE)
  endif(WITH_METHOD_${NAME})

  if(${needs_common})
    set(METHOD_COMMON TRUE PARENT_SCOPE)
  endif(${needs_common})
endmacro(fastd_method)

macro(fastd_method_include_directories name)
  string(REPLACE - _ name_ "${name}")
  string(TOUPPER "${name_}" NAME)

  if(WITH_METHOD_${NAME})
    target_include_directories(method_${name_} PRIVATE ${ARGN})
  endif(WITH_METHOD_${NAME})
endmacro(fastd_method_include_directories)


add_subdirectory(null)

add_subdirectory(generic_gcm)
add_subdirectory(xsalsa20_poly1305)


set(METHOD_SOURCES "${CMAKE_CURRENT_BINARY_DIR}/methods.c")

set(METHOD_DEFINITIONS "")
set(METHOD_LIST "")

foreach(method ${METHODS})
  list(APPEND METHOD_SOURCES $<TARGET_OBJECTS:method_${method}>)

  set(METHOD_DEFINITIONS "${METHOD_DEFINITIONS}\nextern const fastd_method_t fastd_method_${method};")
  set(METHOD_LIST "${METHOD_LIST}\n&fastd_method_${method},")
endforeach(method)


if(METHOD_COMMON)
  list(APPEND METHOD_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/common.c)
endif(METHOD_COMMON)

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/methods.c.in ${CMAKE_CURRENT_BINARY_DIR}/methods.c)

set(METHOD_SOURCES "${METHOD_SOURCES}" PARENT_SCOPE)
