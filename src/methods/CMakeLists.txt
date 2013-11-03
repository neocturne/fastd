add_library(methods STATIC "${CMAKE_CURRENT_BINARY_DIR}/methods.c")
add_library(method_common STATIC EXCLUDE_FROM_ALL "common.c")

macro(fastd_method name)
  fastd_module(method enabled "method" ${name} ${ARGN})

  if(${enabled})
    set_property(GLOBAL APPEND PROPERTY FASTD_METHODS ${name})
  endif(${enabled})
endmacro(fastd_method)

macro(fastd_method_include_directories)
  fastd_module_include_directories(method ${ARGN})
endmacro(fastd_method_include_directories)

macro(fastd_method_link_libraries)
  fastd_module_link_libraries(method ${ARGN})
endmacro(fastd_method_link_libraries)


add_subdirectory(null)
add_subdirectory(generic_gcm)
add_subdirectory(xsalsa20_poly1305)


set(METHOD_DEFINITIONS "")
set(METHOD_LIST "")

get_property(METHODS GLOBAL PROPERTY FASTD_METHODS)
foreach(method ${METHODS})
  string(REPLACE - _ method_ "${method}")

  set(METHOD_DEFINITIONS "${METHOD_DEFINITIONS}\nextern const fastd_method_t fastd_method_${method_};")
  set(METHOD_LIST "${METHOD_LIST}\n&fastd_method_${method_},")
endforeach(method)

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/methods.c.in ${CMAKE_CURRENT_BINARY_DIR}/methods.c)
