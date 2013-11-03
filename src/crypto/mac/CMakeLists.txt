add_library(macs STATIC "${CMAKE_CURRENT_BINARY_DIR}/macs.c")

function(fastd_mac name)
  string(REPLACE - _ name_ "${name}")
  string(TOUPPER "${name_}" NAME)

  set(WITH_MAC_${NAME} TRUE CACHE BOOL "Include the ${name} MAC")

  if(WITH_MAC_${NAME})
    set_property(GLOBAL APPEND PROPERTY FASTD_MACS ${name})
  endif(WITH_MAC_${NAME})
endfunction(fastd_mac)


macro(fastd_mac_impl mac name)
  string(REPLACE - _ mac_ "${mac}")
  string(TOUPPER "${mac_}" MAC)

  fastd_module(mac enabled "MAC implementation" "${mac} ${name}" ${ARGN})

  if(${enabled})
    set_property(GLOBAL APPEND PROPERTY FASTD_MAC_${MAC}_IMPLS ${name})
  endif(${enabled})
endmacro(fastd_mac_impl)

macro(fastd_mac_impl_include_directories mac name)
  fastd_module_include_directories(mac "${mac} ${name}" ${ARGN})
endmacro(fastd_mac_impl_include_directories)

macro(fastd_mac_impl_link_libraries mac name)
  fastd_module_link_libraries(mac "${mac} ${name}" ${ARGN})
endmacro(fastd_mac_impl_link_libraries)

macro(fastd_mac_impl_require mac name)
  fastd_module_require(mac "${mac} ${name}" ${ARGN})
endmacro(fastd_mac_impl_require)


add_subdirectory(ghash)


set(MAC_DEFINITIONS "")
set(MAC_IMPLS "")
set(MAC_LIST "")

get_property(MACS GLOBAL PROPERTY FASTD_MACS)
foreach(mac ${MACS})
  string(REPLACE - _ mac_ "${mac}")
  string(TOUPPER "${mac_}" MAC)

  set(MAC_LIST "${MAC_LIST}\n{\"${mac}\", mac_${mac_}_impls},")
  set(MAC_IMPLS "${MAC_IMPLS}\nstatic const fastd_mac_t *const mac_${mac_}_impls[] = {")

  get_property(IMPLS GLOBAL PROPERTY FASTD_MAC_${MAC}_IMPLS)
  foreach(impl ${IMPLS})
    set(MAC_DEFINITIONS "${MAC_DEFINITIONS}\nextern const fastd_mac_t fastd_mac_${mac_}_${impl};")
    set(MAC_IMPLS "${MAC_IMPLS}&fastd_mac_${mac_}_${impl}, ")
  endforeach(impl)

  set(MAC_IMPLS "${MAC_IMPLS}NULL};")

endforeach(mac)

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/macs.c.in ${CMAKE_CURRENT_BINARY_DIR}/macs.c)
