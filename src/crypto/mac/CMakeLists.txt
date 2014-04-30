add_library(macs STATIC "${CMAKE_CURRENT_BINARY_DIR}/macs.c")

macro(fastd_mac name)
  fastd_module(mac enabled "MAC" ${name} ${ARGN})

  if(${enabled})
    set_property(GLOBAL APPEND PROPERTY FASTD_MACS ${name})
  endif(${enabled})
endmacro(fastd_mac)


macro(fastd_mac_impl mac name)
  string(REPLACE - _ mac_ "${mac}")
  string(TOUPPER "${mac_}" MAC)

  if(WITH_MAC_${MAC})
    fastd_module(mac enabled "MAC implementation" "${mac} ${name}" ${ARGN})

    if(${enabled})
      set_property(TARGET "mac_${mac_}" APPEND PROPERTY FASTD_MAC_IMPLS ${name})
    endif(${enabled})
  endif(WITH_MAC_${MAC})
endmacro(fastd_mac_impl)

macro(fastd_mac_impl_include_directories mac name)
  string(REPLACE - _ mac_ "${mac}")
  string(TOUPPER "${mac_}" MAC)

  if(WITH_MAC_${MAC})
    fastd_module_include_directories(mac "${mac} ${name}" ${ARGN})
  endif(WITH_MAC_${MAC})
endmacro(fastd_mac_impl_include_directories)

macro(fastd_mac_impl_link_libraries mac name)
  string(REPLACE - _ mac_ "${mac}")
  string(TOUPPER "${mac_}" MAC)

  if(WITH_MAC_${MAC})
    fastd_module_link_libraries(mac "${mac} ${name}" ${ARGN})
  endif(WITH_MAC_${MAC})
endmacro(fastd_mac_impl_link_libraries)

macro(fastd_mac_impl_require mac name)
  string(REPLACE - _ mac_ "${mac}")
  string(TOUPPER "${mac_}" MAC)

  if(WITH_MAC_${MAC})
    fastd_module_require(mac "${mac} ${name}" ${ARGN})
  endif(WITH_MAC_${MAC})
endmacro(fastd_mac_impl_require)

macro(fastd_mac_impl_compile_flags mac name source)
  string(REPLACE - _ mac_ "${mac}")
  string(TOUPPER "${mac_}" MAC)

  if(WITH_MAC_${MAC})
    fastd_module_compile_flags(mac "${mac} ${name}" ${source} ${ARGN})
  endif(WITH_MAC_${MAC})
endmacro(fastd_mac_impl_compile_flags)


add_subdirectory(ghash)


set(MAC_DEFINITIONS "")
set(MAC_IMPLS "")
set(MAC_LIST "")

get_property(MACS GLOBAL PROPERTY FASTD_MACS)
foreach(mac ${MACS})
  string(REPLACE - _ mac_ "${mac}")
  string(TOUPPER "${mac_}" MAC)

  set(MAC_DEFINITIONS "${MAC_DEFINITIONS}\nextern const fastd_mac_info_t fastd_mac_info_${mac_};")
  set(MAC_LIST "${MAC_LIST}\n{\"${mac}\", &fastd_mac_info_${mac_}, mac_${mac_}_impls},")
  set(MAC_IMPLS "${MAC_IMPLS}\nstatic const fastd_mac_impl_t mac_${mac_}_impls[] = {")


  get_property(IMPLS TARGET "mac_${mac_}" PROPERTY FASTD_MAC_IMPLS)
  foreach(impl ${IMPLS})
    set(MAC_DEFINITIONS "${MAC_DEFINITIONS}\nextern const fastd_mac_t fastd_mac_${mac_}_${impl};")
    set(MAC_IMPLS "${MAC_IMPLS}{\"${impl}\", &fastd_mac_${mac_}_${impl}}, ")
  endforeach(impl)

  set(MAC_IMPLS "${MAC_IMPLS}{NULL, NULL}};")
endforeach(mac)

get_property(LIBS TARGET macs PROPERTY FASTD_LINK_LIBRARIES)
target_link_libraries(macs ${LIBS})

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/macs.c.in ${CMAKE_CURRENT_BINARY_DIR}/macs.c)
