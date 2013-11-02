set(MACS "")

if(WITH_MAC_GHASH)
  list(APPEND MACS ghash)
endif(WITH_MAC_GHASH)

set(MAC_SOURCES "${CMAKE_CURRENT_BINARY_DIR}/macs.c")

set(MAC_DEFINITIONS "")
set(MAC_IMPLS "")
set(MAC_LIST "")

foreach(mac ${MACS})
  add_subdirectory(${mac})

  list(APPEND MAC_SOURCES ${IMPL_SOURCES})

  set(MAC_LIST "${MAC_LIST}\n{\"${MAC_NAME}\", mac_${mac}_impls},")
  set(MAC_IMPLS "${MAC_IMPLS}\nstatic const fastd_mac_t *const mac_${mac}_impls[] = {")

  foreach(impl ${IMPLS})
    set(MAC_DEFINITIONS "${MAC_DEFINITIONS}\nextern const fastd_mac_t fastd_mac_${mac}_${impl};")
    set(MAC_IMPLS "${MAC_IMPLS}&fastd_mac_${mac}_${impl}, ")
  endforeach(impl)

  set(MAC_IMPLS "${MAC_IMPLS}NULL};")

endforeach(mac)


configure_file(${CMAKE_CURRENT_SOURCE_DIR}/macs.c.in ${CMAKE_CURRENT_BINARY_DIR}/macs.c)


set(MAC_SOURCES "${MAC_SOURCES}" PARENT_SCOPE)
