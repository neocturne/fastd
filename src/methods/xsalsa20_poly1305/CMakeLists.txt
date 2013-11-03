fastd_method(xsalsa20-poly1305
  xsalsa20_poly1305.c
)
fastd_method_include_directories(xsalsa20-poly1305 ${NACL_INCLUDE_DIRS})
fastd_method_link_libraries(xsalsa20-poly1305 method_common ${NACL_LIBRARIES})
fastd_method_require(xsalsa20-poly1305 NACL)
