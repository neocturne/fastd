fastd_method(generic-poly1305
  generic_poly1305.c
)
fastd_method_include_directories(generic-poly1305 ${NACL_INCLUDE_DIR})
fastd_method_link_libraries(generic-poly1305 method_common ${NACL_LIBRARIES})
fastd_method_require(generic-poly1305 NACL)
