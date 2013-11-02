add_library(method_xsalsa20_poly1305 OBJECT
  xsalsa20_poly1305.c
)
set_property(TARGET method_xsalsa20_poly1305 PROPERTY COMPILE_FLAGS "${FASTD_CFLAGS}")
target_include_directories(method_xsalsa20_poly1305 PRIVATE ${NACL_INCLUDE_DIRS})
