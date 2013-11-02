add_library(method_null OBJECT
  null.c
)
set_property(TARGET method_null PROPERTY COMPILE_FLAGS "${FASTD_CFLAGS}")
