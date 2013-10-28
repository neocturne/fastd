include_directories(BEFORE ${FASTD_SOURCE_DIR}/src ${FASTD_BINARY_DIR})

add_library(method_null OBJECT
  null.c
)
set_property(TARGET method_null PROPERTY COMPILE_FLAGS "${FASTD_CFLAGS}")
