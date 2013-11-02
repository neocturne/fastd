include_directories(${FASTD_SOURCE_DIR} ${FASTD_BINARY_DIR}/src)

add_library(method_generic_gcm OBJECT
  generic_gcm.c
)
set_property(TARGET method_generic_gcm PROPERTY COMPILE_FLAGS "${FASTD_CFLAGS}")
