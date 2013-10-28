set(PROTOCOLS ec25519_fhmqvc)

set(PROTOCOL_SOURCES "")

foreach(protocol ${PROTOCOLS})
  add_subdirectory(${protocol})
  list(APPEND PROTOCOL_SOURCES $<TARGET_OBJECTS:protocol_${protocol}>)
endforeach(protocol)

set(PROTOCOL_SOURCES "${PROTOCOL_SOURCES}" PARENT_SCOPE)
