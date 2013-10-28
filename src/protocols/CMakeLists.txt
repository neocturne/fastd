set(PROTOCOLS ec25519_fhmqvc)

set(PROTOCOL_OBJECTS "")

foreach(protocol ${PROTOCOLS})
  add_subdirectory(${protocol})
  list(APPEND PROTOCOL_OBJECTS $<TARGET_OBJECTS:protocol_${protocol}>)
endforeach(protocol)

set(PROTOCOL_OBJECTS "${PROTOCOL_OBJECTS}" PARENT_SCOPE)
