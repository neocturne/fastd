set(IMPLS "")

if(WITH_MAC_GHASH_BUILTIN)
  list(APPEND IMPLS builtin)
endif(WITH_MAC_GHASH_BUILTIN)

set(IMPL_SOURCES "")

foreach(impl ${IMPLS})
  add_subdirectory(${impl})

  list(APPEND IMPL_SOURCES $<TARGET_OBJECTS:mac_ghash_${impl}>)
endforeach(impl)


set(MAC_NAME "ghash" PARENT_SCOPE)
set(IMPLS "${IMPLS}" PARENT_SCOPE)
set(IMPL_SOURCES "${IMPL_SOURCES}" PARENT_SCOPE)
