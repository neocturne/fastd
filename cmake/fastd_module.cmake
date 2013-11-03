function(fastd_module type info name)
  string(TOUPPER "${type}" TYPE)

  string(REPLACE - _ name_ "${name}")
  string(REPLACE " " _ name_ "${name_}")
  string(TOUPPER "${name_}" NAME)

  set(WITH_${TYPE}_${NAME} TRUE CACHE BOOL "Include the ${name} ${info}")

  if(WITH_${TYPE}_${NAME})
    add_library(${type}_${name_} STATIC ${ARGN})
    set_property(TARGET ${type}_${name_} PROPERTY COMPILE_FLAGS "${FASTD_CFLAGS}")

    set_property(TARGET ${type}s APPEND PROPERTY LINK_LIBRARIES ${type}_${name_})

    list(APPEND ${TYPE}S ${name_})
  endif(WITH_${TYPE}_${NAME})
endfunction(fastd_module)

function(fastd_module_include_directories type name)
  string(TOUPPER "${type}" TYPE)

  string(REPLACE - _ name_ "${name}")
  string(REPLACE " " _ name_ "${name_}")
  string(TOUPPER "${name_}" NAME)

  if(WITH_${TYPE}_${NAME})
    target_include_directories(${type}_${name_} PRIVATE ${ARGN})
  endif(WITH_${TYPE}_${NAME})
endfunction(fastd_module_include_directories)

function(fastd_module_link_libraries type name)
  string(TOUPPER "${type}" TYPE)

  string(REPLACE - _ name_ "${name}")
  string(REPLACE " " _ name_ "${name_}")
  string(TOUPPER "${name_}" NAME)

  if(WITH_${TYPE}_${NAME})
    target_link_libraries(${type}_${name_} ${ARGN})
  endif(WITH_${TYPE}_${NAME})
endfunction(fastd_module_link_libraries)
