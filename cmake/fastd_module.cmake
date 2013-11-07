macro(_fastd_module_handle_name)
  string(TOUPPER "${type}" TYPE)

  string(REPLACE - _ name_ "${name}")
  string(REPLACE " " _ name_ "${name_}")
  string(TOUPPER "${name_}" NAME)
endmacro(_fastd_module_handle_name)

function(fastd_module type enabled_var info name)
  _fastd_module_handle_name()

  set(WITH_${TYPE}_${NAME} TRUE CACHE BOOL "Include the ${name} ${info}")

  if(WITH_${TYPE}_${NAME})
    add_library(${type}_${name_} STATIC ${ARGN})
    set_property(TARGET ${type}_${name_} PROPERTY COMPILE_FLAGS "${FASTD_CFLAGS}")

    set_property(TARGET ${type}s APPEND PROPERTY LINK_LIBRARIES ${type}_${name_})

    list(APPEND ${TYPE}S ${name_})

  endif(WITH_${TYPE}_${NAME})

  set(${enabled_var} ${WITH_${TYPE}_${NAME}} PARENT_SCOPE)
endfunction(fastd_module)

function(fastd_module_include_directories type name)
  _fastd_module_handle_name()

  if(WITH_${TYPE}_${NAME})
    set_property(TARGET ${type}_${name_} APPEND PROPERTY INCLUDE_DIRECTORIES ${ARGN})
  endif(WITH_${TYPE}_${NAME})
endfunction(fastd_module_include_directories)

function(fastd_module_link_libraries type name)
  _fastd_module_handle_name()

  if(WITH_${TYPE}_${NAME})
    target_link_libraries(${type}_${name_} ${ARGN})
  endif(WITH_${TYPE}_${NAME})
endfunction(fastd_module_link_libraries)

function(fastd_module_require type name)
  _fastd_module_handle_name()

  if(WITH_${TYPE}_${NAME})
    foreach(req ${ARGN})
      set_property(GLOBAL PROPERTY ${req}_REQUIRED TRUE)
    endforeach(req)
  endif(WITH_${TYPE}_${NAME})
endfunction(fastd_module_require)
