find_program(GIT_EXECUTABLE git DOC "path to the git executable")
mark_as_advanced(GIT_EXECUTABLE)

function(git_version RESULT_VAR DIR)
  set(${RESULT_VAR} "" PARENT_SCOPE)
  if(GIT_EXECUTABLE)
    execute_process(COMMAND ${GIT_EXECUTABLE} describe WORKING_DIRECTORY ${DIR} OUTPUT_VARIABLE git_version_OUTPUT ERROR_VARIABLE git_version_ERROR RESULT_VARIABLE git_version_RESULT OUTPUT_STRIP_TRAILING_WHITESPACE)

    if(${git_version_RESULT} EQUAL 0)
      set(${RESULT_VAR} "${git_version_OUTPUT}" PARENT_SCOPE)
    endif()
  endif()
endfunction(git_version)
