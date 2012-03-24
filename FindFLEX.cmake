#=============================================================================
# Copyright 2009 Kitware, Inc.
# Copyright 2006 Tristan Carel
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 
# * Redistributions of source code must retain the above copyright
#   notice, this list of conditions and the following disclaimer.
# 
# * Redistributions in binary form must reproduce the above copyright
#   notice, this list of conditions and the following disclaimer in the
#   documentation and/or other materials provided with the distribution.
# 
# * Neither the names of Kitware, Inc., the Insight Software Consortium,
#   nor the names of their contributors may be used to endorse or promote
#   products derived from this software without specific prior written
#   permission.
# 
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
# 
# ------------------------------------------------------------------------------
# 
# The above copyright and license notice applies to distributions of
# CMake in source and binary form.  Some source files contain additional
# notices of original copyright by their contributors; see each source
# for details.  Third-party software packages supplied with CMake under
# compatible licenses provide their own copyright notices documented in
# corresponding subdirectories.
#=============================================================================

FIND_PROGRAM(FLEX_EXECUTABLE flex DOC "path to the flex executable")
MARK_AS_ADVANCED(FLEX_EXECUTABLE)

FIND_LIBRARY(FL_LIBRARY NAMES fl
  DOC "Path to the fl library")

FIND_PATH(FLEX_INCLUDE_DIR FlexLexer.h
  DOC "Path to the flex headers")

MARK_AS_ADVANCED(FL_LIBRARY FLEX_INCLUDE_DIR)

SET(FLEX_INCLUDE_DIRS ${FLEX_INCLUDE_DIR})
SET(FLEX_LIBRARIES ${FL_LIBRARY})

IF(FLEX_EXECUTABLE)

  EXECUTE_PROCESS(COMMAND ${FLEX_EXECUTABLE} --version
    OUTPUT_VARIABLE FLEX_version_output
    ERROR_VARIABLE FLEX_version_error
    RESULT_VARIABLE FLEX_version_result
    OUTPUT_STRIP_TRAILING_WHITESPACE)
  IF(NOT ${FLEX_version_result} EQUAL 0)
    IF(FLEX_FIND_REQUIRED)
      MESSAGE(SEND_ERROR "Command \"${FLEX_EXECUTABLE} --version\" failed with output:\n${FLEX_version_output}\n${FLEX_version_error}")
    ELSE()
      MESSAGE("Command \"${FLEX_EXECUTABLE} --version\" failed with output:\n${FLEX_version_output}\n${FLEX_version_error}\nFLEX_VERSION will not be available")
    ENDIF()
  ELSE()
    STRING(REGEX REPLACE "^flex (.*)$" "\\1"
      FLEX_VERSION "${FLEX_version_output}")
  ENDIF()

  #============================================================
  # FLEX_TARGET (public macro)
  #============================================================
  #
  MACRO(FLEX_TARGET Name Input Output)
    SET(FLEX_TARGET_usage "FLEX_TARGET(<Name> <Input> <Output> [COMPILE_FLAGS <string>]")
    IF(${ARGC} GREATER 3)
      IF(${ARGC} EQUAL 5)
        IF("${ARGV3}" STREQUAL "COMPILE_FLAGS")
          SET(FLEX_EXECUTABLE_opts  "${ARGV4}")
          SEPARATE_ARGUMENTS(FLEX_EXECUTABLE_opts)
        ELSE()
          MESSAGE(SEND_ERROR ${FLEX_TARGET_usage})
        ENDIF()
      ELSE()
        MESSAGE(SEND_ERROR ${FLEX_TARGET_usage})
      ENDIF()
    ENDIF()

    STRING(REGEX REPLACE "^(.*)(\\.[^.]*)$" "\\2" _fileext "${Output}")
    STRING(REPLACE "c" "h" _fileext ${_fileext})
    STRING(REGEX REPLACE "^(.*)(\\.[^.]*)$" "\\1${_fileext}"
       OutputHeader "${Output}")

    ADD_CUSTOM_COMMAND(OUTPUT ${Output} ${OutputHeader}
      COMMAND ${FLEX_EXECUTABLE}
      ARGS ${FLEX_EXECUTABLE_opts} -o${Output} --header-file=${OutputHeader} ${Input}
      DEPENDS ${Input}
      COMMENT "[FLEX][${Name}] Building scanner with flex ${FLEX_VERSION}"
      WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})

    SET(FLEX_${Name}_DEFINED TRUE)
    SET(FLEX_${Name}_OUTPUTS ${Output} ${OutputHeader})
    SET(FLEX_${Name}_OUTPUT_HEADER ${OutputHeader})
    SET(FLEX_${Name}_INPUT ${Input})
    SET(FLEX_${Name}_COMPILE_FLAGS ${FLEX_EXECUTABLE_opts})
  ENDMACRO(FLEX_TARGET)
  #============================================================


ENDIF(FLEX_EXECUTABLE)

FIND_PACKAGE_HANDLE_STANDARD_ARGS(FLEX REQUIRED_VARS FLEX_EXECUTABLE
                                       VERSION_VAR FLEX_VERSION)

# FindFLEX.cmake ends here
