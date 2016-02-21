include(CheckCCompilerFlag)
include(CheckCSourceCompiles)
include(CheckPrototypeDefinition)
include(CheckSymbolExists)
include(CheckTypeSize)
set(CMAKE_REQUIRED_DEFINITIONS "-D_GNU_SOURCE")

if(ARCH_X86 OR ARCH_X86_64)
  check_c_compiler_flag("-mpclmul" HAVE_PCLMUL)
endif(ARCH_X86 OR ARCH_X86_64)



if(ENABLE_LTO)
  set(CFLAGS_LTO "-flto")
  set(CFLAGS_NO_LTO "-fno-lto")

  check_c_compiler_flag("-fwhole-program" HAVE_FLAG_WHOLE_PROGRAM)
  if(HAVE_FLAG_WHOLE_PROGRAM)
    set(LDFLAGS_LTO "-flto -fwhole-program")
  else(HAVE_FLAG_WHOLE_PROGRAM)
    set(LDFLAGS_LTO "-flto")
  endif(HAVE_FLAG_WHOLE_PROGRAM)
endif(ENABLE_LTO)


check_c_source_compiles("
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

int main() {
	return AI_ADDRCONFIG;
}
" HAVE_AI_ADDRCONFIG)


check_prototype_definition("get_current_dir_name" "char *get_current_dir_name(void)" "NULL" "unistd.h" HAVE_GET_CURRENT_DIR_NAME)

check_symbol_exists("setresuid" "unistd.h" HAVE_SETRESUID)
check_symbol_exists("setresgid" "unistd.h" HAVE_SETRESGID)

if(NOT DARWIN)
  set(RT_LIBRARY "")
  check_symbol_exists("clock_gettime" "time.h" HAVE_CLOCK_GETTIME)

  if(NOT HAVE_CLOCK_GETTIME)
    set(RT_LIBRARY "rt")
    list(APPEND CMAKE_REQUIRED_LIBRARIES "rt")

    check_symbol_exists("clock_gettime" "time.h" HAVE_CLOCK_GETTIME_RT)
    if(NOT HAVE_CLOCK_GETTIME_RT)
      message(FATAL_ERROR "clock_gettime() not found")
    endif(NOT HAVE_CLOCK_GETTIME_RT)
  endif(NOT HAVE_CLOCK_GETTIME)
endif(NOT DARWIN)


set(CMAKE_REQUIRED_INCLUDES "sys/types.h")

if(NOT DARWIN)
  check_c_source_compiles("
  #include <endian.h>

  int main() {
    return 0;
  }
  " HAVE_ENDIAN_H)

  if(HAVE_ENDIAN_H)
    check_symbol_exists("be32toh" "endian.h" HAVE_LINUX_ENDIAN)

  else(HAVE_ENDIAN_H)
    check_c_source_compiles("
    #include <sys/types.h>
    #include <sys/endian.h>

    int main() {
      return 0;
    }
    " HAVE_SYS_ENDIAN_H)

    if(HAVE_SYS_ENDIAN_H)
      check_symbol_exists("be32toh" "sys/types.h;sys/endian.h" HAVE_LINUX_ENDIAN)

    else(HAVE_SYS_ENDIAN_H)
      message(FATAL_ERROR "Neither <endian.h> nor <sys/endian.h> found")
    endif(HAVE_SYS_ENDIAN_H)
  endif(HAVE_ENDIAN_H)
endif(NOT DARWIN)
