include(CheckCSourceCompiles)

check_c_source_compiles("
#ifndef __i386__
#error not x86
#endif

int main() {return 0;}
" ARCH_X86)

check_c_source_compiles("
#ifndef __x86_64__
#error not x86_64
#endif

int main() {return 0;}
" ARCH_X86_64)
