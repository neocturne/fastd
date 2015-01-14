/*
  Copyright (c) 2012-2015, Matthias Schiffer <mschiffer@universe-factory.net>
  All rights reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions are met:

    1. Redistributions of source code must retain the above copyright notice,
       this list of conditions and the following disclaimer.
    2. Redistributions in binary form must reproduce the above copyright notice,
       this list of conditions and the following disclaimer in the documentation
       and/or other materials provided with the distribution.

  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
  DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
  FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
  CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
  OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

/**
   \file

   CPUID function for x86-based platforms
*/

#pragma once

#include <stdint.h>

/** The FXSR bit in the CPUID return value */
#define CPUID_FXSR	((uint64_t)1 << 24)

/** The SSE2 bit in the CPUID return value */
#define CPUID_SSE2	((uint64_t)1 << 26)

/** The PCLMULQDQ bit in the CPUID return value */
#define CPUID_PCLMULQDQ	((uint64_t)1 << 33)

/** The SSSE3 bit in the CPUID return value */
#define CPUID_SSSE3	((uint64_t)1 << 41)


/** Returns the ECX and EDX return values of CPUID function 1 as a single uint64 */
static inline uint64_t fastd_cpuid(void) {
	unsigned eax, ebx, ecx, edx;

	__asm__ __volatile__ ("mov %%ebx, %%edi;" "cpuid;" "xchgl %%ebx, %%edi;" : "=a" (eax), "=D" (ebx), "=c" (ecx), "=d" (edx) : "a" (1));

	return ((uint64_t)ecx) << 32 | edx;
}
