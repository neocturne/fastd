// SPDX-License-Identifier: BSD-2-Clause
/*
  Copyright (c) Matthias Schiffer <mschiffer@universe-factory.net>
  All rights reserved.
*/

/**
   \file

   CPUID function for x86-based platforms
*/

#pragma once

#include <stdint.h>

/** The FXSR bit in the CPUID return value */
#define CPUID_FXSR ((uint64_t)1 << 24)

/** The SSE2 bit in the CPUID return value */
#define CPUID_SSE2 ((uint64_t)1 << 26)

/** The PCLMULQDQ bit in the CPUID return value */
#define CPUID_PCLMULQDQ ((uint64_t)1 << 33)

/** The SSSE3 bit in the CPUID return value */
#define CPUID_SSSE3 ((uint64_t)1 << 41)


/** Returns the ECX and EDX return values of CPUID function 1 as a single uint64 */
static inline uint64_t fastd_cpuid(void) {
	unsigned long cx, dx;

#if defined(__i386__)
#define REG_PFX "e"
#elif defined(__amd64__)
#define REG_PFX "r"
#endif

	__asm__ __volatile__("mov $1, %%eax \n\t"
			     "mov %%" REG_PFX "bx, %%" REG_PFX "di \n\t"
			     "cpuid \n\t"
			     "mov %%" REG_PFX "di, %%" REG_PFX "bx \n\t"
			     : "=c"(cx), "=d"(dx)
			     :
			     : REG_PFX "ax", REG_PFX "di");

	return ((uint64_t)cx) << 32 | (uint32_t)dx;
}

#undef REG_PFX
