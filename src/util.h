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

   \em Miscellaneous utility functions and macros
 */


#pragma once


#include <sys/types.h>

#ifdef HAVE_ENDIAN_H
#include <endian.h>
#endif

#ifdef HAVE_SYS_ENDIAN_H
#include <sys/endian.h>
#endif


/**
   Returns a pointer to a data structure, given the address of a member contained in the structure

   @param ptr		the address of the member
   @param type		the type of the container
   @param member	the name of the member

   \hideinitializer
 */
#define container_of(ptr, type, member) ({				\
			const __typeof__(((type *)0)->member) *_mptr = (ptr); \
			(type *)((char *)_mptr - offsetof(type, member)); \
		})

/**
   Returns the number of elements of an array

   \hideinitializer
 */
#define array_size(array) (sizeof(array)/sizeof((array)[0]))

/**
   Determines how many blocks of a given size \a a are needed to contain some length \a l
 */
static inline size_t block_count(size_t l, size_t a) {
	return (l+a-1)/a;
}

/**
   Rounds up a length \a l to the next multiple of a block size \a a
 */
static inline size_t alignto(size_t l, size_t a) {
	return block_count(l, a)*a;
}

/**
   Checks if two strings are equal

   @param str1 The first string (may be NULL)
   @param str2 The second string (may be NULL)

   @return True if both strings are NULL or both strings are not NULL and equal
*/
static inline bool strequal(const char *str1, const char *str2) {
	if (str1 && str2)
		return (!strcmp(str1, str2));
	else
		return (str1 == str2);
}

/** Returns the maximum of two size_t values */
static inline size_t max_size_t(size_t a, size_t b) {
	return (a > b) ? a : b;
}

/** Returns the minimum of two size_t values */
static inline size_t min_size_t(size_t a, size_t b) {
	return (a < b) ? a : b;
}


#ifdef __APPLE__

#include <libkern/OSByteOrder.h>

/** Converts a 32bit integer from host byte order to big endian  */
#define htobe32(x) OSSwapHostToBigInt32(x)

/** Converts a 32bit integer from host byte order to little endian  */
#define htole32(x) OSSwapHostToLittleInt32(x)

/** Converts a 32bit integer from big endian to host byte order */
#define be32toh(x) OSSwapBigToHostInt32(x)

/** Converts a 32bit integer from little endian to host byte order */
#define le32toh(x) OSSwapLittleToHostInt32(x)

#elif !defined(HAVE_LINUX_ENDIAN)

/** Converts a 32bit integer from big endian to host byte order */
#define be32toh(x) betoh32(x)

/** Converts a 32bit integer from little endian to host byte order */
#define le32toh(x) letoh32(x)

#endif
