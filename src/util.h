/*
  Copyright (c) 2012-2014, Matthias Schiffer <mschiffer@universe-factory.net>
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
