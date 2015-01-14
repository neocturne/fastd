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

   \em memory allocation functions
 */


#pragma once

#include "log.h"


/**
   Allocates a block of uninitialized memory on the heap

   Terminates the process on failure.
*/
static inline void * fastd_alloc(size_t size) {
	void *ret = malloc(size);
	if (!ret)
		exit_errno("malloc");

	return ret;
}

/**
   Allocates a block of uninitialized memory on the heap, aligned to 16 bytes

   Terminates the process on failure.
*/
static inline void * fastd_alloc_aligned(size_t size, size_t align) {
	void *ret;
	int err = posix_memalign(&ret, align, size);
	if (err)
		exit_error("posix_memalign: %s", strerror(err));

	return ret;
}

/**
   Allocates a block of memory set to zero for an array on the heap

   Terminates the process on failure.
*/
static inline void * fastd_alloc0_array(size_t members, size_t size) {
	void *ret = calloc(members, size);
	if (!ret)
		exit_errno("calloc");

	return ret;
}

/**
   Allocates a block of memory set to zero on the heap

   Terminates the process on failure.
*/
static inline void * fastd_alloc0(size_t size) {
	return fastd_alloc0_array(1, size);
}

/**
   Reallocates a block of memory on the heap

   Terminates the process on failure.
*/
static inline void * fastd_realloc(void *ptr, size_t size) {
	void *ret = realloc(ptr, size);
	if (!ret)
		exit_errno("realloc");

	return ret;
}


/** Allocates a block of uninitialized memory in the size of a given type */
#define fastd_new(type) ((type *)fastd_alloc(sizeof(type)))

/** Allocates a block of uninitialized memory in the size of a given type, aligned to 16 bytes */
#define fastd_new_aligned(type, align) ((type *)fastd_alloc_aligned(sizeof(type), align))

/** Allocates a block of memory set to zero in the size of a given type */
#define fastd_new0(type) ((type *)fastd_alloc0(sizeof(type)))

/** Allocates a block of undefined memory for an array of elements of a given type */
#define fastd_new_array(members, type) ((type *)fastd_alloc(members * sizeof(type)))

/** Allocates a block of memory set to zero for an array of elements of a given type */
#define fastd_new0_array(members, type) ((type *)fastd_alloc0_array(members, sizeof(type)))


/** Duplicates a string (string may be NULL) */
static inline char * fastd_strdup(const char *s) {
	if (!s)
		return NULL;

	char *ret = strdup(s);
	if (!ret)
		exit_errno("strdup");

	return ret;
}

/** Duplicates a string up to a maximum length (string may be NULL) */
static inline char * fastd_strndup(const char *s, size_t n) {
	if (!s)
		return NULL;

	char *ret = strndup(s, n);
	if (!ret)
		exit_errno("strndup");

	return ret;
}
