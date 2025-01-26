// SPDX-License-Identifier: BSD-2-Clause
/*
  Copyright (c) Matthias Schiffer <mschiffer@universe-factory.net>
  All rights reserved.
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
static inline void *fastd_alloc(size_t size) {
	void *ret = malloc(size);
	if (!ret)
		exit_errno("malloc");

	return ret;
}

/**
  Multiplies two size_t values, checking for overflows

  Both arguments are limited to the size of a uint32_t.

  Terminates the process on failure.
*/
static inline size_t fastd_mul_check(size_t members, size_t size) {
	uint64_t v = (uint64_t)members * size;

	if (members > UINT32_MAX || size > UINT32_MAX || v > SIZE_MAX) {
		errno = EOVERFLOW;
		exit_errno("memory allocation error");
	}

	return v;
}

static inline void *fastd_alloc_array(size_t members, size_t size) {
	return fastd_alloc(fastd_mul_check(members, size));
}

/**
   Allocates a block of uninitialized memory on the heap, aligned to 16 bytes

   Terminates the process on failure.
*/
static inline void *fastd_alloc_aligned(size_t size, size_t align) {
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
static inline void *fastd_alloc0_array(size_t members, size_t size) {
	void *ret = calloc(members, size);
	if (!ret)
		exit_errno("calloc");

	return ret;
}

/**
   Allocates a block of memory set to zero on the heap

   Terminates the process on failure.
*/
static inline void *fastd_alloc0(size_t size) {
	return fastd_alloc0_array(1, size);
}

/**
   Reallocates a block of memory on the heap

   Terminates the process on failure.
*/
static inline void *fastd_realloc(void *ptr, size_t size) {
	void *ret = realloc(ptr, size);
	if (!ret)
		exit_errno("realloc");

	return ret;
}

/**
   Reallocates a block of memory for an array on the heap

   Terminates the process on failure.
*/
static inline void *fastd_realloc_array(void *ptr, size_t members, size_t size) {
	return fastd_realloc(ptr, fastd_mul_check(members, size));
}


/** Allocates a block of uninitialized memory in the size of a given type */
#define fastd_new(type) ((type *)fastd_alloc(sizeof(type)))

/** Allocates a block of uninitialized memory in the size of a given type, aligned to 16 bytes */
#define fastd_new_aligned(type, align) ((type *)fastd_alloc_aligned(sizeof(type), align))

/** Allocates a block of memory set to zero in the size of a given type */
#define fastd_new0(type) ((type *)fastd_alloc0(sizeof(type)))

/** Allocates a block of undefined memory for an array of elements of a given type */
#define fastd_new_array(members, type) ((type *)fastd_alloc_array(members, sizeof(type)))

/** Allocates a block of memory set to zero for an array of elements of a given type */
#define fastd_new0_array(members, type) ((type *)fastd_alloc0_array(members, sizeof(type)))


/** Duplicates a string (string may be NULL) */
static inline char *fastd_strdup(const char *s) {
	if (!s)
		return NULL;

	char *ret = strdup(s);
	if (!ret)
		exit_errno("strdup");

	return ret;
}

/** Duplicates a string up to a maximum length (string may be NULL) */
static inline char *fastd_strndup(const char *s, size_t n) {
	if (!s)
		return NULL;

	char *ret = strndup(s, n);
	if (!ret)
		exit_errno("strndup");

	return ret;
}
