// SPDX-License-Identifier: BSD-2-Clause
/*
  Copyright (c) 2012-2016, Matthias Schiffer <mschiffer@universe-factory.net>
  All rights reserved.
*/

/**
   \file

   Typesafe dynamically sized arrays
*/


#include "vector.h"
#include "alloc.h"

#include <string.h>


/** The minimum number of elements to allocate even when less elements are used */
#define MIN_VECTOR_ALLOC 4


/**
   Resizes a vector

   Vector allocations are always powers of 2.

   Internal function, use VECTOR_RESIZE() instead.
*/
void _fastd_vector_resize(fastd_vector_desc_t *desc, void **data, size_t n, size_t elemsize) {
	desc->length = n;

	size_t alloc = desc->allocated;

	if (!alloc) {
		alloc = MIN_VECTOR_ALLOC;
		n = n * 3 / 2;
	}

	while (alloc < n) {
		alloc <<= 1;
		if (!alloc) {
			errno = EOVERFLOW;
			exit_errno("memory allocation error");
		}
	}

	if (alloc != desc->allocated) {
		desc->allocated = alloc;
		*data = fastd_realloc_array(*data, alloc, elemsize);
	}
}

/**
   Inserts an element into a vector

   Internal function, use VECTOR_INSERT() and VECTOR_ADD() instead.
*/
void _fastd_vector_insert(fastd_vector_desc_t *desc, void **data, void *element, size_t pos, size_t elemsize) {
	_fastd_vector_resize(desc, data, desc->length + 1, elemsize);

	void *p = *data + pos * elemsize;

	memmove(p + elemsize, p, (desc->length - pos - 1) * elemsize);
	memcpy(p, element, elemsize);
}

/**
   Deletes an element from a vector

   Internal function, use VECTOR_DELETE() instead.
*/
void _fastd_vector_delete(fastd_vector_desc_t *desc, void **data, size_t pos, size_t elemsize) {
	void *p = *data + pos * elemsize;
	memmove(p, p + elemsize, (desc->length - pos - 1) * elemsize);

	_fastd_vector_resize(desc, data, desc->length - 1, elemsize);
}
