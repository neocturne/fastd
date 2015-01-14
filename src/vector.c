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
		n = n*3/2;
	}

	while (alloc < n)
		alloc <<= 1;
	while (alloc > n*3 && alloc > MIN_VECTOR_ALLOC)
		alloc >>= 1;

	if (alloc != desc->allocated) {
		desc->allocated = alloc;
		*data = fastd_realloc(*data, alloc * elemsize);
	}
}

/**
   Inserts an element into a vector

   Internal function, use VECTOR_INSERT() and VECTOR_ADD() instead.
*/
void _fastd_vector_insert(fastd_vector_desc_t *desc, void **data, void *element, size_t pos, size_t elemsize) {
	_fastd_vector_resize(desc, data, desc->length+1, elemsize);

	void *p = *data + pos*elemsize;

	memmove(p+elemsize, p, (desc->length-pos-1)*elemsize);
	memcpy(p, element, elemsize);
}

/**
   Deletes an element from a vector

   Internal function, use VECTOR_DELETE() instead.
*/
void _fastd_vector_delete(fastd_vector_desc_t *desc, void **data, size_t pos, size_t elemsize) {
	void *p = *data + pos*elemsize;
	memmove(p, p+elemsize, (desc->length-pos-1)*elemsize);

	_fastd_vector_resize(desc, data, desc->length-1, elemsize);
}
