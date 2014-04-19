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


#pragma once

#include <stdlib.h>


typedef struct fastd_vector_desc {
	size_t allocated;
	size_t length;
} fastd_vector_desc_t;


#define VECTOR(type)				\
	struct {				\
		fastd_vector_desc_t desc;	\
		type *data;			\
	}



void _fastd_vector_alloc(fastd_vector_desc_t *desc, void **data, size_t n, size_t elemsize);
void _fastd_vector_resize(fastd_vector_desc_t *desc, void **data, size_t n, size_t elemsize);
void _fastd_vector_insert(fastd_vector_desc_t *desc, void **data, void *element, size_t pos, size_t elemsize);
void _fastd_vector_delete(fastd_vector_desc_t *desc, void **data, size_t pos, size_t elemsize);


#define VECTOR_ALLOC(v, n) ({						\
			__typeof__(v) *_v = &(v);			\
			_fastd_vector_alloc(&_v->desc, (void**)&_v->data, (n), sizeof(*_v->data)); \
		})

#define VECTOR_RESIZE(v, n)  ({						\
			__typeof__(v) *_v = &(v);			\
			_fastd_vector_resize(&_v->desc, (void**)&_v->data, (n), sizeof(*_v->data)); \
		})

#define VECTOR_FREE(v) free((v).data)

#define VECTOR_LEN(v) ((v).desc.length)
#define VECTOR_INDEX(v, i) ((v).data[i])
#define VECTOR_DATA(v) ((v).data)

#define VECTOR_INSERT(v, elem, pos) ({					\
			__typeof__(v) *_v = &(v);			\
			__typeof__(*_v->data) _e = (elem);		\
			_fastd_vector_insert(&_v->desc, (void**)&_v->data, &_e, (pos), sizeof(_e)); \
		})

#define VECTOR_ADD(v, elem) ({						\
			__typeof__(v) *_v = &(v);			\
			VECTOR_INSERT(*_v, (elem), _v->desc.length);	\
		})

#define VECTOR_DELETE(v, pos) ({					\
			__typeof__(v) *_v = &(v);			\
			_fastd_vector_delete(&_v->desc, (void**)&_v->data, (pos), sizeof(*_v->data)); \
		})
