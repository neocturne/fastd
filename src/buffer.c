// SPDX-License-Identifier: BSD-2-Clause
/*
  Copyright (c) 2012-2016, Matthias Schiffer <mschiffer@universe-factory.net>
  All rights reserved.
*/

/**
   \file

   Buffer management
*/


#define FASTD_BUFFER_COUNT 3


#include "fastd.h"


/** The pool of statically allocated buffers */
static fastd_buffer_t *buffers = NULL;


/** Initializes the buffer pool */
void fastd_init_buffers(void) {
	size_t i;
	for (i = 0; i < FASTD_BUFFER_COUNT; i++) {
		fastd_buffer_t *buffer =
			fastd_alloc_aligned(sizeof(*buffer) + ctx.max_buffer, sizeof(fastd_block128_t));
		fastd_buffer_free(buffer);
	}
}

/** Frees the buffer pool */
void fastd_cleanup_buffers(void) {
	size_t i;
	for (i = 0; i < FASTD_BUFFER_COUNT; i++)
		free(fastd_buffer_alloc(0, 0));

	if (buffers)
		exit_bug("too many buffers to free");
}


/**
   Allocates a new buffer from the buffer pool

   A buffer can have headspace which allows changing the data pointer without moving the data.

   The buffer is always allocated aligned to 16 bytes to allow efficient access for SIMD instructions
   etc. in crypto implementations
*/
fastd_buffer_t *fastd_buffer_alloc(const size_t len, const size_t headroom) {
	const size_t base_len = alignto(headroom + len, sizeof(fastd_block128_t));
	if (base_len > ctx.max_buffer)
		exit_fatal("BUG: oversized buffer alloc (%Z > %Z)", base_len, ctx.max_buffer);

	fastd_buffer_t *buffer = buffers;
	if (!buffer)
		exit_bug("out of buffers");

	if (buffer->len != SIZE_MAX)
		exit_bug("dirty freed buffer");

	buffers = buffer->data;

	buffer->data = buffer->base + headroom;
	buffer->len = len;

	return buffer;
}

/** Returns a buffer to the buffer pool */
void fastd_buffer_free(fastd_buffer_t * const buffer) {
	buffer->len = SIZE_MAX;
	buffer->data = buffers;
	buffers = buffer;
}
