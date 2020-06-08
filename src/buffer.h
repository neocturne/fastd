// SPDX-License-Identifier: BSD-2-Clause
/*
  Copyright (c) 2012-2016, Matthias Schiffer <mschiffer@universe-factory.net>
  All rights reserved.
*/

/**
   \file

   Buffer management
*/


#pragma once

#include "alloc.h"


/** A buffer descriptor */
struct fastd_buffer {
	void *base;      /**< The beginning of the allocated memory area */
	size_t base_len; /**< The size of the allocated memory area */

	void *data; /**< The beginning of the actual data in the buffer */
	size_t len; /**< The data length */
};


/**
   Allocate a new buffer

   A buffer can have head and tail space which allows changing with data size without moving the data.

   The buffer is always allocated aligned to 16 bytes to allow efficient access for SIMD instructions
   etc. in crypto implementations
*/
static inline fastd_buffer_t fastd_buffer_alloc(const size_t len, size_t head_space, size_t tail_space) {
	size_t base_len = head_space + len + tail_space;
	void *ptr = fastd_alloc_aligned(base_len, 16);

	return (fastd_buffer_t){ .base = ptr, .base_len = base_len, .data = ptr + head_space, .len = len };
}

/** Duplicates a buffer */
static inline fastd_buffer_t fastd_buffer_dup(const fastd_buffer_t buffer, size_t head_space, size_t tail_space) {
	fastd_buffer_t new_buffer = fastd_buffer_alloc(buffer.len, head_space, tail_space);
	memcpy(new_buffer.data, buffer.data, buffer.len);
	return new_buffer;
}

/** Frees a buffer */
static inline void fastd_buffer_free(fastd_buffer_t buffer) {
	free(buffer.base);
}


/** Pushes the data head (decreases the head space) */
static inline void fastd_buffer_push(fastd_buffer_t *buffer, size_t len) {
	if (len > (size_t)(buffer->data - buffer->base))
		exit_bug("tried to push buffer across base");

	buffer->data -= len;
	buffer->len += len;
}

/** Pushes the data head and fills with zeroes */
static inline void fastd_buffer_push_zero(fastd_buffer_t *buffer, size_t len) {
	fastd_buffer_push(buffer, len);
	memset(buffer->data, 0, len);
}

/** Pushes the data head and copies data into the new space */
static inline void fastd_buffer_push_from(fastd_buffer_t *buffer, const void *data, size_t len) {
	fastd_buffer_push(buffer, len);
	memcpy(buffer->data, data, len);
}


/** Pulls the buffer head (increases the head space) */
static inline void fastd_buffer_pull(fastd_buffer_t *buffer, size_t len) {
	if (buffer->len < len)
		exit_bug("tried to pull buffer across tail");

	buffer->data += len;
	buffer->len -= len;
}

/** Pulls the buffer head, copying the removed buffer data somewhere else */
static inline void fastd_buffer_pull_to(fastd_buffer_t *buffer, void *data, size_t len) {
	memcpy(data, buffer->data, len);
	fastd_buffer_pull(buffer, len);
}
