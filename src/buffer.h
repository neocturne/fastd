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

#include "log.h"
#include "util.h"


/** A buffer descriptor */
struct fastd_buffer {
	void *base;      /**< The beginning of the allocated memory area */
	size_t base_len; /**< The size of the allocated memory area */

	void *data; /**< The beginning of the actual data in the buffer */
	size_t len; /**< The data length */
};


fastd_buffer_t fastd_buffer_alloc(size_t len, size_t head_space);


/** Duplicates a buffer */
static inline fastd_buffer_t fastd_buffer_dup(fastd_buffer_t buffer, size_t head_space) {
	fastd_buffer_t new_buffer = fastd_buffer_alloc(buffer.len, head_space);
	memcpy(new_buffer.data, buffer.data, buffer.len);
	return new_buffer;
}

/** Frees a buffer */
static inline void fastd_buffer_free(fastd_buffer_t buffer) {
	free(buffer.base);
}

/** Zeroes the trailing padding of a buffer, aligned to a multiple of 16 bytes */
static inline void fastd_buffer_zero_pad(fastd_buffer_t buffer) {
	void *end = buffer.data + buffer.len;
	void *end_align = buffer.base + alignto(end - buffer.base, sizeof(fastd_block128_t));
	memset(end, 0, end_align - end);
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
