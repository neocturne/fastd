// SPDX-License-Identifier: BSD-2-Clause
/*
  Copyright (c) Matthias Schiffer <mschiffer@universe-factory.net>
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
	void *data; /**< The beginning of the actual data in the buffer */
	size_t len; /**< The data length */

	uint8_t base[] __attribute__((aligned(16))); /**< Buffer space */
};

/** A view on a buffer */
struct fastd_buffer_view {
	const void *data; /**< The beginning of the data in the buffer view */
	size_t len;       /**< The data length */
};


void fastd_init_buffers(void);
void fastd_cleanup_buffers(void);


fastd_buffer_t *fastd_buffer_alloc(size_t len, size_t headroom);
void fastd_buffer_free(fastd_buffer_t *buffer);


/** Duplicates a buffer */
static inline fastd_buffer_t *fastd_buffer_dup(const fastd_buffer_t *buffer, size_t headroom) {
	fastd_buffer_t *new_buffer = fastd_buffer_alloc(buffer->len, headroom);
	memcpy(new_buffer->data, buffer->data, buffer->len);
	return new_buffer;
}

/**
   Returns the amount of headroom a buffer has
   (the number of bytes that can be pushed)
*/
static inline size_t fastd_buffer_headroom(const fastd_buffer_t *buffer) {
	return (const uint8_t *)buffer->data - buffer->base;
}

/**
   Realigns a buffer so that it has a given minimal headroom and, subtracting
   the minimal headroom, is aligned for fastd_block128_t

   Consumes the passed buffer.
*/
static inline fastd_buffer_t *fastd_buffer_align(fastd_buffer_t *buffer, size_t min_headroom) {
	ssize_t surplus = fastd_buffer_headroom(buffer) - min_headroom;
	if (surplus >= 0 && surplus % sizeof(fastd_block128_t) == 0)
		return buffer;

	fastd_buffer_t *new_buffer = fastd_buffer_dup(buffer, min_headroom);
	fastd_buffer_free(buffer);

	return new_buffer;
}

/** Zeroes the trailing padding of a buffer, aligned to a multiple of 16 bytes */
static inline void fastd_buffer_zero_pad(fastd_buffer_t *buffer) {
	uint8_t *end = buffer->data + buffer->len;
	uint8_t *end_align = buffer->base + alignto(end - buffer->base, sizeof(fastd_block128_t));
	memset(end, 0, end_align - end);
}

/** Pushes the data head (decreases the head space) */
static inline void fastd_buffer_push(fastd_buffer_t *buffer, size_t len) {
	if (len > fastd_buffer_headroom(buffer))
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

/** Creates a read-only view of a buffer */
static inline fastd_buffer_view_t fastd_buffer_get_view(const fastd_buffer_t *buffer) {
	return (fastd_buffer_view_t){ .data = buffer->data, .len = buffer->len };
}

/** Pulls the view head (increases the head space) */
static inline void fastd_buffer_view_pull(fastd_buffer_view_t *view, size_t len) {
	if (view->len < len)
		exit_bug("tried to pull view across tail");

	view->data += len;
	view->len -= len;
}

/** Pulls the view head, copying the removed view data somewhere else */
static inline void fastd_buffer_view_pull_to(fastd_buffer_view_t *view, void *data, size_t len) {
	memcpy(data, view->data, len);
	fastd_buffer_view_pull(view, len);
}
