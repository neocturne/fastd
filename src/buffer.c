// SPDX-License-Identifier: BSD-2-Clause
/*
  Copyright (c) 2012-2016, Matthias Schiffer <mschiffer@universe-factory.net>
  All rights reserved.
*/

/**
   \file

   Buffer management
*/


#include "fastd.h"


/**
   Allocate a new buffer

   A buffer can have head and tail space which allows changing with data size without moving the data.

   The buffer is always allocated aligned to 16 bytes to allow efficient access for SIMD instructions
   etc. in crypto implementations
*/
fastd_buffer_t fastd_buffer_alloc(const size_t len, size_t head_space, size_t tail_space) {
	size_t base_len = alignto(head_space + len + tail_space, sizeof(fastd_block128_t));
	if (base_len > ctx.max_buffer)
		exit_fatal("BUG: oversized buffer alloc", base_len, ctx.max_buffer);

	void *ptr = fastd_alloc_aligned(base_len, sizeof(fastd_block128_t));

	return (fastd_buffer_t){ .base = ptr, .base_len = base_len, .data = ptr + head_space, .len = len };
}
