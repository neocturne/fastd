/*
  Copyright (c) 2012-2013, Matthias Schiffer <mschiffer@universe-factory.net>
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


#ifndef _FASTD_BUFFER_H_
#define _FASTD_BUFFER_H_

#include "log.h"


struct fastd_buffer {
	void *base;
	size_t base_len;

	void *data;
	size_t len;
};


static inline fastd_buffer_t fastd_buffer_alloc(const fastd_context_t *ctx, size_t len, size_t head_space, size_t tail_space) {
	size_t base_len = head_space+len+tail_space;
	void *ptr;
	int err = posix_memalign(&ptr, 16, base_len);
	if (err)
		exit_error(ctx, "posix_memalign: %s", strerror(err));

	return (fastd_buffer_t){ .base = ptr, .base_len = base_len, .data = ptr+head_space, .len = len };
}

static inline fastd_buffer_t fastd_buffer_dup(const fastd_context_t *ctx, fastd_buffer_t buffer, size_t head_space, size_t tail_space) {
	fastd_buffer_t new_buffer = fastd_buffer_alloc(ctx, buffer.len, head_space, tail_space);
	memcpy(new_buffer.data, buffer.data, buffer.len);
	return new_buffer;
}

static inline void fastd_buffer_free(fastd_buffer_t buffer) {
	free(buffer.base);
}


static inline void fastd_buffer_pull_head(const fastd_context_t *ctx, fastd_buffer_t *buffer, size_t len) {
	if (len > (size_t)(buffer->data - buffer->base))
		exit_bug(ctx, "tried to pull buffer across base");

	buffer->data -= len;
	buffer->len += len;
}

static inline void fastd_buffer_pull_head_zero(const fastd_context_t *ctx, fastd_buffer_t *buffer, size_t len) {
	fastd_buffer_pull_head(ctx, buffer, len);
	memset(buffer->data, 0, len);
}

static inline void fastd_buffer_pull_head_from(const fastd_context_t *ctx, fastd_buffer_t *buffer, const void *data, size_t len) {
	fastd_buffer_pull_head(ctx, buffer, len);
	memcpy(buffer->data, data, len);
}


static inline void fastd_buffer_push_head(const fastd_context_t *ctx, fastd_buffer_t *buffer, size_t len) {
	if (buffer->len < len)
		exit_bug(ctx, "tried to push buffer across tail");

	buffer->data += len;
	buffer->len -= len;
}

static inline void fastd_buffer_push_head_to(const fastd_context_t *ctx, fastd_buffer_t *buffer, void *data, size_t len) {
	memcpy(data, buffer->data, len);
	fastd_buffer_push_head(ctx, buffer, len);
}

#endif /* _FASTD_BUFFER_H_ */