/*
  Copyright (c) 2012, Matthias Schiffer <mschiffer@universe-factory.net>
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


#ifndef _FASTD_HANDSHAKE_H_
#define _FASTD_HANDSHAKE_H_

#include "fastd.h"


typedef enum _fastd_handshake_record_type {
	RECORD_HANDSHAKE_TYPE = 0,
	RECORD_REPLY_CODE,
	RECORD_ERROR_DETAIL,
	RECORD_FLAGS,
	RECORD_MODE,
	RECORD_PROTOCOL_NAME,
	RECORD_PROTOCOL1,
	RECORD_PROTOCOL2,
	RECORD_PROTOCOL3,
	RECORD_PROTOCOL4,
	RECORD_PROTOCOL5,
	RECORD_MAX,
} fastd_handshake_record_type;

typedef enum _fastd_reply_code {
	REPLY_SUCCESS = 0,
	REPLY_MANDATORY_MISSING,
	REPLY_UNACCEPTABLE_VALUE,
	REPLY_MAX,
} fastd_reply_code;


typedef struct _fastd_handshake_record {
	size_t length;
	void *data;
} fastd_handshake_record;

struct _fastd_handshake {
	uint8_t req_id;
	uint8_t type;
	fastd_handshake_record records[RECORD_MAX];
};


fastd_buffer fastd_handshake_new_init(fastd_context *ctx, fastd_peer *peer, size_t tail_space);
fastd_buffer fastd_handshake_new_reply(fastd_context *ctx, fastd_peer *peer, const fastd_handshake *handshake, size_t tail_space);

void fastd_handshake_handle(fastd_context *ctx, fastd_peer *peer, fastd_buffer buffer);


static inline void fastd_handshake_add(fastd_context *ctx, fastd_buffer *buffer, fastd_handshake_record_type type, size_t len, const void *data) {
	if ((uint8_t*)buffer->data + buffer->len + 2 + len > (uint8_t*)buffer->base + buffer->base_len)
		exit_bug(ctx, "not enough buffer allocated for handshake");

	uint8_t *dst = (uint8_t*)buffer->data + buffer->len;

	dst[0] = type;
	dst[1] = len;
	memcpy(dst+2, data, len);

	buffer->len += 2 + len;
}

static inline void fastd_handshake_add_uint8(fastd_context *ctx, fastd_buffer *buffer, fastd_handshake_record_type type, uint8_t value) {
	if ((uint8_t*)buffer->data + buffer->len + 3 > (uint8_t*)buffer->base + buffer->base_len)
		exit_bug(ctx, "not enough buffer allocated for handshake");

	uint8_t *dst = (uint8_t*)buffer->data + buffer->len;

	dst[0] = type;
	dst[1] = 1;
	dst[2] = value;

	buffer->len += 3;
}


#endif /* _FASTD_HANDSHAKE_H_ */
