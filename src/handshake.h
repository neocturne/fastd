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


#ifndef _FASTD_HANDSHAKE_H_
#define _FASTD_HANDSHAKE_H_

#include "fastd.h"


typedef enum fastd_handshake_record_type {
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
	RECORD_MTU,
	RECORD_METHOD_NAME,
	RECORD_VERSION_NAME,
	RECORD_METHOD_LIST,
	RECORD_TLV_MAC,
	RECORD_MAX,
} fastd_handshake_record_type_t;

typedef enum fastd_reply_code {
	REPLY_SUCCESS = 0,
	REPLY_MANDATORY_MISSING,
	REPLY_UNACCEPTABLE_VALUE,
	REPLY_MAX,
} fastd_reply_code_t;


typedef struct __attribute__((__packed__)) fastd_handshake_packet {
	uint8_t rsv;
	uint16_t tlv_len;
	uint8_t tlv_data[];
} fastd_handshake_packet_t;

typedef struct fastd_handshake_record {
	size_t length;
	uint8_t *data;
} fastd_handshake_record_t;

struct fastd_handshake {
	uint8_t type;
	const char *peer_version;
	fastd_handshake_record_t records[RECORD_MAX];
	uint16_t tlv_len;
	void *tlv_data;
};


fastd_buffer_t fastd_handshake_new_init(fastd_context_t *ctx, size_t tail_space);
fastd_buffer_t fastd_handshake_new_reply(fastd_context_t *ctx, const fastd_handshake_t *handshake, const fastd_method_t *method, bool with_method_list, size_t tail_space);

void fastd_handshake_handle(fastd_context_t *ctx, fastd_socket_t *sock, const fastd_peer_address_t *local_addr, const fastd_peer_address_t *remote_addr, fastd_peer_t *peer, fastd_buffer_t buffer);


static inline void* fastd_handshake_tlv_data(const fastd_buffer_t *buffer) {
	fastd_handshake_packet_t *packet = buffer->data;
	return packet->tlv_data;
}

static inline uint16_t fastd_handshake_tlv_len(const fastd_buffer_t *buffer) {
	fastd_handshake_packet_t *packet = buffer->data;
	return ntohs(packet->tlv_len);
}

static inline uint8_t* fastd_handshake_extend(fastd_context_t *ctx, fastd_buffer_t *buffer, fastd_handshake_record_type_t type, size_t len) {
	uint8_t *dst = buffer->data + buffer->len;

	if (buffer->data + buffer->len + 4 + len > buffer->base + buffer->base_len)
		exit_bug(ctx, "not enough buffer allocated for handshake");

	buffer->len += 4 + len;

	fastd_handshake_packet_t *packet = buffer->data;
	packet->tlv_len = htons(fastd_handshake_tlv_len(buffer) + 4 + len);

	dst[0] = type;
	dst[1] = type >> 8;
	dst[2] = len;
	dst[3] = len >> 8;

	return dst+4;
}

static inline void fastd_handshake_add(fastd_context_t *ctx, fastd_buffer_t *buffer, fastd_handshake_record_type_t type, size_t len, const void *data) {
	uint8_t *dst = fastd_handshake_extend(ctx, buffer, type, len);

	memcpy(dst, data, len);
}

static inline void fastd_handshake_add_uint8(fastd_context_t *ctx, fastd_buffer_t *buffer, fastd_handshake_record_type_t type, uint8_t value) {
	uint8_t *dst = fastd_handshake_extend(ctx, buffer, type, 1);

	dst[0] = value;
}

static inline void fastd_handshake_add_uint16(fastd_context_t *ctx, fastd_buffer_t *buffer, fastd_handshake_record_type_t type, uint16_t value) {
	uint8_t *dst = fastd_handshake_extend(ctx, buffer, type, 2);

	dst[0] = value;
	dst[1] = value >> 8;
}


#endif /* _FASTD_HANDSHAKE_H_ */
