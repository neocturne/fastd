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


#include "handshake.h"
#include "packet.h"
#include "peer.h"
#include "task.h"

#include <string.h>


static const char const *RECORD_TYPES[RECORD_MAX] = {
	"handshake type",
	"reply code",
	"error detail",
	"flags",
	"mode",
	"protocol name",
};

static const char const *REPLY_TYPES[REPLY_MAX] = {
	"success",
	"mandatory field missing",
	"unacceptable value",
};

#define AS_UINT8(ptr) (*(uint8_t*)(ptr).data)

static inline void handshake_add(fastd_context *ctx, fastd_buffer *buffer, fastd_handshake_record_type type, size_t len, const void *data) {
	if ((uint8_t*)buffer->data + buffer->len + 2 + len > (uint8_t*)buffer->base + buffer->base_len)
		exit_bug(ctx, "not enough buffer allocated for handshake");

	uint8_t *dst = (uint8_t*)buffer->data + buffer->len;

	dst[0] = type;
	dst[1] = len;
	memcpy(dst+2, data, len);

	buffer->len += 2 + len;
}

static inline void handshake_add_uint8(fastd_context *ctx, fastd_buffer *buffer, fastd_handshake_record_type type, uint8_t value) {
	if ((uint8_t*)buffer->data + buffer->len + 3 > (uint8_t*)buffer->base + buffer->base_len)
		exit_bug(ctx, "not enough buffer allocated for handshake");

	uint8_t *dst = (uint8_t*)buffer->data + buffer->len;

	dst[0] = type;
	dst[1] = 1;
	dst[2] = value;

	buffer->len += 3;
}

fastd_buffer fastd_handshake_new_init(fastd_context *ctx, fastd_peer *peer, size_t tail_space) {
	size_t protocol_len = strlen(ctx->conf->protocol->name);
	fastd_buffer buffer = fastd_buffer_alloc(sizeof(fastd_packet), 0,
						 2*3 +           /* handshake type, mode */
						 2+protocol_len+ /* protocol name */
						 tail_space
						 );
	fastd_packet *request = buffer.data;

	request->req_id = ++peer->last_req_id;
	request->rsv = 0;

	handshake_add_uint8(ctx, &buffer, RECORD_HANDSHAKE_TYPE, 1);
	handshake_add_uint8(ctx, &buffer, RECORD_MODE, ctx->conf->mode);

	handshake_add(ctx, &buffer, RECORD_PROTOCOL_NAME, protocol_len, ctx->conf->protocol->name);

	return buffer;
}

fastd_buffer fastd_handshake_new_reply(fastd_context *ctx, fastd_peer *peer, const fastd_handshake *handshake, size_t tail_space) {
	fastd_buffer buffer = fastd_buffer_alloc(sizeof(fastd_packet), 0,
						 2*3 +           /* handshake type, reply code */
						 tail_space
						 );
	fastd_packet *request = buffer.data;

	request->req_id = handshake->req_id;
	request->rsv = 0;

	handshake_add_uint8(ctx, &buffer, RECORD_HANDSHAKE_TYPE, AS_UINT8(handshake->records[RECORD_HANDSHAKE_TYPE])+1);
	handshake_add_uint8(ctx, &buffer, RECORD_REPLY_CODE, 0);

	return buffer;
}


void fastd_handshake_handle(fastd_context *ctx, fastd_peer *peer, fastd_buffer buffer) {
	if (buffer.len < sizeof(fastd_packet)) {
		pr_warn(ctx, "received a short handshake from %P", peer);
		goto end_free;
	}

	fastd_handshake handshake;
	memset(&handshake, 0, sizeof(handshake));

	fastd_packet *packet = buffer.data;

	uint8_t *ptr = packet->tlv_data;
	while (true) {
		if (ptr+2 > (uint8_t*)buffer.data + buffer.len)
			break;

		uint8_t type = ptr[0];
		uint8_t len = ptr[1];

		if (ptr+2+len > (uint8_t*)buffer.data + buffer.len)
			break;

		handshake.records[type].length = len;
		handshake.records[type].data = ptr+2;

		ptr += 2+len;
	}

	handshake.req_id = packet->req_id;

	if (handshake.records[RECORD_HANDSHAKE_TYPE].length != 1)
		goto end_free;

	if (AS_UINT8(handshake.records[RECORD_HANDSHAKE_TYPE]) == 1) {
		uint8_t reply_code = REPLY_SUCCESS;
		uint8_t error_detail = 0;

		if (!handshake.records[RECORD_MODE].data) {
			reply_code = REPLY_MANDATORY_MISSING;
			error_detail = RECORD_MODE;
			goto send_reply;
		}

		if (handshake.records[RECORD_MODE].length != 1 || AS_UINT8(handshake.records[RECORD_MODE]) != ctx->conf->mode) {
			reply_code = REPLY_UNACCEPTABLE_VALUE;
			error_detail = RECORD_MODE;
			goto send_reply;
		}

		if (!handshake.records[RECORD_PROTOCOL_NAME].data) {
			reply_code = REPLY_MANDATORY_MISSING;
			error_detail = RECORD_PROTOCOL_NAME;
			goto send_reply;
		}

		if (handshake.records[RECORD_PROTOCOL_NAME].length != strlen(ctx->conf->protocol->name)
		    || strncmp((char*)handshake.records[RECORD_PROTOCOL_NAME].data, ctx->conf->protocol->name, handshake.records[RECORD_PROTOCOL_NAME].length)) {
			reply_code = REPLY_UNACCEPTABLE_VALUE;
			error_detail = RECORD_PROTOCOL_NAME;
			goto send_reply;
		}

	send_reply:
		if (reply_code) {
			fastd_buffer reply_buffer = fastd_buffer_alloc(sizeof(fastd_packet), 0, 3*3 /* enough space for handshake type, reply code and error detail */);
			fastd_packet *reply = reply_buffer.data;

			reply->req_id = packet->req_id;
			reply->rsv = 0;

			handshake_add_uint8(ctx, &reply_buffer, RECORD_HANDSHAKE_TYPE, 2);
			handshake_add_uint8(ctx, &reply_buffer, RECORD_REPLY_CODE, reply_code);
			handshake_add_uint8(ctx, &reply_buffer, RECORD_ERROR_DETAIL, error_detail);
		}
		else {
			ctx->conf->protocol->handshake_handle(ctx, peer, &handshake);
		}
	}
	else {
		if ((AS_UINT8(handshake.records[RECORD_HANDSHAKE_TYPE]) & 1) == 0) {
			if (packet->req_id != peer->last_req_id) {
				pr_warn(ctx, "received handshake reply with request ID %u from %P while %u was expected", packet->req_id, peer, peer->last_req_id);
				goto end_free;
			}
		}

		if (handshake.records[RECORD_REPLY_CODE].length != 1) {
			pr_warn(ctx, "received handshake reply without reply code from %P", peer);
			goto end_free;
		}

		uint8_t reply_code = AS_UINT8(handshake.records[RECORD_REPLY_CODE]);

		if (reply_code == REPLY_SUCCESS) {
			ctx->conf->protocol->handshake_handle(ctx, peer, &handshake);
		}
		else {
			const char *error_field_str;

			if (reply_code >= REPLY_MAX) {
				pr_warn(ctx, "Handshake with %P failed with unknown code %i", peer, reply_code);
				goto end_free;
			}

			if (handshake.records[RECORD_ERROR_DETAIL].length != 1) {
				pr_warn(ctx, "Handshake with %P failed with code %s", peer, REPLY_TYPES[reply_code]);
				goto end_free;
			}

			uint8_t error_detail = AS_UINT8(handshake.records[RECORD_ERROR_DETAIL]);
			if (error_detail >= RECORD_MAX)
				error_field_str = "<unknown>";
			else
				error_field_str = RECORD_TYPES[error_detail];

			switch (reply_code) {
			case REPLY_MANDATORY_MISSING:
				pr_warn(ctx, "Handshake with %P failed: mandatory field `%s' missing", peer, error_field_str);
				break;

			case REPLY_UNACCEPTABLE_VALUE:
				pr_warn(ctx, "Handshake with %P failed: unacceptable value for field `%s'", peer, error_field_str);
				break;

			default: /* just to silence the warning */
				break;
			}
		}
	}

 end_free:
	fastd_buffer_free(buffer);
}
