/*
  Copyright (c) 2012, Matthias Schiffer <mschiffer@universe-factory.net>
  Partly based on QuickTun Copyright (c) 2010, Ivo Smits <Ivo@UCIS.nl>.
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
	"reply code",
	"error detail",
	"flags",
	"protocol",
	"method name",
};

static const char const *REPLY_TYPES[REPLY_MAX] = {
	"success",
	"mandatory field missing",
	"unacceptable value",
};


static inline void handshake_add(fastd_context *ctx, fastd_buffer *buffer, fastd_handshake_record_type type, size_t len, const void *data) {
	if ((uint8_t*)buffer->data + buffer->len + 2 + len > (uint8_t*)buffer->base + buffer->base_len)
		exit_bug(ctx, "not enough buffer allocated for handshake");

	uint8_t *dst = (uint8_t*)buffer->data + buffer->len;

	dst[0] = type;
	dst[1] = len;
	memcpy(dst+2, data, len);

	buffer->len += 2 + len;
}

void fastd_handshake_send(fastd_context *ctx, fastd_peer *peer) {
	size_t method_len = strlen(ctx->conf->method->name);
	fastd_buffer buffer = fastd_buffer_alloc(sizeof(fastd_packet), 0,
						 2+1 +           /* protocol */
						 2+method_len    /* method name */
						 );
	fastd_packet *request = buffer.data;

	request->reply = 0;
	request->cp = 0;
	request->req_id = ++peer->last_req_id;
	request->rsv = 0;

	uint8_t protocol = ctx->conf->protocol;
	handshake_add(ctx, &buffer, RECORD_PROTOCOL, 1, &protocol);

	handshake_add(ctx, &buffer, RECORD_METHOD_NAME, method_len, ctx->conf->method->name);

	fastd_task_put_send_handshake(ctx, peer, buffer);
}



void fastd_handshake_handle(fastd_context *ctx, fastd_peer *peer, fastd_buffer buffer) {
	if (buffer.len < sizeof(fastd_packet)) {
		pr_warn(ctx, "received an invalid handshake from %P", peer);
		goto end_free;
	}

	fastd_packet *packet = buffer.base;

	size_t lengths[RECORD_MAX];
	void *records[RECORD_MAX] = { 0 };

	uint8_t *ptr = packet->tlv_data;
	while (true) {
		if (ptr+2 > (uint8_t*)buffer.data + buffer.len)
			break;

		uint8_t type = ptr[0];
		uint8_t len = ptr[1];

		if (ptr+2+len > (uint8_t*)buffer.data + buffer.len)
			break;

		lengths[type] = len;
		records[type] = ptr+2;

		ptr += 2+len;
	}

	if (!packet->reply) {
		fastd_buffer reply_buffer;
		fastd_packet *reply;

		uint8_t reply_code = REPLY_SUCCESS;
		uint8_t error_detail = 0;

		if (!records[RECORD_PROTOCOL]) {
			reply_code = REPLY_MANDATORY_MISSING;
			error_detail = RECORD_PROTOCOL;
			goto send_reply;
		}

		if (lengths[RECORD_PROTOCOL] != 1 || *(uint8_t*)records[RECORD_PROTOCOL] != ctx->conf->protocol) {
			reply_code = REPLY_UNACCEPTABLE_VALUE;
			error_detail = RECORD_PROTOCOL;
			goto send_reply;
		}

		if (!records[RECORD_METHOD_NAME]) {
			reply_code = REPLY_MANDATORY_MISSING;
			error_detail = RECORD_METHOD_NAME;
			goto send_reply;
		}

		if (lengths[RECORD_METHOD_NAME] != strlen(ctx->conf->method->name)
		    || strncmp((char*)records[RECORD_METHOD_NAME], ctx->conf->method->name, lengths[RECORD_METHOD_NAME])) {
			reply_code = REPLY_UNACCEPTABLE_VALUE;
			error_detail = RECORD_METHOD_NAME;
			goto send_reply;
		}

	send_reply:
		reply_buffer = fastd_buffer_alloc(sizeof(fastd_packet), 0, 6 /* enough space for reply code and error detail */);
		reply = reply_buffer.data;

		reply->reply = 1;
		reply->cp = packet->cp;
		reply->req_id = packet->req_id;
		reply->rsv = 0;

		handshake_add(ctx, &reply_buffer, RECORD_REPLY_CODE, 1, &reply_code);

		if (reply_code)
			handshake_add(ctx, &reply_buffer, RECORD_ERROR_DETAIL, 1, &error_detail);

		fastd_task_put_send_handshake(ctx, peer, reply_buffer);
	}
	else {
		if (!packet->cp) {
			if (packet->req_id != peer->last_req_id) {
				pr_warn(ctx, "received handshake reply with request ID %u from %P while %u was expected", packet->req_id, peer, peer->last_req_id);
				goto end_free;
			}
		}
		else {
			goto end_free; /* TODO */
		}

		if (!records[RECORD_REPLY_CODE] || lengths[RECORD_REPLY_CODE] != 1) {
			pr_warn(ctx, "received handshake reply without reply code from %P", peer);
			goto end_free;
		}

		uint8_t reply_code = *(uint8_t*)records[RECORD_REPLY_CODE];
		uint8_t error_detail;
		const char *error_field_str;

		switch (reply_code) {
		case REPLY_SUCCESS:
			pr_info(ctx, "Handshake with %P successful.", peer);
			fastd_peer_set_established(ctx, peer);
			ctx->conf->method->init(ctx, peer);
			break;

		default:
			if (reply_code >= REPLY_MAX) {
				pr_warn(ctx, "Handshake with %P failed with unknown code %i", peer, reply_code);
				break;
			}

			if (!records[RECORD_ERROR_DETAIL] || lengths[RECORD_ERROR_DETAIL] != 1) {
				pr_warn(ctx, "Handshake with %P failed with code %s", peer, REPLY_TYPES[reply_code]);
				break;
			}

			error_detail = *(uint8_t*)records[RECORD_ERROR_DETAIL];
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
