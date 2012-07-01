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
	"(protocol specific 1)",
	"(protocol specific 2)",
	"(protocol specific 3)",
	"(protocol specific 4)",
	"(protocol specific 5)",
	"MTU",
	"method name",
	"version name",
};

static const char const *REPLY_TYPES[REPLY_MAX] = {
	"success",
	"mandatory field missing",
	"unacceptable value",
};

#define AS_UINT8(ptr) (*(uint8_t*)(ptr).data)
#define AS_UINT16(ptr) ((*(uint8_t*)(ptr).data) + (*((uint8_t*)(ptr).data+1) << 8))


fastd_buffer fastd_handshake_new_init(fastd_context *ctx, size_t tail_space) {
	size_t protocol_len = strlen(ctx->conf->protocol->name);
	size_t method_len = strlen(ctx->conf->method->name);
	size_t version_len = strlen(FASTD_VERSION);
	fastd_buffer buffer = fastd_buffer_alloc(sizeof(fastd_packet), 0,
						 2*5 +            /* handshake type, mode */
						 6 +		  /* MTU */
						 4+protocol_len + /* protocol name */
						 4+method_len +   /* method name */
						 4+version_len +  /* version name */
						 tail_space
						 );
	fastd_packet *request = buffer.data;

	request->rsv1 = 0;
	request->rsv2 = 0;

	fastd_handshake_add_uint8(ctx, &buffer, RECORD_HANDSHAKE_TYPE, 1);
	fastd_handshake_add_uint8(ctx, &buffer, RECORD_MODE, ctx->conf->mode);
	fastd_handshake_add_uint16(ctx, &buffer, RECORD_MTU, ctx->conf->mtu);

	fastd_handshake_add(ctx, &buffer, RECORD_PROTOCOL_NAME, protocol_len, ctx->conf->protocol->name);
	fastd_handshake_add(ctx, &buffer, RECORD_METHOD_NAME, method_len, ctx->conf->method->name);
	fastd_handshake_add(ctx, &buffer, RECORD_VERSION_NAME, version_len, FASTD_VERSION);

	return buffer;
}

fastd_buffer fastd_handshake_new_reply(fastd_context *ctx, const fastd_handshake *handshake, size_t tail_space) {
	bool first = (AS_UINT8(handshake->records[RECORD_HANDSHAKE_TYPE]) == 1);
	size_t version_len = strlen(FASTD_VERSION);
	size_t extra_size = 0;

	if (first)
		extra_size = 6 +            /* MTU */
			     4+version_len; /* version name */

	fastd_buffer buffer = fastd_buffer_alloc(sizeof(fastd_packet), 0,
						 2*5 +           /* handshake type, reply code */
						 extra_size +
						 tail_space
						 );
	fastd_packet *request = buffer.data;

	request->rsv1 = 0;
	request->rsv2 = 0;

	fastd_handshake_add_uint8(ctx, &buffer, RECORD_HANDSHAKE_TYPE, AS_UINT8(handshake->records[RECORD_HANDSHAKE_TYPE])+1);
	fastd_handshake_add_uint8(ctx, &buffer, RECORD_REPLY_CODE, 0);

	if (first) {
		fastd_handshake_add_uint16(ctx, &buffer, RECORD_MTU, ctx->conf->mtu);
		fastd_handshake_add(ctx, &buffer, RECORD_VERSION_NAME, version_len, FASTD_VERSION);
	}

	return buffer;
}

void fastd_handshake_handle(fastd_context *ctx, const fastd_peer_address *address, const fastd_peer_config *peer_conf, fastd_buffer buffer) {
	if (buffer.len < sizeof(fastd_packet)) {
		pr_warn(ctx, "received a short handshake from %I", address);
		goto end_free;
	}

	fastd_handshake handshake;
	memset(&handshake, 0, sizeof(handshake));

	fastd_packet *packet = buffer.data;

	uint8_t *ptr = packet->tlv_data;
	while (true) {
		if (ptr+4 > (uint8_t*)buffer.data + buffer.len)
			break;

		uint16_t type = ptr[0] + (ptr[1] << 8);
		uint16_t len = ptr[2] + (ptr[3] << 8);

		if (ptr+4+len > (uint8_t*)buffer.data + buffer.len)
			break;

		if (type < RECORD_MAX) {
			handshake.records[type].length = len;
			handshake.records[type].data = ptr+4;
		}

		ptr += 4+len;
	}

	if (handshake.records[RECORD_HANDSHAKE_TYPE].length != 1) {
		pr_debug(ctx, "received handshake without handshake type from %I", address);
		goto end_free;
	}

	handshake.type = AS_UINT8(handshake.records[RECORD_HANDSHAKE_TYPE]);

	if (handshake.records[RECORD_MTU].length == 2) {
		if (AS_UINT16(handshake.records[RECORD_MTU]) != ctx->conf->mtu) {
			pr_warn(ctx, "MTU configuration differs with peer %I: local MTU is %u, remote MTU is %u",
				 address, ctx->conf->mtu, AS_UINT16(handshake.records[RECORD_MTU]));
		}
	}

	if (handshake.type == 1) {
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

		if (!handshake.records[RECORD_METHOD_NAME].data) {
			reply_code = REPLY_MANDATORY_MISSING;
			error_detail = RECORD_METHOD_NAME;
			goto send_reply;
		}

		if (handshake.records[RECORD_METHOD_NAME].length != strlen(ctx->conf->method->name)
		    || strncmp((char*)handshake.records[RECORD_METHOD_NAME].data, ctx->conf->method->name, handshake.records[RECORD_METHOD_NAME].length)) {
			reply_code = REPLY_UNACCEPTABLE_VALUE;
			error_detail = RECORD_METHOD_NAME;
			goto send_reply;
		}

	send_reply:
		if (reply_code) {
			fastd_buffer reply_buffer = fastd_buffer_alloc(sizeof(fastd_packet), 0, 3*5 /* enough space for handshake type, reply code and error detail */);
			fastd_packet *reply = reply_buffer.data;

			reply->rsv1 = 0;
			reply->rsv2 = 0;

			fastd_handshake_add_uint8(ctx, &reply_buffer, RECORD_HANDSHAKE_TYPE, 2);
			fastd_handshake_add_uint8(ctx, &reply_buffer, RECORD_REPLY_CODE, reply_code);
			fastd_handshake_add_uint8(ctx, &reply_buffer, RECORD_ERROR_DETAIL, error_detail);

			fastd_send_handshake(ctx, address, reply_buffer);
		}
		else {
			ctx->conf->protocol->handshake_handle(ctx, address, peer_conf, &handshake);
		}
	}
	else {
		if ((handshake.type & 1) == 0) {
			/*if (packet->req_id != peer->last_req_id) {
				pr_warn(ctx, "received handshake reply with request ID %u from %P while %u was expected", packet->req_id, peer, peer->last_req_id);
				goto end_free;
				}*/
		}

		if (handshake.records[RECORD_REPLY_CODE].length != 1) {
			pr_warn(ctx, "received handshake reply without reply code from %I", address);
			goto end_free;
		}

		uint8_t reply_code = AS_UINT8(handshake.records[RECORD_REPLY_CODE]);

		if (reply_code == REPLY_SUCCESS) {
			ctx->conf->protocol->handshake_handle(ctx, address, peer_conf, &handshake);
		}
		else {
			const char *error_field_str;

			if (reply_code >= REPLY_MAX) {
				pr_warn(ctx, "Handshake with %I failed with unknown code %i", address, reply_code);
				goto end_free;
			}

			if (handshake.records[RECORD_ERROR_DETAIL].length != 1) {
				pr_warn(ctx, "Handshake with %I failed with code %s", address, REPLY_TYPES[reply_code]);
				goto end_free;
			}

			uint8_t error_detail = AS_UINT8(handshake.records[RECORD_ERROR_DETAIL]);
			if (error_detail >= RECORD_MAX)
				error_field_str = "<unknown>";
			else
				error_field_str = RECORD_TYPES[error_detail];

			switch (reply_code) {
			case REPLY_MANDATORY_MISSING:
				pr_warn(ctx, "Handshake with %I failed: mandatory field `%s' missing", address, error_field_str);
				break;

			case REPLY_UNACCEPTABLE_VALUE:
				pr_warn(ctx, "Handshake with %I failed: unacceptable value for field `%s'", address, error_field_str);
				break;

			default: /* just to silence the warning */
				break;
			}
		}
	}

 end_free:
	fastd_buffer_free(buffer);
}
