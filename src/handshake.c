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


#include "handshake.h"
#include "peer.h"


static const char *const RECORD_TYPES[RECORD_MAX] = {
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
	"method list",
	"TLV message authentication code",
};

static const char *const REPLY_TYPES[REPLY_MAX] = {
	"success",
	"mandatory field missing",
	"unacceptable value",
};

#define AS_UINT8(ptr) (*(uint8_t*)(ptr).data)
#define AS_UINT16(ptr) ((*(uint8_t*)(ptr).data) + (*((uint8_t*)(ptr).data+1) << 8))


static uint8_t* create_method_list(fastd_context_t *ctx, size_t *len) {
	*len = strlen(ctx->conf->methods[0]->name);

	int i;
	for (i = 1; i < MAX_METHODS; i++) {
		if (!ctx->conf->methods[i])
			break;

		*len += strlen(ctx->conf->methods[i]->name) + 1;
	}

	uint8_t *ret = malloc(*len+1);
	char *ptr = (char*)ret;

	for (i = 0; i < MAX_METHODS; i++) {
		if (!ctx->conf->methods[i])
			break;

		ptr = stpcpy(ptr, ctx->conf->methods[i]->name) + 1;
	}

	return ret;
}

static inline bool string_equal(const char *str, const char *buf, size_t maxlen) {
	if (strlen(str) != strnlen(buf, maxlen))
		return false;

	return !strncmp(str, buf, maxlen);
}

static inline bool record_equal(const char *str, const fastd_handshake_record_t *record) {
	return string_equal(str, (const char*)record->data, record->length);
}

static const fastd_method_t* method_from_name(fastd_context_t *ctx, const char *name, size_t n) {
	int i;
	for (i = 0; i < MAX_METHODS; i++) {
		if (!ctx->conf->methods[i])
			break;

		if (string_equal(ctx->conf->methods[i]->name, name, n))
			return ctx->conf->methods[i];
	}

	return NULL;
}

static fastd_string_stack_t* parse_string_list(const uint8_t *data, size_t len) {
	const uint8_t *end = data+len;
	fastd_string_stack_t *ret = NULL;

	while (data < end) {
		fastd_string_stack_t *part = fastd_string_stack_dupn((char*)data, end-data);
		part->next = ret;
		ret = part;
		data += strlen(part->str) + 1;
	}

	return ret;
}

static fastd_buffer_t new_handshake(fastd_context_t *ctx, uint8_t type, const fastd_method_t *method, bool with_method_list, size_t tail_space) {
	size_t version_len = strlen(FASTD_VERSION);
	size_t protocol_len = strlen(ctx->conf->protocol->name);
	size_t method_len = method ? strlen(method->name) : 0;

	size_t method_list_len = 0;
	uint8_t *method_list = NULL;

	if (with_method_list)
		method_list = create_method_list(ctx, &method_list_len);

	fastd_buffer_t buffer = fastd_buffer_alloc(ctx, sizeof(fastd_handshake_packet_t), 1,
						   3*5 +               /* handshake type, mode, reply code */
						   6 +                 /* MTU */
						   4+version_len +     /* version name */
						   4+protocol_len +    /* protocol name */
						   4+method_len +      /* method name */
						   4+method_list_len + /* supported method name list */
						   tail_space);
	fastd_handshake_packet_t *packet = buffer.data;

	packet->rsv = 0;
	packet->tlv_len = 0;

	fastd_handshake_add_uint8(ctx, &buffer, RECORD_HANDSHAKE_TYPE, type);
	fastd_handshake_add_uint8(ctx, &buffer, RECORD_MODE, ctx->conf->mode);
	fastd_handshake_add_uint16(ctx, &buffer, RECORD_MTU, ctx->conf->mtu);

	fastd_handshake_add(ctx, &buffer, RECORD_VERSION_NAME, version_len, FASTD_VERSION);
	fastd_handshake_add(ctx, &buffer, RECORD_PROTOCOL_NAME, protocol_len, ctx->conf->protocol->name);

	if (method)
		fastd_handshake_add(ctx, &buffer, RECORD_METHOD_NAME, method_len, method->name);

	if (with_method_list) {
		fastd_handshake_add(ctx, &buffer, RECORD_METHOD_LIST, method_list_len, method_list);
		free(method_list);
	}

	return buffer;
}

fastd_buffer_t fastd_handshake_new_init(fastd_context_t *ctx, size_t tail_space) {
	if (ctx->conf->secure_handshakes)
		return new_handshake(ctx, 1, NULL, false, tail_space);
	else
		return new_handshake(ctx, 1, ctx->conf->method_default, true, tail_space);
}

fastd_buffer_t fastd_handshake_new_reply(fastd_context_t *ctx, const fastd_handshake_t *handshake, const fastd_method_t *method, bool with_method_list, size_t tail_space) {
	fastd_buffer_t buffer = new_handshake(ctx, handshake->type+1, method, with_method_list, tail_space);
	fastd_handshake_add_uint8(ctx, &buffer, RECORD_REPLY_CODE, 0);
	return buffer;
}

static void print_error(fastd_context_t *ctx, const char *prefix, const fastd_peer_address_t *remote_addr, uint8_t reply_code, uint8_t error_detail) {
	const char *error_field_str;

	if (error_detail >= RECORD_MAX)
		error_field_str = "<unknown>";
	else
		error_field_str = RECORD_TYPES[error_detail];

	switch (reply_code) {
	case REPLY_SUCCESS:
		break;

	case REPLY_MANDATORY_MISSING:
		pr_warn(ctx, "Handshake with %I failed: %s error: mandatory field `%s' missing", remote_addr, prefix, error_field_str);
		break;

	case REPLY_UNACCEPTABLE_VALUE:
		pr_warn(ctx, "Handshake with %I failed: %s error: unacceptable value for field `%s'", remote_addr, prefix, error_field_str);
		break;

	default:
		pr_warn(ctx, "Handshake with %I failed: %s error: unknown code %i", remote_addr, prefix, reply_code);
	}
}

static void send_error(fastd_context_t *ctx, fastd_socket_t *sock, const fastd_peer_address_t *local_addr, const fastd_peer_address_t *remote_addr, fastd_peer_t *peer, const fastd_handshake_t *handshake, uint8_t reply_code, uint8_t error_detail) {
	print_error(ctx, "sending", remote_addr, reply_code, error_detail);

	fastd_buffer_t buffer = fastd_buffer_alloc(ctx, sizeof(fastd_handshake_packet_t), 0, 3*5 /* enough space for handshake type, reply code and error detail */);
	fastd_handshake_packet_t *reply = buffer.data;

	reply->rsv = 0;
	reply->tlv_len = 0;

	fastd_handshake_add_uint8(ctx, &buffer, RECORD_HANDSHAKE_TYPE, handshake->type+1);
	fastd_handshake_add_uint8(ctx, &buffer, RECORD_REPLY_CODE, reply_code);
	fastd_handshake_add_uint8(ctx, &buffer, RECORD_ERROR_DETAIL, error_detail);

	fastd_send_handshake(ctx, sock, local_addr, remote_addr, peer, buffer);
}

static inline fastd_handshake_t parse_tlvs(const fastd_buffer_t *buffer) {
	fastd_handshake_t handshake = {};

	if (buffer->len < sizeof(fastd_handshake_packet_t))
		return handshake;

	fastd_handshake_packet_t *packet = buffer->data;

	size_t len = buffer->len - sizeof(fastd_handshake_packet_t);
	if (packet->tlv_len) {
		size_t tlv_len = fastd_handshake_tlv_len(buffer);
		if (tlv_len > len)
			return handshake;

		len = tlv_len;
	}

	uint8_t *ptr = packet->tlv_data, *end = packet->tlv_data + len;
	handshake.tlv_len = len;
	handshake.tlv_data = packet->tlv_data;

	while (true) {
		if (ptr+4 > end)
			break;

		uint16_t type = ptr[0] + (ptr[1] << 8);
		uint16_t len = ptr[2] + (ptr[3] << 8);

		if (ptr+4+len > end)
			break;

		if (type < RECORD_MAX) {
			handshake.records[type].length = len;
			handshake.records[type].data = ptr+4;
		}

		ptr += 4+len;
	}

	return handshake;
}

static inline void print_error_reply(fastd_context_t *ctx, const fastd_peer_address_t *remote_addr, const fastd_handshake_t *handshake) {
	uint8_t reply_code = AS_UINT8(handshake->records[RECORD_REPLY_CODE]);
	uint8_t error_detail = RECORD_MAX;

	if (handshake->records[RECORD_ERROR_DETAIL].length == 1)
		error_detail = AS_UINT8(handshake->records[RECORD_ERROR_DETAIL]);

	print_error(ctx, "received", remote_addr, reply_code, error_detail);
}

static inline bool check_records(fastd_context_t *ctx, fastd_socket_t *sock, const fastd_peer_address_t *local_addr, const fastd_peer_address_t *remote_addr, fastd_peer_t *peer, const fastd_handshake_t *handshake) {
	if (handshake->records[RECORD_PROTOCOL_NAME].data) {
		if (!record_equal(ctx->conf->protocol->name, &handshake->records[RECORD_PROTOCOL_NAME])) {
			send_error(ctx, sock, local_addr, remote_addr, peer, handshake, REPLY_UNACCEPTABLE_VALUE, RECORD_PROTOCOL_NAME);
			return false;
		}
	}

	if (handshake->records[RECORD_MODE].data) {
		if (handshake->records[RECORD_MODE].length != 1 || AS_UINT8(handshake->records[RECORD_MODE]) != ctx->conf->mode) {
			send_error(ctx, sock, local_addr, remote_addr, peer, handshake, REPLY_UNACCEPTABLE_VALUE, RECORD_MODE);
			return false;
		}
	}

	if (!ctx->conf->secure_handshakes || handshake->type > 1) {
		if (handshake->records[RECORD_MTU].length == 2) {
			if (AS_UINT16(handshake->records[RECORD_MTU]) != ctx->conf->mtu) {
				pr_warn(ctx, "MTU configuration differs with peer %I: local MTU is %u, remote MTU is %u",
					remote_addr, ctx->conf->mtu, AS_UINT16(handshake->records[RECORD_MTU]));
			}
		}
	}

	if (handshake->type > 1) {
		if (handshake->records[RECORD_REPLY_CODE].length != 1) {
			pr_warn(ctx, "received handshake reply without reply code from %I", remote_addr);
			return false;
		}

		if (AS_UINT8(handshake->records[RECORD_REPLY_CODE]) != REPLY_SUCCESS) {
			print_error_reply(ctx, remote_addr, handshake);
			return false;
		}
	}

	return true;
}

static inline const fastd_method_t* get_method(fastd_context_t *ctx, const fastd_handshake_t *handshake) {
	if (handshake->records[RECORD_METHOD_LIST].data && handshake->records[RECORD_METHOD_LIST].length) {
		fastd_string_stack_t *method_list = parse_string_list(handshake->records[RECORD_METHOD_LIST].data, handshake->records[RECORD_METHOD_LIST].length);

		const fastd_method_t *method;
		fastd_string_stack_t *method_name = method_list;

		while (method_name) {
			const fastd_method_t *cur_method = method_from_name(ctx, method_name->str, SIZE_MAX);

			if (cur_method)
				method = cur_method;

			method_name = method_name->next;
		}

		fastd_string_stack_free(method_list);

		return method;
	}

	if (!handshake->records[RECORD_METHOD_NAME].data)
		return NULL;

	return method_from_name(ctx, (const char*)handshake->records[RECORD_METHOD_NAME].data, handshake->records[RECORD_METHOD_NAME].length);
}

void fastd_handshake_handle(fastd_context_t *ctx, fastd_socket_t *sock, const fastd_peer_address_t *local_addr, const fastd_peer_address_t *remote_addr, fastd_peer_t *peer, fastd_buffer_t buffer) {
	fastd_handshake_t handshake = parse_tlvs(&buffer);

	if (!handshake.tlv_data) {
		pr_warn(ctx, "received a short handshake from %I", remote_addr);
		goto end_free;
	}

	if (handshake.records[RECORD_HANDSHAKE_TYPE].length != 1) {
		pr_debug(ctx, "received handshake without handshake type from %I", remote_addr);
		goto end_free;
	}

	handshake.type = AS_UINT8(handshake.records[RECORD_HANDSHAKE_TYPE]);

	if (!check_records(ctx, sock, local_addr, remote_addr, peer, &handshake))
		goto end_free;

	const fastd_method_t *method = get_method(ctx, &handshake);

	if (handshake.type > 1 && !method) {
		send_error(ctx, sock, local_addr, remote_addr, peer, &handshake, REPLY_UNACCEPTABLE_VALUE, RECORD_METHOD_NAME);
		goto end_free;
	}

	ctx->conf->protocol->handshake_handle(ctx, sock, local_addr, remote_addr, peer, &handshake, method);

 end_free:
	fastd_buffer_free(buffer);
}
