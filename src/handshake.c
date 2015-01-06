/*
  Copyright (c) 2012-2014, Matthias Schiffer <mschiffer@universe-factory.net>
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

/**
   \file

   Functions and structures for composing and decomposing handshake packets
*/


#include "handshake.h"
#include "method.h"
#include "peer.h"
#include <fastd_version.h>


/** Human-readable names for the TLV record types */
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


/** Reads a TLV record as an 8bit integer */
static inline uint8_t as_uint8(const fastd_handshake_record_t *record) {
	return record->data[0];
}

/** Reads a TLV record as a 16bit integer (big endian) */
static inline uint16_t as_uint16(const fastd_handshake_record_t *record) {
	return (uint16_t)as_uint8(record) << 8 | record->data[1];
}

/** Reads a TLV record as a 24bit integer (big endian) */
static inline uint32_t as_uint24(const fastd_handshake_record_t *record) {
	return (uint32_t)as_uint16(record) << 8 | record->data[2];
}

/** Reads a TLV record as a 32bit integer (big endian) */
static inline uint32_t as_uint32(const fastd_handshake_record_t *record) {
	return as_uint24(record) << 8 | record->data[3];
}

/** Reads a TLV record as a 16bit integer (little endian) */
static inline uint16_t as_uint16_le(const fastd_handshake_record_t *record) {
	return as_uint8(record) | (uint16_t)record->data[1] << 8;
}

/** Reads a TLV record as a variable-length integer (little endian) */
static inline uint32_t as_uint(const fastd_handshake_record_t *record) {
	switch(record->length) {
	case 0:
		return 0;
	case 1:
		return as_uint8(record);
	case 2:
		return as_uint16(record);
	case 3:
		return as_uint24(record);
	case 4:
		return as_uint32(record);
	default:
		return 0xffffffffULL;
	}
}


/** Generates a zero-separated list of supported methods */
static uint8_t * create_method_list(size_t *len) {
	size_t n, i;
	for (n = 0; conf.methods[n].name; n++) {
	}

	*len = 0;
	size_t lens[n];

	for (i = 0; i < n; i++) {
		lens[i] = strlen(conf.methods[i].name) + 1;
		*len += lens[i];
	}

	uint8_t *ret = fastd_alloc(*len);
	(*len)--;

	uint8_t *ptr = ret;

	for (i = 0; i < n; i++) {
		memcpy(ptr, conf.methods[i].name, lens[i]);
		ptr += lens[i];
	}

	return ret;
}

/** Checks if a string is equal to a buffer with a maximum length */
static inline bool string_equal(const char *str, const char *buf, size_t maxlen) {
	if (strlen(str) != strnlen(buf, maxlen))
		return false;

	return !strncmp(str, buf, maxlen);
}

/** Checks if a string is equal to the value of a TLV record */
static inline bool record_equal(const char *str, const fastd_handshake_record_t *record) {
	return string_equal(str, (const char *)record->data, record->length);
}

/** Parses a list of zero-separated strings */
static fastd_string_stack_t * parse_string_list(const uint8_t *data, size_t len) {
	const uint8_t *end = data+len;
	fastd_string_stack_t *ret = NULL;

	while (data < end) {
		fastd_string_stack_t *part = fastd_string_stack_dupn((char *)data, end-data);
		part->next = ret;
		ret = part;
		data += strlen(part->str) + 1;
	}

	return ret;
}

/** Allocates and initializes a new handshake packet */
static fastd_buffer_t new_handshake(uint8_t type, const fastd_method_info_t *method, bool with_method_list, size_t tail_space) {
	size_t version_len = strlen(FASTD_VERSION);
	size_t protocol_len = strlen(conf.protocol->name);
	size_t method_len = method ? strlen(method->name) : 0;

	size_t method_list_len = 0;
	uint8_t *method_list = NULL;

	if (with_method_list)
		method_list = create_method_list(&method_list_len);

	fastd_buffer_t buffer = fastd_buffer_alloc(sizeof(fastd_handshake_packet_t), 1,
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

	fastd_handshake_add_uint8(&buffer, RECORD_HANDSHAKE_TYPE, type);
	fastd_handshake_add_uint8(&buffer, RECORD_MODE, conf.mode);
	fastd_handshake_add_uint16_le(&buffer, RECORD_MTU, conf.mtu);

	fastd_handshake_add(&buffer, RECORD_VERSION_NAME, version_len, FASTD_VERSION);
	fastd_handshake_add(&buffer, RECORD_PROTOCOL_NAME, protocol_len, conf.protocol->name);

	if (method && (!with_method_list || !conf.secure_handshakes))
		fastd_handshake_add(&buffer, RECORD_METHOD_NAME, method_len, method->name);

	if (with_method_list) {
		fastd_handshake_add(&buffer, RECORD_METHOD_LIST, method_list_len, method_list);
		free(method_list);
	}

	return buffer;
}

/** Allocates and initializes a new initial handshake packet */
fastd_buffer_t fastd_handshake_new_init(size_t tail_space) {
	return new_handshake(1, NULL, !conf.secure_handshakes, tail_space);
}

/** Allocates and initializes a new reply handshake packet */
fastd_buffer_t fastd_handshake_new_reply(uint8_t type, const fastd_method_info_t *method, bool with_method_list, size_t tail_space) {
	fastd_buffer_t buffer = new_handshake(type, method, with_method_list, tail_space);
	fastd_handshake_add_uint8(&buffer, RECORD_REPLY_CODE, 0);
	return buffer;
}

/** Prints the error corresponding to the given reply code and error detail */
static void print_error(const char *prefix, const fastd_peer_address_t *remote_addr, uint8_t reply_code, uint16_t error_detail) {
	const char *error_field_str;

	if (error_detail >= RECORD_MAX)
		error_field_str = "<unknown>";
	else
		error_field_str = RECORD_TYPES[error_detail];

	switch (reply_code) {
	case REPLY_SUCCESS:
		break;

	case REPLY_MANDATORY_MISSING:
		pr_warn("Handshake with %I failed: %s error: mandatory field `%s' missing", remote_addr, prefix, error_field_str);
		break;

	case REPLY_UNACCEPTABLE_VALUE:
		switch (error_detail) {
		case RECORD_PROTOCOL_NAME:
			pr_warn("Handshake with %I failed: %s error: peer doesn't use the handshake protocol `%s'", remote_addr, prefix, conf.protocol->name);
			break;

		case RECORD_MODE:
			pr_warn("Handshake with %I failed: %s error: TUN/TAP mode mismatch", remote_addr, prefix);
			break;

		case RECORD_METHOD_NAME:
		case RECORD_METHOD_LIST:
			pr_warn("Handshake with %I failed: %s error: no common methods are configured", remote_addr, prefix);
			break;

		default:
			pr_warn("Handshake with %I failed: %s error: unacceptable value for field `%s'", remote_addr, prefix, error_field_str);
		}

		break;

	default:
		pr_warn("Handshake with %I failed: %s error: unknown code %i", remote_addr, prefix, reply_code);
	}
}

/** Sends an error reply to a peer */
static void send_error(fastd_socket_t *sock, const fastd_peer_address_t *local_addr, const fastd_peer_address_t *remote_addr, fastd_peer_t *peer, const fastd_handshake_t *handshake, uint8_t reply_code, uint16_t error_detail) {
	print_error("sending", remote_addr, reply_code, error_detail);

	fastd_buffer_t buffer = fastd_buffer_alloc(sizeof(fastd_handshake_packet_t), 0, 3*5 /* enough space for handshake type, reply code and error detail */);
	fastd_handshake_packet_t *reply = buffer.data;

	reply->rsv = 0;
	reply->tlv_len = 0;

	fastd_handshake_add_uint8(&buffer, RECORD_HANDSHAKE_TYPE, handshake->type+1);
	fastd_handshake_add_uint8(&buffer, RECORD_REPLY_CODE, reply_code);
	fastd_handshake_add_uint(&buffer, RECORD_ERROR_DETAIL, error_detail);

	fastd_send_handshake(sock, local_addr, remote_addr, peer, buffer);
}

/** Parses the TLV records of a handshake */
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

/** Prints the error found in a received handshake */
static inline void print_error_reply(const fastd_peer_address_t *remote_addr, const fastd_handshake_t *handshake) {
	uint8_t reply_code = as_uint8(&handshake->records[RECORD_REPLY_CODE]);
	uint16_t error_detail = RECORD_MAX;

	if (handshake->records[RECORD_ERROR_DETAIL].length == 1 || handshake->records[RECORD_ERROR_DETAIL].length == 2)
		error_detail = as_uint(&handshake->records[RECORD_ERROR_DETAIL]);

	print_error("received", remote_addr, reply_code, error_detail);
}

/** Does some basic validity checks on a received handshake */
static inline bool check_records(fastd_socket_t *sock, const fastd_peer_address_t *local_addr, const fastd_peer_address_t *remote_addr, fastd_peer_t *peer, const fastd_handshake_t *handshake) {
	if (handshake->records[RECORD_PROTOCOL_NAME].data) {
		if (!record_equal(conf.protocol->name, &handshake->records[RECORD_PROTOCOL_NAME])) {
			send_error(sock, local_addr, remote_addr, peer, handshake, REPLY_UNACCEPTABLE_VALUE, RECORD_PROTOCOL_NAME);
			return false;
		}
	}

	if (handshake->records[RECORD_MODE].data) {
		if (handshake->records[RECORD_MODE].length != 1 || as_uint8(&handshake->records[RECORD_MODE]) != conf.mode) {
			send_error(sock, local_addr, remote_addr, peer, handshake, REPLY_UNACCEPTABLE_VALUE, RECORD_MODE);
			return false;
		}
	}

	if (!conf.secure_handshakes || handshake->type > 1) {
		if (handshake->records[RECORD_MTU].length == 2) {
			if (as_uint16_le(&handshake->records[RECORD_MTU]) != conf.mtu) {
				pr_warn("MTU configuration differs with peer %I: local MTU is %u, remote MTU is %u",
					remote_addr, conf.mtu, as_uint16_le(&handshake->records[RECORD_MTU]));
			}
		}
	}

	if (handshake->type > 1) {
		if (handshake->records[RECORD_REPLY_CODE].length != 1) {
			pr_warn("received handshake reply without reply code from %I", remote_addr);
			return false;
		}

		if (as_uint8(&handshake->records[RECORD_REPLY_CODE]) != REPLY_SUCCESS) {
			print_error_reply(remote_addr, handshake);
			return false;
		}
	}

	return true;
}

/** Returns the method info with a specified name and length */
static inline const fastd_method_info_t * get_method_by_name(const char *name, size_t n) {
	char name0[n+1];
	memcpy(name0, name, n);
	name0[n] = 0;

	return fastd_method_get_by_name(name0);
}

/** Returns the most appropriate method to negotiate with a peer a handshake was received from */
static inline const fastd_method_info_t * get_method(const fastd_handshake_t *handshake) {
	if (handshake->records[RECORD_METHOD_LIST].data && handshake->records[RECORD_METHOD_LIST].length) {
		fastd_string_stack_t *method_list = parse_string_list(handshake->records[RECORD_METHOD_LIST].data, handshake->records[RECORD_METHOD_LIST].length);

		const fastd_method_info_t *method = NULL;

		fastd_string_stack_t *method_name;
		for (method_name = method_list; method_name; method_name = method_name->next) {
			const fastd_method_info_t *cur_method = fastd_method_get_by_name(method_name->str);

			if (cur_method)
				method = cur_method;
		}

		fastd_string_stack_free(method_list);

		return method;
	}

	if (!handshake->records[RECORD_METHOD_NAME].data)
		return NULL;

	return get_method_by_name((const char *)handshake->records[RECORD_METHOD_NAME].data, handshake->records[RECORD_METHOD_NAME].length);
}

/** Handles a handshake packet */
void fastd_handshake_handle(fastd_socket_t *sock, const fastd_peer_address_t *local_addr, const fastd_peer_address_t *remote_addr, fastd_peer_t *peer, fastd_buffer_t buffer) {
	char *peer_version = NULL;
	const fastd_method_info_t *method = NULL;

	fastd_handshake_t handshake = parse_tlvs(&buffer);

	if (!handshake.tlv_data) {
		pr_warn("received a short handshake from %I", remote_addr);
		goto end_free;
	}

	if (handshake.records[RECORD_HANDSHAKE_TYPE].length != 1) {
		pr_debug("received handshake without handshake type from %I", remote_addr);
		goto end_free;
	}

	handshake.type = as_uint8(&handshake.records[RECORD_HANDSHAKE_TYPE]);

	if (!check_records(sock, local_addr, remote_addr, peer, &handshake))
		goto end_free;

	if (!conf.secure_handshakes || handshake.type > 1) {
		method = get_method(&handshake);

		if (handshake.records[RECORD_VERSION_NAME].data)
			handshake.peer_version = peer_version = fastd_strndup((const char *)handshake.records[RECORD_VERSION_NAME].data, handshake.records[RECORD_VERSION_NAME].length);
	}

	if (handshake.type > 1 && !method) {
		send_error(sock, local_addr, remote_addr, peer, &handshake, REPLY_UNACCEPTABLE_VALUE, RECORD_METHOD_LIST);
		goto end_free;
	}

	conf.protocol->handshake_handle(sock, local_addr, remote_addr, peer, &handshake, method);

 end_free:
	free(peer_version);
	fastd_buffer_free(buffer);
}
