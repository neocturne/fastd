// SPDX-License-Identifier: BSD-2-Clause
/*
  Copyright (c) 2012-2021, Matthias Schiffer <mschiffer@universe-factory.net>
  All rights reserved.
*/

/**
   \file

   Functions and structures for composing and decomposing handshake packets
*/


#include "handshake.h"
#include "method.h"
#include "peer.h"
#include "peer_group.h"
#include "version.h"


/** Human-readable names for the TLV record types */
static const char *const RECORD_TYPES[RECORD_MAX] = {
	"handshake type",
	"reply code",
	"error detail",
	"flags",
	"mode",
	"protocol name",
	"sender public key",
	"recipient public key",
	"sender ephemeral public key",
	"recipient ephemeral public key",
	"compat handshake authentication tag",
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

/** Reads a TLV record as a 16bit integer (little endian) */
static inline uint16_t as_uint16(const fastd_handshake_record_t *record) {
	return (uint16_t)record->data[1] << 8 | as_uint8(record);
}

/** Reads a TLV record as a 24bit integer (little endian) */
static inline uint32_t as_uint24(const fastd_handshake_record_t *record) {
	return (uint32_t)record->data[2] << 16 | as_uint16(record);
}

/** Reads a TLV record as a 32bit integer (little endian) */
static inline uint32_t as_uint32(const fastd_handshake_record_t *record) {
	return (uint32_t)record->data[3] << 24 | as_uint24(record);
}

/** Reads a TLV record as a variable-length integer (little endian) */
static inline uint32_t as_uint(const fastd_handshake_record_t *record) {
	switch (record->length) {
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
		return UINT32_C(0xffffffff);
	}
}


/** Returns the mode ID to use in the handshake TLVs */
static inline uint8_t get_mode_id(void) {
	switch (conf.mode) {
	case MODE_TAP:
	case MODE_MULTITAP:
		return 0;

	case MODE_TUN:
		return 1;

	default:
		exit_bug("get_mode_id: invalid mode");
	}
}

/** Generates a zero-separated list of supported methods */
static uint8_t *create_method_list(const fastd_string_stack_t *methods, size_t *len) {
	size_t n = 0, i;
	const fastd_string_stack_t *method;
	for (method = methods; method; method = method->next)
		n++;

	*len = 0;
	size_t lens[n];

	for (method = methods, i = 0; method; method = method->next, i++) {
		lens[i] = strlen(method->str) + 1;
		*len += lens[i];
	}

	uint8_t *ret = fastd_alloc(*len);
	(*len)--;

	uint8_t *ptr = ret;

	for (method = methods, i = 0; method; method = method->next, i++) {
		memcpy(ptr, method->str, lens[i]);
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
static fastd_string_stack_t *parse_string_list(const uint8_t *data, size_t len) {
	const uint8_t *end = data + len;
	fastd_string_stack_t *ret = NULL;

	while (data < end) {
		fastd_string_stack_t *part = fastd_string_stack_dupn((char *)data, end - data);
		part->next = ret;
		ret = part;
		data += strlen(part->str) + 1;
	}

	return ret;
}

/** Allocates and initializes a new handshake packet */
static fastd_buffer_t *new_handshake(
	uint8_t type, uint16_t mtu, const fastd_method_info_t *method, const fastd_string_stack_t *methods,
	size_t tail_space) {
	size_t version_len = strlen(FASTD_VERSION);
	size_t protocol_len = strlen(conf.protocol->name);
	size_t method_len = method ? strlen(method->name) : 0;

	size_t method_list_len = 0;
	uint8_t *method_list = NULL;

	if (methods)
		method_list = create_method_list(methods, &method_list_len);

	size_t buffer_space = sizeof(fastd_control_packet_t) + sizeof(fastd_handshake_packet_t) +
			      4 * RECORD_LEN(1) +           /* handshake type, flags, mode, reply code */
			      (mtu ? RECORD_LEN(2) : 0) +   /* MTU */
			      RECORD_LEN(version_len) +     /* version name */
			      RECORD_LEN(protocol_len) +    /* protocol name */
			      RECORD_LEN(method_len) +      /* method name */
			      RECORD_LEN(method_list_len) + /* supported method name list */
			      tail_space;

	/* TODO: Make this a soft error */
	if (buffer_space > MAX_HANDSHAKE_SIZE)
		exit_bug("oversized handshake packet");

	fastd_buffer_t *buffer = fastd_buffer_alloc(buffer_space, 0);

	fastd_buffer_pull(buffer, sizeof(fastd_control_packet_t));

	fastd_handshake_packet_t *packet = buffer->data;
	*packet = (fastd_handshake_packet_t){
		.packet_type = PACKET_HANDSHAKE,
	};
	buffer->len = sizeof(*packet);

	fastd_handshake_add_uint8(buffer, RECORD_HANDSHAKE_TYPE, type);
	fastd_handshake_add_uint8(buffer, RECORD_FLAGS, FLAG_L2TP_SUPPORT);
	fastd_handshake_add_uint8(buffer, RECORD_MODE, get_mode_id());

	if (mtu)
		fastd_handshake_add_uint16(buffer, RECORD_MTU, mtu);

	fastd_handshake_add(buffer, RECORD_VERSION_NAME, version_len, FASTD_VERSION);
	fastd_handshake_add(buffer, RECORD_PROTOCOL_NAME, protocol_len, conf.protocol->name);

	if (method && !methods)
		fastd_handshake_add(buffer, RECORD_METHOD_NAME, method_len, method->name);

	if (methods) {
		fastd_handshake_add(buffer, RECORD_METHOD_LIST, method_list_len, method_list);
		free(method_list);
	}

	return buffer;
}

/** Allocates and initializes a new initial handshake packet */
fastd_buffer_t *fastd_handshake_new_init(size_t tail_space) {
	return new_handshake(1, 0, NULL, NULL, tail_space);
}

/** Allocates and initializes a new reply handshake packet */
fastd_buffer_t *fastd_handshake_new_reply(
	uint8_t type, uint16_t mtu, const fastd_method_info_t *method, const fastd_string_stack_t *methods,
	size_t tail_space) {
	fastd_buffer_t *buffer = new_handshake(type, mtu, method, methods, tail_space);
	fastd_handshake_add_uint8(buffer, RECORD_REPLY_CODE, 0);
	return buffer;
}

/** Prints the error corresponding to the given reply code and error detail */
static void print_error(
	const char *prefix, const fastd_peer_t *peer, const fastd_peer_address_t *remote_addr, uint8_t reply_code,
	uint16_t error_detail) {
	const char *error_field_str;

	if (error_detail >= RECORD_MAX)
		error_field_str = "<unknown>";
	else
		error_field_str = RECORD_TYPES[error_detail];

	switch (reply_code) {
	case REPLY_SUCCESS:
		break;

	case REPLY_MANDATORY_MISSING:
		pr_warn("Handshake with %I failed: %s error: mandatory field `%s' missing", remote_addr, prefix,
			error_field_str);
		break;

	case REPLY_UNACCEPTABLE_VALUE:
		switch (error_detail) {
		case RECORD_PROTOCOL_NAME:
			pr_warn("Handshake with %I failed: %s error: peer doesn't use the handshake protocol `%s'",
				remote_addr, prefix, conf.protocol->name);
			break;

		case RECORD_MODE:
			pr_warn("Handshake with %I failed: %s error: TUN/TAP mode mismatch", remote_addr, prefix);
			break;

		case RECORD_MTU:
			pr_warn("Handshake with %I failed: %s error: MTU configuration differs with peer (local MTU is %u)",
				remote_addr, prefix, fastd_peer_get_mtu(peer));
			break;

		case RECORD_METHOD_NAME:
		case RECORD_METHOD_LIST:
			pr_warn("Handshake with %I failed: %s error: no common methods are configured", remote_addr,
				prefix);
			break;

		default:
			pr_warn("Handshake with %I failed: %s error: unacceptable value for field `%s'", remote_addr,
				prefix, error_field_str);
		}

		break;

	default:
		pr_warn("Handshake with %I failed: %s error: unknown code %i", remote_addr, prefix, reply_code);
	}
}

/** Sends and frees a handshake packet */
void fastd_handshake_send_free(
	const fastd_socket_t *sock, const fastd_peer_address_t *local_addr, const fastd_peer_address_t *remote_addr,
	fastd_peer_t *peer, fastd_buffer_t *buffer, unsigned flags) {

	/* For the initial handshake, we send two handshakes: one for old
	 * and one for new fastd versions */

	if (flags == FLAG_INITIAL || !(flags & FLAG_L2TP_SUPPORT))
		fastd_send(sock, local_addr, remote_addr, peer, buffer, 0);

	if (flags == FLAG_INITIAL || (flags & FLAG_L2TP_SUPPORT)) {
		const fastd_control_packet_t header = {
			.packet_type = PACKET_CONTROL,
			.flags_ver = PACKET_L2TP_VERSION,
			.length = htobe16(sizeof(header)),
		};
		fastd_buffer_push_from(buffer, &header, sizeof(header));

		fastd_send(sock, local_addr, remote_addr, peer, buffer, 0);
	}

	fastd_buffer_free(buffer);
}

/** Sends an error reply to a peer */
void fastd_handshake_send_error(
	fastd_socket_t *sock, const fastd_peer_address_t *local_addr, const fastd_peer_address_t *remote_addr,
	fastd_peer_t *peer, const fastd_handshake_t *handshake, uint8_t reply_code, uint16_t error_detail) {
	print_error("sending", peer, remote_addr, reply_code, error_detail);

	fastd_buffer_t *buffer = fastd_buffer_alloc(
		sizeof(fastd_control_packet_t) + sizeof(fastd_handshake_packet_t) +
			4 * RECORD_LEN(1) /* enough space for handshake type, flags, reply code and error detail */,
		0);

	fastd_buffer_pull(buffer, sizeof(fastd_control_packet_t));

	fastd_handshake_packet_t *reply = buffer->data;
	*reply = (fastd_handshake_packet_t){
		.packet_type = PACKET_HANDSHAKE,
	};

	buffer->len = sizeof(*reply);

	fastd_handshake_add_uint8(buffer, RECORD_HANDSHAKE_TYPE, handshake->type + 1);
	fastd_handshake_add_uint8(buffer, RECORD_FLAGS, FLAG_L2TP_SUPPORT);
	fastd_handshake_add_uint8(buffer, RECORD_REPLY_CODE, reply_code);
	fastd_handshake_add_uint(buffer, RECORD_ERROR_DETAIL, error_detail);

	fastd_handshake_send_free(sock, local_addr, remote_addr, peer, buffer, handshake->flags);
}

/** Parses the TLV records of a handshake */
static inline fastd_handshake_t parse_tlvs(const fastd_buffer_t *buffer) {
	fastd_handshake_t handshake = {};

	if (buffer->len < sizeof(fastd_handshake_packet_t))
		return handshake;

	fastd_handshake_packet_t *packet = buffer->data;

	size_t tlv_len = fastd_handshake_tlv_len(buffer);
	if (buffer->len < sizeof(fastd_handshake_packet_t) + tlv_len)
		return handshake;

	uint8_t *ptr = packet->tlv_data, *end = packet->tlv_data + tlv_len;
	handshake.tlv_len = tlv_len;
	handshake.tlv_data = packet->tlv_data;

	while (true) {
		if (ptr + 4 > end)
			break;

		uint16_t type, len;

		type = ptr[0] + (ptr[1] << 8);
		len = ptr[2] + (ptr[3] << 8);

		if (ptr + RECORD_LEN(len) > end)
			break;

		if (type < RECORD_MAX) {
			handshake.records[type].length = len;
			handshake.records[type].data = ptr + 4;
		}

		ptr += RECORD_LEN(len);
	}

	return handshake;
}

/** Prints the error found in a received handshake */
static inline void print_error_reply(
	const fastd_peer_t *peer, const fastd_peer_address_t *remote_addr, const fastd_handshake_t *handshake) {
	uint8_t reply_code = as_uint8(&handshake->records[RECORD_REPLY_CODE]);
	uint16_t error_detail = RECORD_MAX;

	if (handshake->records[RECORD_ERROR_DETAIL].length == 1 || handshake->records[RECORD_ERROR_DETAIL].length == 2)
		error_detail = as_uint(&handshake->records[RECORD_ERROR_DETAIL]);

	print_error("received", peer, remote_addr, reply_code, error_detail);
}

/** Does some basic validity checks on a received handshake */
static inline bool check_records(
	fastd_socket_t *sock, const fastd_peer_address_t *local_addr, const fastd_peer_address_t *remote_addr,
	fastd_peer_t *peer, const fastd_handshake_t *handshake) {
	if (handshake->records[RECORD_FLAGS].data) {
		if (handshake->records[RECORD_FLAGS].length != 1 || (handshake->flags & ~FLAG_ALL)) {
			fastd_handshake_send_error(
				sock, local_addr, remote_addr, peer, handshake, REPLY_UNACCEPTABLE_VALUE, RECORD_FLAGS);
			return false;
		}
	}

	if (handshake->records[RECORD_PROTOCOL_NAME].data) {
		if (!record_equal(conf.protocol->name, &handshake->records[RECORD_PROTOCOL_NAME])) {
			fastd_handshake_send_error(
				sock, local_addr, remote_addr, peer, handshake, REPLY_UNACCEPTABLE_VALUE,
				RECORD_PROTOCOL_NAME);
			return false;
		}
	}

	if (handshake->records[RECORD_MODE].data) {
		if (handshake->records[RECORD_MODE].length != 1 ||
		    as_uint8(&handshake->records[RECORD_MODE]) != get_mode_id()) {
			fastd_handshake_send_error(
				sock, local_addr, remote_addr, peer, handshake, REPLY_UNACCEPTABLE_VALUE, RECORD_MODE);
			return false;
		}
	}

	if (handshake->type > 1) {
		if (handshake->records[RECORD_REPLY_CODE].length != 1) {
			pr_warn("received handshake reply without reply code from %I", remote_addr);
			return false;
		}

		if (as_uint8(&handshake->records[RECORD_REPLY_CODE]) != REPLY_SUCCESS) {
			print_error_reply(peer, remote_addr, handshake);
			return false;
		}
	}

	return true;
}

/** Checks if an MTU record of a handshake matches the configured MTU for a peer */
bool fastd_handshake_check_mtu(
	fastd_socket_t *sock, const fastd_peer_address_t *local_addr, const fastd_peer_address_t *remote_addr,
	fastd_peer_t *peer, const fastd_handshake_t *handshake) {
	if (handshake->records[RECORD_MTU].length == 2) {
		if (as_uint16(&handshake->records[RECORD_MTU]) != fastd_peer_get_mtu(peer)) {
			fastd_handshake_send_error(
				sock, local_addr, remote_addr, peer, handshake, REPLY_UNACCEPTABLE_VALUE, RECORD_MTU);
			return false;
		}
	}

	return true;
}

/** Returns the method info with a specified name and length */
static inline const fastd_method_info_t *
get_method_by_name(const fastd_string_stack_t *methods, const char *name, size_t n) {
	char name0[n + 1];
	memcpy(name0, name, n);
	name0[n] = 0;

	if (!fastd_string_stack_contains(methods, name0))
		return NULL;

	return fastd_method_get_by_name(name0);
}

/** Returns the most appropriate method to negotiate with a peer a handshake was received from */
const fastd_method_info_t *
fastd_handshake_get_method_by_name_list(const fastd_peer_t *peer, const fastd_handshake_t *handshake) {
	const fastd_string_stack_t *methods = *fastd_peer_group_lookup_peer(peer, methods);

	if (!handshake->records[RECORD_METHOD_LIST].data || !handshake->records[RECORD_METHOD_LIST].length)
		return NULL;

	fastd_string_stack_t *method_list = parse_string_list(
		handshake->records[RECORD_METHOD_LIST].data, handshake->records[RECORD_METHOD_LIST].length);

	const fastd_method_info_t *method = NULL;

	fastd_string_stack_t *method_name;
	for (method_name = method_list; method_name; method_name = method_name->next) {
		if (!fastd_string_stack_contains(methods, method_name->str))
			continue;

		method = fastd_method_get_by_name(method_name->str);
		if (!method)
			exit_bug("fastd_method_get_by_name: can't find configured method");
	}

	fastd_string_stack_free(method_list);

	return method;
}

const fastd_method_info_t *
fastd_handshake_get_method_by_name(const fastd_peer_t *peer, const fastd_handshake_t *handshake) {
	if (!handshake->records[RECORD_METHOD_NAME].data)
		return NULL;

	const fastd_string_stack_t *methods = *fastd_peer_group_lookup_peer(peer, methods);

	return get_method_by_name(
		methods, (const char *)handshake->records[RECORD_METHOD_NAME].data,
		handshake->records[RECORD_METHOD_NAME].length);
}

/** Handles a handshake packet */
void fastd_handshake_handle(
	fastd_socket_t *sock, const fastd_peer_address_t *local_addr, const fastd_peer_address_t *remote_addr,
	fastd_peer_t *peer, fastd_buffer_t *buffer, bool has_control_header) {

	fastd_handshake_t handshake = parse_tlvs(buffer);

	if (!handshake.tlv_data) {
		pr_warn("received a short handshake from %I", remote_addr);
		return;
	}

	if (handshake.records[RECORD_HANDSHAKE_TYPE].length != 1) {
		pr_debug("received handshake without handshake type from %I", remote_addr);
		return;
	}

	handshake.type = as_uint8(&handshake.records[RECORD_HANDSHAKE_TYPE]);

	if (handshake.records[RECORD_FLAGS].length >= 1)
		handshake.flags = as_uint8(&handshake.records[RECORD_FLAGS]);

	/* If the peer has L2TP support, it has sent two handshakes, one for
	 * old fastd versions and one for new ones. Ignore the old handshake. */
	if (!has_control_header && (handshake.flags & FLAG_L2TP_SUPPORT))
		return;

	if (!check_records(sock, local_addr, remote_addr, peer, &handshake))
		return;

	char *peer_version = NULL;

	if (handshake.type > 1) {
		if (handshake.records[RECORD_VERSION_NAME].data)
			handshake.peer_version = peer_version = fastd_strndup(
				(const char *)handshake.records[RECORD_VERSION_NAME].data,
				handshake.records[RECORD_VERSION_NAME].length);
	}

	conf.protocol->handshake_handle(sock, local_addr, remote_addr, peer, &handshake);

	free(peer_version);
}
