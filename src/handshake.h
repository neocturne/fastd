// SPDX-License-Identifier: BSD-2-Clause
/*
  Copyright (c) Matthias Schiffer <mschiffer@universe-factory.net>
  All rights reserved.
*/

/**
   \file

   Functions and structures for composing and decomposing handshake packets
*/


#pragma once

#include "fastd.h"


/**
   The maximum size of a handshake

   The value is chosen to always allow unfragmented transmission over an IPV6
   link with MTU 1280 (subtracting the 40-byte IPv6 and 8-byte UDP headers)
 */
#define MAX_HANDSHAKE_SIZE 1232


/**
   The type field of a handshake TLV record

   In the handshake packet, the type field will be 2 bytes wide and little endian
*/
typedef enum fastd_handshake_record_type {
	RECORD_HANDSHAKE_TYPE = 0,      /**< the handshake type (initial, response or finish) */
	RECORD_REPLY_CODE,              /**< The reply code */
	RECORD_ERROR_DETAIL,            /**< The error detail code */
	RECORD_FLAGS,                   /**< The flags field */
	RECORD_MODE,                    /**< The mode field */
	RECORD_PROTOCOL_NAME,           /**< The handshake protocol */
	RECORD_SENDER_KEY,              /**< Sender public key */
	RECORD_RECIPIENT_KEY,           /**< Recipient public key */
	RECORD_SENDER_HANDSHAKE_KEY,    /**< Sender ephemeral public key */
	RECORD_RECIPIENT_HANDSHAKE_KEY, /**< Recipient ephemeral public key */
	RECORD_HANDSHAKE_TAG,           /**< pre-v11 compat handshake authentication tag */
	RECORD_MTU,                     /**< MTU field */
	RECORD_METHOD_NAME,             /**< The default/chosen method */
	RECORD_VERSION_NAME,            /**< The fastd version */
	RECORD_METHOD_LIST,             /**< Zero-separated list of supported methods */
	RECORD_TLV_MAC,                 /**< Message authentication code of the TLV records */
	RECORD_MAX,                     /**< (Number of defined record types) */
} fastd_handshake_record_type_t;

/** The reply codes */
typedef enum fastd_reply_code {
	REPLY_SUCCESS = 0,        /**< The handshake was sucessfull */
	REPLY_MANDATORY_MISSING,  /**< A required TLV field is missing */
	REPLY_UNACCEPTABLE_VALUE, /**< A TLV field has an invalid value */
	REPLY_MAX,                /**< (Number of defined reply codes */
} fastd_reply_code_t;


/** Calculates the space needed for a TLV record of length len */
#define RECORD_LEN(len) ((len) + 4)


/** fastd supports the new L2TP-compatible packet types; ignore packets using the old types */
#define FLAG_L2TP_SUPPORT 0x01
/** Union of all defined flags */
#define FLAG_ALL 0x01

/** Passed to fastd_handshake_send_free() for the initial handshake */
#define FLAG_INITIAL ((unsigned)-1)


/** The handshake packet structure */
typedef struct fastd_handshake_packet {
	uint8_t packet_type; /**< Packet type (must be PACKET_HANDSHAKE) */
	uint8_t rsv;         /**< Reserved (must be 0) */
	uint16_t tlv_len;    /**< Length of the TLV records */
	uint8_t tlv_data[];  /**< TLV record data */
} fastd_handshake_packet_t;

/** A record descriptor */
typedef struct fastd_handshake_record {
	size_t length; /**< The length of the value */
	uint8_t *data; /**< Points to the value of the TLV record */
} fastd_handshake_record_t;

/** Describes a handshake packet */
struct fastd_handshake {
	uint8_t type;                                 /**< The handshake type */
	uint8_t flags;                                /**< Handshake flags */
	const char *peer_version;                     /**< The fastd version of the peer */
	fastd_handshake_record_t records[RECORD_MAX]; /**< The TLV records of the handshake */
	uint16_t tlv_len;                             /**< The length of the TLV record data */
	void *tlv_data;                               /**< TLV record data */
};


fastd_buffer_t *fastd_handshake_new_init(size_t tail_space);
fastd_buffer_t *fastd_handshake_new_reply(
	uint8_t type, uint16_t mtu, const fastd_method_info_t *method, const fastd_string_stack_t *methods,
	size_t tail_space);

void fastd_handshake_send_free(
	const fastd_socket_t *sock, const fastd_peer_address_t *local_addr, const fastd_peer_address_t *remote_addr,
	fastd_peer_t *peer, fastd_buffer_t *buffer, unsigned flags);
void fastd_handshake_send_error(
	fastd_socket_t *sock, const fastd_peer_address_t *local_addr, const fastd_peer_address_t *remote_addr,
	fastd_peer_t *peer, const fastd_handshake_t *handshake, uint8_t reply_code, uint16_t error_detail);
bool fastd_handshake_check_mtu(
	fastd_socket_t *sock, const fastd_peer_address_t *local_addr, const fastd_peer_address_t *remote_addr,
	fastd_peer_t *peer, const fastd_handshake_t *handshake);

const fastd_method_info_t *
fastd_handshake_get_method_by_name_list(const fastd_peer_t *peer, const fastd_handshake_t *handshake);
const fastd_method_info_t *
fastd_handshake_get_method_by_name(const fastd_peer_t *peer, const fastd_handshake_t *handshake);

void fastd_handshake_handle(
	fastd_socket_t *sock, const fastd_peer_address_t *local_addr, const fastd_peer_address_t *remote_addr,
	fastd_peer_t *peer, fastd_buffer_t *buffer, bool has_control_header);


/** Returns the TLV data of a handshake packet in a given buffer */
static inline void *fastd_handshake_tlv_data(const fastd_buffer_t *buffer) {
	fastd_handshake_packet_t *packet = buffer->data;
	return packet->tlv_data;
}

/** Returns the length the TLV data of a handshake packet in a given buffer */
static inline uint16_t fastd_handshake_tlv_len(const fastd_buffer_t *buffer) {
	fastd_handshake_packet_t *packet = buffer->data;
	return ntohs(packet->tlv_len);
}

/** Adds an uninitialized TLV record of given type and length to a handshake buffer */
static inline uint8_t *fastd_handshake_extend(fastd_buffer_t *buffer, fastd_handshake_record_type_t type, size_t len) {
	uint8_t *dst = buffer->data + buffer->len;

	if ((uint8_t *)buffer->data + buffer->len + RECORD_LEN(len) > buffer->base + ctx.max_buffer)
		exit_bug("not enough buffer allocated for handshake");

	buffer->len += RECORD_LEN(len);

	fastd_handshake_packet_t *packet = buffer->data;
	packet->tlv_len = htons(fastd_handshake_tlv_len(buffer) + RECORD_LEN(len));

	dst[0] = type;
	dst[1] = type >> 8;
	dst[2] = len;
	dst[3] = len >> 8;

	return dst + 4;
}

/** Adds an TLV record of given type and length initialized with arbitraty data to a handshake buffer */
static inline void
fastd_handshake_add(fastd_buffer_t *buffer, fastd_handshake_record_type_t type, size_t len, const void *data) {
	uint8_t *dst = fastd_handshake_extend(buffer, type, len);

	memcpy(dst, data, len);
}

/** Adds an TLV record of given type and length initialized with zeros to a handshake buffer */
static inline uint8_t *
fastd_handshake_add_zero(fastd_buffer_t *buffer, fastd_handshake_record_type_t type, size_t len) {
	uint8_t *dst = fastd_handshake_extend(buffer, type, len);

	memset(dst, 0, len);
	return dst;
}

/** Adds an uint8 TLV record of given type and value to a handshake buffer */
static inline void
fastd_handshake_add_uint8(fastd_buffer_t *buffer, fastd_handshake_record_type_t type, uint8_t value) {
	uint8_t *dst = fastd_handshake_extend(buffer, type, 1);

	dst[0] = value;
}

/** Adds an uint16 TLV record of given type and value to a handshake buffer */
static inline void
fastd_handshake_add_uint16(fastd_buffer_t *buffer, fastd_handshake_record_type_t type, uint16_t value) {
	uint8_t *dst = fastd_handshake_extend(buffer, type, 2);

	dst[0] = value;
	dst[1] = value >> 8;
}

/** Adds an uint24 TLV record of given type and value to a handshake buffer */
static inline void
fastd_handshake_add_uint24(fastd_buffer_t *buffer, fastd_handshake_record_type_t type, uint32_t value) {
	uint8_t *dst = fastd_handshake_extend(buffer, type, 3);

	dst[0] = value;
	dst[1] = value >> 8;
	dst[2] = value >> 16;
}

/** Adds an uint32 TLV record of given type and value to a handshake buffer */
static inline void
fastd_handshake_add_uint32(fastd_buffer_t *buffer, fastd_handshake_record_type_t type, uint32_t value) {
	uint8_t *dst = fastd_handshake_extend(buffer, type, 4);

	dst[0] = value;
	dst[1] = value >> 8;
	dst[2] = value >> 16;
	dst[3] = value >> 24;
}

/** Adds an TLV record of given type and value to a handshake buffer, automatically using a 1- to 4-byte value */
static inline void
fastd_handshake_add_uint(fastd_buffer_t *buffer, fastd_handshake_record_type_t type, uint32_t value) {
	if (value > 0xffffff)
		fastd_handshake_add_uint32(buffer, type, value);
	else if (value > 0xffff)
		fastd_handshake_add_uint24(buffer, type, value);
	else if (value > 0xff)
		fastd_handshake_add_uint16(buffer, type, value);
	else
		fastd_handshake_add_uint8(buffer, type, value);
}
