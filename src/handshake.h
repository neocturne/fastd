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


#pragma once

#include "fastd.h"


/**
   The type field of a handshake TLV record

   In the handshake packet, the type field will be 2 bytes wide and big endian
*/
typedef enum fastd_handshake_record_type {
	RECORD_HANDSHAKE_TYPE = 0,	/**< the handshake type (initial, response or finish) */
	RECORD_REPLY_CODE,		/**< The reply code */
	RECORD_ERROR_DETAIL,		/**< The error detail code */
	RECORD_FLAGS,			/**< The flags field */
	RECORD_MODE,			/**< The mode field */
	RECORD_PROTOCOL_NAME,		/**< The handshake protocol */
	RECORD_PROTOCOL1,		/**< Protocol-specific value 1 */
	RECORD_PROTOCOL2,		/**< Protocol-specific value 2 */
	RECORD_PROTOCOL3,		/**< Protocol-specific value 3 */
	RECORD_PROTOCOL4,		/**< Protocol-specific value 4 */
	RECORD_PROTOCOL5,		/**< Protocol-specific value 5 */
	RECORD_MTU,			/**< MTU field */
	RECORD_METHOD_NAME,		/**< The default/chosen method */
	RECORD_VERSION_NAME,		/**< The fastd version */
	RECORD_METHOD_LIST,		/**< Zero-separated list of supported methods */
	RECORD_TLV_MAC,			/**< Message authentication code of the TLV records */
	RECORD_MAX,			/**< (Number of defined record types) */
} fastd_handshake_record_type_t;

/** The reply codes */
typedef enum fastd_reply_code {
	REPLY_SUCCESS = 0,		/**< The handshake was sucessfull */
	REPLY_MANDATORY_MISSING,	/**< A required TLV field is missing */
	REPLY_UNACCEPTABLE_VALUE,	/**< A TLV field has an invalid value */
	REPLY_MAX,			/**< (Number of defined reply codes */
} fastd_reply_code_t;


/** The handshake packet structure (not including the initial packet type byte) */
typedef struct __attribute__((__packed__)) fastd_handshake_packet {
	uint8_t rsv;			/**< Reserved (must be 0) */
	uint16_t tlv_len;		/**< Length of the TLV records (before fastd v11 this was always 0, which is interpreted as "the whole packet") */
	uint8_t tlv_data[];		/**< TLV record data */
} fastd_handshake_packet_t;

/** A record descriptor */
typedef struct fastd_handshake_record {
	size_t length;			/**< The length of the value */
	uint8_t *data;			/**< Points to the value of the TLV record */
} fastd_handshake_record_t;

/** Describes a handshake packet */
struct fastd_handshake {
	uint8_t type;			/**< The handshake type */
	const char *peer_version;	/**< The fastd version of the peer */
	fastd_handshake_record_t records[RECORD_MAX]; /**< The TLV records of the handshake */
	uint16_t tlv_len;		/**< The length of the TLV record data */
	void *tlv_data;			/**< TLV record data */
};


fastd_buffer_t fastd_handshake_new_init(size_t tail_space);
fastd_buffer_t fastd_handshake_new_reply(uint8_t type, const fastd_method_info_t *method, bool with_method_list, size_t tail_space);

void fastd_handshake_handle(fastd_socket_t *sock, const fastd_peer_address_t *local_addr, const fastd_peer_address_t *remote_addr, fastd_peer_t *peer, fastd_buffer_t buffer);


/** Returns the TLV data of a handshake packet in a given buffer */
static inline void * fastd_handshake_tlv_data(const fastd_buffer_t *buffer) {
	fastd_handshake_packet_t *packet = buffer->data;
	return packet->tlv_data;
}

/** Returns the length the TLV data of a handshake packet in a given buffer */
static inline uint16_t fastd_handshake_tlv_len(const fastd_buffer_t *buffer) {
	fastd_handshake_packet_t *packet = buffer->data;
	return ntohs(packet->tlv_len);
}

/** Adds an uninitialized TLV record of given type and length to a handshake buffer */
static inline uint8_t * fastd_handshake_extend(fastd_buffer_t *buffer, fastd_handshake_record_type_t type, size_t len) {
	uint8_t *dst = buffer->data + buffer->len;

	if (buffer->data + buffer->len + 4 + len > buffer->base + buffer->base_len)
		exit_bug("not enough buffer allocated for handshake");

	buffer->len += 4 + len;

	fastd_handshake_packet_t *packet = buffer->data;
	packet->tlv_len = htons(fastd_handshake_tlv_len(buffer) + 4 + len);

	dst[0] = type;
	dst[1] = type >> 8;
	dst[2] = len;
	dst[3] = len >> 8;

	return dst+4;
}

/** Adds an TLV record of given type and length initialized with arbitraty data to a handshake buffer */
static inline void fastd_handshake_add(fastd_buffer_t *buffer, fastd_handshake_record_type_t type, size_t len, const void *data) {
	uint8_t *dst = fastd_handshake_extend(buffer, type, len);

	memcpy(dst, data, len);
}

/** Adds an TLV record of given type and length initialized with zeros to a handshake buffer */
static inline uint8_t * fastd_handshake_add_zero(fastd_buffer_t *buffer, fastd_handshake_record_type_t type, size_t len) {
	uint8_t *dst = fastd_handshake_extend(buffer, type, len);

	memset(dst, 0, len);
	return dst;
}

/** Adds an uint8 TLV record of given type and value to a handshake buffer */
static inline void fastd_handshake_add_uint8(fastd_buffer_t *buffer, fastd_handshake_record_type_t type, uint8_t value) {
	uint8_t *dst = fastd_handshake_extend(buffer, type, 1);

	dst[0] = value;
}

/** Adds an uint16 TLV record of given type and value to a handshake buffer */
static inline void fastd_handshake_add_uint16(fastd_buffer_t *buffer, fastd_handshake_record_type_t type, uint16_t value) {
	uint8_t *dst = fastd_handshake_extend(buffer, type, 2);

	dst[0] = value;
	dst[1] = value >> 8;
}
