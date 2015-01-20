/*
  Copyright (c) 2012-2015, Matthias Schiffer <mschiffer@universe-factory.net>
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
	RECORD_SENDER_KEY,		/**< Sender public key */
	RECORD_RECIPIENT_KEY,		/**< Recipient public key */
	RECORD_SENDER_HANDSHAKE_KEY,	/**< Sender ephemeral public key */
	RECORD_RECIPIENT_HANDSHAKE_KEY,	/**< Recipient ephemeral public key */
	RECORD_HANDSHAKE_TAG,		/**< pre-v11 compat handshake authentication tag */
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
	bool little_endian;		/**< true if the old little-endian handshake format is used */
};

/** A buffer a handshake to send is prepared in */
struct fastd_handshake_buffer {
	fastd_buffer_t buffer;		/**< The actual buffer */
	bool little_endian;		/**< true if the old little-endian handshake format is used */
};


fastd_handshake_buffer_t fastd_handshake_new_init(size_t tail_space);
fastd_handshake_buffer_t fastd_handshake_new_reply(uint8_t type, bool little_endian, const fastd_method_info_t *method, const fastd_string_stack_t *methods, size_t tail_space);

void fastd_handshake_send_error(fastd_socket_t *sock, const fastd_peer_address_t *local_addr, const fastd_peer_address_t *remote_addr, fastd_peer_t *peer, const fastd_handshake_t *handshake, uint8_t reply_code, uint16_t error_detail);
const fastd_method_info_t * fastd_handshake_get_method(const fastd_peer_t *peer, const fastd_handshake_t *handshake);
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
static inline uint8_t * fastd_handshake_extend(fastd_handshake_buffer_t *buffer, fastd_handshake_record_type_t type, size_t len) {
	uint8_t *dst = buffer->buffer.data + buffer->buffer.len;

	if (buffer->buffer.data + buffer->buffer.len + 4 + len > buffer->buffer.base + buffer->buffer.base_len)
		exit_bug("not enough buffer allocated for handshake");

	buffer->buffer.len += 4 + len;

	fastd_handshake_packet_t *packet = buffer->buffer.data;
	packet->tlv_len = htons(fastd_handshake_tlv_len(&buffer->buffer) + 4 + len);

	if (buffer->little_endian) {
		dst[0] = type;
		dst[1] = type >> 8;
		dst[2] = len;
		dst[3] = len >> 8;
	}
	else {
		dst[0] = type >> 8;
		dst[1] = type;
		dst[2] = len >> 8;
		dst[3] = len;
	}

	return dst+4;
}

/** Adds an TLV record of given type and length initialized with arbitraty data to a handshake buffer */
static inline void fastd_handshake_add(fastd_handshake_buffer_t *buffer, fastd_handshake_record_type_t type, size_t len, const void *data) {
	uint8_t *dst = fastd_handshake_extend(buffer, type, len);

	memcpy(dst, data, len);
}

/** Adds an TLV record of given type and length initialized with zeros to a handshake buffer */
static inline uint8_t * fastd_handshake_add_zero(fastd_handshake_buffer_t *buffer, fastd_handshake_record_type_t type, size_t len) {
	uint8_t *dst = fastd_handshake_extend(buffer, type, len);

	memset(dst, 0, len);
	return dst;
}

/** Adds an uint8 TLV record of given type and value to a handshake buffer */
static inline void fastd_handshake_add_uint8(fastd_handshake_buffer_t *buffer, fastd_handshake_record_type_t type, uint8_t value) {
	uint8_t *dst = fastd_handshake_extend(buffer, type, 1);

	dst[0] = value;
}

/** Adds an uint16 TLV record of given type and value to a handshake buffer */
static inline void fastd_handshake_add_uint16(fastd_handshake_buffer_t *buffer, fastd_handshake_record_type_t type, uint16_t value) {
	uint8_t *dst = fastd_handshake_extend(buffer, type, 2);

	dst[0] = value >> 8;
	dst[1] = value;
}

/** Adds an uint24 TLV record of given type and value to a handshake buffer */
static inline void fastd_handshake_add_uint24(fastd_handshake_buffer_t *buffer, fastd_handshake_record_type_t type, uint32_t value) {
	uint8_t *dst = fastd_handshake_extend(buffer, type, 3);

	dst[0] = value >> 16;
	dst[1] = value >> 8;
	dst[2] = value;
}

/** Adds an uint32 TLV record of given type and value to a handshake buffer */
static inline void fastd_handshake_add_uint32(fastd_handshake_buffer_t *buffer, fastd_handshake_record_type_t type, uint32_t value) {
	uint8_t *dst = fastd_handshake_extend(buffer, type, 4);

	dst[0] = value >> 24;
	dst[1] = value >> 16;
	dst[2] = value >> 8;
	dst[3] = value;
}

/** Adds an uint16 TLV record of given type and value to a handshake buffer (potentially encoded as little endian) */
static inline void fastd_handshake_add_uint16_endian(fastd_handshake_buffer_t *buffer, fastd_handshake_record_type_t type, uint16_t value) {
	uint8_t *dst = fastd_handshake_extend(buffer, type, 2);

	if (buffer->little_endian) {
		dst[0] = value;
		dst[1] = value >> 8;
	}
	else {
		dst[0] = value >> 8;
		dst[1] = value;
	}
}

/** Adds an TLV record of given type and value to a handshake buffer, automatically using a 1- to 4-byte value */
static inline void fastd_handshake_add_uint(fastd_handshake_buffer_t *buffer, fastd_handshake_record_type_t type, uint32_t value) {
	if (value > 0xffffff)
		fastd_handshake_add_uint32(buffer, type, value);
	if (value > 0xffff)
		fastd_handshake_add_uint24(buffer, type, value);
	if (value > 0xff)
		fastd_handshake_add_uint16(buffer, type, value);
	else
		fastd_handshake_add_uint8(buffer, type, value);
}
