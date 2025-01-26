// SPDX-License-Identifier: BSD-2-Clause
/*
  Copyright (c) Matthias Schiffer <mschiffer@universe-factory.net>
  All rights reserved.
*/

/**
   \file

   Definitions for the common packet format used by most methods
*/


#pragma once

#include "../fastd.h"


/** The length of the nonce in the common method packet header */
#define COMMON_NONCEBYTES 6

/** The length of the common method packet header */
#define COMMON_HEADBYTES (2 + COMMON_NONCEBYTES)

/** The headroom to reserve in common methods */
#define COMMON_HEADROOM (alignto(COMMON_HEADBYTES, sizeof(fastd_block128_t)))


/** Common method session state */
typedef struct fastd_method_common {
	fastd_peer_t *peer;

	unsigned flags; /**< Session flags */

	fastd_timeout_t valid_till;    /**< How long the session is valid */
	fastd_timeout_t refresh_after; /**< When to try refreshing the session */

	uint8_t send_nonce[COMMON_NONCEBYTES];    /**< The next nonce to use */
	uint8_t receive_nonce[COMMON_NONCEBYTES]; /**< The hightest nonce received to far for this session */

	fastd_timeout_t reorder_timeout; /**< How long to packets with a lower sequence number (nonce) than the newest
					    received */
	uint64_t receive_reorder_seen;   /**< Bitmap specifying which of the 64 sequence numbers (nonces) before \a
					    receive_nonce have bit seen */
} fastd_method_common_t;


void fastd_method_common_init(fastd_method_common_t *session, fastd_peer_t *peer, unsigned session_flags);
bool fastd_method_is_nonce_valid(
	const fastd_method_common_t *session, const uint8_t nonce[COMMON_NONCEBYTES], int64_t *age);
fastd_tristate_t
fastd_method_reorder_check(fastd_method_common_t *session, const uint8_t nonce[COMMON_NONCEBYTES], int64_t age);


/**
   The common \a session_is_valid implementation

   A session is valid when session->valid_till has not timeouted, unless almost all nonces have been used up (which \b
   should be impossible)
*/
static inline bool fastd_method_session_common_is_valid(const fastd_method_common_t *session) {
	if (session->send_nonce[0] == 0xff && session->send_nonce[1] == 0xff)
		return false;

	return (!fastd_timed_out(session->valid_till));
}

/**
   The common \a session_is_initiator implementation

   The initiator of a session uses the odd nonces, the responder the even ones.
*/
static inline bool fastd_method_session_common_is_initiator(const fastd_method_common_t *session) {
	return (session->flags & FASTD_SESSION_INITIATOR);
}

/**
   The common \a session_want_refresh implementation

   A session wants to be refreshed when session->refresh_after has timeouted, or if lots of nonces have been used up
*/
static inline bool fastd_method_session_common_want_refresh(const fastd_method_common_t *session) {
	if (session->send_nonce[0] == 0xff)
		return true;

	if (fastd_method_session_common_is_initiator(session) && fastd_timed_out(session->refresh_after))
		return true;

	return false;
}

/** The common \a session_superseded implementation */
static inline void fastd_method_session_common_superseded(fastd_method_common_t *session) {
	fastd_timeout_t valid_max = ctx.now + KEY_VALID_OLD;

	if (valid_max < session->valid_till)
		session->valid_till = valid_max;
}

/**
   Increments the send nonce

   As one side of a connection uses the even nonces and the other side the odd ones,
   the nonce is always incremented by 2.
*/
static inline void fastd_method_increment_nonce(fastd_method_common_t *session) {
	session->send_nonce[COMMON_NONCEBYTES - 1] += 2;

	if (!(session->send_nonce[COMMON_NONCEBYTES - 1] & (~1))) {
		int i;
		for (i = COMMON_NONCEBYTES - 2; i >= 0; i--) {
			if (++session->send_nonce[i])
				break;
		}
	}
}

static inline uint8_t fastd_method_packet_type(unsigned session_flags) {
	if (session_flags & FASTD_SESSION_COMPAT)
		return PACKET_DATA_COMPAT;
	else
		return PACKET_DATA;
}

/** Adds the common header to a packet buffer */
static inline void fastd_method_put_common_header_raw(
	fastd_buffer_t *buffer, const uint8_t nonce[COMMON_NONCEBYTES], uint8_t flags, unsigned session_flags) {
	const uint8_t packet_type = fastd_method_packet_type(session_flags);

	fastd_buffer_push_from(buffer, nonce, COMMON_NONCEBYTES);
	fastd_buffer_push_from(buffer, &flags, 1);
	fastd_buffer_push_from(buffer, &packet_type, 1);
}

/** Adds the common header to a packet buffer and increments the nonce in the session state */
static inline void
fastd_method_put_common_header(fastd_method_common_t *session, fastd_buffer_t *buffer, uint8_t flags) {
	fastd_method_put_common_header_raw(buffer, session->send_nonce, flags, session->flags);
	fastd_method_increment_nonce(session);
}

/** Removes the common header from a view of a packet buffer */
static inline void fastd_method_take_common_header(
	fastd_buffer_view_t *buffer, uint8_t nonce[COMMON_NONCEBYTES], uint8_t *packet_type, uint8_t *flags) {
	fastd_buffer_view_pull_to(buffer, packet_type, 1);
	fastd_buffer_view_pull_to(buffer, flags, 1);
	fastd_buffer_view_pull_to(buffer, nonce, COMMON_NONCEBYTES);
}

/** Handles the common header of a packet */
static inline bool fastd_method_handle_common_header(
	const fastd_method_common_t *session, fastd_buffer_view_t *buffer, uint8_t nonce[COMMON_NONCEBYTES],
	uint8_t *flags, int64_t *age) {
	uint8_t packet_type;

	fastd_method_take_common_header(buffer, nonce, &packet_type, flags);
	return (packet_type == fastd_method_packet_type(session->flags)) &&
	       fastd_method_is_nonce_valid(session, nonce, age);
}


/**
   Expands a nonce from COMMON_NONCEBYTES to a buffer of arbitrary length

   The last byte of the buffer is set to 1 as many cryptographic algorithms are specified to have a counter starting
   with 1 concatenated to the nonce
*/
static inline void fastd_method_expand_nonce(uint8_t *buf, const uint8_t nonce[COMMON_NONCEBYTES], size_t len) {
	if (!len)
		return;

	memset(buf, 0, len);
	memcpy(buf, nonce, min_size_t(len, COMMON_NONCEBYTES));
	buf[len - 1] = 1;
}
