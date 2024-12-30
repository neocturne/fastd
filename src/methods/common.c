// SPDX-License-Identifier: BSD-2-Clause
/*
  Copyright (c) Matthias Schiffer <mschiffer@universe-factory.net>
  All rights reserved.
*/

/**
   \file

   Definitions for the common packet format used by most methods
*/


#include "common.h"


/** Common initialization for a new session */
void fastd_method_common_init(fastd_method_common_t *session, fastd_peer_t *peer, unsigned session_flags) {
	memset(session, 0, sizeof(*session));

	session->peer = peer;
	session->flags = session_flags;

	session->valid_till = ctx.now + KEY_VALID;
	session->refresh_after = ctx.now + KEY_REFRESH - fastd_rand(0, KEY_REFRESH_SPLAY);

	if (session_flags & FASTD_SESSION_INITIATOR) {
		session->send_nonce[COMMON_NONCEBYTES - 1] = 3;
	} else {
		session->send_nonce[COMMON_NONCEBYTES - 1] = 2;
		session->receive_nonce[COMMON_NONCEBYTES - 1] = 1;
	}
}

/** Checks if a received nonce is valid */
bool fastd_method_is_nonce_valid(
	const fastd_method_common_t *session, const uint8_t nonce[COMMON_NONCEBYTES], int64_t *age) {
	if ((nonce[0] & 1) != (session->receive_nonce[0] & 1))
		return false;

	size_t i;
	*age = 0;

	for (i = 0; i < COMMON_NONCEBYTES; i++) {
		*age <<= 8;
		*age += session->receive_nonce[i] - nonce[i];
	}

	*age >>= 1;

	if (*age >= 0) {
		if (fastd_timed_out(session->reorder_timeout))
			return false;

		if (*age > 64)
			return false;
	}

	return true;
}

/**
   Checks if a possibly reordered packet should be accepted

   Returns a tristate: undef if it should not be accepted (duplicate or too old),
   false if the packet is okay and not reordered and true
   if it is reordered.
*/
fastd_tristate_t
fastd_method_reorder_check(fastd_method_common_t *session, const uint8_t nonce[COMMON_NONCEBYTES], int64_t age) {
	if (age < 0) {
		size_t shift = -age;

		if (shift >= 64)
			session->receive_reorder_seen = 0;
		else
			session->receive_reorder_seen <<= shift;

		if (shift <= 64)
			session->receive_reorder_seen |= ((uint64_t)1 << (shift - 1));

		memcpy(session->receive_nonce, nonce, COMMON_NONCEBYTES);
		session->reorder_timeout = ctx.now + REORDER_TIME;
		return FASTD_TRISTATE_FALSE;
	} else if (age == 0 || session->receive_reorder_seen & ((uint64_t)1 << (age - 1))) {
		pr_debug("dropping duplicate packet from %P (age %u)", session->peer, (unsigned)age);
		return FASTD_TRISTATE_UNDEF;
	} else {
		pr_debug2("accepting reordered packet from %P (age %u)", session->peer, (unsigned)age);
		session->receive_reorder_seen |= ((uint64_t)1 << (age - 1));
		return FASTD_TRISTATE_TRUE;
	}
}
