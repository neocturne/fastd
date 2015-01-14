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

   Definitions for the common packet format used by most methods
*/


#include "common.h"


/** Common initialization for a new session */
void fastd_method_common_init(fastd_method_common_t *session, bool initiator) {
	memset(session, 0, sizeof(*session));

	session->valid_till = ctx.now + KEY_VALID;
	session->refresh_after = ctx.now + KEY_REFRESH - fastd_rand(0, KEY_REFRESH_SPLAY);

	if (initiator) {
		session->send_nonce[COMMON_NONCEBYTES-1] = 3;
	}
	else {
		session->send_nonce[COMMON_NONCEBYTES-1] = 2;
		session->receive_nonce[COMMON_NONCEBYTES-1] = 1;
	}
}

/** Checks if a received nonce is valid */
bool fastd_method_is_nonce_valid(const fastd_method_common_t *session, const uint8_t nonce[COMMON_NONCEBYTES], int64_t *age) {
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
fastd_tristate_t fastd_method_reorder_check(fastd_peer_t *peer, fastd_method_common_t *session, const uint8_t nonce[COMMON_NONCEBYTES], int64_t age) {
	if (age < 0) {
		size_t shift = age < (-64) ? 64 : ((size_t)-age);

		if (shift >= 64)
			session->receive_reorder_seen = 0;
		else
			session->receive_reorder_seen <<= shift;

		if (shift <= 64)
			session->receive_reorder_seen |= ((uint64_t)1 << (shift-1));

		memcpy(session->receive_nonce, nonce, COMMON_NONCEBYTES);
		session->reorder_timeout = ctx.now + REORDER_TIME;
		return fastd_tristate_false;
	}
	else if (age == 0 || session->receive_reorder_seen & (1 << (age-1))) {
		pr_debug("dropping duplicate packet from %P (age %u)", peer, (unsigned)age);
		return fastd_tristate_undef;
	}
	else {
		pr_debug2("accepting reordered packet from %P (age %u)", peer, (unsigned)age);
		session->receive_reorder_seen |= (1 << (age-1));
		return fastd_tristate_true;
	}
}
