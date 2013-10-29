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


#ifndef _FASTD_METHODS_COMMON_H_
#define _FASTD_METHODS_COMMON_H_

#include "../fastd.h"


#define COMMON_NONCEBYTES 7


typedef struct fastd_method_common {
	struct timespec valid_till;
	struct timespec refresh_after;

	uint8_t send_nonce[COMMON_NONCEBYTES];
	uint8_t receive_nonce[COMMON_NONCEBYTES];

	struct timespec receive_last;
	uint64_t receive_reorder_seen;
} fastd_method_common_t;


void fastd_method_common_init(fastd_context_t *ctx, fastd_method_common_t *session, bool initiator);
bool fastd_method_is_nonce_valid(fastd_context_t *ctx, const fastd_method_common_t *session, const uint8_t nonce[COMMON_NONCEBYTES], int64_t *age);
bool fastd_method_reorder_check(fastd_context_t *ctx, fastd_peer_t *peer, fastd_method_common_t *session, const uint8_t nonce[COMMON_NONCEBYTES], int64_t age);


static inline bool fastd_method_session_common_is_valid(fastd_context_t *ctx, const fastd_method_common_t *session) {
	return (timespec_after(&session->valid_till, &ctx->now));
}

static inline bool fastd_method_session_common_is_initiator(const fastd_method_common_t *session) {
	return (session->send_nonce[0] & 1);
}

static inline bool fastd_method_session_common_want_refresh(fastd_context_t *ctx, const fastd_method_common_t *session) {
	return timespec_after(&ctx->now, &session->refresh_after);
}

static inline void fastd_method_session_common_superseded(fastd_context_t *ctx, fastd_method_common_t *session) {
	struct timespec valid_max = ctx->now;
	valid_max.tv_sec += ctx->conf->key_valid_old;

	if (timespec_after(&session->valid_till, &valid_max))
		session->valid_till = valid_max;
}

static inline void fastd_method_increment_nonce(fastd_method_common_t *session) {
	session->send_nonce[0] += 2;

	if (session->send_nonce[0] == 0 || session->send_nonce[0] == 1) {
		int i;
		for (i = 1; i < COMMON_NONCEBYTES; i++) {
			session->send_nonce[i]++;
			if (session->send_nonce[i] != 0)
				break;
		}
	}
}

#endif /* _FASTD_METHODS_COMMON_H_ */
