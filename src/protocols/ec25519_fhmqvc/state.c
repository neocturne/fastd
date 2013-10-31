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


static void init_protocol_state(fastd_context_t *ctx) {
	if (!ctx->protocol_state) {
		ctx->protocol_state = calloc(1, sizeof(fastd_protocol_state_t));

		ctx->protocol_state->prev_handshake_key.preferred_till = ctx->conf->long_ago;
		ctx->protocol_state->handshake_key.preferred_till = ctx->conf->long_ago;
	}
}

static void new_handshake_key(fastd_context_t *ctx, keypair_t *key) {
		fastd_random_bytes(ctx, key->secret.p, 32, false);
		ecc_25519_gf_sanitize_secret(&key->secret, &key->secret);

		ecc_25519_work_t work;
		ecc_25519_scalarmult_base(&work, &key->secret);
		ecc_25519_store_packed(&key->public, &work);
}

void fastd_protocol_ec25519_fhmqvc_maintenance(fastd_context_t *ctx) {
	init_protocol_state(ctx);

	if (!is_handshake_key_preferred(ctx, &ctx->protocol_state->handshake_key)) {
		pr_debug(ctx, "generating new handshake key");

		ctx->protocol_state->prev_handshake_key = ctx->protocol_state->handshake_key;

		ctx->protocol_state->handshake_key.serial++;

		new_handshake_key(ctx, &ctx->protocol_state->handshake_key.key);

		ctx->protocol_state->handshake_key.preferred_till = ctx->now;
		ctx->protocol_state->handshake_key.preferred_till.tv_sec += 15;

		ctx->protocol_state->handshake_key.valid_till = ctx->now;
		ctx->protocol_state->handshake_key.valid_till.tv_sec += 30;
	}
}

void fastd_protocol_ec25519_fhmqvc_init_peer_state(fastd_context_t *ctx, fastd_peer_t *peer) {
	init_protocol_state(ctx);

	if (peer->protocol_state)
		exit_bug(ctx, "tried to reinit peer state");

	peer->protocol_state = calloc(1, sizeof(fastd_protocol_peer_state_t));
	peer->protocol_state->last_serial = ctx->protocol_state->handshake_key.serial;
}

static void reset_session(fastd_context_t *ctx, protocol_session_t *session) {
	if (session->method)
		session->method->session_free(ctx, session->method_state);
	secure_memzero(session, sizeof(protocol_session_t));
}

void fastd_protocol_ec25519_fhmqvc_reset_peer_state(fastd_context_t *ctx, fastd_peer_t *peer) {
	if (!peer->protocol_state)
		return;

	reset_session(ctx, &peer->protocol_state->old_session);
	reset_session(ctx, &peer->protocol_state->session);
}

void fastd_protocol_ec25519_fhmqvc_free_peer_state(fastd_context_t *ctx, fastd_peer_t *peer) {
	if (peer->protocol_state) {
		reset_session(ctx, &peer->protocol_state->old_session);
		reset_session(ctx, &peer->protocol_state->session);

		free(peer->protocol_state);
	}
}
