// SPDX-License-Identifier: BSD-2-Clause
/*
  Copyright (c) Matthias Schiffer <mschiffer@universe-factory.net>
  All rights reserved.
*/

/**
   \file

   ec25519-fhmqvc protocol: state handling
*/


#include "../../crypto.h"
#include "handshake.h"


/** Allocates the protocol-specific state */
static void init_protocol_state(void) {
	if (!ctx.protocol_state) {
		ctx.protocol_state = fastd_new0(fastd_protocol_state_t);

		ctx.protocol_state->prev_handshake_key.preferred_till = ctx.now;
		ctx.protocol_state->handshake_key.preferred_till = ctx.now;
	}
}

/** Generates a new ephemeral keypair */
static void new_handshake_key(keypair_t *key) {
	fastd_random_bytes(key->secret.p, SECRETKEYBYTES, false);
	ecc_25519_gf_sanitize_secret(&key->secret, &key->secret);

	ecc_25519_work_t work;
	ecc_25519_scalarmult_base(&work, &key->secret);
	ecc_25519_store_packed_legacy(&key->public.int256, &work);

	if (!divide_key(&key->secret))
		exit_bug("generated invalid ephemeral key");
}

/**
   Performs maintenance tasks on the protocol state

   If there is currently no preferred ephemeral keypair, a new one
   will be generated.
*/
void fastd_protocol_ec25519_fhmqvc_maintenance(void) {
	init_protocol_state();

	if (!is_handshake_key_preferred(&ctx.protocol_state->handshake_key)) {
		pr_debug("generating new handshake key");

		ctx.protocol_state->prev_handshake_key = ctx.protocol_state->handshake_key;

		ctx.protocol_state->handshake_key.serial++;

		new_handshake_key(&ctx.protocol_state->handshake_key.key);

		ctx.protocol_state->handshake_key.preferred_till = ctx.now + 15000;
		ctx.protocol_state->handshake_key.valid_till = ctx.now + 30000;
	}
}

/** Allocated protocol-specific peer state */
void fastd_protocol_ec25519_fhmqvc_init_peer_state(fastd_peer_t *peer) {
	init_protocol_state();

	if (peer->protocol_state)
		exit_bug("tried to reinit peer state");

	peer->protocol_state = fastd_new0(fastd_protocol_peer_state_t);
	peer->protocol_state->last_serial = ctx.protocol_state->handshake_key.serial;
}

/** Resets a the state of a session, freeing method-specific state */
static void reset_session(protocol_session_t *session) {
	if (session->method)
		session->method->provider->session_free(session->method_state);
	secure_memzero(session, sizeof(protocol_session_t));
}

/** Resets all protocol-specific state of a peer */
void fastd_protocol_ec25519_fhmqvc_reset_peer_state(fastd_peer_t *peer) {
	if (!peer->protocol_state)
		return;

	reset_session(&peer->protocol_state->old_session);
	reset_session(&peer->protocol_state->session);
}

/** Frees the protocol-specific state */
void fastd_protocol_ec25519_fhmqvc_free_peer_state(fastd_peer_t *peer) {
	if (peer->protocol_state) {
		reset_session(&peer->protocol_state->old_session);
		reset_session(&peer->protocol_state->session);

		free(peer->protocol_state);
	}
}
