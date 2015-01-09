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

   ec25519-fhmqvc protocol: basic functions
*/


#include "ec25519_fhmqvc.h"


/** Converts a private or public key from a hexadecimal string representation to a uint8 array */
static inline bool read_key(uint8_t key[32], const char *hexkey) {
	if ((strlen(hexkey) != 64) || (strspn(hexkey, "0123456789abcdefABCDEF") != 64))
		return false;

	size_t i;
	for (i = 0; i < 32; i++)
		sscanf(&hexkey[2*i], "%02hhx", &key[i]);

	return true;
}

/** Checks if the current session with a peers needs refreshing */
static inline void check_session_refresh(fastd_peer_t *peer) {
	protocol_session_t *session = &peer->protocol_state->session;

	if (!session->refreshing && session->method->provider->session_want_refresh(session->method_state)) {
		pr_verbose("refreshing session with %P", peer);
		session->handshakes_cleaned = true;
		session->refreshing = true;
		fastd_peer_schedule_handshake(peer, 0);
	}
}

/** Initializes the protocol-specific configuration */
static fastd_protocol_config_t * protocol_init(void) {
	fastd_protocol_config_t *protocol_config = fastd_new(fastd_protocol_config_t);

	if (!conf.secret)
		exit_error("no secret key configured");

	if (!read_key(protocol_config->key.secret.p, conf.secret))
		exit_error("invalid secret key");

	ecc_25519_work_t work;
	ecc_25519_scalarmult_base(&work, &protocol_config->key.secret);
	ecc_25519_store_packed(&protocol_config->key.public.int256, &work);

	if (!divide_key(&protocol_config->key.secret))
		exit_error("invalid secret key");

	return protocol_config;
}

/** Parses a peer's key */
static fastd_protocol_key_t * protocol_read_key(const char *key) {
	fastd_protocol_key_t *ret = fastd_new(fastd_protocol_key_t);

	if (read_key(ret->key.u8, key)) {
		if (ecc_25519_load_packed(&ret->unpacked, &ret->key.int256)) {
			if (!ecc_25519_is_identity(&ret->unpacked))
				return ret;
		}
	}

	free(ret);
	return NULL;
}


/** Checks if a peer is configured using our own key */
static bool protocol_check_peer(const fastd_peer_t *peer) {
	if (memcmp(conf.protocol_config->key.public.u8, peer->key->key.u8, PUBLICKEYBYTES) == 0) {
		pr_verbose("found own key as %P, ignoring peer", peer);
		return false;
	}

	return true;
}

/** Checks if the current session with a peer is valid and resets the connection if not */
static inline bool check_session(fastd_peer_t *peer) {
	if (is_session_valid(&peer->protocol_state->session))
		return true;

	pr_verbose("active session with %P timed out", peer);
	fastd_peer_reset(peer);
	return false;
}

/** Determines if the old or the new session should be used for sending a packet */
static inline bool use_old_session(const fastd_protocol_peer_state_t *state) {
	if (!state->session.method->provider->session_is_initiator(state->session.method_state))
		return false;

	if (!is_session_valid(&state->old_session))
		return false;

	return true;
}

/** Handles a payload packet received from a peer */
static void protocol_handle_recv(fastd_peer_t *peer, fastd_buffer_t buffer) {
	if (!peer->protocol_state || !check_session(peer))
		goto fail;

	fastd_buffer_t recv_buffer;
	bool ok = false, reordered;

	if (is_session_valid(&peer->protocol_state->old_session)) {
		reordered = false;
		if (peer->protocol_state->old_session.method->provider->decrypt(peer, peer->protocol_state->old_session.method_state, &recv_buffer, buffer, &reordered))
			ok = true;
	}

	if (!ok) {
		reordered = false;
		if (peer->protocol_state->session.method->provider->decrypt(peer, peer->protocol_state->session.method_state, &recv_buffer, buffer, &reordered)) {
			ok = true;

			if (peer->protocol_state->old_session.method) {
				pr_debug("invalidating old session with %P", peer);
				peer->protocol_state->old_session.method->provider->session_free(peer->protocol_state->old_session.method_state);
				peer->protocol_state->old_session = (protocol_session_t){};
			}

			if (!peer->protocol_state->session.handshakes_cleaned) {
				pr_debug("cleaning left handshakes with %P", peer);
				fastd_peer_unschedule_handshake(peer);
				peer->protocol_state->session.handshakes_cleaned = true;

				if (peer->protocol_state->session.method->provider->session_is_initiator(peer->protocol_state->session.method_state))
					fastd_protocol_ec25519_fhmqvc_send_empty(peer, &peer->protocol_state->session);
			}

			check_session_refresh(peer);
		}
	}

	if (!ok) {
		pr_verbose("verification failed for packet received from %P", peer);
		goto fail;
	}

	fastd_peer_seen(peer);

	if (recv_buffer.len)
		fastd_handle_receive(peer, recv_buffer, reordered);
	else
		fastd_buffer_free(recv_buffer);

	return;

 fail:
	fastd_buffer_free(buffer);
}

/** Encrypts and sends a packet to a peer using a specified session */
static void session_send(fastd_peer_t *peer, fastd_buffer_t buffer, protocol_session_t *session) {
	size_t stat_size = buffer.len;

	fastd_buffer_t send_buffer;
	if (!session->method->provider->encrypt(peer, session->method_state, &send_buffer, buffer)) {
		fastd_buffer_free(buffer);
		pr_error("failed to encrypt packet for %P", peer);
		return;
	}

	fastd_send(peer->sock, &peer->local_address, &peer->address, peer, send_buffer, stat_size);
	peer->keepalive_timeout = ctx.now + KEEPALIVE_TIMEOUT;
}

/** Encrypts and sends a packet to a peer */
static void protocol_send(fastd_peer_t *peer, fastd_buffer_t buffer) {
	if (!peer->protocol_state || !fastd_peer_is_established(peer) || !check_session(peer)) {
		fastd_buffer_free(buffer);
		return;
	}

	check_session_refresh(peer);

	if (use_old_session(peer->protocol_state)) {
		pr_debug2("sending packet for old session to %P", peer);
		session_send(peer, buffer, &peer->protocol_state->old_session);
	}
	else {
		session_send(peer, buffer, &peer->protocol_state->session);
	}
}

/** Sends an empty payload packet (i.e. keepalive) to a peer using a specified session */
void fastd_protocol_ec25519_fhmqvc_send_empty(fastd_peer_t *peer, protocol_session_t *session) {
	session_send(peer, fastd_buffer_alloc(0, alignto(session->method->provider->min_encrypt_head_space, 8), session->method->provider->min_encrypt_tail_space), session);
}

/** get_current_method implementation for ec25519-fhmqvp */
const fastd_method_info_t * protocol_get_current_method(const fastd_peer_t *peer) {
	if (!peer->protocol_state || !fastd_peer_is_established(peer))
		return NULL;

	if (use_old_session(peer->protocol_state))
		return peer->protocol_state->old_session.method;
	else
		return peer->protocol_state->session.method;
}


/** The \em ec25519-fhmqvc protocol definition */
const fastd_protocol_t fastd_protocol_ec25519_fhmqvc = {
	.name = "ec25519-fhmqvc",

	.init = protocol_init,

	.handshake_init = fastd_protocol_ec25519_fhmqvc_handshake_init,
	.handshake_handle = fastd_protocol_ec25519_fhmqvc_handshake_handle,
#ifdef WITH_DYNAMIC_PEERS
	.handle_verify_return = fastd_protocol_ec25519_fhmqvc_handle_verify_return,
#endif

	.handle_recv = protocol_handle_recv,
	.send = protocol_send,

	.init_peer_state = fastd_protocol_ec25519_fhmqvc_init_peer_state,
	.reset_peer_state = fastd_protocol_ec25519_fhmqvc_reset_peer_state,
	.free_peer_state = fastd_protocol_ec25519_fhmqvc_free_peer_state,

	.read_key = protocol_read_key,
	.check_peer = protocol_check_peer,
	.find_peer = fastd_protocol_ec25519_fhmqvc_find_peer,

	.get_current_method = protocol_get_current_method,

	.generate_key = fastd_protocol_ec25519_fhmqvc_generate_key,
	.show_key = fastd_protocol_ec25519_fhmqvc_show_key,

	.set_shell_env = fastd_protocol_ec25519_fhmqvc_set_shell_env,
	.describe_peer = fastd_protocol_ec25519_fhmqvc_describe_peer,
};
