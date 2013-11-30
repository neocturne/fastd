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


#include "ec25519_fhmqvc.h"


static inline bool read_key(uint8_t key[32], const char *hexkey) {
	if ((strlen(hexkey) != 64) || (strspn(hexkey, "0123456789abcdefABCDEF") != 64))
		return false;

	int i;
	for (i = 0; i < 32; i++)
		sscanf(&hexkey[2*i], "%02hhx", &key[i]);

	return true;
}

static inline void check_session_refresh(fastd_context_t *ctx, fastd_peer_t *peer) {
	protocol_session_t *session = &peer->protocol_state->session;

	if (!session->refreshing && session->method->method->session_want_refresh(ctx, session->method_state)) {
		pr_verbose(ctx, "refreshing session with %P", peer);
		session->handshakes_cleaned = true;
		session->refreshing = true;
		fastd_peer_schedule_handshake(ctx, peer, 0);
	}
}

static fastd_protocol_config_t* protocol_init(fastd_context_t *ctx) {
	fastd_protocol_config_t *protocol_config = malloc(sizeof(fastd_protocol_config_t));

	if (!ctx->conf->secret)
		exit_error(ctx, "no secret key configured");

	if (!read_key(protocol_config->key.secret.p, ctx->conf->secret))
		exit_error(ctx, "invalid secret key");

	ecc_25519_work_t work;
	ecc_25519_scalarmult_base(&work, &protocol_config->key.secret);
	ecc_25519_store_packed(&protocol_config->key.public.int256, &work);

	return protocol_config;
}

static void protocol_peer_configure(fastd_context_t *ctx, fastd_peer_config_t *peer_conf) {
	if (peer_conf->protocol_config)
		return;

	if (!peer_conf->key) {
		pr_warn(ctx, "no key configured for `%s', disabling peer", peer_conf->name);
		return;
	}

	aligned_int256_t key;
	if (!read_key(key.u8, peer_conf->key)) {
		pr_warn(ctx, "invalid key configured for `%s', disabling peer", peer_conf->name);
		return;
	}

	peer_conf->protocol_config = malloc(sizeof(fastd_protocol_peer_config_t));
	peer_conf->protocol_config->public_key = key;

	if (memcmp(&peer_conf->protocol_config->public_key, &ctx->conf->protocol_config->key.public, 32) == 0)
		pr_debug(ctx, "found own key as `%s', ignoring peer", peer_conf->name);
}

static inline bool check_session(fastd_context_t *ctx, fastd_peer_t *peer) {
	if (is_session_valid(ctx, &peer->protocol_state->session))
		return true;

	pr_verbose(ctx, "active session with %P timed out", peer);
	fastd_peer_reset(ctx, peer);
	return false;
}

static void protocol_handle_recv(fastd_context_t *ctx, fastd_peer_t *peer, fastd_buffer_t buffer) {
	if (!peer->protocol_state || !check_session(ctx, peer))
		goto fail;

	fastd_buffer_t recv_buffer;
	bool ok = false;

	if (is_session_valid(ctx, &peer->protocol_state->old_session)) {
		if (peer->protocol_state->old_session.method->method->decrypt(ctx, peer, peer->protocol_state->old_session.method_state, &recv_buffer, buffer))
			ok = true;
	}

	if (!ok) {
		if (peer->protocol_state->session.method->method->decrypt(ctx, peer, peer->protocol_state->session.method_state, &recv_buffer, buffer)) {
			ok = true;

			if (peer->protocol_state->old_session.method) {
				pr_debug(ctx, "invalidating old session with %P", peer);
				peer->protocol_state->old_session.method->method->session_free(ctx, peer->protocol_state->old_session.method_state);
				peer->protocol_state->old_session = (protocol_session_t){};
			}

			if (!peer->protocol_state->session.handshakes_cleaned) {
				pr_debug(ctx, "cleaning left handshakes with %P", peer);
				fastd_peer_unschedule_handshake(ctx, peer);
				peer->protocol_state->session.handshakes_cleaned = true;

				if (peer->protocol_state->session.method->method->session_is_initiator(ctx, peer->protocol_state->session.method_state))
					fastd_protocol_ec25519_fhmqvc_send_empty(ctx, peer, &peer->protocol_state->session);
			}

			check_session_refresh(ctx, peer);
		}
	}

	if (!ok) {
		pr_verbose(ctx, "verification failed for packet received from %P", peer);
		goto fail;
	}

	fastd_peer_seen(ctx, peer);

	if (recv_buffer.len)
		fastd_handle_receive(ctx, peer, recv_buffer);
	else
		fastd_buffer_free(recv_buffer);

	return;

 fail:
	fastd_buffer_free(buffer);
}

static void session_send(fastd_context_t *ctx, fastd_peer_t *peer, fastd_buffer_t buffer, protocol_session_t *session) {
	size_t stat_size = buffer.len;

	fastd_buffer_t send_buffer;
	if (!session->method->method->encrypt(ctx, peer, session->method_state, &send_buffer, buffer)) {
		fastd_buffer_free(buffer);
		pr_error(ctx, "failed to encrypt packet for %P", peer);
		return;
	}

	fastd_send(ctx, peer->sock, &peer->local_address, &peer->address, peer, send_buffer, stat_size);
	peer->last_send = ctx->now;
}

static void protocol_send(fastd_context_t *ctx, fastd_peer_t *peer, fastd_buffer_t buffer) {
	if (!peer->protocol_state || !fastd_peer_is_established(peer) || !check_session(ctx, peer)) {
		fastd_buffer_free(buffer);
		return;
	}

	check_session_refresh(ctx, peer);

	if (peer->protocol_state->session.method->method->session_is_initiator(ctx, peer->protocol_state->session.method_state) && is_session_valid(ctx, &peer->protocol_state->old_session)) {
		pr_debug2(ctx, "sending packet for old session to %P", peer);
		session_send(ctx, peer, buffer, &peer->protocol_state->old_session);
	}
	else {
		session_send(ctx, peer, buffer, &peer->protocol_state->session);
	}
}

void fastd_protocol_ec25519_fhmqvc_send_empty(fastd_context_t *ctx, fastd_peer_t *peer, protocol_session_t *session) {
	session_send(ctx, peer, fastd_buffer_alloc(ctx, 0, alignto(session->method->method->min_encrypt_head_space, 8), session->method->method->min_encrypt_tail_space), session);
}

const fastd_protocol_t fastd_protocol_ec25519_fhmqvc = {
	.name = "ec25519-fhmqvc",

	.init = protocol_init,
	.peer_configure = protocol_peer_configure,

	.peer_check = fastd_protocol_ec25519_fhmqvc_peer_check,
	.peer_check_temporary = fastd_protocol_ec25519_fhmqvc_peer_check_temporary,

	.handshake_init = fastd_protocol_ec25519_fhmqvc_handshake_init,
	.handshake_handle = fastd_protocol_ec25519_fhmqvc_handshake_handle,

	.handle_recv = protocol_handle_recv,
	.send = protocol_send,

	.init_peer_state = fastd_protocol_ec25519_fhmqvc_init_peer_state,
	.reset_peer_state = fastd_protocol_ec25519_fhmqvc_reset_peer_state,
	.free_peer_state = fastd_protocol_ec25519_fhmqvc_free_peer_state,

	.generate_key = fastd_protocol_ec25519_fhmqvc_generate_key,
	.show_key = fastd_protocol_ec25519_fhmqvc_show_key,
	.set_shell_env = fastd_protocol_ec25519_fhmqvc_set_shell_env,
	.describe_peer = fastd_protocol_ec25519_fhmqvc_describe_peer,
};
