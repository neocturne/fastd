/*
  Copyright (c) 2012, Matthias Schiffer <mschiffer@universe-factory.net>
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


#define _GNU_SOURCE

#include "fastd.h"
#include "handshake.h"
#include "peer.h"
#include "task.h"

#include <arpa/inet.h>

#include <libuecc/ecc.h>
#include <crypto_auth_hmacsha256.h>
#include <crypto_hash_sha256.h>


#define PUBLICKEYBYTES 32
#define SECRETKEYBYTES 32
#define HMACBYTES crypto_auth_hmacsha256_BYTES
#define HASHBYTES crypto_hash_sha256_BYTES


#if HASHBYTES != crypto_auth_hmacsha256_KEYBYTES
#error bug: HASHBYTES != crypto_auth_hmacsha256_KEYBYTES
#endif

#if HASHBYTES != SECRETKEYBYTES
#error bug: HASHBYTES != SECRETKEYBYTES
#endif


struct _fastd_protocol_config {
	ecc_secret_key_256 secret_key;
	ecc_public_key_256 public_key;
};

typedef enum _handshake_state {
	HANDSHAKE_STATE_INIT,
	HANDSHAKE_STATE_RESPONSE,
	HANDSHAKE_STATE_ESTABLISHED
} handshake_state;

struct _fastd_protocol_peer_config {
	ecc_public_key_256 public_key;
};

typedef struct _protocol_handshake {
	const fastd_peer_config *peer_config;

	handshake_state state;
	ecc_secret_key_256 secret_key;
	ecc_public_key_256 public_key;
	ecc_public_key_256 peer_key;
	ecc_public_key_256 sigma;
	uint8_t shared_handshake_key[HASHBYTES];
} protocol_handshake;

typedef struct _protocol_session {
	bool handshakes_cleaned;
	bool refreshing;

	fastd_method_session_state *method_state;
} protocol_session;

struct _fastd_protocol_peer_state {
	protocol_session old_session;
	protocol_session session;

	protocol_handshake *initiating_handshake;
	protocol_handshake *accepting_handshake;
};


#define RECORD_SENDER_KEY RECORD_PROTOCOL1
#define RECORD_RECEIPIENT_KEY RECORD_PROTOCOL2
#define RECORD_SENDER_HANDSHAKE_KEY RECORD_PROTOCOL3
#define RECORD_RECEIPIENT_HANDSHAKE_KEY RECORD_PROTOCOL4
#define RECORD_T RECORD_PROTOCOL5


static void protocol_send(fastd_context *ctx, fastd_peer *peer, fastd_buffer buffer);


static inline bool read_key(uint8_t key[32], const char *hexkey) {
	if ((strlen(hexkey) != 64) || (strspn(hexkey, "0123456789abcdefABCDEF") != 64))
		return false;

	int i;
	for (i = 0; i < 32; i++)
		sscanf(&hexkey[2*i], "%02hhx", &key[i]);

	return true;
}

static inline bool is_session_valid(fastd_context *ctx, const protocol_session *session) {
	return ctx->conf->method->session_is_valid(ctx, session->method_state);
}

static inline void check_session_refresh(fastd_context *ctx, fastd_peer *peer) {
	protocol_session *session = &peer->protocol_state->session;

	if (!session->refreshing && ctx->conf->method->session_want_refresh(ctx, session->method_state)) {
		pr_debug(ctx, "refreshing session with %P", peer);
		session->refreshing = true;
		fastd_task_schedule_handshake(ctx, peer, 0);
	}
}

static fastd_protocol_config* protocol_init(fastd_context *ctx) {
	fastd_protocol_config *protocol_config = malloc(sizeof(fastd_protocol_config));

	if (!ctx->conf->secret)
		exit_error(ctx, "no secret key configured");

	if (!read_key(protocol_config->secret_key.s, ctx->conf->secret))
		exit_error(ctx, "invalid secret key");

	ecc_25519_work work;
	ecc_25519_scalarmult_base(&work, &protocol_config->secret_key);
	ecc_25519_store(&protocol_config->public_key, &work);

	return protocol_config;
}

static void protocol_peer_configure(fastd_context *ctx, fastd_peer_config *peer_conf) {
	ecc_public_key_256 key;

	if (!peer_conf->key) {
		pr_warn(ctx, "no key configured for `%s', disabling peer", peer_conf->name);
		peer_conf->enabled = false;
		return;
	}

	if (!read_key(key.p, peer_conf->key)) {
		pr_warn(ctx, "invalid key configured for `%s', disabling peer", peer_conf->name);
		peer_conf->enabled = false;
		return;
	}

	peer_conf->protocol_config = malloc(sizeof(fastd_protocol_peer_config));
	peer_conf->protocol_config->public_key = key;
}

static void init_peer_state(fastd_context *ctx, fastd_peer *peer) {
	if (peer->protocol_state)
		return;

	peer->protocol_state = malloc(sizeof(fastd_protocol_peer_state));
	memset(peer->protocol_state, 0, sizeof(fastd_protocol_peer_state));
}

static inline void free_handshake(protocol_handshake *handshake) {
	if (handshake) {
		memset(handshake, 0, sizeof(protocol_handshake));
		free(handshake);
	}
}

static void protocol_peer_config_purged(fastd_context *ctx, fastd_peer_config *peer_conf) {
	fastd_peer *peer;
	for (peer = ctx->peers; peer; peer = peer->next) {
		if (!peer->protocol_state)
			continue;

		if (peer->protocol_state->initiating_handshake &&
		    peer->protocol_state->initiating_handshake->peer_config == peer_conf) {
			free_handshake(peer->protocol_state->initiating_handshake);
			peer->protocol_state->initiating_handshake = NULL;
		}

		if (peer->protocol_state->accepting_handshake &&
		    peer->protocol_state->accepting_handshake->peer_config == peer_conf) {
			free_handshake(peer->protocol_state->accepting_handshake);
			peer->protocol_state->accepting_handshake = NULL;
		}
	}
}

static protocol_handshake* new_handshake(fastd_context *ctx, fastd_peer *peer, const fastd_peer_config *peer_config, bool initiate) {
	protocol_handshake **handshake;

	if (initiate)
		handshake = &peer->protocol_state->initiating_handshake;
	else
		handshake = &peer->protocol_state->accepting_handshake;

	free_handshake(*handshake);

	*handshake = malloc(sizeof(protocol_handshake));

	(*handshake)->peer_config = peer_config;

	(*handshake)->state = HANDSHAKE_STATE_INIT;

	fastd_random_bytes(ctx, (*handshake)->secret_key.s, 32, false);
	ecc_25519_secret_sanitize(&(*handshake)->secret_key, &(*handshake)->secret_key);

	ecc_25519_work work;
	ecc_25519_scalarmult_base(&work, &(*handshake)->secret_key);
	ecc_25519_store(&(*handshake)->public_key, &work);

	return *handshake;
}

static void protocol_handshake_init(fastd_context *ctx, fastd_peer *peer) {
	init_peer_state(ctx, peer);

	fastd_buffer buffer = fastd_handshake_new_init(ctx, peer, 3*(4+PUBLICKEYBYTES) /* sender key, receipient key, handshake key */);

	protocol_handshake *handshake = new_handshake(ctx, peer, peer->config, true);

	fastd_handshake_add(ctx, &buffer, RECORD_SENDER_KEY, PUBLICKEYBYTES, ctx->conf->protocol_config->public_key.p);

	if (handshake->peer_config)
		fastd_handshake_add(ctx, &buffer, RECORD_RECEIPIENT_KEY, PUBLICKEYBYTES, handshake->peer_config->protocol_config->public_key.p);
	else
		pr_debug(ctx, "sending handshake to unknown peer %P", peer);

	fastd_handshake_add(ctx, &buffer, RECORD_SENDER_HANDSHAKE_KEY, PUBLICKEYBYTES, handshake->public_key.p);

	fastd_send_handshake(ctx, peer, buffer);
}

static inline bool has_field(const fastd_handshake *handshake, uint8_t type, size_t length) {
	return (handshake->records[type].length == length);
}

static void respond_handshake(fastd_context *ctx, fastd_peer *peer, const fastd_handshake *handshake) {
	pr_debug(ctx, "responding handshake with %P...", peer);

	uint8_t hashinput[5*PUBLICKEYBYTES];
	uint8_t hashbuf[HASHBYTES];
	uint8_t hmacbuf[HMACBYTES];

	memcpy(hashinput, peer->protocol_state->accepting_handshake->public_key.p, PUBLICKEYBYTES);
	memcpy(hashinput+PUBLICKEYBYTES, peer->protocol_state->accepting_handshake->peer_key.p, PUBLICKEYBYTES);
	memcpy(hashinput+2*PUBLICKEYBYTES, ctx->conf->protocol_config->public_key.p, PUBLICKEYBYTES);
	memcpy(hashinput+3*PUBLICKEYBYTES, peer->protocol_state->accepting_handshake->peer_config->protocol_config->public_key.p, PUBLICKEYBYTES);

	crypto_hash_sha256(hashbuf, hashinput, 4*PUBLICKEYBYTES);

	ecc_secret_key_256 d = {{0}}, e = {{0}}, eb, s;

	memcpy(d.s, hashbuf, HASHBYTES/2);
	memcpy(e.s, hashbuf+HASHBYTES/2, HASHBYTES/2);

	d.s[15] |= 0x80;
	e.s[15] |= 0x80;

	ecc_25519_secret_mult(&eb, &e, &ctx->conf->protocol_config->secret_key);
	ecc_25519_secret_add(&s, &eb, &peer->protocol_state->accepting_handshake->secret_key);

	ecc_25519_work work, workX;
	ecc_25519_load(&work, &peer->protocol_state->accepting_handshake->peer_config->protocol_config->public_key);
	ecc_25519_load(&workX, &peer->protocol_state->accepting_handshake->peer_key);

	ecc_25519_scalarmult(&work, &d, &work);
	ecc_25519_add(&work, &workX, &work);
	ecc_25519_scalarmult(&work, &s, &work);

	if (ecc_25519_is_identity(&work))
		return;

	ecc_25519_store(&peer->protocol_state->accepting_handshake->sigma, &work);

	memcpy(hashinput+4*PUBLICKEYBYTES, peer->protocol_state->accepting_handshake->sigma.p, PUBLICKEYBYTES);
	crypto_hash_sha256(peer->protocol_state->accepting_handshake->shared_handshake_key, hashinput, 5*PUBLICKEYBYTES);

	memcpy(hashinput, ctx->conf->protocol_config->public_key.p, PUBLICKEYBYTES);
	memcpy(hashinput+PUBLICKEYBYTES, peer->protocol_state->accepting_handshake->public_key.p, PUBLICKEYBYTES);

	crypto_auth_hmacsha256(hmacbuf, hashinput, 2*PUBLICKEYBYTES, peer->protocol_state->accepting_handshake->shared_handshake_key);

	fastd_buffer buffer = fastd_handshake_new_reply(ctx, peer, handshake, 4*(4+PUBLICKEYBYTES) + 4+HMACBYTES);

	fastd_handshake_add(ctx, &buffer, RECORD_SENDER_KEY, PUBLICKEYBYTES, ctx->conf->protocol_config->public_key.p);
	fastd_handshake_add(ctx, &buffer, RECORD_RECEIPIENT_KEY, PUBLICKEYBYTES, peer->protocol_state->accepting_handshake->peer_config->protocol_config->public_key.p);
	fastd_handshake_add(ctx, &buffer, RECORD_SENDER_HANDSHAKE_KEY, PUBLICKEYBYTES, peer->protocol_state->accepting_handshake->public_key.p);
	fastd_handshake_add(ctx, &buffer, RECORD_RECEIPIENT_HANDSHAKE_KEY, PUBLICKEYBYTES, peer->protocol_state->accepting_handshake->peer_key.p);
	fastd_handshake_add(ctx, &buffer, RECORD_T, HMACBYTES, hmacbuf);

	fastd_send_handshake(ctx, peer, buffer);

	peer->protocol_state->accepting_handshake->state = HANDSHAKE_STATE_RESPONSE;
}

static void establish(fastd_context *ctx, fastd_peer *peer, const fastd_peer_config *peer_config, bool initiator,
		      const ecc_public_key_256 *A, const ecc_public_key_256 *B, const ecc_public_key_256 *X,
		      const ecc_public_key_256 *Y, const ecc_public_key_256 *sigma) {
	uint8_t hashinput[5*PUBLICKEYBYTES];
	uint8_t hash[HASHBYTES];

	pr_verbose(ctx, "New session with %P established.", peer);

	if (is_session_valid(ctx, &peer->protocol_state->session) && !is_session_valid(ctx, &peer->protocol_state->old_session)) {
		ctx->conf->method->session_free(ctx, peer->protocol_state->old_session.method_state);
		peer->protocol_state->old_session = peer->protocol_state->session;
	}
	else {
		ctx->conf->method->session_free(ctx, peer->protocol_state->session.method_state);
	}

	memcpy(hashinput, X->p, PUBLICKEYBYTES);
	memcpy(hashinput+PUBLICKEYBYTES, Y->p, PUBLICKEYBYTES);
	memcpy(hashinput+2*PUBLICKEYBYTES, A->p, PUBLICKEYBYTES);
	memcpy(hashinput+3*PUBLICKEYBYTES, B->p, PUBLICKEYBYTES);
	memcpy(hashinput+4*PUBLICKEYBYTES, sigma->p, PUBLICKEYBYTES);
	crypto_hash_sha256(hash, hashinput, 5*PUBLICKEYBYTES);

	peer->protocol_state->session.handshakes_cleaned = false;
	peer->protocol_state->session.refreshing = false;
	peer->protocol_state->session.method_state = ctx->conf->method->session_init(ctx, hash, HASHBYTES, initiator);

	free_handshake(peer->protocol_state->initiating_handshake);
	peer->protocol_state->initiating_handshake = NULL;

	free_handshake(peer->protocol_state->accepting_handshake);
	peer->protocol_state->accepting_handshake = NULL;

	fastd_peer_seen(ctx, peer);

	if (peer_config != peer->config) {
		fastd_peer *perm_peer;
		for (perm_peer = ctx->peers; perm_peer; perm_peer = perm_peer->next) {
			if (perm_peer->config == peer_config) {
				peer = fastd_peer_set_established_merge(ctx, perm_peer, peer);
				break;
			}
		}
	}
	else {
		fastd_peer_set_established(ctx, peer);
	}

	fastd_task_schedule_keepalive(ctx, peer, ctx->conf->keepalive_interval*1000);

	if (!initiator)
		protocol_send(ctx, peer, fastd_buffer_alloc(0, ctx->conf->method->min_encrypt_head_space(ctx), 0));
}

static void finish_handshake(fastd_context *ctx, fastd_peer *peer, const fastd_handshake *handshake) {
	pr_debug(ctx, "finishing handshake with %P...", peer);

	uint8_t hashinput[5*PUBLICKEYBYTES];
	uint8_t hashbuf[HASHBYTES];
	uint8_t hmacbuf[HMACBYTES];

	memcpy(hashinput, peer->protocol_state->initiating_handshake->peer_key.p, PUBLICKEYBYTES);
	memcpy(hashinput+PUBLICKEYBYTES, peer->protocol_state->initiating_handshake->public_key.p, PUBLICKEYBYTES);
	memcpy(hashinput+2*PUBLICKEYBYTES, peer->protocol_state->initiating_handshake->peer_config->protocol_config->public_key.p, PUBLICKEYBYTES);
	memcpy(hashinput+3*PUBLICKEYBYTES, ctx->conf->protocol_config->public_key.p, PUBLICKEYBYTES);

	crypto_hash_sha256(hashbuf, hashinput, 4*PUBLICKEYBYTES);

	ecc_secret_key_256 d = {{0}}, e = {{0}}, da, s;

	memcpy(d.s, hashbuf, HASHBYTES/2);
	memcpy(e.s, hashbuf+HASHBYTES/2, HASHBYTES/2);

	d.s[15] |= 0x80;
	e.s[15] |= 0x80;

	ecc_25519_secret_mult(&da, &d, &ctx->conf->protocol_config->secret_key);
	ecc_25519_secret_add(&s, &da, &peer->protocol_state->initiating_handshake->secret_key);

	ecc_25519_work work, workY;
	ecc_25519_load(&work, &peer->protocol_state->initiating_handshake->peer_config->protocol_config->public_key);
	ecc_25519_load(&workY, &peer->protocol_state->initiating_handshake->peer_key);

	ecc_25519_scalarmult(&work, &e, &work);
	ecc_25519_add(&work, &workY, &work);
	ecc_25519_scalarmult(&work, &s, &work);

	if (ecc_25519_is_identity(&work))
		return;

	ecc_25519_store(&peer->protocol_state->initiating_handshake->sigma, &work);

	memcpy(hashinput+4*PUBLICKEYBYTES, peer->protocol_state->initiating_handshake->sigma.p, PUBLICKEYBYTES);
	crypto_hash_sha256(peer->protocol_state->initiating_handshake->shared_handshake_key, hashinput, 5*PUBLICKEYBYTES);

	memcpy(hashinput, peer->protocol_state->initiating_handshake->peer_config->protocol_config->public_key.p, PUBLICKEYBYTES);
	memcpy(hashinput+PUBLICKEYBYTES, peer->protocol_state->initiating_handshake->peer_key.p, PUBLICKEYBYTES);

	if(crypto_auth_hmacsha256_verify(handshake->records[RECORD_T].data, hashinput, 2*PUBLICKEYBYTES, peer->protocol_state->initiating_handshake->shared_handshake_key) != 0) {
		pr_warn(ctx, "received invalid protocol handshake response from %P", peer);
		return;
	}

	memcpy(hashinput, ctx->conf->protocol_config->public_key.p, PUBLICKEYBYTES);
	memcpy(hashinput+PUBLICKEYBYTES, peer->protocol_state->initiating_handshake->public_key.p, PUBLICKEYBYTES);
	crypto_auth_hmacsha256(hmacbuf, hashinput, 2*PUBLICKEYBYTES, peer->protocol_state->initiating_handshake->shared_handshake_key);

	fastd_buffer buffer = fastd_handshake_new_reply(ctx, peer, handshake, 4*(4+PUBLICKEYBYTES) + 4+HMACBYTES);

	fastd_handshake_add(ctx, &buffer, RECORD_SENDER_KEY, PUBLICKEYBYTES, ctx->conf->protocol_config->public_key.p);
	fastd_handshake_add(ctx, &buffer, RECORD_RECEIPIENT_KEY, PUBLICKEYBYTES, peer->protocol_state->initiating_handshake->peer_config->protocol_config->public_key.p);
	fastd_handshake_add(ctx, &buffer, RECORD_SENDER_HANDSHAKE_KEY, PUBLICKEYBYTES, peer->protocol_state->initiating_handshake->public_key.p);
	fastd_handshake_add(ctx, &buffer, RECORD_RECEIPIENT_HANDSHAKE_KEY, PUBLICKEYBYTES, peer->protocol_state->initiating_handshake->peer_key.p);
	fastd_handshake_add(ctx, &buffer, RECORD_T, HMACBYTES, hmacbuf);

	fastd_send_handshake(ctx, peer, buffer);

	establish(ctx, peer, peer->protocol_state->initiating_handshake->peer_config, true,
		  &peer->protocol_state->initiating_handshake->public_key,
		  &peer->protocol_state->initiating_handshake->peer_key,
		  &ctx->conf->protocol_config->public_key,
		  &peer->protocol_state->initiating_handshake->peer_config->protocol_config->public_key,
		  &peer->protocol_state->initiating_handshake->sigma);
}

static void handle_finish_handshake(fastd_context *ctx, fastd_peer *peer, const fastd_handshake *handshake) {
	pr_debug(ctx, "handling handshake finish with %P...", peer);

	uint8_t hashinput[2*PUBLICKEYBYTES];

	memcpy(hashinput, peer->protocol_state->accepting_handshake->peer_config->protocol_config->public_key.p, PUBLICKEYBYTES);
	memcpy(hashinput+PUBLICKEYBYTES, peer->protocol_state->accepting_handshake->peer_key.p, PUBLICKEYBYTES);

	if(crypto_auth_hmacsha256_verify(handshake->records[RECORD_T].data, hashinput, 2*PUBLICKEYBYTES, peer->protocol_state->accepting_handshake->shared_handshake_key) != 0) {
		pr_warn(ctx, "received invalid protocol handshake finish from %P", peer);
		return;
	}

	establish(ctx, peer, peer->protocol_state->accepting_handshake->peer_config, false,
		  &peer->protocol_state->accepting_handshake->peer_key,
		  &peer->protocol_state->accepting_handshake->public_key,
		  &peer->protocol_state->accepting_handshake->peer_config->protocol_config->public_key,
		  &ctx->conf->protocol_config->public_key,
		  &peer->protocol_state->accepting_handshake->sigma);
}

static inline const fastd_peer_config* match_sender_key(fastd_context *ctx, const fastd_peer *peer, const unsigned char key[32]) {
	if (peer->config) {
		if (memcmp(peer->config->protocol_config->public_key.p, key, PUBLICKEYBYTES) == 0)
			return peer->config;
	}

	if (fastd_peer_is_temporary(peer) || fastd_peer_is_floating(peer)) {
		fastd_peer_config *config;
		for (config = ctx->conf->peers; config; config = config->next) {
			if (!fastd_peer_config_is_floating(config))
				continue;

		if (memcmp(config->protocol_config->public_key.p, key, PUBLICKEYBYTES) == 0)
			return config;
		}
	}

	return NULL;
}

static void kill_handshakes(fastd_context *ctx, fastd_peer *peer) {
	pr_debug(ctx, "there is a handshake conflict, retrying in a moment...");

	free_handshake(peer->protocol_state->initiating_handshake);
	peer->protocol_state->initiating_handshake = NULL;

	free_handshake(peer->protocol_state->accepting_handshake);
	peer->protocol_state->accepting_handshake = NULL;
}

static void protocol_handshake_handle(fastd_context *ctx, fastd_peer *peer, const fastd_handshake *handshake) {
	init_peer_state(ctx, peer);

	if (!has_field(handshake, RECORD_SENDER_KEY, PUBLICKEYBYTES)) {
		pr_debug(ctx, "received handshake without sender key from %P", peer);
		return;
	}

	const fastd_peer_config *peer_config = match_sender_key(ctx, peer, handshake->records[RECORD_SENDER_KEY].data);

	if (handshake->type > 1 && !has_field(handshake, RECORD_RECEIPIENT_KEY, PUBLICKEYBYTES)) {
		pr_debug(ctx, "received handshake reply without receipient key from %P", peer);
		return;
	}
	else if(has_field(handshake, RECORD_RECEIPIENT_KEY, PUBLICKEYBYTES)) {
		if (memcmp(ctx->conf->protocol_config->public_key.p, handshake->records[RECORD_RECEIPIENT_KEY].data, PUBLICKEYBYTES) != 0) {
			pr_debug(ctx, "received protocol handshake with wrong receipient key from %P", peer);
			return;
		}
	}

	if (!has_field(handshake, RECORD_SENDER_HANDSHAKE_KEY, PUBLICKEYBYTES)) {
		pr_debug(ctx, "received handshake without sender handshake key from %P", peer);
		return;
	}

	if (handshake->type > 1 && !has_field(handshake, RECORD_RECEIPIENT_HANDSHAKE_KEY, PUBLICKEYBYTES)) {
		pr_debug(ctx, "received handshake reply without receipient handshake key from %P", peer);
		return;
	}

	if (handshake->type > 1 && !has_field(handshake, RECORD_T, HMACBYTES)) {
		pr_debug(ctx, "received handshake reply without HMAC from %P", peer);
		return;
	}

	switch(handshake->type) {
	case 1:
		new_handshake(ctx, peer, peer_config, false);
		memcpy(peer->protocol_state->accepting_handshake->peer_key.p, handshake->records[RECORD_SENDER_HANDSHAKE_KEY].data, PUBLICKEYBYTES);
		respond_handshake(ctx, peer, handshake);
		break;

	case 2:
		if (!peer->protocol_state->initiating_handshake || peer->protocol_state->initiating_handshake->state != HANDSHAKE_STATE_INIT) {
			pr_debug(ctx, "received unexpected handshake response from %P", peer);
			return;
		}

		if (peer->protocol_state->initiating_handshake->peer_config != peer_config) {
			if (peer->protocol_state->initiating_handshake->peer_config) {
				pr_debug(ctx, "received handshake response with wrong sender key from %P", peer);
				return;
			}
			else {
				peer->protocol_state->initiating_handshake->peer_config = peer_config;
			}
		}

		if (memcmp(peer->protocol_state->initiating_handshake->public_key.p, handshake->records[RECORD_RECEIPIENT_HANDSHAKE_KEY].data, PUBLICKEYBYTES) != 0) {
			pr_debug(ctx, "received handshake response with unexpected receipient handshake key from %P", peer);
			return;
		}

		pr_debug(ctx, "received handshake response from %P", peer);

		if (peer->protocol_state->accepting_handshake) {
			kill_handshakes(ctx, peer);
			return;
		}

		memcpy(peer->protocol_state->initiating_handshake->peer_key.p, handshake->records[RECORD_SENDER_HANDSHAKE_KEY].data, PUBLICKEYBYTES);

		finish_handshake(ctx, peer, handshake);
		break;

	case 3:
		if (!peer->protocol_state->accepting_handshake || peer->protocol_state->accepting_handshake->state != HANDSHAKE_STATE_RESPONSE) {
			pr_debug(ctx, "received unexpected protocol handshake finish from %P", peer);
			return;
		}

		if (peer->protocol_state->accepting_handshake->peer_config != peer_config) {
			pr_debug(ctx, "received protocol handshake finish with wrong sender key from %P", peer);
			return;
		}

		if (memcmp(peer->protocol_state->accepting_handshake->public_key.p, handshake->records[RECORD_RECEIPIENT_HANDSHAKE_KEY].data, PUBLICKEYBYTES) != 0) {
			pr_debug(ctx, "received handshake response with unexpected receipient handshake key from %P", peer);
			return;
		}

		if (memcmp(peer->protocol_state->accepting_handshake->peer_key.p, handshake->records[RECORD_SENDER_HANDSHAKE_KEY].data, PUBLICKEYBYTES) != 0) {
			pr_debug(ctx, "received handshake response with unexpected sender handshake key from %P", peer);
			return;
		}

		pr_debug(ctx, "received handshake finish from %P", peer);

		if (peer->protocol_state->initiating_handshake && peer->protocol_state->initiating_handshake->state != HANDSHAKE_STATE_INIT) {
			kill_handshakes(ctx, peer);
			return;
		}

		handle_finish_handshake(ctx, peer, handshake);
		break;

	default:
		pr_debug(ctx, "received handshake reply with unknown type %u", handshake->type);
	}
}

static void protocol_handle_recv(fastd_context *ctx, fastd_peer *peer, fastd_buffer buffer) {
	if (!fastd_peer_is_established(peer)) {
		pr_debug(ctx, "received unexpected packet from %P", peer);

		if (fastd_peer_is_temporary(peer)) {
			pr_debug(ctx, "sending handshake to temporary peer %P", peer);
			fastd_task_schedule_handshake(ctx, peer, 0);
		}

		goto fail;
	}

	if (!peer->protocol_state || !is_session_valid(ctx, &peer->protocol_state->session))
		goto fail;

	fastd_buffer recv_buffer;
	bool ok = false;

	if (is_session_valid(ctx, &peer->protocol_state->old_session)) {
		if (ctx->conf->method->decrypt(ctx, peer->protocol_state->old_session.method_state, &recv_buffer, buffer))
			ok = true;
	}

	if (!ok) {
		if (ctx->conf->method->decrypt(ctx, peer->protocol_state->session.method_state, &recv_buffer, buffer)) {
			ok = true;

			if (!peer->protocol_state->session.handshakes_cleaned) {
				pr_debug(ctx, "cleaning left handshakes with %P", peer);
				fastd_task_delete_peer_handshakes(ctx, peer);
				peer->protocol_state->session.handshakes_cleaned = true;

				if (ctx->conf->method->session_is_initiator(ctx, peer->protocol_state->session.method_state))
					protocol_send(ctx, peer, fastd_buffer_alloc(0, ctx->conf->method->min_encrypt_head_space(ctx), 0));
			}

			if (peer->protocol_state->old_session.method_state) {
				pr_debug(ctx, "invalidating old session with %P", peer);
				ctx->conf->method->session_free(ctx, peer->protocol_state->old_session.method_state);
				peer->protocol_state->old_session.method_state = NULL;
			}

			check_session_refresh(ctx, peer);
		}
	}

	if (!ok) {
		pr_debug(ctx, "verification failed for packet received from %P", peer);
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

static void protocol_send(fastd_context *ctx, fastd_peer *peer, fastd_buffer buffer) {
	if (!peer->protocol_state || !is_session_valid(ctx, &peer->protocol_state->session))
		goto fail;

	check_session_refresh(ctx, peer);

	protocol_session *session;
	if (ctx->conf->method->session_is_initiator(ctx, peer->protocol_state->session.method_state) && is_session_valid(ctx, &peer->protocol_state->old_session)) {
		pr_debug(ctx, "sending packet for old session to %P", peer);
		session = &peer->protocol_state->old_session;
	}
	else {
		session = &peer->protocol_state->session;
	}

	fastd_buffer send_buffer;
	if (!ctx->conf->method->encrypt(ctx, session->method_state, &send_buffer, buffer))
		goto fail;
	
	fastd_send(ctx, peer, send_buffer);

	fastd_task_delete_peer_keepalives(ctx, peer);
	fastd_task_schedule_keepalive(ctx, peer, ctx->conf->keepalive_interval*1000);
	return;

 fail:
	fastd_buffer_free(buffer);
}

static void protocol_free_peer_state(fastd_context *ctx, fastd_peer *peer) {
	if (peer->protocol_state) {
		free_handshake(peer->protocol_state->initiating_handshake);
		free_handshake(peer->protocol_state->accepting_handshake);

		ctx->conf->method->session_free(ctx, peer->protocol_state->old_session.method_state);
		ctx->conf->method->session_free(ctx, peer->protocol_state->session.method_state);

		free(peer->protocol_state);
	}
}


static void hexdump(const char *desc, unsigned char d[32]) {
	printf("%s", desc);

	int i;
	for (i = 0; i < 32; i++)
		printf("%02x", d[i]);

	printf("\n");
}

static void protocol_generate_key(fastd_context *ctx) {
	ecc_secret_key_256 secret_key;
	ecc_public_key_256 public_key;

	pr_info(ctx, "Reading 32 bytes from /dev/random...");

	fastd_random_bytes(ctx, secret_key.s, 32, true);
	ecc_25519_secret_sanitize(&secret_key, &secret_key);

	ecc_25519_work work;
	ecc_25519_scalarmult_base(&work, &secret_key);
	ecc_25519_store(&public_key, &work);

	hexdump("Secret: ", secret_key.s);
	hexdump("Public: ", public_key.p);
}


const fastd_protocol fastd_protocol_ec25519_fhmqvc = {
	.name = "ec25519-fhmqvc",

	.init = protocol_init,
	.peer_configure = protocol_peer_configure,
	.peer_config_purged = protocol_peer_config_purged,

	.handshake_init = protocol_handshake_init,
	.handshake_handle = protocol_handshake_handle,

	.handle_recv = protocol_handle_recv,
	.send = protocol_send,

	.free_peer_state = protocol_free_peer_state,

	.generate_key = protocol_generate_key,
};
