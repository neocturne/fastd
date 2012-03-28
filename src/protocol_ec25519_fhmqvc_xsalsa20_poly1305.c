/*
  Copyright (c) 2012, Matthias Schiffer <mschiffer@universe-factory.net>
  Partly based on QuickTun Copyright (c) 2010, Ivo Smits <Ivo@UCIS.nl>.
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
#include "peer.h"
#include "task.h"

#include <arpa/inet.h>

#include <libuecc/ecc.h>
#include <crypto_auth_hmacsha256.h>
#include <crypto_hash_sha256.h>
#include <crypto_secretbox_xsalsa20poly1305.h>


#define NONCEBYTES 7
#define PUBLICKEYBYTES 32
#define SECRETKEYBYTES 32
#define HMACBYTES crypto_auth_hmacsha256_BYTES
#define HASHBYTES crypto_hash_sha256_BYTES


#if HASHBYTES != crypto_auth_hmacsha256_KEYBYTES
#error bug: HASHBYTES != crypto_auth_hmacsha256_KEYBYTES
#endif

#if HASHBYTES != crypto_secretbox_xsalsa20poly1305_KEYBYTES
#error bug: HASHBYTES != crypto_secretbox_xsalsa20poly1305_KEYBYTES
#endif

#if HASHBYTES != SECRETKEYBYTES
#error bug: HASHBYTES != SECRETKEYBYTES
#endif

#if crypto_secretbox_xsalsa20poly1305_BOXZEROBYTES < NONCEBYTES
#error bug: crypto_secretbox_xsalsa20poly1305_BOXZEROBYTES < NONCEBYTES
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
	bool valid;
	uint8_t key[HASHBYTES];
	struct timespec since;

	uint8_t send_nonce[NONCEBYTES];
	uint8_t receive_nonce[NONCEBYTES];
} protocol_session;

struct _fastd_protocol_peer_state {
	protocol_session old_session;
	protocol_session session;

	protocol_handshake *initiating_handshake;
	protocol_handshake *accepting_handshake;
};

typedef enum _handshake_packet_type {
	HANDSHAKE_PACKET_INIT = 0,
	HANDSHAKE_PACKET_RESPONSE,
	HANDSHAKE_PACKET_FINISH
} handshake_packet_type;


typedef struct __attribute__ ((__packed__)) _protocol_handshake_packet_common {
	uint8_t noncepad[NONCEBYTES];
	uint8_t type;

	uint8_t sender_key[PUBLICKEYBYTES];
	uint8_t receipient_key[PUBLICKEYBYTES];
} protocol_handshake_packet_common;

typedef struct __attribute__ ((__packed__)) _protocol_handshake_init_packet {
	protocol_handshake_packet_common common;
	uint8_t handshake_key[PUBLICKEYBYTES];
} protocol_handshake_init_packet;

typedef struct __attribute__ ((__packed__)) _protocol_handshake_response_finish_packet {
	protocol_handshake_packet_common common;
	uint8_t handshake_key[PUBLICKEYBYTES];
	uint8_t handshake_key2[PUBLICKEYBYTES];
	uint8_t t[HMACBYTES];
} protocol_handshake_response_packet, protocol_handshake_finish_packet;

typedef union _protocol_handshake_packet {
	protocol_handshake_packet_common common;
	protocol_handshake_init_packet init;
	protocol_handshake_response_packet response;
	protocol_handshake_finish_packet finish;
} protocol_handshake_packet;


static inline bool read_key(uint8_t key[32], const char *hexkey) {
	if ((strlen(hexkey) != 64) || (strspn(hexkey, "0123456789abcdefABCDEF") != 64))
		return false;

	int i;
	for (i = 0; i < 32; i++)
		sscanf(&hexkey[2*i], "%02hhx", &key[i]);

	return true;
}

static inline bool is_nonce_zero(const uint8_t nonce[NONCEBYTES]) {
	int i;
	for (i = 0; i < NONCEBYTES; i++) {
		if (nonce[i] != 0)
			return false;
	}

	return true;
}

static inline void increment_nonce(uint8_t nonce[NONCEBYTES]) {
	nonce[0] += 2;

	if (nonce[0] == 0 || nonce[0] == 1) {
		int i;
		for (i = 1; i < NONCEBYTES; i++) {
			nonce[i]++;
			if (nonce[i] != 0)
				break;
		}
	}
}

static inline bool is_nonce_valid(const uint8_t nonce[NONCEBYTES], const uint8_t old_nonce[NONCEBYTES]) {
	if ((nonce[0] & 1) != (old_nonce[0] & 1))
		return false;

	int i;
	for (i = NONCEBYTES-1; i >= 0; i--) {
		if (nonce[i] > old_nonce[i])
			return true;
		if (nonce[i] < old_nonce[i])
			return false;
	}

	return false;
}

static void protocol_init(fastd_context *ctx, fastd_config *conf) {
	conf->protocol_config = malloc(sizeof(fastd_protocol_config));

	if (!conf->secret)
		exit_error(ctx, "no secret key configured");

	if (!read_key(conf->protocol_config->secret_key.s, conf->secret))
		exit_error(ctx, "invalid secret key");

	ecc_25519_work work;
	ecc_25519_scalarmult_base(&work, &conf->protocol_config->secret_key);
	ecc_25519_store(&conf->protocol_config->public_key, &work);

	fastd_peer_config *peer;
	for (peer = conf->peers; peer; peer = peer->next) {
		ecc_public_key_256 key;

		if (!peer->key) {
			pr_warn(ctx, "no key configured for %P, disabling peer", peer);
			peer->enabled = false;
			continue;
		}

		if (!read_key(key.p, peer->key)) {
			pr_warn(ctx, "invalid key configured for %P, disabling peer", peer);
			peer->enabled = false;
			continue;
		}

		peer->protocol_config = malloc(sizeof(fastd_protocol_peer_config));
		peer->protocol_config->public_key = key;
	}
}

static size_t protocol_max_packet_size(fastd_context *ctx) {
	return (fastd_max_packet_size(ctx) + NONCEBYTES);
}

static size_t protocol_min_encrypt_head_space(fastd_context *ctx) {
	return crypto_secretbox_xsalsa20poly1305_ZEROBYTES;
}

static size_t protocol_min_decrypt_head_space(fastd_context *ctx) {
	return (crypto_secretbox_xsalsa20poly1305_BOXZEROBYTES - NONCEBYTES);
}

static void create_peer_state(fastd_context *ctx, fastd_peer *peer) {
	peer->protocol_state = malloc(sizeof(fastd_protocol_peer_state));

	peer->protocol_state->old_session.valid = false;
	peer->protocol_state->session.valid = false;
	peer->protocol_state->initiating_handshake = NULL;
	peer->protocol_state->accepting_handshake = NULL;
}

static inline void free_handshake(protocol_handshake *handshake) {
	if (handshake) {
		memset(handshake, 0, sizeof(protocol_handshake));
		free(handshake);
	}
}

static void new_handshake(fastd_context *ctx, fastd_peer *peer, const fastd_peer_config *peer_config, bool initiate) {
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
}

static void protocol_init_peer(fastd_context *ctx, fastd_peer *peer) {
	pr_info(ctx, "Initializing session with %P...", peer);

	if (peer->protocol_state) {
		pr_warn(ctx, "trying to reinitialize session with %P", peer);
		return;
	}

	if (fastd_peer_is_temporary(peer)) {
		pr_warn(ctx, "trying to initialize session for temporary peer %P", peer);
		return;
	}

	create_peer_state(ctx, peer);

	new_handshake(ctx, peer, peer->config, true);

	fastd_buffer buffer = fastd_buffer_alloc(sizeof(protocol_handshake_init_packet), 0, 0);
	protocol_handshake_init_packet *packet = buffer.data;

	memset(packet->common.noncepad, 0, NONCEBYTES);
	packet->common.type = HANDSHAKE_PACKET_INIT;
	memcpy(packet->common.sender_key, ctx->conf->protocol_config->public_key.p, PUBLICKEYBYTES);
	memcpy(packet->common.receipient_key, peer->protocol_state->initiating_handshake->peer_config->protocol_config->public_key.p, PUBLICKEYBYTES);
	memcpy(packet->handshake_key, peer->protocol_state->initiating_handshake->public_key.p, PUBLICKEYBYTES);

	fastd_task_put_send(ctx, peer, buffer);
}

static void respond_handshake(fastd_context *ctx, fastd_peer *peer) {
	pr_info(ctx, "Responding protocol handshake with %P...", peer);

	uint8_t hashinput[5*PUBLICKEYBYTES];
	uint8_t hashbuf[HASHBYTES];

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

	ecc_25519_store(&peer->protocol_state->accepting_handshake->sigma, &work);

	memcpy(hashinput+4*PUBLICKEYBYTES, peer->protocol_state->accepting_handshake->sigma.p, PUBLICKEYBYTES);
	crypto_hash_sha256(peer->protocol_state->accepting_handshake->shared_handshake_key, hashinput, 5*PUBLICKEYBYTES);

	memcpy(hashinput, ctx->conf->protocol_config->public_key.p, PUBLICKEYBYTES);
	memcpy(hashinput+PUBLICKEYBYTES, peer->protocol_state->accepting_handshake->public_key.p, PUBLICKEYBYTES);

	fastd_buffer buffer = fastd_buffer_alloc(sizeof(protocol_handshake_response_packet), 0, 0);
	protocol_handshake_response_packet *packet = buffer.data;

	memset(packet->common.noncepad, 0, NONCEBYTES);
	packet->common.type = HANDSHAKE_PACKET_RESPONSE;
	memcpy(packet->common.sender_key, ctx->conf->protocol_config->public_key.p, PUBLICKEYBYTES);
	memcpy(packet->common.receipient_key, peer->protocol_state->accepting_handshake->peer_config->protocol_config->public_key.p, PUBLICKEYBYTES);
	memcpy(packet->handshake_key, peer->protocol_state->accepting_handshake->peer_key.p, PUBLICKEYBYTES);
	memcpy(packet->handshake_key2, peer->protocol_state->accepting_handshake->public_key.p, PUBLICKEYBYTES);

	crypto_auth_hmacsha256(packet->t, hashinput, 2*PUBLICKEYBYTES, peer->protocol_state->accepting_handshake->shared_handshake_key);

	fastd_task_put_send(ctx, peer, buffer);

	peer->protocol_state->accepting_handshake->state = HANDSHAKE_STATE_RESPONSE;
}

static void establish(fastd_context *ctx, fastd_peer *peer, const fastd_peer_config *peer_config, bool initiator) {
	int i;

	peer->protocol_state->session.valid = true;
	peer->protocol_state->session.since = ctx->now;

	peer->protocol_state->session.send_nonce[0] = initiator ? 3 : 2;
	peer->protocol_state->session.receive_nonce[0] = initiator ? 0 : 1;
	for (i = 1; i < NONCEBYTES; i++) {
		peer->protocol_state->session.send_nonce[i] = 0;
		peer->protocol_state->session.receive_nonce[i] = 0;
	}

	pr_info(ctx, "Connection with %P established.", peer);

	if (peer_config != peer->config) {
		fastd_peer *perm_peer;
		for (perm_peer = ctx->peers; perm_peer; perm_peer = perm_peer->next) {
			if (perm_peer->config == peer_config) {
				fastd_peer_merge(ctx, perm_peer, peer);
				break;
			}
		}
	}
}

static void finish_handshake(fastd_context *ctx, fastd_peer *peer, uint8_t t[HMACBYTES]) {
	pr_info(ctx, "Finishing protocol handshake with %P...", peer);

	uint8_t hashinput[5*PUBLICKEYBYTES];
	uint8_t hashbuf[HASHBYTES];

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

	ecc_25519_store(&peer->protocol_state->initiating_handshake->sigma, &work);

	memcpy(hashinput+4*PUBLICKEYBYTES, peer->protocol_state->initiating_handshake->sigma.p, PUBLICKEYBYTES);
	crypto_hash_sha256(peer->protocol_state->initiating_handshake->shared_handshake_key, hashinput, 5*PUBLICKEYBYTES);

	memcpy(hashinput, peer->protocol_state->initiating_handshake->peer_config->protocol_config->public_key.p, PUBLICKEYBYTES);
	memcpy(hashinput+PUBLICKEYBYTES, peer->protocol_state->initiating_handshake->peer_key.p, PUBLICKEYBYTES);

	if(crypto_auth_hmacsha256_verify(t, hashinput, 2*PUBLICKEYBYTES, peer->protocol_state->initiating_handshake->shared_handshake_key) != 0) {
		pr_warn(ctx, "received invalid protocol handshake response from %P", peer);
		return;
	}

	memcpy(hashinput, ctx->conf->protocol_config->public_key.p, PUBLICKEYBYTES);
	memcpy(hashinput+PUBLICKEYBYTES, peer->protocol_state->initiating_handshake->public_key.p, PUBLICKEYBYTES);

	fastd_buffer buffer = fastd_buffer_alloc(sizeof(protocol_handshake_finish_packet), 0, 0);
	protocol_handshake_finish_packet *packet = buffer.data;

	memset(packet->common.noncepad, 0, NONCEBYTES);
	packet->common.type = HANDSHAKE_PACKET_FINISH;
	memcpy(packet->common.sender_key, ctx->conf->protocol_config->public_key.p, PUBLICKEYBYTES);
	memcpy(packet->common.receipient_key, peer->protocol_state->initiating_handshake->peer_config->protocol_config->public_key.p, PUBLICKEYBYTES);
	memcpy(packet->handshake_key, peer->protocol_state->initiating_handshake->peer_key.p, PUBLICKEYBYTES);
	memcpy(packet->handshake_key2, peer->protocol_state->initiating_handshake->public_key.p, PUBLICKEYBYTES);

	crypto_auth_hmacsha256(packet->t, hashinput, 2*PUBLICKEYBYTES, peer->protocol_state->initiating_handshake->shared_handshake_key);

	fastd_task_put_send(ctx, peer, buffer);

	if (peer->protocol_state->session.valid)
		peer->protocol_state->old_session = peer->protocol_state->session;

	memcpy(hashinput, peer->protocol_state->initiating_handshake->public_key.p, PUBLICKEYBYTES);
	memcpy(hashinput+PUBLICKEYBYTES, peer->protocol_state->initiating_handshake->peer_key.p, PUBLICKEYBYTES);
	memcpy(hashinput+2*PUBLICKEYBYTES, ctx->conf->protocol_config->public_key.p, PUBLICKEYBYTES);
	memcpy(hashinput+3*PUBLICKEYBYTES, peer->protocol_state->initiating_handshake->peer_config->protocol_config->public_key.p, PUBLICKEYBYTES);
	memcpy(hashinput+4*PUBLICKEYBYTES, peer->protocol_state->initiating_handshake->sigma.p, PUBLICKEYBYTES);
	crypto_hash_sha256(peer->protocol_state->session.key, hashinput, 5*PUBLICKEYBYTES);

	establish(ctx, peer, peer->protocol_state->initiating_handshake->peer_config, true);
}

static void handle_finish_handshake(fastd_context *ctx, fastd_peer *peer, uint8_t t[HMACBYTES]) {
	uint8_t hashinput[5*PUBLICKEYBYTES];

	memcpy(hashinput, peer->protocol_state->accepting_handshake->peer_config->protocol_config->public_key.p, PUBLICKEYBYTES);
	memcpy(hashinput+PUBLICKEYBYTES, peer->protocol_state->accepting_handshake->peer_key.p, PUBLICKEYBYTES);

	if(crypto_auth_hmacsha256_verify(t, hashinput, 2*PUBLICKEYBYTES, peer->protocol_state->accepting_handshake->shared_handshake_key) != 0) {
		pr_warn(ctx, "received invalid protocol handshake finish from %P", peer);
		return;
	}

	if (peer->protocol_state->session.valid)
		peer->protocol_state->old_session = peer->protocol_state->session;

	memcpy(hashinput, peer->protocol_state->accepting_handshake->peer_key.p, PUBLICKEYBYTES);
	memcpy(hashinput+PUBLICKEYBYTES, peer->protocol_state->accepting_handshake->public_key.p, PUBLICKEYBYTES);
	memcpy(hashinput+2*PUBLICKEYBYTES, peer->protocol_state->accepting_handshake->peer_config->protocol_config->public_key.p, PUBLICKEYBYTES);
	memcpy(hashinput+3*PUBLICKEYBYTES, ctx->conf->protocol_config->public_key.p, PUBLICKEYBYTES);
	memcpy(hashinput+4*PUBLICKEYBYTES, peer->protocol_state->accepting_handshake->sigma.p, PUBLICKEYBYTES);
	crypto_hash_sha256(peer->protocol_state->session.key, hashinput, 5*PUBLICKEYBYTES);

	establish(ctx, peer, peer->protocol_state->accepting_handshake->peer_config, false);
}

static inline const fastd_peer_config* match_sender_key(fastd_context *ctx, const fastd_peer *peer, const protocol_handshake_packet *packet) {
	if (peer->config) {
		if (memcmp(peer->config->protocol_config->public_key.p, packet->common.sender_key, PUBLICKEYBYTES) == 0)
			return peer->config;
	}

	if (fastd_peer_is_temporary(peer) || fastd_peer_is_floating(peer)) {
		fastd_peer_config *config;
		for (config = ctx->conf->peers; config; config = config->next) {
			if (!fastd_peer_config_is_floating(config))
				continue;

		if (memcmp(config->protocol_config->public_key.p, packet->common.sender_key, PUBLICKEYBYTES) == 0)
			return config;
		}
	}

	return NULL;
}

static void protocol_handle_recv(fastd_context *ctx, fastd_peer *peer, fastd_buffer buffer) {
	if (buffer.len < NONCEBYTES)
		goto end;

	/* protocol handshake */
	if (is_nonce_zero(buffer.data)) {
		if (buffer.len < sizeof(protocol_handshake_packet_common)) {
			pr_debug(ctx, "received short protocol handshake from %P", peer);
			goto end;
		}

		protocol_handshake_packet *packet = buffer.data;

		if (!peer->protocol_state)
			create_peer_state(ctx, peer);

		if (memcmp(ctx->conf->protocol_config->public_key.p, packet->common.receipient_key, PUBLICKEYBYTES) != 0) {
			pr_debug(ctx, "received protocol handshake with wrong receipient key from %P", peer);
			goto end;
		}

		const fastd_peer_config *peer_config = match_sender_key(ctx, peer, packet);

		switch (packet->common.type) {
		case HANDSHAKE_PACKET_INIT:
			if (buffer.len < sizeof(protocol_handshake_init_packet)) {
				pr_debug(ctx, "received short protocol handshake init from %P", peer);
				goto end;
			}

			if (!peer_config) {
				pr_debug(ctx, "received protocol handshake init with wrong sender key from %P", peer);
				goto end;
			}

			pr_debug(ctx, "received protocol handshake init from %P", peer);

			new_handshake(ctx, peer, peer_config, false);
			memcpy(peer->protocol_state->accepting_handshake->peer_key.p, packet->init.handshake_key, PUBLICKEYBYTES);

			fastd_peer_set_established(peer);
			respond_handshake(ctx, peer);

			break;

		case HANDSHAKE_PACKET_RESPONSE:
			if (buffer.len < sizeof(protocol_handshake_response_packet)) {
				pr_debug(ctx, "received short protocol handshake response from %P", peer);
				goto end;
			}

			if (!peer->protocol_state->initiating_handshake || peer->protocol_state->initiating_handshake->state != HANDSHAKE_STATE_INIT) {
				pr_debug(ctx, "received unexpected protocol handshake response from %P", peer);
				goto end;
			}

			if (peer->protocol_state->initiating_handshake->peer_config != peer_config) {
				pr_debug(ctx, "received protocol handshake response with wrong sender key from %P", peer);
				goto end;
			}

			if (memcmp(peer->protocol_state->initiating_handshake->public_key.p, packet->response.handshake_key, PUBLICKEYBYTES) != 0) {
				pr_debug(ctx, "received protocol handshake response with unexpected handshake key from %P", peer);
				goto end;
			}

			pr_debug(ctx, "received protocol handshake response from %P", peer);
			memcpy(peer->protocol_state->initiating_handshake->peer_key.p, packet->response.handshake_key2, PUBLICKEYBYTES);

			finish_handshake(ctx, peer, packet->response.t);

			break;

		case HANDSHAKE_PACKET_FINISH:
			if (buffer.len < sizeof(protocol_handshake_finish_packet)) {
				pr_debug(ctx, "received short protocol handshake finish from %P", peer);
				goto end;
			}

			if (!peer->protocol_state->accepting_handshake || peer->protocol_state->accepting_handshake->state != HANDSHAKE_STATE_RESPONSE) {
				pr_debug(ctx, "received unexpected protocol handshake finish from %P", peer);
				goto end;
			}

			if (peer->protocol_state->accepting_handshake->peer_config != peer_config) {
				pr_debug(ctx, "received protocol handshake finish with wrong sender key from %P", peer);
				goto end;
			}

			if (memcmp(peer->protocol_state->accepting_handshake->public_key.p, packet->finish.handshake_key, PUBLICKEYBYTES) != 0) {
				pr_debug(ctx, "received protocol handshake finish with unexpected handshake key from %P", peer);
				goto end;
			}

			if (memcmp(peer->protocol_state->accepting_handshake->peer_key.p, packet->finish.handshake_key2, PUBLICKEYBYTES) != 0) {
				pr_debug(ctx, "received protocol handshake finish with unexpected peer handshake key from %P", peer);
				goto end;
			}



			pr_debug(ctx, "received protocol handshake finish from %P", peer);

			handle_finish_handshake(ctx, peer, packet->finish.t);
			break;

		default:
			pr_debug(ctx, "received protocol handshake with invalid type from %P", peer);
			goto end;
		}
	}
	else {
		if (!peer->protocol_state || !peer->protocol_state->session.valid) {
			pr_debug(ctx, "received unexpected non-handshake packet from %P", peer);
			goto end;
		}

		if (!is_nonce_valid(buffer.data, peer->protocol_state->session.receive_nonce)) {
			pr_debug(ctx, "received packet with invalid nonce from %P", peer);
			goto end;
		}

		uint8_t nonce[crypto_secretbox_xsalsa20poly1305_NONCEBYTES];
		memcpy(nonce, buffer.data, NONCEBYTES);
		memset(nonce+NONCEBYTES, 0, crypto_secretbox_xsalsa20poly1305_NONCEBYTES-NONCEBYTES);

		fastd_buffer_pull_head(&buffer, crypto_secretbox_xsalsa20poly1305_BOXZEROBYTES-NONCEBYTES);
		memset(buffer.data, 0, crypto_secretbox_xsalsa20poly1305_BOXZEROBYTES);

		fastd_buffer recv_buffer = fastd_buffer_alloc(buffer.len, 0, 0);

		if (crypto_secretbox_xsalsa20poly1305_open(recv_buffer.data, buffer.data, buffer.len, nonce, peer->protocol_state->session.key) != 0) {
			pr_debug(ctx, "verification failed for packet received from %P", peer);
			fastd_buffer_free(recv_buffer);
			goto end;
		}

		fastd_buffer_push_head(&recv_buffer, crypto_secretbox_xsalsa20poly1305_ZEROBYTES);
		fastd_task_put_handle_recv(ctx, peer, recv_buffer);

		memcpy(peer->protocol_state->session.receive_nonce, nonce, NONCEBYTES);
	}

 end:
	fastd_buffer_free(buffer);
}

static void protocol_send(fastd_context *ctx, fastd_peer *peer, fastd_buffer buffer) {
	if (!peer->protocol_state || !peer->protocol_state->session.valid) {
		fastd_buffer_free(buffer);
		return;
	}

	fastd_buffer_pull_head(&buffer, crypto_secretbox_xsalsa20poly1305_ZEROBYTES);
	memset(buffer.data, 0, crypto_secretbox_xsalsa20poly1305_ZEROBYTES);

	fastd_buffer send_buffer = fastd_buffer_alloc(buffer.len, 0, 0);

	uint8_t nonce[crypto_secretbox_xsalsa20poly1305_NONCEBYTES];
	memcpy(nonce, peer->protocol_state->session.send_nonce, NONCEBYTES);
	memset(nonce+NONCEBYTES, 0, crypto_secretbox_xsalsa20poly1305_NONCEBYTES-NONCEBYTES);

	crypto_secretbox_xsalsa20poly1305(send_buffer.data, buffer.data, buffer.len, nonce, peer->protocol_state->session.key);

	fastd_buffer_free(buffer);

	fastd_buffer_push_head(&send_buffer, crypto_secretbox_xsalsa20poly1305_BOXZEROBYTES-NONCEBYTES);
	memcpy(send_buffer.data, peer->protocol_state->session.send_nonce, NONCEBYTES);

	fastd_task_put_send(ctx, peer, send_buffer);

	increment_nonce(peer->protocol_state->session.send_nonce);
}

static void protocol_free_peer_state(fastd_context *ctx, fastd_peer *peer) {
	if (peer->protocol_state) {
		free_handshake(peer->protocol_state->initiating_handshake);
		free_handshake(peer->protocol_state->accepting_handshake);

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


const fastd_protocol fastd_protocol_ec25519_fhmqvc_xsalsa20_poly1305 = {
	.name = "ec25519-fhmqvc-xsalsa20-poly1305",

	.init = protocol_init,

	.max_packet_size = protocol_max_packet_size,
	.min_encrypt_head_space = protocol_min_encrypt_head_space,
	.min_decrypt_head_space = protocol_min_decrypt_head_space,

	.init_peer = protocol_init_peer,
	.handle_recv = protocol_handle_recv,
	.send = protocol_send,

	.free_peer_state = protocol_free_peer_state,

	.generate_key = protocol_generate_key,
};
