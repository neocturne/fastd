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


#define NONCEBYTES crypto_secretbox_xsalsa20poly1305_NONCEBYTES
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


struct _fastd_protocol_context {
	ecc_secret_key_256 secret_key;
	ecc_public_key_256 public_key;
};

typedef enum _handshake_state {
	HANDSHAKE_STATE_INIT = 0,
	HANDSHAKE_STATE_RESPONSE,
	HANDSHAKE_STATE_FINISH,
	HANDSHAKE_STATE_ESTABLISHED
} handshake_state;

struct _fastd_protocol_peer_state {
	ecc_public_key_256 peer_public_key;

	handshake_state state;
	ecc_secret_key_256 handshake_secret_key;
	ecc_public_key_256 handshake_public_key;
	ecc_public_key_256 peer_handshake_key;
	ecc_public_key_256 sigma;

	uint8_t shared_handshake_key[HASHBYTES];
	uint8_t shared_session_key[HASHBYTES];
	uint8_t send_nonce[NONCEBYTES];
	uint8_t receive_nonce[NONCEBYTES];
};

typedef enum _handshake_packet_type {
	HANDSHAKE_PACKET_INIT = 0,
	HANDSHAKE_PACKET_RESPONSE,
	HANDSHAKE_PACKET_FINISH
} handshake_packet_type;

typedef struct __attribute__ ((__packed__)) _protocol_handshake_init_packet {
	uint8_t noncepad[NONCEBYTES];
	uint8_t type;

	uint8_t sender_key[PUBLICKEYBYTES];
	uint8_t receipient_key[PUBLICKEYBYTES];
	uint8_t handshake_key[PUBLICKEYBYTES];
} protocol_handshake_init_packet;

typedef struct __attribute__ ((__packed__)) _protocol_handshake_response_finish_packet {
	uint8_t noncepad[NONCEBYTES];
	uint8_t type;

	uint8_t sender_key[PUBLICKEYBYTES];
	uint8_t receipient_key[PUBLICKEYBYTES];
	uint8_t handshake_key[PUBLICKEYBYTES];
	uint8_t handshake_key2[PUBLICKEYBYTES];
	uint8_t t[HMACBYTES];
} protocol_handshake_response_packet, protocol_handshake_finish_packet;

typedef union _protocol_handshake_packet {
	struct {
		uint8_t noncepad[NONCEBYTES];
		uint8_t type;
	};
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

static void protocol_init(fastd_context *ctx) {
	ctx->protocol_context = malloc(sizeof(fastd_protocol_context));

	if (!ctx->conf->secret)
		exit_error(ctx, "no secret key configured");

	if (!read_key(ctx->protocol_context->secret_key.s, ctx->conf->secret))
		exit_error(ctx, "invalid secret key");

	ecc_25519_work work;
	ecc_25519_scalarmult_base(&work, &ctx->protocol_context->secret_key);
	ecc_25519_store(&ctx->protocol_context->public_key, &work);
}

static size_t protocol_max_packet_size(fastd_context *ctx) {
	return (fastd_max_packet_size(ctx) - NONCEBYTES);
}

static char* protocol_peer_str(const fastd_context *ctx, const fastd_peer *peer) {
	char addr_buf[INET6_ADDRSTRLEN] = "";
	char *ret;

	const char *temp = fastd_peer_is_temporary(peer) ? " (temporary)" : "";

	switch (peer->address.sa.sa_family) {
	case AF_UNSPEC:
		if (asprintf(&ret, "<floating>%s", temp) > 0)
			return ret;
		break;

	case AF_INET:
		if (inet_ntop(AF_INET, &peer->address.in.sin_addr, addr_buf, sizeof(addr_buf))) {
			if (asprintf(&ret, "%s:%u%s", addr_buf, ntohs(peer->address.in.sin_port), temp) > 0)
				return ret;
		}
		break;

	case AF_INET6:
		if (inet_ntop(AF_INET6, &peer->address.in6.sin6_addr, addr_buf, sizeof(addr_buf))) {
			if (asprintf(&ret, "[%s]:%u%s", addr_buf, ntohs(peer->address.in6.sin6_port), temp) > 0)
				return ret;
		}
		break;

	default:
		exit_bug(ctx, "unsupported address family");
	}

	return NULL;
}

static bool create_peer_state(fastd_context *ctx, fastd_peer *peer) {
	peer->protocol_state = malloc(sizeof(fastd_protocol_peer_state));

	if (!peer->config->key) {
		pr_warn(ctx, "no public key configured - ignoring peer %P", peer);
		return false;
	}

	if (!read_key(peer->protocol_state->peer_public_key.p, peer->config->key)) {
		pr_warn(ctx, "invalid public key configured - ignoring peer %P", peer);
		return false;
	}

	peer->protocol_state->state = HANDSHAKE_STATE_INIT;

	return true;
}

static void protocol_init_peer(fastd_context *ctx, fastd_peer *peer) {
	pr_info(ctx, "Initializing session with %P...", peer);

	if (peer->protocol_state) {
		pr_warn(ctx, "trying to reinitialize session with %P", peer);
		return;
	}

	if (!create_peer_state(ctx, peer))
		return; /* TODO disable peer */

	fastd_random_bytes(ctx, peer->protocol_state->handshake_secret_key.s, 32, false);
	ecc_25519_secret_sanitize(&peer->protocol_state->handshake_secret_key, &peer->protocol_state->handshake_secret_key);

	ecc_25519_work work;
	ecc_25519_scalarmult_base(&work, &peer->protocol_state->handshake_secret_key);
	ecc_25519_store(&peer->protocol_state->handshake_public_key, &work);

	fastd_buffer buffer = fastd_buffer_alloc(sizeof(protocol_handshake_init_packet), 0, 0);
	protocol_handshake_init_packet *packet = buffer.data;

	memset(packet->noncepad, 0, NONCEBYTES);
	packet->type = HANDSHAKE_PACKET_INIT;
	memcpy(packet->sender_key, ctx->protocol_context->public_key.p, PUBLICKEYBYTES);
	memcpy(packet->receipient_key, peer->protocol_state->peer_public_key.p, PUBLICKEYBYTES);
	memcpy(packet->handshake_key, peer->protocol_state->handshake_public_key.p, PUBLICKEYBYTES);

	fastd_task_put_send(ctx, peer, buffer);
}

static void respond_handshake(fastd_context *ctx, fastd_peer *peer) {
	pr_info(ctx, "Responding protocol handshake with %P...", peer);

	fastd_random_bytes(ctx, peer->protocol_state->handshake_secret_key.s, 32, false);
	ecc_25519_secret_sanitize(&peer->protocol_state->handshake_secret_key, &peer->protocol_state->handshake_secret_key);

	ecc_25519_work work;
	ecc_25519_scalarmult_base(&work, &peer->protocol_state->handshake_secret_key);
	ecc_25519_store(&peer->protocol_state->handshake_public_key, &work);

	uint8_t hashinput[5*PUBLICKEYBYTES];
	uint8_t hashbuf[HASHBYTES];

	memcpy(hashinput, peer->protocol_state->handshake_public_key.p, PUBLICKEYBYTES);
	memcpy(hashinput+PUBLICKEYBYTES, peer->protocol_state->peer_handshake_key.p, PUBLICKEYBYTES);
	memcpy(hashinput+2*PUBLICKEYBYTES, ctx->protocol_context->public_key.p, PUBLICKEYBYTES);
	memcpy(hashinput+3*PUBLICKEYBYTES, peer->protocol_state->peer_public_key.p, PUBLICKEYBYTES);

	crypto_hash_sha256(hashbuf, hashinput, 4*PUBLICKEYBYTES);

	ecc_secret_key_256 d = {{0}}, e = {{0}}, eb, s;

	memcpy(d.s, hashbuf, HASHBYTES/2);
	memcpy(e.s, hashbuf+HASHBYTES/2, HASHBYTES/2);

	d.s[15] |= 0x80;
	e.s[15] |= 0x80;

	ecc_25519_secret_mult(&eb, &e, &ctx->protocol_context->secret_key);
	ecc_25519_secret_add(&s, &eb, &peer->protocol_state->handshake_secret_key);

	ecc_25519_work workX;
	ecc_25519_load(&work, &peer->protocol_state->peer_public_key);
	ecc_25519_load(&workX, &peer->protocol_state->peer_handshake_key);

	ecc_25519_scalarmult(&work, &d, &work);
	ecc_25519_add(&work, &workX, &work);
	ecc_25519_scalarmult(&work, &s, &work);

	ecc_25519_store(&peer->protocol_state->sigma, &work);

	memcpy(hashinput+4*PUBLICKEYBYTES, peer->protocol_state->sigma.p, PUBLICKEYBYTES);
	crypto_hash_sha256(peer->protocol_state->shared_handshake_key, hashinput, 5*PUBLICKEYBYTES);

	memcpy(hashinput, ctx->protocol_context->public_key.p, PUBLICKEYBYTES);
	memcpy(hashinput+PUBLICKEYBYTES, peer->protocol_state->handshake_public_key.p, PUBLICKEYBYTES);

	fastd_buffer buffer = fastd_buffer_alloc(sizeof(protocol_handshake_response_packet), 0, 0);
	protocol_handshake_response_packet *packet = buffer.data;

	memset(packet->noncepad, 0, NONCEBYTES);
	packet->type = HANDSHAKE_PACKET_RESPONSE;
	memcpy(packet->sender_key, ctx->protocol_context->public_key.p, PUBLICKEYBYTES);
	memcpy(packet->receipient_key, peer->protocol_state->peer_public_key.p, PUBLICKEYBYTES);
	memcpy(packet->handshake_key, peer->protocol_state->peer_handshake_key.p, PUBLICKEYBYTES);
	memcpy(packet->handshake_key2, peer->protocol_state->handshake_public_key.p, PUBLICKEYBYTES);

	crypto_auth_hmacsha256(packet->t, hashinput, 2*PUBLICKEYBYTES, peer->protocol_state->shared_handshake_key);

	fastd_task_put_send(ctx, peer, buffer);

	peer->protocol_state->state = HANDSHAKE_STATE_RESPONSE;
}

static void establish(fastd_context *ctx, fastd_peer *peer, bool initiator) {
	peer->protocol_state->state = HANDSHAKE_STATE_ESTABLISHED;

	int i;

	peer->protocol_state->send_nonce[0] = initiator ? 3 : 2;
	peer->protocol_state->receive_nonce[0] = initiator ? 0 : 1;
	for (i = 1; i < NONCEBYTES; i++) {
		peer->protocol_state->send_nonce[i] = 0;
		peer->protocol_state->receive_nonce[i] = 0;
	}

	pr_info(ctx, "Connection with %P established.", peer);
}

static void finish_handshake(fastd_context *ctx, fastd_peer *peer, uint8_t t[HMACBYTES]) {
	pr_info(ctx, "Finishing protocol handshake with %P...", peer);

	uint8_t hashinput[5*PUBLICKEYBYTES];
	uint8_t hashbuf[HASHBYTES];

	memcpy(hashinput, peer->protocol_state->peer_handshake_key.p, PUBLICKEYBYTES);
	memcpy(hashinput+PUBLICKEYBYTES, peer->protocol_state->handshake_public_key.p, PUBLICKEYBYTES);
	memcpy(hashinput+2*PUBLICKEYBYTES, peer->protocol_state->peer_public_key.p, PUBLICKEYBYTES);
	memcpy(hashinput+3*PUBLICKEYBYTES, ctx->protocol_context->public_key.p, PUBLICKEYBYTES);

	crypto_hash_sha256(hashbuf, hashinput, 4*PUBLICKEYBYTES);

	ecc_secret_key_256 d = {{0}}, e = {{0}}, da, s;

	memcpy(d.s, hashbuf, HASHBYTES/2);
	memcpy(e.s, hashbuf+HASHBYTES/2, HASHBYTES/2);

	d.s[15] |= 0x80;
	e.s[15] |= 0x80;

	ecc_25519_secret_mult(&da, &d, &ctx->protocol_context->secret_key);
	ecc_25519_secret_add(&s, &da, &peer->protocol_state->handshake_secret_key);

	ecc_25519_work work, workY;
	ecc_25519_load(&work, &peer->protocol_state->peer_public_key);
	ecc_25519_load(&workY, &peer->protocol_state->peer_handshake_key);

	ecc_25519_scalarmult(&work, &e, &work);
	ecc_25519_add(&work, &workY, &work);
	ecc_25519_scalarmult(&work, &s, &work);

	ecc_25519_store(&peer->protocol_state->sigma, &work);

	memcpy(hashinput+4*PUBLICKEYBYTES, peer->protocol_state->sigma.p, PUBLICKEYBYTES);
	crypto_hash_sha256(peer->protocol_state->shared_handshake_key, hashinput, 5*PUBLICKEYBYTES);

	memcpy(hashinput, peer->protocol_state->peer_public_key.p, PUBLICKEYBYTES);
	memcpy(hashinput+PUBLICKEYBYTES, peer->protocol_state->peer_handshake_key.p, PUBLICKEYBYTES);

	if(crypto_auth_hmacsha256_verify(t, hashinput, 2*PUBLICKEYBYTES, peer->protocol_state->shared_handshake_key) != 0) {
		pr_warn(ctx, "received invalid protocol handshake response from %P", peer);
		return;
	}

	memcpy(hashinput, ctx->protocol_context->public_key.p, PUBLICKEYBYTES);
	memcpy(hashinput+PUBLICKEYBYTES, peer->protocol_state->handshake_public_key.p, PUBLICKEYBYTES);

	fastd_buffer buffer = fastd_buffer_alloc(sizeof(protocol_handshake_finish_packet), 0, 0);
	protocol_handshake_finish_packet *packet = buffer.data;

	memset(packet->noncepad, 0, NONCEBYTES);
	packet->type = HANDSHAKE_PACKET_FINISH;
	memcpy(packet->sender_key, ctx->protocol_context->public_key.p, PUBLICKEYBYTES);
	memcpy(packet->receipient_key, peer->protocol_state->peer_public_key.p, PUBLICKEYBYTES);
	memcpy(packet->handshake_key, peer->protocol_state->peer_handshake_key.p, PUBLICKEYBYTES);
	memcpy(packet->handshake_key2, peer->protocol_state->handshake_public_key.p, PUBLICKEYBYTES);

	crypto_auth_hmacsha256(packet->t, hashinput, 2*PUBLICKEYBYTES, peer->protocol_state->shared_handshake_key);

	fastd_task_put_send(ctx, peer, buffer);

	memcpy(hashinput, peer->protocol_state->handshake_public_key.p, PUBLICKEYBYTES);
	memcpy(hashinput+PUBLICKEYBYTES, peer->protocol_state->peer_handshake_key.p, PUBLICKEYBYTES);
	memcpy(hashinput+2*PUBLICKEYBYTES, ctx->protocol_context->public_key.p, PUBLICKEYBYTES);
	memcpy(hashinput+3*PUBLICKEYBYTES, peer->protocol_state->peer_public_key.p, PUBLICKEYBYTES);
	memcpy(hashinput+4*PUBLICKEYBYTES, peer->protocol_state->sigma.p, PUBLICKEYBYTES);
	crypto_hash_sha256(peer->protocol_state->shared_session_key, hashinput, 5*PUBLICKEYBYTES);

	establish(ctx, peer, true);
}

static void handle_finish_handshake(fastd_context *ctx, fastd_peer *peer, uint8_t t[HMACBYTES]) {
	uint8_t hashinput[5*PUBLICKEYBYTES];

	memcpy(hashinput, peer->protocol_state->peer_public_key.p, PUBLICKEYBYTES);
	memcpy(hashinput+PUBLICKEYBYTES, peer->protocol_state->peer_handshake_key.p, PUBLICKEYBYTES);

	if(crypto_auth_hmacsha256_verify(t, hashinput, 2*PUBLICKEYBYTES, peer->protocol_state->shared_handshake_key) != 0) {
		pr_warn(ctx, "received invalid protocol handshake finish from %P", peer);
		return;
	}

	memcpy(hashinput, peer->protocol_state->peer_handshake_key.p, PUBLICKEYBYTES);
	memcpy(hashinput+PUBLICKEYBYTES, peer->protocol_state->handshake_public_key.p, PUBLICKEYBYTES);
	memcpy(hashinput+2*PUBLICKEYBYTES, peer->protocol_state->peer_public_key.p, PUBLICKEYBYTES);
	memcpy(hashinput+3*PUBLICKEYBYTES, ctx->protocol_context->public_key.p, PUBLICKEYBYTES);
	memcpy(hashinput+4*PUBLICKEYBYTES, peer->protocol_state->sigma.p, PUBLICKEYBYTES);
	crypto_hash_sha256(peer->protocol_state->shared_session_key, hashinput, 5*PUBLICKEYBYTES);

	establish(ctx, peer, false);
}

static void protocol_handle_recv(fastd_context *ctx, fastd_peer *peer, fastd_buffer buffer) {
	if (buffer.len < NONCEBYTES)
		goto end;

	/* protocol handshake */
	if (is_nonce_zero(buffer.data)) {
		if (buffer.len < NONCEBYTES+1) {
			pr_debug(ctx, "received short protocol handshake from %P", peer);
			goto end;
		}

		protocol_handshake_packet *packet = buffer.data;

		if (!peer->config) {
			pr_debug(ctx, "received protocol handshake from temporary peer %P", peer);
			goto end;
		}

		if (!peer->protocol_state) {
			if (!create_peer_state(ctx, peer))
				goto end; /* TODO disable peer */
		}

		switch (packet->type) {
		case HANDSHAKE_PACKET_INIT:
			if (buffer.len < sizeof(protocol_handshake_init_packet)) {
				pr_debug(ctx, "received short protocol handshake init from %P", peer);
				goto end;
			}

			if (memcmp(ctx->protocol_context->public_key.p, packet->init.receipient_key, PUBLICKEYBYTES) != 0) {
				pr_debug(ctx, "received protocol handshake init with wrong receipient key from %P", peer);
				goto end;
			}

			if (memcmp(peer->protocol_state->peer_public_key.p, packet->init.sender_key, PUBLICKEYBYTES) != 0) {
				pr_debug(ctx, "received protocol handshake init with wrong sender key from %P", peer);
				goto end;
			}

			if (peer->protocol_state->state != HANDSHAKE_STATE_INIT) {
				pr_debug(ctx, "received unexpected protocol handshake init from %P", peer);
				goto end;
			}

			pr_debug(ctx, "received protocol handshake init from %P", peer);
			memcpy(peer->protocol_state->peer_handshake_key.p, packet->init.handshake_key, PUBLICKEYBYTES);

			fastd_peer_set_established(ctx, peer);
			respond_handshake(ctx, peer);

			break;

		case HANDSHAKE_PACKET_RESPONSE:
			if (buffer.len < sizeof(protocol_handshake_response_packet)) {
				pr_debug(ctx, "received short protocol handshake response from %P", peer);
				goto end;
			}

			if (memcmp(ctx->protocol_context->public_key.p, packet->response.receipient_key, PUBLICKEYBYTES) != 0) {
				pr_debug(ctx, "received protocol handshake response with wrong receipient key from %P", peer);
				goto end;
			}

			if (memcmp(peer->protocol_state->peer_public_key.p, packet->response.sender_key, PUBLICKEYBYTES) != 0) {
				pr_debug(ctx, "received protocol handshake response with wrong sender key from %P", peer);
				goto end;
			}

			if (memcmp(peer->protocol_state->handshake_public_key.p, packet->response.handshake_key, PUBLICKEYBYTES) != 0) {
				pr_debug(ctx, "received protocol handshake response with unexpected handshake key from %P", peer);
				goto end;
			}

			if (peer->protocol_state->state != HANDSHAKE_STATE_INIT) {
				pr_debug(ctx, "received unexpected protocol handshake response from %P", peer);
				goto end;
			}


			pr_debug(ctx, "received protocol handshake response from %P", peer);
			memcpy(peer->protocol_state->peer_handshake_key.p, packet->response.handshake_key2, PUBLICKEYBYTES);

			finish_handshake(ctx, peer, packet->response.t);

			break;

		case HANDSHAKE_PACKET_FINISH:
			if (buffer.len < sizeof(protocol_handshake_finish_packet)) {
				pr_debug(ctx, "received short protocol handshake finish from %P", peer);
				goto end;
			}

			if (memcmp(ctx->protocol_context->public_key.p, packet->finish.receipient_key, PUBLICKEYBYTES) != 0) {
				pr_debug(ctx, "received protocol handshake finish with wrong receipient key from %P", peer);
				goto end;
			}

			if (memcmp(peer->protocol_state->peer_public_key.p, packet->finish.sender_key, PUBLICKEYBYTES) != 0) {
				pr_debug(ctx, "received protocol handshake finish with wrong sender key from %P", peer);
				goto end;
			}

			if (memcmp(peer->protocol_state->handshake_public_key.p, packet->finish.handshake_key, PUBLICKEYBYTES) != 0) {
				pr_debug(ctx, "received protocol handshake finish with unexpected handshake key from %P", peer);
				goto end;
			}

			if (memcmp(peer->protocol_state->peer_handshake_key.p, packet->finish.handshake_key2, PUBLICKEYBYTES) != 0) {
				pr_debug(ctx, "received protocol handshake finish with unexpected peer handshake key from %P", peer);
				goto end;
			}

			if (peer->protocol_state->state != HANDSHAKE_STATE_RESPONSE) {
				pr_debug(ctx, "received unexpected protocol handshake finish from %P", peer);
				goto end;
			}


			pr_debug(ctx, "received protocol handshake finish from %P", peer);

			handle_finish_handshake(ctx, peer, packet->finish.t);

			break;
		}
	}
	else {
		if (!peer->protocol_state || peer->protocol_state->state != HANDSHAKE_STATE_ESTABLISHED) {
			pr_debug(ctx, "received unexpected non-handshake packet from %P", peer);
			goto end;
		}
	}

 end:
	fastd_buffer_free(buffer);
}

static void protocol_send(fastd_context *ctx, fastd_peer *peer, fastd_buffer buffer) {
	fastd_buffer_free(buffer);
}

static void protocol_free_peer_state(fastd_context *ctx, fastd_peer *peer) {
	free(peer->protocol_state);
}


const fastd_protocol fastd_protocol_ec25519_fhmqvc_xsalsa20_poly1305 = {
	.name = "ec25519-fhmqvc-xsalsa20-poly1305",

	.init = protocol_init,

	.max_packet_size = protocol_max_packet_size,

	.peer_str = protocol_peer_str,

	.init_peer = protocol_init_peer,
	.handle_recv = protocol_handle_recv,
	.send = protocol_send,

	.free_peer_state = protocol_free_peer_state,
};
