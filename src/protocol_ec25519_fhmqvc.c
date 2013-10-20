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


#include "fastd.h"
#include "handshake.h"
#include "peer.h"
#include "sha256.h"


#include <libuecc/ecc.h>


#define PUBLICKEYBYTES 32
#define SECRETKEYBYTES 32
#define HASHBYTES FASTD_SHA256_HASH_BYTES


#if HASHBYTES != FASTD_HMACSHA256_KEY_BYTES
#error bug: HASHBYTES != FASTD_HMACSHA256_KEY_BYTES
#endif

#if HASHBYTES != SECRETKEYBYTES
#error bug: HASHBYTES != SECRETKEYBYTES
#endif


typedef ecc_int256_t __attribute__((aligned(4))) aligned_int256_t;

typedef struct keypair {
	ecc_int256_t secret;
	aligned_int256_t public;
} keypair_t;

struct fastd_protocol_config {
	keypair_t key;
};

typedef struct handshake_key {
	uint64_t serial;
	struct timespec preferred_till;
	struct timespec valid_till;

	/* keypair used as initiator */
	keypair_t key1;

	/* keypair used as responder */
	keypair_t key2;
} handshake_key_t;

struct fastd_protocol_state {
	handshake_key_t prev_handshake_key;
	handshake_key_t handshake_key;
};

struct fastd_protocol_peer_config {
	aligned_int256_t public_key;
};

typedef struct protocol_session {
	struct timespec established;

	bool handshakes_cleaned;
	bool refreshing;

	const fastd_method_t *method;
	fastd_method_session_state_t *method_state;
} protocol_session_t;

struct fastd_protocol_peer_state {
	protocol_session_t old_session;
	protocol_session_t session;

	uint64_t last_serial;

	/* handshake cache */
	uint64_t last_handshake_serial;
	aligned_int256_t peer_handshake_key;
	aligned_int256_t sigma;
	fastd_sha256_t shared_handshake_key;
};


#define RECORD_SENDER_KEY RECORD_PROTOCOL1
#define RECORD_RECEIPIENT_KEY RECORD_PROTOCOL2
#define RECORD_SENDER_HANDSHAKE_KEY RECORD_PROTOCOL3
#define RECORD_RECEIPIENT_HANDSHAKE_KEY RECORD_PROTOCOL4
#define RECORD_T RECORD_PROTOCOL5


static void send_empty(fastd_context_t *ctx, fastd_peer_t *peer, protocol_session_t *session);


static inline bool read_key(uint8_t key[32], const char *hexkey) {
	if ((strlen(hexkey) != 64) || (strspn(hexkey, "0123456789abcdefABCDEF") != 64))
		return false;

	int i;
	for (i = 0; i < 32; i++)
		sscanf(&hexkey[2*i], "%02hhx", &key[i]);

	return true;
}

static inline bool is_handshake_key_valid(fastd_context_t *ctx, const handshake_key_t *handshake_key) {
	return timespec_after(&handshake_key->valid_till, &ctx->now);
}

static inline bool is_handshake_key_preferred(fastd_context_t *ctx, const handshake_key_t *handshake_key) {
	return timespec_after(&handshake_key->preferred_till, &ctx->now);
}

static inline bool is_session_valid(fastd_context_t *ctx, const protocol_session_t *session) {
	return (session->method && session->method->session_is_valid(ctx, session->method_state));
}

static bool backoff(fastd_context_t *ctx, const fastd_peer_t *peer) {
	return (peer->protocol_state && is_session_valid(ctx, &peer->protocol_state->session)
		&& timespec_diff(&ctx->now, &peer->protocol_state->session.established) < 15000);
}

static inline void check_session_refresh(fastd_context_t *ctx, fastd_peer_t *peer) {
	protocol_session_t *session = &peer->protocol_state->session;

	if (!session->refreshing && session->method->session_is_initiator(ctx, session->method_state) && session->method->session_want_refresh(ctx, session->method_state)) {
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
	ecc_25519_store_packed(&protocol_config->key.public, &work);

	return protocol_config;
}

static inline void hexdump(char out[65], const unsigned char d[32]) {
	int i;
	for (i = 0; i < 32; i++)
		snprintf(out+2*i, 3, "%02x", d[i]);
}

static size_t key_count(fastd_context_t *ctx, const unsigned char key[32]) {
	size_t ret = 0;

	fastd_peer_config_t *p;
	for (p = ctx->conf->peers; p; p = p->next) {
		if (!p->protocol_config)
			continue;

		if (memcmp(p->protocol_config->public_key.p, key, 32) == 0)
			ret++;
	}

	return ret;
}

static void protocol_peer_configure(fastd_context_t *ctx, fastd_peer_config_t *peer_conf) {
	if (peer_conf->protocol_config)
		return;

	if (!peer_conf->key) {
		pr_warn(ctx, "no key configured for `%s', disabling peer", peer_conf->name);
		return;
	}

	aligned_int256_t key;
	if (!read_key(key.p, peer_conf->key)) {
		pr_warn(ctx, "invalid key configured for `%s', disabling peer", peer_conf->name);
		return;
	}

	peer_conf->protocol_config = malloc(sizeof(fastd_protocol_peer_config_t));
	peer_conf->protocol_config->public_key = key;

	if (memcmp(peer_conf->protocol_config->public_key.p, ctx->conf->protocol_config->key.public.p, 32) == 0)
		pr_debug(ctx, "found own key as `%s', ignoring peer", peer_conf->name);
}

static bool protocol_peer_check(fastd_context_t *ctx, fastd_peer_config_t *peer_conf) {
	if (!peer_conf->protocol_config)
		return false;

	if (memcmp(peer_conf->protocol_config->public_key.p, ctx->conf->protocol_config->key.public.p, 32) == 0)
		return false;

	if (key_count(ctx, peer_conf->protocol_config->public_key.p) > 1) {
		char buf[65];
		hexdump(buf, peer_conf->protocol_config->public_key.p);
		pr_warn(ctx, "more than one peer is configured with key %s, disabling %s", buf, peer_conf->name);
		return false;
	}

	return true;
}

static bool protocol_peer_check_temporary(fastd_context_t *ctx, fastd_peer_t *peer) {
	if (key_count(ctx, peer->protocol_config->public_key.p)) {
		char buf[65];
		hexdump(buf, peer->protocol_config->public_key.p);
		pr_info(ctx, "key %s is configured now, deleting temporary peer.", buf);
		return false;
	}

	return true;
}

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

static void maintenance(fastd_context_t *ctx) {
	init_protocol_state(ctx);

	if (!is_handshake_key_preferred(ctx, &ctx->protocol_state->handshake_key)) {
		pr_debug(ctx, "generating new handshake key");

		ctx->protocol_state->prev_handshake_key = ctx->protocol_state->handshake_key;

		ctx->protocol_state->handshake_key.serial++;

		new_handshake_key(ctx, &ctx->protocol_state->handshake_key.key1);
		new_handshake_key(ctx, &ctx->protocol_state->handshake_key.key2);

		ctx->protocol_state->handshake_key.preferred_till = ctx->now;
		ctx->protocol_state->handshake_key.preferred_till.tv_sec += 15;

		ctx->protocol_state->handshake_key.valid_till = ctx->now;
		ctx->protocol_state->handshake_key.valid_till.tv_sec += 30;
	}
}

static void protocol_handshake_init(fastd_context_t *ctx, const fastd_socket_t *sock, const fastd_peer_address_t *local_addr, const fastd_peer_address_t *remote_addr, fastd_peer_t *peer) {
	maintenance(ctx);

	fastd_buffer_t buffer = fastd_handshake_new_init(ctx, 3*(4+PUBLICKEYBYTES) /* sender key, receipient key, handshake key */);

	fastd_handshake_add(ctx, &buffer, RECORD_SENDER_KEY, PUBLICKEYBYTES, ctx->conf->protocol_config->key.public.p);

	if (peer)
		fastd_handshake_add(ctx, &buffer, RECORD_RECEIPIENT_KEY, PUBLICKEYBYTES, peer->protocol_config->public_key.p);
	else
		pr_debug(ctx, "sending handshake to unknown peer %I", remote_addr);

	fastd_handshake_add(ctx, &buffer, RECORD_SENDER_HANDSHAKE_KEY, PUBLICKEYBYTES, ctx->protocol_state->handshake_key.key1.public.p);

	fastd_send_handshake(ctx, sock, local_addr, remote_addr, peer, buffer);
}


static bool update_shared_handshake_key(fastd_context_t *ctx, const fastd_peer_t *peer, const handshake_key_t *handshake_key, const aligned_int256_t *peer_handshake_key) {
	if (peer->protocol_state->last_handshake_serial == handshake_key->serial) {
		if (memcmp(&peer->protocol_state->peer_handshake_key, peer_handshake_key, PUBLICKEYBYTES) == 0)
			return true;
	}

	fastd_sha256_t hashbuf;
	fastd_sha256_blocks(&hashbuf,
			    handshake_key->key2.public.p,
			    peer_handshake_key->p,
			    ctx->conf->protocol_config->key.public.p,
			    peer->protocol_config->public_key.p,
			    NULL);

	ecc_int256_t d = {{0}}, e = {{0}}, eb, s;

	memcpy(d.p, hashbuf.b, HASHBYTES/2);
	memcpy(e.p, hashbuf.b+HASHBYTES/2, HASHBYTES/2);

	d.p[15] |= 0x80;
	e.p[15] |= 0x80;

	ecc_25519_gf_mult(&eb, &e, &ctx->conf->protocol_config->key.secret);
	ecc_25519_gf_add(&s, &eb, &handshake_key->key2.secret);

	ecc_25519_work_t work, workX;
	if (!ecc_25519_load_packed(&workX, peer_handshake_key))
		return false;

	ecc_25519_scalarmult(&work, &ecc_25519_gf_order, &workX);
	if (!ecc_25519_is_identity(&work))
		return false;

	if (!ecc_25519_load_packed(&work, &peer->protocol_config->public_key))
		return false;

	ecc_25519_scalarmult(&work, &d, &work);
	ecc_25519_add(&work, &workX, &work);
	ecc_25519_scalarmult(&work, &s, &work);

	if (ecc_25519_is_identity(&work))
		return false;

	ecc_25519_store_packed(&peer->protocol_state->sigma, &work);

	fastd_sha256_blocks(&peer->protocol_state->shared_handshake_key,
			    handshake_key->key2.public.p,
			    peer_handshake_key->p,
			    ctx->conf->protocol_config->key.public.p,
			    peer->protocol_config->public_key.p,
			    peer->protocol_state->sigma.p,
			    NULL);

	peer->protocol_state->last_handshake_serial = handshake_key->serial;
	peer->protocol_state->peer_handshake_key = *peer_handshake_key;

	return true;
}

static void clear_shared_handshake_key(fastd_context_t *ctx UNUSED, const fastd_peer_t *peer) {
	memset(&peer->protocol_state->sigma, 0, sizeof(peer->protocol_state->sigma));
	memset(&peer->protocol_state->shared_handshake_key, 0, sizeof(peer->protocol_state->shared_handshake_key));

	peer->protocol_state->last_handshake_serial = 0;
	memset(&peer->protocol_state->peer_handshake_key, 0, sizeof(peer->protocol_state->peer_handshake_key));
}

static void respond_handshake(fastd_context_t *ctx, const fastd_socket_t *sock, const fastd_peer_address_t *local_addr, const fastd_peer_address_t *remote_addr, fastd_peer_t *peer,
			      const handshake_key_t *handshake_key, const aligned_int256_t *peer_handshake_key, const fastd_handshake_t *handshake, const fastd_method_t *method) {
	pr_debug(ctx, "responding handshake with %P[%I]...", peer, remote_addr);

	if (!update_shared_handshake_key(ctx, peer, handshake_key, peer_handshake_key))
		return;

	fastd_buffer_t buffer = fastd_handshake_new_reply(ctx, handshake, method, true, 4*(4+PUBLICKEYBYTES) + 2*(4+HASHBYTES));

	fastd_handshake_add(ctx, &buffer, RECORD_SENDER_KEY, PUBLICKEYBYTES, ctx->conf->protocol_config->key.public.p);
	fastd_handshake_add(ctx, &buffer, RECORD_RECEIPIENT_KEY, PUBLICKEYBYTES, peer->protocol_config->public_key.p);
	fastd_handshake_add(ctx, &buffer, RECORD_SENDER_HANDSHAKE_KEY, PUBLICKEYBYTES, handshake_key->key2.public.p);
	fastd_handshake_add(ctx, &buffer, RECORD_RECEIPIENT_HANDSHAKE_KEY, PUBLICKEYBYTES, peer_handshake_key->p);

	fastd_sha256_t hmacbuf;

	if (!ctx->conf->secure_handshakes) {
		fastd_hmacsha256_blocks(&hmacbuf, peer->protocol_state->shared_handshake_key.w, ctx->conf->protocol_config->key.public.p, handshake_key->key2.public.p, NULL);
		fastd_handshake_add(ctx, &buffer, RECORD_T, HASHBYTES, hmacbuf.b);
	}

	memset(&hmacbuf, 0, sizeof(hmacbuf));
	fastd_handshake_add(ctx, &buffer, RECORD_TLV_MAC, HASHBYTES, hmacbuf.b);
	fastd_hmacsha256(&hmacbuf, peer->protocol_state->shared_handshake_key.w, fastd_handshake_tlv_data(&buffer), fastd_handshake_tlv_len(&buffer));
	memcpy(buffer.data+buffer.len-HASHBYTES, hmacbuf.b, HASHBYTES);

	fastd_send_handshake(ctx, sock, local_addr, remote_addr, peer, buffer);
}

static bool establish(fastd_context_t *ctx, fastd_peer_t *peer, const fastd_method_t *method, fastd_socket_t *sock,
		      const fastd_peer_address_t *local_addr, const fastd_peer_address_t *remote_addr, bool initiator,
		      const aligned_int256_t *A, const aligned_int256_t *B, const aligned_int256_t *X,
		      const aligned_int256_t *Y, const aligned_int256_t *sigma, uint64_t serial) {
	if (serial <= peer->protocol_state->last_serial) {
		pr_debug(ctx, "ignoring handshake from %P[%I] because of handshake key reuse", peer, remote_addr);
		return false;
	}

	pr_verbose(ctx, "%I authorized as %P", remote_addr, peer);

	if (!fastd_peer_claim_address(ctx, peer, sock, local_addr, remote_addr)) {
		pr_warn(ctx, "can't set address %I which is used by a fixed peer", remote_addr);
		fastd_peer_reset(ctx, peer);
		return false;
	}

	if (is_session_valid(ctx, &peer->protocol_state->session) && !is_session_valid(ctx, &peer->protocol_state->old_session)) {
		if (peer->protocol_state->old_session.method)
			peer->protocol_state->old_session.method->session_free(ctx, peer->protocol_state->old_session.method_state);
		peer->protocol_state->old_session = peer->protocol_state->session;
	}
	else {
		if (peer->protocol_state->session.method)
			peer->protocol_state->session.method->session_free(ctx, peer->protocol_state->session.method_state);
	}

	if (peer->protocol_state->old_session.method) {
		if (peer->protocol_state->old_session.method != method) {
			pr_debug(ctx, "method of %P[%I] has changed, terminating old session", peer, remote_addr);
			peer->protocol_state->old_session.method->session_free(ctx, peer->protocol_state->old_session.method_state);
			peer->protocol_state->old_session = (protocol_session_t){};
		}
		else {
			peer->protocol_state->old_session.method->session_superseded(ctx, peer->protocol_state->old_session.method_state);
		}
	}

	fastd_sha256_t hash;
	fastd_sha256_blocks(&hash, X->p, Y->p, A->p, B->p, sigma->p, NULL);

	peer->protocol_state->session.established = ctx->now;
	peer->protocol_state->session.handshakes_cleaned = false;
	peer->protocol_state->session.refreshing = false;
	peer->protocol_state->session.method = method;
	peer->protocol_state->session.method_state = method->session_init(ctx, hash.b, HASHBYTES, initiator);
	peer->protocol_state->last_serial = serial;

	fastd_peer_seen(ctx, peer);

	fastd_peer_set_established(ctx, peer);

	pr_verbose(ctx, "new session with %P established using method `%s'.", peer, method->name);

	if (initiator)
		fastd_peer_schedule_handshake_default(ctx, peer);
	else
		send_empty(ctx, peer, &peer->protocol_state->session);

	return true;
}

static inline bool has_field(const fastd_handshake_t *handshake, uint8_t type, size_t length) {
	return (handshake->records[type].length == length);
}

static void finish_handshake(fastd_context_t *ctx, fastd_socket_t *sock, const fastd_peer_address_t *local_addr, const fastd_peer_address_t *remote_addr, fastd_peer_t *peer, const handshake_key_t *handshake_key, const aligned_int256_t *peer_handshake_key,
			     const fastd_handshake_t *handshake, const fastd_method_t *method) {
	pr_debug(ctx, "finishing handshake with %P[%I]...", peer, remote_addr);

	fastd_sha256_t hashbuf;
	fastd_sha256_blocks(&hashbuf,
			    peer_handshake_key->p,
			    handshake_key->key1.public.p,
			    peer->protocol_config->public_key.p,
			    ctx->conf->protocol_config->key.public.p,
			    NULL);

	ecc_int256_t d = {{0}}, e = {{0}}, da, s;

	memcpy(d.p, hashbuf.b, HASHBYTES/2);
	memcpy(e.p, hashbuf.b+HASHBYTES/2, HASHBYTES/2);

	d.p[15] |= 0x80;
	e.p[15] |= 0x80;

	ecc_25519_gf_mult(&da, &d, &ctx->conf->protocol_config->key.secret);
	ecc_25519_gf_add(&s, &da, &handshake_key->key1.secret);

	ecc_25519_work_t work, workY;
	if (!ecc_25519_load_packed(&workY, peer_handshake_key))
		return;

	ecc_25519_scalarmult(&work, &ecc_25519_gf_order, &workY);
	if (!ecc_25519_is_identity(&work))
		return;

	if (!ecc_25519_load_packed(&work, &peer->protocol_config->public_key))
		return;

	ecc_25519_scalarmult(&work, &e, &work);
	ecc_25519_add(&work, &workY, &work);
	ecc_25519_scalarmult(&work, &s, &work);

	if (ecc_25519_is_identity(&work))
		return;

	aligned_int256_t sigma;
	ecc_25519_store_packed(&sigma, &work);

	fastd_sha256_t shared_handshake_key;
	fastd_sha256_blocks(&shared_handshake_key,
			    peer_handshake_key->p,
			    handshake_key->key1.public.p,
			    peer->protocol_config->public_key.p,
			    ctx->conf->protocol_config->key.public.p,
			    sigma.p,
			    NULL);

	bool valid;
	if (has_field(handshake, RECORD_TLV_MAC, HASHBYTES)) {
		uint8_t mac[HASHBYTES];
		memcpy(mac, handshake->records[RECORD_TLV_MAC].data, HASHBYTES);
		memset(handshake->records[RECORD_TLV_MAC].data, 0, HASHBYTES);

		valid = fastd_hmacsha256_verify(mac, shared_handshake_key.w, handshake->tlv_data, handshake->tlv_len);
	}
	else {
		valid = fastd_hmacsha256_blocks_verify(handshake->records[RECORD_T].data, shared_handshake_key.w, peer->protocol_config->public_key.p, peer_handshake_key->p, NULL);
	}

	if (!valid) {
		pr_warn(ctx, "received invalid protocol handshake response from %P[%I]", peer, remote_addr);
		return;
	}

	if (!establish(ctx, peer, method, sock, local_addr, remote_addr, true, &handshake_key->key1.public, peer_handshake_key, &ctx->conf->protocol_config->key.public,
		       &peer->protocol_config->public_key, &sigma, handshake_key->serial))
		return;

	fastd_buffer_t buffer = fastd_handshake_new_reply(ctx, handshake, method, false, 4*(4+PUBLICKEYBYTES) + 2*(4+HASHBYTES));

	fastd_handshake_add(ctx, &buffer, RECORD_SENDER_KEY, PUBLICKEYBYTES, ctx->conf->protocol_config->key.public.p);
	fastd_handshake_add(ctx, &buffer, RECORD_RECEIPIENT_KEY, PUBLICKEYBYTES, peer->protocol_config->public_key.p);
	fastd_handshake_add(ctx, &buffer, RECORD_SENDER_HANDSHAKE_KEY, PUBLICKEYBYTES, handshake_key->key1.public.p);
	fastd_handshake_add(ctx, &buffer, RECORD_RECEIPIENT_HANDSHAKE_KEY, PUBLICKEYBYTES, peer_handshake_key->p);

	fastd_sha256_t hmacbuf;

	if (!ctx->conf->secure_handshakes) {
		fastd_hmacsha256_blocks(&hmacbuf, shared_handshake_key.w, ctx->conf->protocol_config->key.public.p, handshake_key->key1.public.p, NULL);
		fastd_handshake_add(ctx, &buffer, RECORD_T, HASHBYTES, hmacbuf.b);
	}

	memset(&hmacbuf, 0, sizeof(hmacbuf));
	fastd_handshake_add(ctx, &buffer, RECORD_TLV_MAC, HASHBYTES, hmacbuf.b);
	fastd_hmacsha256(&hmacbuf, shared_handshake_key.w, fastd_handshake_tlv_data(&buffer), fastd_handshake_tlv_len(&buffer));
	memcpy(buffer.data+buffer.len-HASHBYTES, hmacbuf.b, HASHBYTES);

	fastd_send_handshake(ctx, sock, local_addr, remote_addr, peer, buffer);
}

static void handle_finish_handshake(fastd_context_t *ctx, fastd_socket_t *sock, const fastd_peer_address_t *local_addr, const fastd_peer_address_t *remote_addr,
				    fastd_peer_t *peer, const handshake_key_t *handshake_key, const aligned_int256_t *peer_handshake_key,
				    const fastd_handshake_t *handshake, const fastd_method_t *method) {
	pr_debug(ctx, "handling handshake finish with %P[%I]...", peer, remote_addr);

	if (!update_shared_handshake_key(ctx, peer, handshake_key, peer_handshake_key))
		return;

	bool valid;
	if (has_field(handshake, RECORD_TLV_MAC, HASHBYTES)) {
		uint8_t mac[HASHBYTES];
		memcpy(mac, handshake->records[RECORD_TLV_MAC].data, HASHBYTES);
		memset(handshake->records[RECORD_TLV_MAC].data, 0, HASHBYTES);

		valid = fastd_hmacsha256_verify(mac, peer->protocol_state->shared_handshake_key.w, handshake->tlv_data, handshake->tlv_len);
	}
	else {
		valid = fastd_hmacsha256_blocks_verify(handshake->records[RECORD_T].data, peer->protocol_state->shared_handshake_key.w, peer->protocol_config->public_key.p, peer_handshake_key->p, NULL);
	}

	if (!valid) {
		pr_warn(ctx, "received invalid protocol handshake finish from %P[%I]", peer, remote_addr);
		return;
	}

	establish(ctx, peer, method, sock, local_addr, remote_addr, false, peer_handshake_key, &handshake_key->key2.public, &peer->protocol_config->public_key,
		  &ctx->conf->protocol_config->key.public, &peer->protocol_state->sigma, handshake_key->serial);

	clear_shared_handshake_key(ctx, peer);
}

static fastd_peer_t* find_sender_key(fastd_context_t *ctx, const fastd_peer_address_t *address, const unsigned char key[32], fastd_peer_t *peers) {
	errno = 0;

	fastd_peer_t *ret = NULL, *peer;

	for (peer = peers; peer; peer = peer->next) {
		if (memcmp(peer->protocol_config->public_key.p, key, PUBLICKEYBYTES) == 0) {
			if (!fastd_peer_matches_address(ctx, peer, address)) {
				errno = EPERM;
				return NULL;
			}

			ret = peer;
			continue;
		}

		if (fastd_peer_owns_address(ctx, peer, address)) {
			errno = EPERM;
			return NULL;
		}
	}

	if (!ret)
		errno = ENOENT;

	return ret;
}

static fastd_peer_t* match_sender_key(fastd_context_t *ctx, const fastd_socket_t *sock, const fastd_peer_address_t *address, fastd_peer_t *peer, const unsigned char key[32]) {
	errno = 0;

	if (sock->peer && peer != sock->peer)
		exit_bug(ctx, "packet without correct peer set on dynamic socket");

	if (peer) {
		if (memcmp(peer->protocol_config->public_key.p, key, PUBLICKEYBYTES) == 0)
			return peer;

		if (fastd_peer_owns_address(ctx, peer, address)) {
			errno = EPERM;
			return NULL;
		}
	}

	peer = find_sender_key(ctx, address, key, ctx->peers);

	if (!peer && errno == ENOENT)
		peer = find_sender_key(ctx, address, key, ctx->peers_temp);

	return peer;
}

static inline fastd_peer_t* add_temporary(fastd_context_t *ctx, const fastd_peer_address_t *local_addr, const fastd_peer_address_t *remote_addr, const unsigned char key[32]) {
	if (!fastd_peer_allow_unknown(ctx)) {
		pr_debug(ctx, "ignoring handshake from %I (unknown key)", remote_addr);
		return NULL;
	}

	if (key_count(ctx, key)) {
		pr_debug(ctx, "ignoring handshake from %I (disabled key)", remote_addr);
		return NULL;
	}

	fastd_peer_t *peer = fastd_peer_add_temporary(ctx);

	peer->protocol_config = malloc(sizeof(fastd_protocol_peer_config_t));
	memcpy(peer->protocol_config->public_key.p, key, PUBLICKEYBYTES);

	/* Ugly hack */
	peer->protocol_state->last_serial--;

	if (!fastd_peer_verify_temporary(ctx, peer, local_addr, remote_addr)) {
		pr_debug(ctx, "ignoring handshake from %P[%I] (verification failed)", peer, remote_addr);
		fastd_peer_delete(ctx, peer);
		return NULL;
	}

	return peer;
}

static inline keypair_t* get_handshake_keypair(handshake_key_t *handshake_key, uint8_t type) {
	return (type % 2) ? &handshake_key->key2 : &handshake_key->key1;
}

static void protocol_handshake_handle(fastd_context_t *ctx, fastd_socket_t *sock, const fastd_peer_address_t *local_addr, const fastd_peer_address_t *remote_addr, fastd_peer_t *peer, const fastd_handshake_t *handshake, const fastd_method_t *method) {
	char *peer_version_name = NULL;
	bool temporary_added = false;

	maintenance(ctx);

	if (!has_field(handshake, RECORD_SENDER_KEY, PUBLICKEYBYTES)) {
		pr_debug(ctx, "received handshake without sender key from %I", remote_addr);
		return;
	}

	peer = match_sender_key(ctx, sock, remote_addr, peer, handshake->records[RECORD_SENDER_KEY].data);
	if (!peer) {
		switch (errno) {
		case EPERM:
			pr_debug(ctx, "ignoring handshake from %I (incorrect source address)", remote_addr);
			return;

		case ENOENT:
			peer = add_temporary(ctx, local_addr, remote_addr, handshake->records[RECORD_SENDER_KEY].data);
			if (peer) {
				temporary_added = true;
				break;
			}

			return;

		default:
			exit_bug(ctx, "match_sender_key: unknown error");
		}
	}

	if (fastd_peer_is_temporary(peer) && !temporary_added) {
		if (!fastd_peer_verify_temporary(ctx, peer, local_addr, remote_addr)) {
			pr_debug(ctx, "ignoring handshake from %P[%I] (verification failed)", peer, remote_addr);
			return;
		}
	}

	if (!fastd_peer_may_connect(ctx, peer)) {
		pr_debug(ctx, "ignoring handshake from %P[%I] because of local constraints", peer, remote_addr);
		return;
	}

	if (backoff(ctx, peer)) {
		pr_debug(ctx, "received repeated handshakes from %P[%I], ignoring", peer, remote_addr);
		return;
	}

	if (has_field(handshake, RECORD_RECEIPIENT_KEY, PUBLICKEYBYTES)) {
		if (memcmp(ctx->conf->protocol_config->key.public.p, handshake->records[RECORD_RECEIPIENT_KEY].data, PUBLICKEYBYTES) != 0) {
			pr_debug(ctx, "received protocol handshake with wrong receipient key from %P[%I]", peer, remote_addr);
			return;
		}
	}

	if (!has_field(handshake, RECORD_SENDER_HANDSHAKE_KEY, PUBLICKEYBYTES)) {
		pr_debug(ctx, "received handshake without sender handshake key from %P[%I]", peer, remote_addr);
		return;
	}

	aligned_int256_t peer_handshake_key;
	memcpy(peer_handshake_key.p, handshake->records[RECORD_SENDER_HANDSHAKE_KEY].data, PUBLICKEYBYTES);

	if (handshake->type == 1) {
		if (timespec_diff(&ctx->now, &peer->last_handshake_response) < (int)ctx->conf->min_handshake_interval*1000
		    && fastd_peer_address_equal(remote_addr, &peer->last_handshake_response_address)) {
			pr_debug(ctx, "not responding repeated handshake from %P[%I]", peer, remote_addr);
			return;
		}

		if (handshake->records[RECORD_VERSION_NAME].data)
			peer_version_name = strndup((const char*)handshake->records[RECORD_VERSION_NAME].data, handshake->records[RECORD_VERSION_NAME].length);

		pr_verbose(ctx, "received handshake from %P[%I] using fastd %s", peer, remote_addr, peer_version_name);
		free(peer_version_name);

		peer->last_handshake_response = ctx->now;
		peer->last_handshake_response_address = *remote_addr;
		respond_handshake(ctx, sock, local_addr, remote_addr, peer, &ctx->protocol_state->handshake_key, &peer_handshake_key, handshake, method);
		return;
	}

	if (!has_field(handshake, RECORD_RECEIPIENT_KEY, PUBLICKEYBYTES)) {
		pr_debug(ctx, "received handshake reply without receipient key from %P[%I]", peer, remote_addr);
		return;
	}

	if (!has_field(handshake, RECORD_RECEIPIENT_HANDSHAKE_KEY, PUBLICKEYBYTES)) {
		pr_debug(ctx, "received handshake reply without receipient handshake key from %P[%I]", peer, remote_addr);
		return;
	}

	if (!has_field(handshake, RECORD_TLV_MAC, HASHBYTES)) {
		if (ctx->conf->secure_handshakes || !has_field(handshake, RECORD_T, HASHBYTES)) {
			pr_debug(ctx, "received handshake reply without HMAC from %P[%I]", peer, remote_addr);
			return;
		}
	}

	handshake_key_t *handshake_key;
	if (is_handshake_key_valid(ctx, &ctx->protocol_state->handshake_key) &&
	    memcmp(get_handshake_keypair(&ctx->protocol_state->handshake_key, handshake->type)->public.p, handshake->records[RECORD_RECEIPIENT_HANDSHAKE_KEY].data, PUBLICKEYBYTES) == 0) {
		handshake_key = &ctx->protocol_state->handshake_key;
	}
	else if (is_handshake_key_valid(ctx, &ctx->protocol_state->prev_handshake_key) &&
		 memcmp(get_handshake_keypair(&ctx->protocol_state->prev_handshake_key, handshake->type)->public.p, handshake->records[RECORD_RECEIPIENT_HANDSHAKE_KEY].data, PUBLICKEYBYTES) == 0) {
		handshake_key = &ctx->protocol_state->prev_handshake_key;
	}
	else {
		pr_debug(ctx, "received handshake reply with unexpected receipient handshake key from %P[%I]", peer, remote_addr);
		return;
	}

	switch (handshake->type) {
	case 2:
		if (handshake->records[RECORD_VERSION_NAME].data)
			peer_version_name = strndup((const char*)handshake->records[RECORD_VERSION_NAME].data, handshake->records[RECORD_VERSION_NAME].length);

		pr_verbose(ctx, "received handshake response from %P[%I] using fastd %s", peer, remote_addr, peer_version_name);
		free(peer_version_name);

		finish_handshake(ctx, sock, local_addr, remote_addr, peer, handshake_key, &peer_handshake_key, handshake, method);
		break;

	case 3:
		pr_debug(ctx, "received handshake finish from %P[%I]", peer, remote_addr);

		handle_finish_handshake(ctx, sock, local_addr, remote_addr, peer, handshake_key, &peer_handshake_key, handshake, method);
		break;

	default:
		pr_debug(ctx, "received handshake reply with unknown type %u from %P[%I]", handshake->type, peer, remote_addr);
	}
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
		if (peer->protocol_state->old_session.method->decrypt(ctx, peer, peer->protocol_state->old_session.method_state, &recv_buffer, buffer))
			ok = true;
	}

	if (!ok) {
		if (peer->protocol_state->session.method->decrypt(ctx, peer, peer->protocol_state->session.method_state, &recv_buffer, buffer)) {
			ok = true;

			if (peer->protocol_state->old_session.method) {
				pr_debug(ctx, "invalidating old session with %P", peer);
				peer->protocol_state->old_session.method->session_free(ctx, peer->protocol_state->old_session.method_state);
				peer->protocol_state->old_session = (protocol_session_t){};
			}

			if (!peer->protocol_state->session.handshakes_cleaned) {
				pr_debug(ctx, "cleaning left handshakes with %P", peer);
				fastd_peer_unschedule_handshake(ctx, peer);
				peer->protocol_state->session.handshakes_cleaned = true;

				if (peer->protocol_state->session.method->session_is_initiator(ctx, peer->protocol_state->session.method_state))
					send_empty(ctx, peer, &peer->protocol_state->session);
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
	if (!session->method->encrypt(ctx, peer, session->method_state, &send_buffer, buffer)) {
		fastd_buffer_free(buffer);
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

	if (peer->protocol_state->session.method->session_is_initiator(ctx, peer->protocol_state->session.method_state) && is_session_valid(ctx, &peer->protocol_state->old_session)) {
		pr_debug2(ctx, "sending packet for old session to %P", peer);
		session_send(ctx, peer, buffer, &peer->protocol_state->old_session);
	}
	else {
		session_send(ctx, peer, buffer, &peer->protocol_state->session);
	}
}

static void send_empty(fastd_context_t *ctx, fastd_peer_t *peer, protocol_session_t *session) {
	session_send(ctx, peer, fastd_buffer_alloc(ctx, 0, alignto(session->method->min_encrypt_head_space(ctx), 8), session->method->min_encrypt_tail_space(ctx)), session);
}

static void protocol_init_peer_state(fastd_context_t *ctx, fastd_peer_t *peer) {
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

static void protocol_reset_peer_state(fastd_context_t *ctx, fastd_peer_t *peer) {
	if (!peer->protocol_state)
		return;

	reset_session(ctx, &peer->protocol_state->old_session);
	reset_session(ctx, &peer->protocol_state->session);
}

static void protocol_free_peer_state(fastd_context_t *ctx, fastd_peer_t *peer) {
	if (peer->protocol_state) {
		reset_session(ctx, &peer->protocol_state->old_session);
		reset_session(ctx, &peer->protocol_state->session);

		free(peer->protocol_state);
	}
}

static inline void print_hexdump(const char *desc, unsigned char d[32]) {
	char buf[65];
	hexdump(buf, d);

	printf("%s%s\n", desc, buf);
}

static void protocol_generate_key(fastd_context_t *ctx) {
	ecc_int256_t secret_key;
	ecc_int256_t public_key;

	if (!ctx->conf->machine_readable)
		pr_info(ctx, "Reading 32 bytes from /dev/random...");

	fastd_random_bytes(ctx, secret_key.p, 32, true);
	ecc_25519_gf_sanitize_secret(&secret_key, &secret_key);

	ecc_25519_work_t work;
	ecc_25519_scalarmult_base(&work, &secret_key);
	ecc_25519_store_packed(&public_key, &work);

	if (ctx->conf->machine_readable) {
		print_hexdump("", secret_key.p);
	}
	else {
		print_hexdump("Secret: ", secret_key.p);
		print_hexdump("Public: ", public_key.p);
	}
}

static void protocol_show_key(fastd_context_t *ctx) {
	if (ctx->conf->machine_readable)
		print_hexdump("", ctx->conf->protocol_config->key.public.p);
	else
		print_hexdump("Public: ", ctx->conf->protocol_config->key.public.p);
}

static void protocol_set_shell_env(fastd_context_t *ctx, const fastd_peer_t *peer) {
	char buf[65];

	hexdump(buf, ctx->conf->protocol_config->key.public.p);
	setenv("LOCAL_KEY", buf, 1);

	if (peer && peer->protocol_config) {
		hexdump(buf, peer->protocol_config->public_key.p);
		setenv("PEER_KEY", buf, 1);
	}
	else {
		unsetenv("PEER_KEY");
	}
}

static bool protocol_describe_peer(const fastd_context_t *ctx UNUSED, const fastd_peer_t *peer, char *buf, size_t len) {
	if (peer && peer->protocol_config) {
		char dumpbuf[65];

		hexdump(dumpbuf, peer->protocol_config->public_key.p);
		snprintf(buf, len, "%.16s", dumpbuf);
		return true;
	}
	else {
		return false;
	}
}

const fastd_protocol_t fastd_protocol_ec25519_fhmqvc = {
	.name = "ec25519-fhmqvc",

	.init = protocol_init,
	.peer_configure = protocol_peer_configure,
	.peer_check = protocol_peer_check,
	.peer_check_temporary = protocol_peer_check_temporary,

	.handshake_init = protocol_handshake_init,
	.handshake_handle = protocol_handshake_handle,

	.handle_recv = protocol_handle_recv,
	.send = protocol_send,

	.init_peer_state = protocol_init_peer_state,
	.reset_peer_state = protocol_reset_peer_state,
	.free_peer_state = protocol_free_peer_state,

	.generate_key = protocol_generate_key,
	.show_key = protocol_show_key,
	.set_shell_env = protocol_set_shell_env,
	.describe_peer = protocol_describe_peer,
};
