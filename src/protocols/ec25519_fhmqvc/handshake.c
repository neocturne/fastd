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
#include "../../handshake.h"
#include "../../hkdf_sha256.h"


#define PUBLICKEYBYTES 32
#define SECRETKEYBYTES 32
#define HASHBYTES FASTD_SHA256_HASH_BYTES


#if HASHBYTES != FASTD_HMACSHA256_KEY_BYTES
#error bug: HASHBYTES != FASTD_HMACSHA256_KEY_BYTES
#endif

#if HASHBYTES != SECRETKEYBYTES
#error bug: HASHBYTES != SECRETKEYBYTES
#endif


#define RECORD_SENDER_KEY RECORD_PROTOCOL1
#define RECORD_RECEIPIENT_KEY RECORD_PROTOCOL2
#define RECORD_SENDER_HANDSHAKE_KEY RECORD_PROTOCOL3
#define RECORD_RECEIPIENT_HANDSHAKE_KEY RECORD_PROTOCOL4
#define RECORD_T RECORD_PROTOCOL5


static void derive_key(fastd_sha256_t *out, size_t blocks, const uint32_t *salt, const char *method_name,
		       const aligned_int256_t *A, const aligned_int256_t *B, const aligned_int256_t *X, const aligned_int256_t *Y,
		       const aligned_int256_t *sigma) {
	size_t methodlen = strlen(method_name);
	uint8_t info[4*PUBLICKEYBYTES + methodlen];

	memcpy(info, A, PUBLICKEYBYTES);
	memcpy(info+PUBLICKEYBYTES, B, PUBLICKEYBYTES);
	memcpy(info+2*PUBLICKEYBYTES, X, PUBLICKEYBYTES);
	memcpy(info+3*PUBLICKEYBYTES, Y, PUBLICKEYBYTES);
	memcpy(info+4*PUBLICKEYBYTES, method_name, methodlen);

	fastd_sha256_t prk;
	fastd_hkdf_sha256_extract(&prk, salt, sigma->u32, PUBLICKEYBYTES);

	fastd_hkdf_sha256_expand(out, blocks, &prk, info, sizeof(info));
}

static inline void supersede_session(fastd_context_t *ctx, fastd_peer_t *peer, const fastd_method_info_t *method) {
	if (is_session_valid(ctx, &peer->protocol_state->session) && !is_session_valid(ctx, &peer->protocol_state->old_session)) {
		if (peer->protocol_state->old_session.method)
			peer->protocol_state->old_session.method->provider->session_free(ctx, peer->protocol_state->old_session.method_state);
		peer->protocol_state->old_session = peer->protocol_state->session;
	}
	else {
		if (peer->protocol_state->session.method)
			peer->protocol_state->session.method->provider->session_free(ctx, peer->protocol_state->session.method_state);
	}

	if (peer->protocol_state->old_session.method) {
		if (peer->protocol_state->old_session.method != method) {
			pr_debug(ctx, "method of %P has changed, terminating old session", peer);
			peer->protocol_state->old_session.method->provider->session_free(ctx, peer->protocol_state->old_session.method_state);
			peer->protocol_state->old_session = (protocol_session_t){};
		}
		else {
			peer->protocol_state->old_session.method->provider->session_superseded(ctx, peer->protocol_state->old_session.method_state);
		}
	}
}

static inline bool new_session(fastd_context_t *ctx, fastd_peer_t *peer, const fastd_method_info_t *method, bool initiator,
			       const aligned_int256_t *A, const aligned_int256_t *B, const aligned_int256_t *X, const aligned_int256_t *Y,
			       const aligned_int256_t *sigma, const uint32_t *salt, uint64_t serial) {

	supersede_session(ctx, peer, method);

	if (salt) {
		size_t blocks = block_count(method->provider->key_length(ctx, method->method), sizeof(fastd_sha256_t));
		fastd_sha256_t secret[blocks];
		derive_key(secret, blocks, salt, method->name, A, B, X, Y, sigma);

		peer->protocol_state->session.method_state = method->provider->session_init(ctx, method->method, (const uint8_t*)secret, initiator);
	}
	else {
		fastd_sha256_t hash;
		fastd_sha256_blocks(&hash, X->u32, Y->u32, A->u32, B->u32, sigma->u32, NULL);
		peer->protocol_state->session.method_state = method->provider->session_init_compat(ctx, method->method, hash.b, HASHBYTES, initiator);
	}

	if (!peer->protocol_state->session.method_state)
		return false;

	peer->protocol_state->session.handshakes_cleaned = false;
	peer->protocol_state->session.refreshing = false;
	peer->protocol_state->session.method = method;
	peer->protocol_state->last_serial = serial;

	return true;
}

static bool establish(fastd_context_t *ctx, fastd_peer_t *peer, const fastd_method_info_t *method, fastd_socket_t *sock,
		      const fastd_peer_address_t *local_addr, const fastd_peer_address_t *remote_addr, bool initiator,
		      const aligned_int256_t *A, const aligned_int256_t *B, const aligned_int256_t *X, const aligned_int256_t *Y,
		      const aligned_int256_t *sigma, const uint32_t *salt, uint64_t serial) {
	if (serial <= peer->protocol_state->last_serial) {
		pr_debug(ctx, "ignoring handshake from %P[%I] because of handshake key reuse", peer, remote_addr);
		return false;
	}

	if (!salt && !method->provider->session_init_compat) {
		pr_warn(ctx, "can't establish compat session with %P[%I] (method without compat support)", peer, remote_addr);
		return false;
	}

	pr_verbose(ctx, "%I authorized as %P", remote_addr, peer);

	if (!fastd_peer_claim_address(ctx, peer, sock, local_addr, remote_addr)) {
		pr_warn(ctx, "can't set address %I which is used by a fixed peer", remote_addr);
		fastd_peer_reset(ctx, peer);
		return false;
	}

	if (!new_session(ctx, peer, method, initiator, A, B, X, Y, sigma, salt, serial)) {
		pr_error(ctx, "failed to initialize method session for %P (method `%s'%s)", peer, method->name, salt ? "" : " (compat mode)");
		fastd_peer_reset(ctx, peer);
		return false;
	}

	peer->establish_handshake_timeout = fastd_in_seconds(ctx, ctx->conf->min_handshake_interval);
	fastd_peer_seen(ctx, peer);
	fastd_peer_set_established(ctx, peer);

	pr_verbose(ctx, "new session with %P established using method `%s'%s.", peer, method->name, salt ? "" : " (compat mode)");

	if (initiator)
		fastd_peer_schedule_handshake_default(ctx, peer);
	else
		fastd_protocol_ec25519_fhmqvc_send_empty(ctx, peer, &peer->protocol_state->session);

	return true;
}


static inline bool has_field(const fastd_handshake_t *handshake, uint8_t type, size_t length) {
	return (handshake->records[type].length == length);
}

static inline bool secure_handshake(const fastd_handshake_t *handshake) {
	return has_field(handshake, RECORD_TLV_MAC, HASHBYTES);
}


static bool make_shared_handshake_key(fastd_context_t *ctx, const ecc_int256_t *handshake_key, bool initiator,
				      const aligned_int256_t *A, const aligned_int256_t *B,
				      const aligned_int256_t *X, const aligned_int256_t *Y,
				      aligned_int256_t *sigma,
				      fastd_sha256_t *shared_handshake_key,
				      fastd_sha256_t *shared_handshake_key_compat) {
	static const uint32_t zero_salt[FASTD_HMACSHA256_KEY_WORDS] = {};

	ecc_25519_work_t work, workXY;

	if (!ecc_25519_load_packed(&workXY, initiator ? &Y->int256 : &X->int256))
		return false;

	ecc_25519_scalarmult(&work, &ecc_25519_gf_order, &workXY);
	if (!ecc_25519_is_identity(&work))
		return false;

	if (!ecc_25519_load_packed(&work, initiator ? &B->int256 : &A->int256))
		return false;

	fastd_sha256_t hashbuf;
	fastd_sha256_blocks(&hashbuf, Y->u32, X->u32, B->u32, A->u32, NULL);

	ecc_int256_t d = {{0}}, e = {{0}}, s;

	memcpy(d.p, hashbuf.b, HASHBYTES/2);
	memcpy(e.p, hashbuf.b+HASHBYTES/2, HASHBYTES/2);

	d.p[15] |= 0x80;
	e.p[15] |= 0x80;

	if (initiator) {
		ecc_int256_t da;
		ecc_25519_gf_mult(&da, &d, &ctx->conf->protocol_config->key.secret);
		ecc_25519_gf_add(&s, &da, handshake_key);

		ecc_25519_scalarmult(&work, &e, &work);
	}
	else {
		ecc_int256_t eb;
		ecc_25519_gf_mult(&eb, &e, &ctx->conf->protocol_config->key.secret);
		ecc_25519_gf_add(&s, &eb, handshake_key);

		ecc_25519_scalarmult(&work, &d, &work);
	}

	ecc_25519_add(&work, &workXY, &work);
	ecc_25519_scalarmult(&work, &s, &work);

	if (ecc_25519_is_identity(&work))
		return false;

	ecc_25519_store_packed(&sigma->int256, &work);

	if (shared_handshake_key)
		derive_key(shared_handshake_key, 1, zero_salt, "", A, B, X, Y, sigma);

	if (shared_handshake_key_compat)
		fastd_sha256_blocks(shared_handshake_key_compat, Y->u32, X->u32, B->u32, A->u32, sigma->u32, NULL);

	return true;
}

static bool update_shared_handshake_key(fastd_context_t *ctx, const fastd_peer_t *peer, const handshake_key_t *handshake_key, const aligned_int256_t *peer_handshake_key) {
	if (peer->protocol_state->last_handshake_serial == handshake_key->serial) {
		if (memcmp(&peer->protocol_state->peer_handshake_key, peer_handshake_key, PUBLICKEYBYTES) == 0)
			return true;
	}

	bool compat = !ctx->conf->secure_handshakes;

	if (!make_shared_handshake_key(ctx, &handshake_key->key.secret, false,
				       &peer->protocol_config->public_key,
				       &ctx->conf->protocol_config->key.public,
				       peer_handshake_key,
				       &handshake_key->key.public,
				       &peer->protocol_state->sigma,
				       &peer->protocol_state->shared_handshake_key,
				       compat ? &peer->protocol_state->shared_handshake_key_compat : NULL))
		return false;

	peer->protocol_state->last_handshake_serial = handshake_key->serial;
	peer->protocol_state->peer_handshake_key = *peer_handshake_key;

	return true;
}

static void clear_shared_handshake_key(fastd_context_t *ctx UNUSED, const fastd_peer_t *peer) {
	memset(&peer->protocol_state->sigma, 0, sizeof(peer->protocol_state->sigma));
	memset(&peer->protocol_state->shared_handshake_key, 0, sizeof(peer->protocol_state->shared_handshake_key));
	memset(&peer->protocol_state->shared_handshake_key_compat, 0, sizeof(peer->protocol_state->shared_handshake_key_compat));

	peer->protocol_state->last_handshake_serial = 0;
	memset(&peer->protocol_state->peer_handshake_key, 0, sizeof(peer->protocol_state->peer_handshake_key));
}

static void respond_handshake(fastd_context_t *ctx, const fastd_socket_t *sock, const fastd_peer_address_t *local_addr, const fastd_peer_address_t *remote_addr, fastd_peer_t *peer,
			      const handshake_key_t *handshake_key, const aligned_int256_t *peer_handshake_key, const fastd_handshake_t *handshake, const fastd_method_info_t *method) {
	pr_debug(ctx, "responding handshake with %P[%I]...", peer, remote_addr);

	if (!update_shared_handshake_key(ctx, peer, handshake_key, peer_handshake_key))
		return;

	fastd_buffer_t buffer = fastd_handshake_new_reply(ctx, handshake, method, true, 4*(4+PUBLICKEYBYTES) + 2*(4+HASHBYTES));

	fastd_handshake_add(ctx, &buffer, RECORD_SENDER_KEY, PUBLICKEYBYTES, &ctx->conf->protocol_config->key.public);
	fastd_handshake_add(ctx, &buffer, RECORD_RECEIPIENT_KEY, PUBLICKEYBYTES, &peer->protocol_config->public_key);
	fastd_handshake_add(ctx, &buffer, RECORD_SENDER_HANDSHAKE_KEY, PUBLICKEYBYTES, &handshake_key->key.public);
	fastd_handshake_add(ctx, &buffer, RECORD_RECEIPIENT_HANDSHAKE_KEY, PUBLICKEYBYTES, peer_handshake_key);

	fastd_sha256_t hmacbuf;

	if (!ctx->conf->secure_handshakes) {
		fastd_hmacsha256_blocks(&hmacbuf, peer->protocol_state->shared_handshake_key_compat.w, ctx->conf->protocol_config->key.public.u32, handshake_key->key.public.u32, NULL);
		fastd_handshake_add(ctx, &buffer, RECORD_T, HASHBYTES, hmacbuf.b);
	}

	uint8_t *mac = fastd_handshake_add_zero(ctx, &buffer, RECORD_TLV_MAC, HASHBYTES);
	fastd_hmacsha256(&hmacbuf, peer->protocol_state->shared_handshake_key.w, fastd_handshake_tlv_data(&buffer), fastd_handshake_tlv_len(&buffer));
	memcpy(mac, hmacbuf.b, HASHBYTES);

	fastd_send_handshake(ctx, sock, local_addr, remote_addr, peer, buffer);
}

static void finish_handshake(fastd_context_t *ctx, fastd_socket_t *sock, const fastd_peer_address_t *local_addr, const fastd_peer_address_t *remote_addr, fastd_peer_t *peer, const handshake_key_t *handshake_key, const aligned_int256_t *peer_handshake_key,
			     const fastd_handshake_t *handshake, const fastd_method_info_t *method) {
	pr_debug(ctx, "finishing handshake with %P[%I]...", peer, remote_addr);

	bool compat = !secure_handshake(handshake);

	aligned_int256_t sigma;
	fastd_sha256_t shared_handshake_key, shared_handshake_key_compat;
	if (!make_shared_handshake_key(ctx, &handshake_key->key.secret, true,
				       &ctx->conf->protocol_config->key.public,
				       &peer->protocol_config->public_key,
				       &handshake_key->key.public,
				       peer_handshake_key,
				       &sigma,
				       compat ? NULL : &shared_handshake_key,
				       compat ? &shared_handshake_key_compat : NULL))
		return;

	bool valid;
	if (!compat) {
		uint8_t mac[HASHBYTES];
		memcpy(mac, handshake->records[RECORD_TLV_MAC].data, HASHBYTES);
		memset(handshake->records[RECORD_TLV_MAC].data, 0, HASHBYTES);

		valid = fastd_hmacsha256_verify(mac, shared_handshake_key.w, handshake->tlv_data, handshake->tlv_len);
	}
	else {
		valid = fastd_hmacsha256_blocks_verify(handshake->records[RECORD_T].data, shared_handshake_key_compat.w, peer->protocol_config->public_key.u32, peer_handshake_key->u32, NULL);
	}

	if (!valid) {
		pr_warn(ctx, "received invalid protocol handshake response from %P[%I]", peer, remote_addr);
		return;
	}

	if (!establish(ctx, peer, method, sock, local_addr, remote_addr, true, &handshake_key->key.public, peer_handshake_key, &ctx->conf->protocol_config->key.public,
		       &peer->protocol_config->public_key, &sigma, compat ? NULL : shared_handshake_key.w, handshake_key->serial))
		return;

	fastd_buffer_t buffer = fastd_handshake_new_reply(ctx, handshake, method, false, 4*(4+PUBLICKEYBYTES) + 2*(4+HASHBYTES));

	fastd_handshake_add(ctx, &buffer, RECORD_SENDER_KEY, PUBLICKEYBYTES, &ctx->conf->protocol_config->key.public);
	fastd_handshake_add(ctx, &buffer, RECORD_RECEIPIENT_KEY, PUBLICKEYBYTES, &peer->protocol_config->public_key);
	fastd_handshake_add(ctx, &buffer, RECORD_SENDER_HANDSHAKE_KEY, PUBLICKEYBYTES, &handshake_key->key.public);
	fastd_handshake_add(ctx, &buffer, RECORD_RECEIPIENT_HANDSHAKE_KEY, PUBLICKEYBYTES, peer_handshake_key);

	if (!compat) {
		fastd_sha256_t hmacbuf;
		uint8_t *mac = fastd_handshake_add_zero(ctx, &buffer, RECORD_TLV_MAC, HASHBYTES);
		fastd_hmacsha256(&hmacbuf, shared_handshake_key.w, fastd_handshake_tlv_data(&buffer), fastd_handshake_tlv_len(&buffer));
		memcpy(mac, hmacbuf.b, HASHBYTES);
	}
	else {
		fastd_sha256_t hmacbuf;
		fastd_hmacsha256_blocks(&hmacbuf, shared_handshake_key_compat.w, ctx->conf->protocol_config->key.public.u32, handshake_key->key.public.u32, NULL);
		fastd_handshake_add(ctx, &buffer, RECORD_T, HASHBYTES, hmacbuf.b);
	}

	fastd_send_handshake(ctx, sock, local_addr, remote_addr, peer, buffer);
}

static void handle_finish_handshake(fastd_context_t *ctx, fastd_socket_t *sock, const fastd_peer_address_t *local_addr, const fastd_peer_address_t *remote_addr,
				    fastd_peer_t *peer, const handshake_key_t *handshake_key, const aligned_int256_t *peer_handshake_key,
				    const fastd_handshake_t *handshake, const fastd_method_info_t *method) {
	pr_debug(ctx, "handling handshake finish with %P[%I]...", peer, remote_addr);

	bool compat = !secure_handshake(handshake);

	if (!update_shared_handshake_key(ctx, peer, handshake_key, peer_handshake_key))
		return;

	bool valid;
	if (!compat) {
		uint8_t mac[HASHBYTES];
		memcpy(mac, handshake->records[RECORD_TLV_MAC].data, HASHBYTES);
		memset(handshake->records[RECORD_TLV_MAC].data, 0, HASHBYTES);

		valid = fastd_hmacsha256_verify(mac, peer->protocol_state->shared_handshake_key.w, handshake->tlv_data, handshake->tlv_len);
	}
	else {
		valid = fastd_hmacsha256_blocks_verify(handshake->records[RECORD_T].data, peer->protocol_state->shared_handshake_key_compat.w, peer->protocol_config->public_key.u32, peer_handshake_key->u32, NULL);
	}

	if (!valid) {
		pr_warn(ctx, "received invalid protocol handshake finish from %P[%I]", peer, remote_addr);
		return;
	}

	establish(ctx, peer, method, sock, local_addr, remote_addr, false, peer_handshake_key, &handshake_key->key.public, &peer->protocol_config->public_key,
		  &ctx->conf->protocol_config->key.public, &peer->protocol_state->sigma, compat ? NULL : peer->protocol_state->shared_handshake_key.w, handshake_key->serial);

	clear_shared_handshake_key(ctx, peer);
}

static fastd_peer_t* find_sender_key(fastd_context_t *ctx, const fastd_peer_address_t *address, const unsigned char key[32], fastd_peer_t *peers) {
	errno = 0;

	fastd_peer_t *ret = NULL, *peer;

	for (peer = peers; peer; peer = peer->next) {
		if (memcmp(&peer->protocol_config->public_key, key, PUBLICKEYBYTES) == 0) {
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
		if (memcmp(&peer->protocol_config->public_key, key, PUBLICKEYBYTES) == 0)
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

static size_t key_count(fastd_context_t *ctx, const unsigned char key[32]) {
	size_t ret = 0;

	fastd_peer_config_t *p;
	for (p = ctx->conf->peers; p; p = p->next) {
		if (!p->protocol_config)
			continue;

		if (memcmp(&p->protocol_config->public_key, key, 32) == 0)
			ret++;
	}

	return ret;
}

bool fastd_protocol_ec25519_fhmqvc_peer_check(fastd_context_t *ctx, fastd_peer_config_t *peer_conf) {
	if (!peer_conf->protocol_config)
		return false;

	if (memcmp(&peer_conf->protocol_config->public_key, &ctx->conf->protocol_config->key.public, 32) == 0)
		return false;

	if (key_count(ctx, peer_conf->protocol_config->public_key.u8) > 1) {
		char buf[65];
		hexdump(buf, peer_conf->protocol_config->public_key.u8);
		pr_warn(ctx, "more than one peer is configured with key %s, disabling %s", buf, peer_conf->name);
		return false;
	}

	return true;
}

bool fastd_protocol_ec25519_fhmqvc_peer_check_temporary(fastd_context_t *ctx, fastd_peer_t *peer) {
	if (key_count(ctx, peer->protocol_config->public_key.u8)) {
		char buf[65];
		hexdump(buf, peer->protocol_config->public_key.u8);
		pr_info(ctx, "key %s is configured now, deleting temporary peer.", buf);
		return false;
	}

	return true;
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
	memcpy(&peer->protocol_config->public_key, key, PUBLICKEYBYTES);

	/* Ugly hack */
	peer->protocol_state->last_serial--;

	if (!fastd_peer_verify_temporary(ctx, peer, local_addr, remote_addr)) {
		pr_debug(ctx, "ignoring handshake from %P[%I] (verification failed)", peer, remote_addr);
		fastd_peer_delete(ctx, peer);
		return NULL;
	}

	return peer;
}


void fastd_protocol_ec25519_fhmqvc_handshake_init(fastd_context_t *ctx, const fastd_socket_t *sock, const fastd_peer_address_t *local_addr, const fastd_peer_address_t *remote_addr, fastd_peer_t *peer) {
	fastd_protocol_ec25519_fhmqvc_maintenance(ctx);

	fastd_buffer_t buffer = fastd_handshake_new_init(ctx, 3*(4+PUBLICKEYBYTES) /* sender key, receipient key, handshake key */);

	fastd_handshake_add(ctx, &buffer, RECORD_SENDER_KEY, PUBLICKEYBYTES, &ctx->conf->protocol_config->key.public);

	if (peer)
		fastd_handshake_add(ctx, &buffer, RECORD_RECEIPIENT_KEY, PUBLICKEYBYTES, &peer->protocol_config->public_key);
	else
		pr_debug(ctx, "sending handshake to unknown peer %I", remote_addr);

	fastd_handshake_add(ctx, &buffer, RECORD_SENDER_HANDSHAKE_KEY, PUBLICKEYBYTES, &ctx->protocol_state->handshake_key.key.public);

	fastd_send_handshake(ctx, sock, local_addr, remote_addr, peer, buffer);
}

void fastd_protocol_ec25519_fhmqvc_handshake_handle(fastd_context_t *ctx, fastd_socket_t *sock, const fastd_peer_address_t *local_addr, const fastd_peer_address_t *remote_addr, fastd_peer_t *peer, const fastd_handshake_t *handshake, const fastd_method_info_t *method) {
	bool temporary_added = false;

	fastd_protocol_ec25519_fhmqvc_maintenance(ctx);

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

	if (!fastd_timed_out(ctx, &peer->establish_handshake_timeout)) {
		pr_debug(ctx, "received repeated handshakes from %P[%I], ignoring", peer, remote_addr);
		return;
	}

	if (has_field(handshake, RECORD_RECEIPIENT_KEY, PUBLICKEYBYTES)) {
		if (memcmp(&ctx->conf->protocol_config->key.public, handshake->records[RECORD_RECEIPIENT_KEY].data, PUBLICKEYBYTES) != 0) {
			pr_debug(ctx, "received protocol handshake with wrong receipient key from %P[%I]", peer, remote_addr);
			return;
		}
	}

	if (!has_field(handshake, RECORD_SENDER_HANDSHAKE_KEY, PUBLICKEYBYTES)) {
		pr_debug(ctx, "received handshake without sender handshake key from %P[%I]", peer, remote_addr);
		return;
	}

	aligned_int256_t peer_handshake_key;
	memcpy(&peer_handshake_key, handshake->records[RECORD_SENDER_HANDSHAKE_KEY].data, PUBLICKEYBYTES);

	if (handshake->type == 1) {
		if (!fastd_timed_out(ctx, &peer->last_handshake_response_timeout)
		    && fastd_peer_address_equal(remote_addr, &peer->last_handshake_response_address)) {
			pr_debug(ctx, "not responding to repeated handshake from %P[%I]", peer, remote_addr);
			return;
		}

		pr_verbose(ctx, "received handshake from %P[%I]%s%s", peer, remote_addr, handshake->peer_version ? " using fastd " : "", handshake->peer_version ?: "");

		peer->last_handshake_response_timeout = fastd_in_seconds(ctx, ctx->conf->min_handshake_interval);
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

	if (!secure_handshake(handshake)) {
		if (ctx->conf->secure_handshakes || !has_field(handshake, RECORD_T, HASHBYTES)) {
			pr_debug(ctx, "received handshake reply without HMAC from %P[%I]", peer, remote_addr);
			return;
		}
	}

	handshake_key_t *handshake_key;
	if (is_handshake_key_valid(ctx, &ctx->protocol_state->handshake_key) &&
	    memcmp(&ctx->protocol_state->handshake_key.key.public, handshake->records[RECORD_RECEIPIENT_HANDSHAKE_KEY].data, PUBLICKEYBYTES) == 0) {
		handshake_key = &ctx->protocol_state->handshake_key;
	}
	else if (is_handshake_key_valid(ctx, &ctx->protocol_state->prev_handshake_key) &&
		 memcmp(&ctx->protocol_state->prev_handshake_key.key.public, handshake->records[RECORD_RECEIPIENT_HANDSHAKE_KEY].data, PUBLICKEYBYTES) == 0) {
		handshake_key = &ctx->protocol_state->prev_handshake_key;
	}
	else {
		pr_debug(ctx, "received handshake reply with unexpected receipient handshake key from %P[%I]", peer, remote_addr);
		return;
	}

	switch (handshake->type) {
	case 2:
		pr_verbose(ctx, "received handshake response from %P[%I]%s%s", peer, remote_addr, handshake->peer_version ? " using fastd " : "", handshake->peer_version ?: "");

		finish_handshake(ctx, sock, local_addr, remote_addr, peer, handshake_key, &peer_handshake_key, handshake, method);
		break;

	case 3:
		pr_debug(ctx, "received handshake finish from %P[%I]%s%s", peer, remote_addr, handshake->peer_version ? " using fastd " : "", handshake->peer_version ?: "");

		handle_finish_handshake(ctx, sock, local_addr, remote_addr, peer, handshake_key, &peer_handshake_key, handshake, method);
		break;

	default:
		pr_debug(ctx, "received handshake reply with unknown type %u from %P[%I]", handshake->type, peer, remote_addr);
	}
}
