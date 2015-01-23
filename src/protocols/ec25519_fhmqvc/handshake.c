/*
  Copyright (c) 2012-2015, Matthias Schiffer <mschiffer@universe-factory.net>
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

   ec25519-fhmqvc protocol: handshake handling
*/

#include "handshake.h"
#include "../../crypto.h"
#include "../../handshake.h"
#include "../../hkdf_sha256.h"
#include "../../verify.h"


/** The size of the hash outputs used in the handshake */
#define HASHBYTES FASTD_SHA256_HASH_BYTES


#if HASHBYTES != FASTD_HMACSHA256_KEY_BYTES
#error bug: HASHBYTES != FASTD_HMACSHA256_KEY_BYTES
#endif

#if HASHBYTES != SECRETKEYBYTES
#error bug: HASHBYTES != SECRETKEYBYTES
#endif


/** Provides the proper arguments for passing a key for the %H log format */
#define KEY_PRINT(k) (const uint8_t *)(k), (size_t)PUBLICKEYBYTES


/** Derives a key of arbitraty length from the shared key material after a handshake using the HKDF algorithm */
static void derive_key(fastd_sha256_t *out, size_t blocks, const uint32_t *salt, const char *method_name,
		       const aligned_int256_t *A, const aligned_int256_t *B, const aligned_int256_t *X, const aligned_int256_t *Y,
		       const aligned_int256_t *sigma) {
	size_t methodlen = strlen(method_name);
	uint8_t info[4*PUBLICKEYBYTES + methodlen] __attribute__((aligned(8)));

	memcpy(info, A, PUBLICKEYBYTES);
	memcpy(info+PUBLICKEYBYTES, B, PUBLICKEYBYTES);
	memcpy(info+2*PUBLICKEYBYTES, X, PUBLICKEYBYTES);
	memcpy(info+3*PUBLICKEYBYTES, Y, PUBLICKEYBYTES);
	memcpy(info+4*PUBLICKEYBYTES, method_name, methodlen);

	fastd_sha256_t prk;
	fastd_hkdf_sha256_extract(&prk, salt, sigma->u32, PUBLICKEYBYTES);

	fastd_hkdf_sha256_expand(out, blocks, &prk, info, sizeof(info));
}

/** Marks the active session as superseded and moves it to the \e old_session field of the protocol peer state */
static inline void supersede_session(fastd_peer_t *peer, const fastd_method_info_t *method) {
	if (is_session_valid(&peer->protocol_state->session) && !is_session_valid(&peer->protocol_state->old_session)) {
		if (peer->protocol_state->old_session.method)
			peer->protocol_state->old_session.method->provider->session_free(peer->protocol_state->old_session.method_state);
		peer->protocol_state->old_session = peer->protocol_state->session;
	}
	else {
		if (peer->protocol_state->session.method)
			peer->protocol_state->session.method->provider->session_free(peer->protocol_state->session.method_state);
	}

	if (peer->protocol_state->old_session.method) {
		if (peer->protocol_state->old_session.method != method) {
			pr_debug("method of %P has changed, terminating old session", peer);
			peer->protocol_state->old_session.method->provider->session_free(peer->protocol_state->old_session.method_state);
			peer->protocol_state->old_session = (protocol_session_t){};
		}
		else {
			peer->protocol_state->old_session.method->provider->session_superseded(peer->protocol_state->old_session.method_state);
		}
	}
}

/** Initalizes a new session with a peer using a specified method */
static inline bool new_session(fastd_peer_t *peer, const fastd_method_info_t *method, bool initiator,
			       const aligned_int256_t *A, const aligned_int256_t *B, const aligned_int256_t *X, const aligned_int256_t *Y,
			       const aligned_int256_t *sigma, const uint32_t *salt, uint64_t serial) {

	supersede_session(peer, method);

	if (salt) {
		size_t blocks = block_count(method->provider->key_length(method->method), sizeof(fastd_sha256_t));
		fastd_sha256_t secret[blocks ?: 1];
		derive_key(secret, blocks, salt, method->name, A, B, X, Y, sigma);

		peer->protocol_state->session.method_state = method->provider->session_init(method->method, (const uint8_t *)secret, initiator);
	}
	else {
		fastd_sha256_t hash;
		fastd_sha256_blocks(&hash, X->u32, Y->u32, A->u32, B->u32, sigma->u32, NULL);
		peer->protocol_state->session.method_state = method->provider->session_init_compat(method->method, hash.b, HASHBYTES, initiator);
	}

	if (!peer->protocol_state->session.method_state)
		return false;

	peer->protocol_state->session.handshakes_cleaned = false;
	peer->protocol_state->session.refreshing = false;
	peer->protocol_state->session.method = method;
	peer->protocol_state->last_serial = serial;

	return true;
}

/** Establishes a connection with a peer after a successful handshake */
static bool establish(fastd_peer_t *peer, const fastd_method_info_t *method, fastd_socket_t *sock,
		      const fastd_peer_address_t *local_addr, const fastd_peer_address_t *remote_addr, bool initiator,
		      const aligned_int256_t *A, const aligned_int256_t *B, const aligned_int256_t *X, const aligned_int256_t *Y,
		      const aligned_int256_t *sigma, const uint32_t *salt, uint64_t serial) {
	if (serial <= peer->protocol_state->last_serial) {
		pr_debug("ignoring handshake from %P[%I] because of handshake key reuse", peer, remote_addr);
		return false;
	}

	if (!salt && !method->provider->session_init_compat) {
		pr_warn("can't establish compat session with %P[%I] (method without compat support)", peer, remote_addr);
		return false;
	}

	pr_verbose("%I authorized as %P", remote_addr, peer);

	if (!fastd_peer_claim_address(peer, sock, local_addr, remote_addr, true)) {
		pr_warn("can't establish session with %P[%I] as the address is used by another peer", peer, remote_addr);
		fastd_peer_reset(peer);
		return false;
	}

	if (!new_session(peer, method, initiator, A, B, X, Y, sigma, salt, serial)) {
		pr_error("failed to initialize method session for %P (method `%s'%s)", peer, method->name, salt ? "" : ", compat mode");
		fastd_peer_reset(peer);
		return false;
	}

	peer->establish_handshake_timeout = ctx.now + MIN_HANDSHAKE_INTERVAL;
	fastd_peer_seen(peer);
	fastd_peer_set_established(peer);

	pr_verbose("new session with %P established using method `%s'%s.", peer, method->name, salt ? "" : " (compat mode)");

	if (initiator)
		fastd_peer_schedule_handshake_default(peer);
	else
		fastd_protocol_ec25519_fhmqvc_send_empty(peer, &peer->protocol_state->session);

	return true;
}


/** Checks if a handshake has a field of a given type and length */
static inline bool has_field(const fastd_handshake_t *handshake, uint8_t type, size_t length) {
	return (handshake->records[type].length == length);
}

/** Checks the handshake has a TLV MAC field, meaning the handshake was sent by fastd v11 or newer */
static inline bool secure_handshake(const fastd_handshake_t *handshake) {
	return has_field(handshake, RECORD_TLV_MAC, HASHBYTES);
}


/** Derives the shares handshake key for computing the MACs used in the handshake */
static bool make_shared_handshake_key(bool initiator, const keypair_t *handshake_key,
				      const fastd_protocol_key_t *peer_key, const aligned_int256_t *peer_handshake_key,
				      aligned_int256_t *sigma,
				      fastd_sha256_t *shared_handshake_key,
				      fastd_sha256_t *shared_handshake_key_compat) {
	static const uint32_t zero_salt[FASTD_HMACSHA256_KEY_WORDS] = {};

	const aligned_int256_t *A, *B, *X, *Y;
	ecc_25519_work_t work, workXY;

	if (!ecc_25519_load_packed(&workXY, &peer_handshake_key->int256))
		return false;

	if (ecc_25519_is_identity(&workXY))
		return false;

	if (initiator) {
		A = &conf.protocol_config->key.public;
		B = &peer_key->key;
		X = &handshake_key->public;
		Y = peer_handshake_key;
	}
	else {
		A = &peer_key->key;
		B = &conf.protocol_config->key.public;
		X = peer_handshake_key;
		Y = &handshake_key->public;
	}

	fastd_sha256_t hashbuf;
	fastd_sha256_blocks(&hashbuf, Y->u32, X->u32, B->u32, A->u32, NULL);

	ecc_int256_t d = {{0}}, e = {{0}}, s;

	memcpy(d.p, hashbuf.b, HASHBYTES/2);
	memcpy(e.p, hashbuf.b+HASHBYTES/2, HASHBYTES/2);

	d.p[15] |= 0x80;
	e.p[15] |= 0x80;

	if (initiator) {
		ecc_int256_t da;
		ecc_25519_gf_mult(&da, &d, &conf.protocol_config->key.secret);
		ecc_25519_gf_add(&s, &da, &handshake_key->secret);

		ecc_25519_scalarmult_bits(&work, &e, &peer_key->unpacked, 128);
	}
	else {
		ecc_int256_t eb;
		ecc_25519_gf_mult(&eb, &e, &conf.protocol_config->key.secret);
		ecc_25519_gf_add(&s, &eb, &handshake_key->secret);

		ecc_25519_scalarmult_bits(&work, &d, &peer_key->unpacked, 128);
	}

	ecc_25519_add(&work, &workXY, &work);

	/*
	  Both our secret keys have been divided by 8 before, so we multiply
	  the point with 8 here to compensate.

	  By multiplying with 8, we prevent small-subgroup attacks (8 is the order
	  of the curves twist, see djb's Curve25519 paper). While the factor 8 should
	  be in the private keys anyways, the reduction modulo the subgroup order (in ecc_25519_gf_*)
	  will only preserve it if the point actually lies on our subgroup.
	*/
	octuple_point(&work);

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

/** Checks if the currently cached shared handshake key is valid and generates a new one otherwise  */
static bool update_shared_handshake_key(const fastd_peer_t *peer, const handshake_key_t *handshake_key, const aligned_int256_t *peer_handshake_key) {
	if (peer->protocol_state->last_handshake_serial == handshake_key->serial) {
		if (secure_memequal(&peer->protocol_state->peer_handshake_key, peer_handshake_key, PUBLICKEYBYTES))
			return true;
	}

	bool compat = !conf.secure_handshakes;

	if (!make_shared_handshake_key(false, &handshake_key->key,
				       peer->key,
				       peer_handshake_key,
				       &peer->protocol_state->sigma,
				       &peer->protocol_state->shared_handshake_key,
				       compat ? &peer->protocol_state->shared_handshake_key_compat : NULL))
		return false;

	peer->protocol_state->last_handshake_serial = handshake_key->serial;
	peer->protocol_state->peer_handshake_key = *peer_handshake_key;

	return true;
}

/** Resets the handshake cache for a peer */
static void clear_shared_handshake_key(const fastd_peer_t *peer) {
	memset(&peer->protocol_state->sigma, 0, sizeof(peer->protocol_state->sigma));
	memset(&peer->protocol_state->shared_handshake_key, 0, sizeof(peer->protocol_state->shared_handshake_key));
	memset(&peer->protocol_state->shared_handshake_key_compat, 0, sizeof(peer->protocol_state->shared_handshake_key_compat));

	peer->protocol_state->last_handshake_serial = 0;
	memset(&peer->protocol_state->peer_handshake_key, 0, sizeof(peer->protocol_state->peer_handshake_key));
}

/** Sends a reply to an initial handshake (type 1) */
static void respond_handshake(const fastd_socket_t *sock, const fastd_peer_address_t *local_addr, const fastd_peer_address_t *remote_addr, fastd_peer_t *peer,
			      const aligned_int256_t *peer_handshake_key, const fastd_method_info_t *method, bool little_endian) {
	pr_debug("responding handshake with %P[%I]...", peer, remote_addr);

	const handshake_key_t *handshake_key = &ctx.protocol_state->handshake_key;

	if (!update_shared_handshake_key(peer, handshake_key, peer_handshake_key))
		return;

	fastd_handshake_buffer_t buffer = fastd_handshake_new_reply(2, little_endian, method, fastd_peer_get_methods(peer), 4*(4+PUBLICKEYBYTES) + 2*(4+HASHBYTES));

	fastd_handshake_add(&buffer, RECORD_SENDER_KEY, PUBLICKEYBYTES, &conf.protocol_config->key.public);
	fastd_handshake_add(&buffer, RECORD_RECIPIENT_KEY, PUBLICKEYBYTES, &peer->key->key);
	fastd_handshake_add(&buffer, RECORD_SENDER_HANDSHAKE_KEY, PUBLICKEYBYTES, &handshake_key->key.public);
	fastd_handshake_add(&buffer, RECORD_RECIPIENT_HANDSHAKE_KEY, PUBLICKEYBYTES, peer_handshake_key);

	fastd_sha256_t hmacbuf;

	if (!conf.secure_handshakes) {
		fastd_hmacsha256_blocks(&hmacbuf, peer->protocol_state->shared_handshake_key_compat.w, conf.protocol_config->key.public.u32, handshake_key->key.public.u32, NULL);
		fastd_handshake_add(&buffer, RECORD_HANDSHAKE_TAG, HASHBYTES, hmacbuf.b);
	}

	uint8_t *mac = fastd_handshake_add_zero(&buffer, RECORD_TLV_MAC, HASHBYTES);
	fastd_hmacsha256(&hmacbuf, peer->protocol_state->shared_handshake_key.w, fastd_handshake_tlv_data(&buffer.buffer), fastd_handshake_tlv_len(&buffer.buffer));
	memcpy(mac, hmacbuf.b, HASHBYTES);

	fastd_send_handshake(sock, local_addr, remote_addr, peer, buffer.buffer);
}

/** Sends a reply to a handshake response (type 2) */
static void finish_handshake(fastd_socket_t *sock, const fastd_peer_address_t *local_addr, const fastd_peer_address_t *remote_addr, fastd_peer_t *peer, const handshake_key_t *handshake_key, const aligned_int256_t *peer_handshake_key,
			     const fastd_handshake_t *handshake, const fastd_method_info_t *method) {
	pr_debug("finishing handshake with %P[%I]...", peer, remote_addr);

	bool compat = !secure_handshake(handshake);

	aligned_int256_t sigma;
	fastd_sha256_t shared_handshake_key, shared_handshake_key_compat;
	if (!make_shared_handshake_key(true, &handshake_key->key,
				       peer->key,
				       peer_handshake_key,
				       &sigma,
				       compat ? NULL : &shared_handshake_key,
				       compat ? &shared_handshake_key_compat : NULL))
		return;

	bool valid;
	if (!compat) {
		uint8_t mac[HASHBYTES] __attribute__((aligned(8)));
		memcpy(mac, handshake->records[RECORD_TLV_MAC].data, HASHBYTES);
		memset(handshake->records[RECORD_TLV_MAC].data, 0, HASHBYTES);

		valid = fastd_hmacsha256_verify(mac, shared_handshake_key.w, handshake->tlv_data, handshake->tlv_len);
	}
	else {
		valid = fastd_hmacsha256_blocks_verify(handshake->records[RECORD_HANDSHAKE_TAG].data, shared_handshake_key_compat.w, peer->key->key.u32, peer_handshake_key->u32, NULL);
	}

	if (!valid) {
		pr_warn("received invalid protocol handshake response from %P[%I]", peer, remote_addr);
		return;
	}

	if (!establish(peer, method, sock, local_addr, remote_addr, true, &handshake_key->key.public, peer_handshake_key, &conf.protocol_config->key.public,
		       &peer->key->key, &sigma, compat ? NULL : shared_handshake_key.w, handshake_key->serial))
		return;

	fastd_handshake_buffer_t buffer = fastd_handshake_new_reply(3, handshake->little_endian, method, NULL, 4*(4+PUBLICKEYBYTES) + 2*(4+HASHBYTES));

	fastd_handshake_add(&buffer, RECORD_SENDER_KEY, PUBLICKEYBYTES, &conf.protocol_config->key.public);
	fastd_handshake_add(&buffer, RECORD_RECIPIENT_KEY, PUBLICKEYBYTES, &peer->key->key);
	fastd_handshake_add(&buffer, RECORD_SENDER_HANDSHAKE_KEY, PUBLICKEYBYTES, &handshake_key->key.public);
	fastd_handshake_add(&buffer, RECORD_RECIPIENT_HANDSHAKE_KEY, PUBLICKEYBYTES, peer_handshake_key);

	if (!compat) {
		fastd_sha256_t hmacbuf;
		uint8_t *mac = fastd_handshake_add_zero(&buffer, RECORD_TLV_MAC, HASHBYTES);
		fastd_hmacsha256(&hmacbuf, shared_handshake_key.w, fastd_handshake_tlv_data(&buffer.buffer), fastd_handshake_tlv_len(&buffer.buffer));
		memcpy(mac, hmacbuf.b, HASHBYTES);
	}
	else {
		fastd_sha256_t hmacbuf;
		fastd_hmacsha256_blocks(&hmacbuf, shared_handshake_key_compat.w, conf.protocol_config->key.public.u32, handshake_key->key.public.u32, NULL);
		fastd_handshake_add(&buffer, RECORD_HANDSHAKE_TAG, HASHBYTES, hmacbuf.b);
	}

	fastd_send_handshake(sock, local_addr, remote_addr, peer, buffer.buffer);
}

/** Handles a reply to a handshake response (type 3) */
static void handle_finish_handshake(fastd_socket_t *sock, const fastd_peer_address_t *local_addr, const fastd_peer_address_t *remote_addr,
				    fastd_peer_t *peer, const handshake_key_t *handshake_key, const aligned_int256_t *peer_handshake_key,
				    const fastd_handshake_t *handshake, const fastd_method_info_t *method) {
	pr_debug("handling handshake finish with %P[%I]...", peer, remote_addr);

	bool compat = !secure_handshake(handshake);

	if (!update_shared_handshake_key(peer, handshake_key, peer_handshake_key))
		return;

	bool valid;
	if (!compat) {
		uint8_t mac[HASHBYTES];
		memcpy(mac, handshake->records[RECORD_TLV_MAC].data, HASHBYTES);
		memset(handshake->records[RECORD_TLV_MAC].data, 0, HASHBYTES);

		valid = fastd_hmacsha256_verify(mac, peer->protocol_state->shared_handshake_key.w, handshake->tlv_data, handshake->tlv_len);
	}
	else {
		valid = fastd_hmacsha256_blocks_verify(handshake->records[RECORD_HANDSHAKE_TAG].data, peer->protocol_state->shared_handshake_key_compat.w, peer->key->key.u32, peer_handshake_key->u32, NULL);
	}

	if (!valid) {
		pr_warn("received invalid protocol handshake finish from %P[%I]", peer, remote_addr);
		return;
	}

	establish(peer, method, sock, local_addr, remote_addr, false, peer_handshake_key, &handshake_key->key.public, &peer->key->key,
		  &conf.protocol_config->key.public, &peer->protocol_state->sigma, compat ? NULL : peer->protocol_state->shared_handshake_key.w, handshake_key->serial);

	clear_shared_handshake_key(peer);
}

/** Searches the peer a public key belongs to, optionally restricting matches to a specific sender address */
static fastd_peer_t * find_key(const uint8_t key[PUBLICKEYBYTES], const fastd_peer_address_t *address) {
	errno = 0;

	fastd_peer_t *ret = NULL;
	size_t i;

	for (i = 0; i < VECTOR_LEN(ctx.peers); i++) {
		fastd_peer_t *peer = VECTOR_INDEX(ctx.peers, i);

		if (address && !fastd_peer_is_enabled(peer))
			continue;

		if (secure_memequal(&peer->key->key, key, PUBLICKEYBYTES)) {
			if (!address)
				return peer;

			if (!fastd_peer_matches_address(peer, address)) {
				errno = EPERM;
				return NULL;
			}

			ret = peer;
			continue;
		}

		if (address && fastd_peer_owns_address(peer, address)) {
			errno = EPERM;
			return NULL;
		}
	}

	if (!ret)
		errno = ENOENT;

	return ret;
}

/** Searches the peer a public key belongs to (including disabled peers) */
fastd_peer_t * fastd_protocol_ec25519_fhmqvc_find_peer(const fastd_protocol_key_t *key) {
	return find_key(key->key.u8, NULL);
}

/** Checks if a key matches a peer and searches the correct peer if it doesn't */
static fastd_peer_t * match_sender_key(const fastd_socket_t *sock, const fastd_peer_address_t *address, fastd_peer_t *peer, const uint8_t key[PUBLICKEYBYTES]) {
	errno = 0;

	if (sock->peer && peer != sock->peer)
		exit_bug("packet without correct peer set on dynamic socket");

	if (peer) {
		if (secure_memequal(&peer->key->key, key, PUBLICKEYBYTES))
			return peer;

		if (fastd_peer_owns_address(peer, address)) {
			errno = EPERM;
			return NULL;
		}
	}

	return find_key(key, address);
}

/** Sends an initial handshake (type 1) to a peer */
void fastd_protocol_ec25519_fhmqvc_handshake_init(fastd_socket_t *sock, const fastd_peer_address_t *local_addr, const fastd_peer_address_t *remote_addr, fastd_peer_t *peer) {
	fastd_protocol_ec25519_fhmqvc_maintenance();

	fastd_handshake_buffer_t buffer = fastd_handshake_new_init(3*(4+PUBLICKEYBYTES) /* sender key, recipient key, handshake key */);

	fastd_handshake_add(&buffer, RECORD_SENDER_KEY, PUBLICKEYBYTES, &conf.protocol_config->key.public);

	if (peer) {
		fastd_handshake_add(&buffer, RECORD_RECIPIENT_KEY, PUBLICKEYBYTES, &peer->key->key);

		pr_verbose("sending handshake to %P[%I]...", peer, remote_addr);
	}
	else {
		pr_verbose("sending handshake to unknown peer %I", remote_addr);
	}

	fastd_handshake_add(&buffer, RECORD_SENDER_HANDSHAKE_KEY, PUBLICKEYBYTES, &ctx.protocol_state->handshake_key.key.public);

	if (!peer || !fastd_peer_is_established(peer))
		fastd_peer_exec_shell_command(&conf.on_connect, peer, (local_addr && local_addr->sa.sa_family) ? local_addr : sock->bound_addr, remote_addr);

	fastd_send_handshake(sock, local_addr, remote_addr, peer, buffer.buffer);
}


/** Prints a message when a handshake from an unknown peer is received */
static inline void print_unknown_key(const fastd_peer_address_t *addr, const unsigned char key[PUBLICKEYBYTES]) {
	pr_verbose("ignoring handshake from %I (unknown key %H)", addr, KEY_PRINT(key));
}


#ifdef WITH_DYNAMIC_PEERS

/** Data attached to an asynchronous on-verify run */
typedef struct verify_data {
	aligned_int256_t peer_handshake_key;		/**< The public key of the peer being verified */
	bool little_endian;				/**< The handshake endianess */
} verify_data_t;

/** Adds a dynamic peer for an unknown key */
static fastd_peer_t * add_dynamic(fastd_socket_t *sock, const fastd_peer_address_t *addr, const unsigned char key[PUBLICKEYBYTES]) {
	if (!fastd_allow_verify()) {
		print_unknown_key(addr, key);
		return NULL;
	}

	if (sock->peer) {
		/* WTF? */
		pr_debug("ignoring handshake from %I (received on another peer's socket)", addr);
		return NULL;
	}

	if (memcmp(&conf.protocol_config->key.public, key, PUBLICKEYBYTES) == 0) {
		pr_debug("ignoring handshake from %I (used our own key)", addr);
		return NULL;
	}

	if (find_key(key, NULL)) {
		pr_debug("ignoring handshake from %I (disabled key %H)", addr, KEY_PRINT(key));
		return NULL;
	}

	fastd_protocol_key_t peer_key;
	memcpy(&peer_key.key, key, PUBLICKEYBYTES);

	if (!ecc_25519_load_packed(&peer_key.unpacked, &peer_key.key.int256)
		|| ecc_25519_is_identity(&peer_key.unpacked)) {
		pr_debug("ignoring handshake from %I (invalid key)", addr);
		return NULL;
	}

	fastd_peer_t *peer = fastd_new0(fastd_peer_t);
	peer->group = conf.peer_group;
	peer->config_state = CONFIG_DYNAMIC;

	peer->key = fastd_new(fastd_protocol_key_t);
	*peer->key = peer_key;

	if (!fastd_peer_add(peer))
		exit_bug("failed to add dynamic peer");

	/* Ugly hack */
	peer->protocol_state->last_serial--;

	return peer;
}

/** Is called when a handshake from a dynamic peer is received */
static bool handle_dynamic(fastd_socket_t *sock, const fastd_peer_address_t *local_addr, const fastd_peer_address_t *remote_addr,
			     fastd_peer_t *peer, const fastd_handshake_t *handshake, const fastd_method_info_t *method) {
	if (handshake->type > 2 || !fastd_timed_out(peer->verify_timeout))
		return !fastd_timed_out(peer->verify_valid_timeout);

	verify_data_t verify_data;
	memset(&verify_data, 0, sizeof(verify_data));
	memcpy(&verify_data.peer_handshake_key, handshake->records[RECORD_SENDER_HANDSHAKE_KEY].data, PUBLICKEYBYTES);
	verify_data.little_endian = handshake->little_endian;

	fastd_tristate_t verified = fastd_verify_peer(peer, sock, local_addr, remote_addr, method, &verify_data, sizeof(verify_data));

	if (!verified.set)
		/* async verify */
		return false;

	if (!verified.state) {
		pr_debug("ignoring handshake from %P[%I] (verification failed)", peer, remote_addr);
		fastd_peer_delete(peer);
		return false;
	}

	return true;
}

/** Handles a reply from an asynchronous on-verify command */
void fastd_protocol_ec25519_fhmqvc_handle_verify_return(fastd_peer_t *peer, fastd_socket_t *sock, const fastd_peer_address_t *local_addr, const fastd_peer_address_t *remote_addr,
							const fastd_method_info_t *method, const void *protocol_data, bool ok) {
	if (!ok)
		return;

	const verify_data_t *data = protocol_data;

	peer->last_handshake_response_timeout = ctx.now + MIN_HANDSHAKE_INTERVAL;
	peer->last_handshake_response_address = *remote_addr;
	respond_handshake(sock, local_addr, remote_addr, peer, &data->peer_handshake_key, method, data->little_endian);
}

#else

/** Dummy add dynamic function for fastd versions without on-verify support */
static inline fastd_peer_t * add_dynamic(UNUSED fastd_socket_t *sock, const fastd_peer_address_t *addr, const unsigned char key[PUBLICKEYBYTES]) {
	print_unknown_key(addr, key);
	return NULL;
}

#endif /* WITH_DYNAMIC_PEERS */


/** Handles a received handshake packet */
void fastd_protocol_ec25519_fhmqvc_handshake_handle(fastd_socket_t *sock, const fastd_peer_address_t *local_addr, const fastd_peer_address_t *remote_addr,
						    fastd_peer_t *peer, const fastd_handshake_t *handshake) {
	fastd_protocol_ec25519_fhmqvc_maintenance();

	if (!has_field(handshake, RECORD_SENDER_KEY, PUBLICKEYBYTES)) {
		pr_debug("received handshake without sender key from %I", remote_addr);
		return;
	}

	peer = match_sender_key(sock, remote_addr, peer, handshake->records[RECORD_SENDER_KEY].data);
	if (!peer) {
		switch (errno) {
		case EPERM:
			pr_debug("ignoring handshake from %I with key %H (incorrect source address)", remote_addr, KEY_PRINT(handshake->records[RECORD_SENDER_KEY].data));
			return;

		case ENOENT:
			peer = add_dynamic(sock, remote_addr, handshake->records[RECORD_SENDER_KEY].data);
			if (peer)
				break;

			return;

		default:
			exit_bug("match_sender_key: unknown error");
		}
	}

	if (!has_field(handshake, RECORD_SENDER_HANDSHAKE_KEY, PUBLICKEYBYTES)) {
		pr_debug("received handshake without sender handshake key from %P[%I]", peer, remote_addr);
		return;
	}

	if (!fastd_peer_may_connect(peer)) {
		pr_debug("ignoring handshake from %P[%I] because of local constraints", peer, remote_addr);
		return;
	}

	if (!fastd_timed_out(peer->establish_handshake_timeout)) {
		pr_debug("received repeated handshakes from %P[%I], ignoring", peer, remote_addr);
		return;
	}

	if (has_field(handshake, RECORD_RECIPIENT_KEY, PUBLICKEYBYTES)) {
		if (!secure_memequal(&conf.protocol_config->key.public, handshake->records[RECORD_RECIPIENT_KEY].data, PUBLICKEYBYTES)) {
			pr_debug("received protocol handshake with wrong recipient key from %P[%I]", peer, remote_addr);
			return;
		}
	}

	const fastd_method_info_t *method = fastd_handshake_get_method(peer, handshake);

#ifdef WITH_DYNAMIC_PEERS
	if (fastd_peer_is_dynamic(peer)) {
		if (!handle_dynamic(sock, local_addr, remote_addr, peer, handshake, method))
			return;
	}
#endif

	aligned_int256_t peer_handshake_key;
	memcpy(&peer_handshake_key, handshake->records[RECORD_SENDER_HANDSHAKE_KEY].data, PUBLICKEYBYTES);

	if (handshake->type == 1) {
		if (!fastd_timed_out(peer->last_handshake_response_timeout)
		    && fastd_peer_address_equal(remote_addr, &peer->last_handshake_response_address)) {
			pr_debug("not responding to repeated handshake from %P[%I]", peer, remote_addr);
			return;
		}

		pr_verbose("received handshake from %P[%I]%s%s", peer, remote_addr, handshake->peer_version ? " using fastd " : "", handshake->peer_version ?: "");

		peer->last_handshake_response_timeout = ctx.now + MIN_HANDSHAKE_INTERVAL;
		peer->last_handshake_response_address = *remote_addr;
		respond_handshake(sock, local_addr, remote_addr, peer, &peer_handshake_key, method, handshake->little_endian);
		return;
	}

	if (!method) {
		fastd_handshake_send_error(sock, local_addr, remote_addr, peer, handshake, REPLY_UNACCEPTABLE_VALUE, RECORD_METHOD_LIST);
		return;
	}

	if (!has_field(handshake, RECORD_RECIPIENT_KEY, PUBLICKEYBYTES)) {
		pr_debug("recived handshake reply without recipient key from %P[%I]", peer, remote_addr);
		return;
	}

	if (!has_field(handshake, RECORD_RECIPIENT_HANDSHAKE_KEY, PUBLICKEYBYTES)) {
		pr_debug("received handshake reply without receipient handshake key from %P[%I]", peer, remote_addr);
		return;
	}

	if (!secure_handshake(handshake)) {
		if (conf.secure_handshakes || !has_field(handshake, RECORD_HANDSHAKE_TAG, HASHBYTES)) {
			pr_debug("received handshake reply without HMAC from %P[%I]", peer, remote_addr);
			return;
		}
	}

	handshake_key_t *handshake_key;
	if (is_handshake_key_valid(&ctx.protocol_state->handshake_key) &&
	    secure_memequal(&ctx.protocol_state->handshake_key.key.public, handshake->records[RECORD_RECIPIENT_HANDSHAKE_KEY].data, PUBLICKEYBYTES)) {
		handshake_key = &ctx.protocol_state->handshake_key;
	}
	else if (is_handshake_key_valid(&ctx.protocol_state->prev_handshake_key) &&
		 secure_memequal(&ctx.protocol_state->prev_handshake_key.key.public, handshake->records[RECORD_RECIPIENT_HANDSHAKE_KEY].data, PUBLICKEYBYTES)) {
		handshake_key = &ctx.protocol_state->prev_handshake_key;
	}
	else {
		pr_debug("received handshake reply with unexpected recipient handshake key from %P[%I]", peer, remote_addr);
		return;
	}

	switch (handshake->type) {
	case 2:
		pr_verbose("received handshake response from %P[%I]%s%s", peer, remote_addr, handshake->peer_version ? " using fastd " : "", handshake->peer_version ?: "");

		finish_handshake(sock, local_addr, remote_addr, peer, handshake_key, &peer_handshake_key, handshake, method);
		break;

	case 3:
		pr_debug("received handshake finish from %P[%I]%s%s", peer, remote_addr, handshake->peer_version ? " using fastd " : "", handshake->peer_version ?: "");

		handle_finish_handshake(sock, local_addr, remote_addr, peer, handshake_key, &peer_handshake_key, handshake, method);
		break;

	default:
		pr_debug("received handshake reply with unknown type %u from %P[%I]", handshake->type, peer, remote_addr);
	}
}
