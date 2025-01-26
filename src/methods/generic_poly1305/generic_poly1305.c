// SPDX-License-Identifier: BSD-2-Clause
/*
  Copyright (c) Matthias Schiffer <mschiffer@universe-factory.net>
  All rights reserved.
*/

/**
   \file

   generic-poly1305 method provider

   The Poly1305 authenticator is very secure, but for performance reasons
   not really recommendable on embedded systems.
*/


#include "../../crypto.h"
#include "../../method.h"
#include "../common.h"

#ifdef HAVE_LIBSODIUM
#include <sodium/crypto_onetimeauth_poly1305.h>
#else
#include <nacl/crypto_onetimeauth_poly1305.h>
#endif


/** The length of the key used by Poly1305 */
#define KEYBYTES crypto_onetimeauth_poly1305_KEYBYTES

/** The length of the authentication tag */
#define TAGBYTES crypto_onetimeauth_poly1305_BYTES


/** A specific method provided by this provider */
struct fastd_method {
	const fastd_cipher_info_t *cipher_info; /**< The cipher used */
};

/** The method-specific session state */
struct fastd_method_session_state {
	fastd_method_common_t common; /**< The common method state */

	const fastd_method_t *method;       /**< The specific method used */
	const fastd_cipher_t *cipher;       /**< The cipher implementation used */
	fastd_cipher_state_t *cipher_state; /**< The cipher state */
};


/** Instanciates a method using a name of the pattern "<cipher>+poly1305" */
static bool method_create_by_name(const char *name, fastd_method_t **method) {
	fastd_method_t m;

	size_t len = strlen(name);
	if (len < 9)
		return false;

	if (strcmp(name + len - 9, "+poly1305"))
		return false;

	char cipher_name[len - 8];
	memcpy(cipher_name, name, len - 9);
	cipher_name[len - 9] = 0;

	m.cipher_info = fastd_cipher_info_get_by_name(cipher_name);
	if (!m.cipher_info)
		return false;

	if (m.cipher_info->iv_length <= COMMON_NONCEBYTES)
		return false;

	*method = fastd_new(fastd_method_t);
	**method = m;

	return true;
}

/** Frees a method */
static void method_destroy(fastd_method_t *method) {
	free(method);
}

/** Returns the key length used by a method */
static size_t method_key_length(const fastd_method_t *method) {
	return method->cipher_info->key_length;
}

/** Initializes a session */
static fastd_method_session_state_t *
method_session_init(fastd_peer_t *peer, const fastd_method_t *method, const uint8_t *secret, unsigned session_flags) {
	fastd_method_session_state_t *session = fastd_new(fastd_method_session_state_t);

	fastd_method_common_init(&session->common, peer, session_flags);
	session->method = method;
	session->cipher = fastd_cipher_get(session->method->cipher_info);
	session->cipher_state = session->cipher->init(secret, 0);

	return session;
}

/** Checks if the session is currently valid */
static bool method_session_is_valid(fastd_method_session_state_t *session) {
	return (session && fastd_method_session_common_is_valid(&session->common));
}

/** Checks if this side is the initator of the session */
static bool method_session_is_initiator(fastd_method_session_state_t *session) {
	return fastd_method_session_common_is_initiator(&session->common);
}

/** Checks if the session should be refreshed */
static bool method_session_want_refresh(fastd_method_session_state_t *session) {
	return fastd_method_session_common_want_refresh(&session->common);
}

/** Marks the session as superseded */
static void method_session_superseded(fastd_method_session_state_t *session) {
	fastd_method_session_common_superseded(&session->common);
}

/** Frees the session state */
static void method_session_free(fastd_method_session_state_t *session) {
	if (session) {
		session->cipher->free(session->cipher_state);
		free(session);
	}
}


/** Encrypts and authenticates a packet */
static fastd_buffer_t *method_encrypt(fastd_method_session_state_t *session, fastd_buffer_t *in) {
	fastd_buffer_push_zero(in, KEYBYTES);

	fastd_buffer_t *out = fastd_buffer_alloc(in->len, COMMON_HEADROOM);

	uint8_t nonce[session->method->cipher_info->iv_length] __attribute__((aligned(8)));
	fastd_method_expand_nonce(nonce, session->common.send_nonce, sizeof(nonce));

	int n_blocks = block_count(in->len, sizeof(fastd_block128_t));

	const fastd_block128_t *inblocks = in->data;
	fastd_block128_t *outblocks = out->data;
	uint8_t tag[TAGBYTES] __attribute__((aligned(8)));

	if (!session->cipher->crypt(
		    session->cipher_state, outblocks, inblocks, n_blocks * sizeof(fastd_block128_t), nonce))
		goto fail;

	const unsigned char *key = outblocks->b;
	fastd_buffer_pull(out, KEYBYTES);

	crypto_onetimeauth_poly1305(tag, out->data, out->len, key);

	fastd_buffer_push_from(out, tag, TAGBYTES);

	fastd_buffer_free(in);

	fastd_method_put_common_header(&session->common, out, 0);

	return out;

fail:
	fastd_buffer_free(out);
	return NULL;
}

/** Verifies and decrypts a packet */
static fastd_buffer_t *method_decrypt(fastd_method_session_state_t *session, fastd_buffer_t *in, bool *reordered) {
	if (in->len < COMMON_HEADBYTES + TAGBYTES)
		return NULL;

	if (!method_session_is_valid(session))
		return NULL;


	uint8_t in_nonce[COMMON_NONCEBYTES];
	uint8_t flags;
	int64_t age;

	fastd_buffer_view_t in_view = fastd_buffer_get_view(in);
	if (!fastd_method_handle_common_header(&session->common, &in_view, in_nonce, &flags, &age))
		return NULL;

	if (flags)
		return NULL;

	uint8_t nonce[session->method->cipher_info->iv_length] __attribute__((aligned(8)));
	fastd_method_expand_nonce(nonce, in_nonce, sizeof(nonce));

	uint8_t tag[TAGBYTES] __attribute__((aligned(8)));
	fastd_buffer_pull(in, COMMON_HEADBYTES);
	fastd_buffer_pull_to(in, tag, TAGBYTES);
	fastd_buffer_push_zero(in, KEYBYTES);

	fastd_buffer_t *out = fastd_buffer_alloc(in->len, ssub_size_t(conf.encrypt_headroom, KEYBYTES));

	int n_blocks = block_count(in->len, sizeof(fastd_block128_t));
	const fastd_block128_t *inblocks = in->data;
	fastd_block128_t *outblocks = out->data;

	bool ok = session->cipher->crypt(
		session->cipher_state, outblocks, inblocks, n_blocks * sizeof(fastd_block128_t), nonce);

	fastd_buffer_pull(in, KEYBYTES);

	if (!ok)
		goto fail;

	if (crypto_onetimeauth_poly1305_verify(tag, in->data, in->len, out->data) != 0)
		goto fail;

	fastd_buffer_free(in);

	fastd_buffer_pull(out, KEYBYTES);

	fastd_tristate_t reorder_check = fastd_method_reorder_check(&session->common, in_nonce, age);
	if (reorder_check.set)
		*reordered = reorder_check.state;
	else
		out->len = 0;

	return out;

fail:
	fastd_buffer_free(out);

	/* restore input buffer */
	fastd_buffer_push_from(in, tag, TAGBYTES);
	fastd_method_put_common_header_raw(in, in_nonce, 0, session->common.flags);

	return NULL;
}


/** The generic-poly1305 method provider */
const fastd_method_provider_t fastd_method_generic_poly1305 = {
	.overhead = COMMON_HEADBYTES + TAGBYTES,
	.encrypt_headroom = KEYBYTES,
	.decrypt_headroom = KEYBYTES - TAGBYTES,

	.create_by_name = method_create_by_name,
	.destroy = method_destroy,

	.key_length = method_key_length,

	.session_init = method_session_init,
	.session_is_valid = method_session_is_valid,
	.session_is_initiator = method_session_is_initiator,
	.session_want_refresh = method_session_want_refresh,
	.session_superseded = method_session_superseded,
	.session_free = method_session_free,

	.encrypt = method_encrypt,
	.decrypt = method_decrypt,
};
