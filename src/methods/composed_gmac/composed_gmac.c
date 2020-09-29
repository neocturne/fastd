// SPDX-License-Identifier: BSD-2-Clause
/*
  Copyright (c) 2012-2016, Matthias Schiffer <mschiffer@universe-factory.net>
  All rights reserved.
*/

/**
   \file

   composed-gmac method provider

   composed-gmac combines any cipher (or null) with GMAC, while another cipher is
   used to generate the GHASH keys. Combining the null cipher with GMAC allows creating
   unencrypted, authenticated-only methods.
*/


#include "../../crypto/mac/ghash/ghash.h"

#include "../../crypto.h"
#include "../../method.h"
#include "../common.h"


/** A block of zeros */
static const fastd_block128_t ZERO_BLOCK = {};


/** A specific method provided by this provider */
struct fastd_method {
	const fastd_cipher_info_t *cipher_info;      /**< The cipher used for encryption */
	const fastd_cipher_info_t *gmac_cipher_info; /**< The cipher used for authenticaton */
	const fastd_mac_info_t *ghash_info;          /**< GHASH */
};

/** The method-specific session state */
struct fastd_method_session_state {
	fastd_method_common_t common; /**< The common method state */

	const fastd_method_t *method; /**< The specific method used */

	const fastd_cipher_t *cipher;       /**< The cipher implementation used for encryption */
	fastd_cipher_state_t *cipher_state; /**< The cipher state for encryption */

	const fastd_cipher_t *gmac_cipher;       /**< The cipher implementation used for authentication */
	fastd_cipher_state_t *gmac_cipher_state; /**< The cipher state for authentication */

	const fastd_mac_t *ghash;       /**< The GHASH implementation */
	fastd_mac_state_t *ghash_state; /**< The GHASH state */
};


/** Instanciates a method using a name of the pattern "<cipher>+<cipher>+gmac" (or "<cipher>+<cipher>-gmac" for block
 * ciphers in counter mode, e.g. null+aes128-gmac instead of null+aes128-ctr+gmac) */
static bool method_create_by_name(const char *name, fastd_method_t **method) {
	fastd_method_t m;

	m.ghash_info = fastd_mac_info_get_by_name("ghash");
	if (!m.ghash_info)
		return false;

	size_t len = strlen(name);
	char cipher_name[len];

	if (len >= 5 && !strcmp(name + len - 5, "-gmac")) {
		memcpy(cipher_name, name, len - 4);
		strncpy(cipher_name + len - 4, "ctr", 4);
	} else if (len >= 5 && !strcmp(name + len - 5, "+gmac")) {
		if (len >= 9 && !strcmp(name + len - 9, "-ctr+gmac"))
			return false;

		memcpy(cipher_name, name, len - 5);
		cipher_name[len - 5] = 0;
	} else {
		return false;
	}

	char *gmac_cipher_name = strchr(cipher_name, '+');

	if (!gmac_cipher_name)
		return false;

	*gmac_cipher_name = 0;
	gmac_cipher_name++;

	m.cipher_info = fastd_cipher_info_get_by_name(cipher_name);
	if (!m.cipher_info)
		return false;

	if (m.cipher_info->iv_length && m.cipher_info->iv_length <= COMMON_NONCEBYTES)
		return false;

	m.gmac_cipher_info = fastd_cipher_info_get_by_name(gmac_cipher_name);
	if (!m.gmac_cipher_info)
		return false;

	if (m.gmac_cipher_info->iv_length <= COMMON_NONCEBYTES)
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
	return method->cipher_info->key_length + method->gmac_cipher_info->key_length;
}

/** Initializes a session */
static fastd_method_session_state_t *
method_session_init(const fastd_method_t *method, const uint8_t *secret, bool initiator) {
	fastd_method_session_state_t *session = fastd_new(fastd_method_session_state_t);

	fastd_method_common_init(&session->common, initiator);
	session->method = method;

	session->cipher = fastd_cipher_get(method->cipher_info);
	session->cipher_state = session->cipher->init(secret, 0);

	session->gmac_cipher = fastd_cipher_get(method->gmac_cipher_info);
	session->gmac_cipher_state = session->gmac_cipher->init(secret + method->cipher_info->key_length, 0);

	fastd_block128_t H;

	size_t gmac_iv_length = method->gmac_cipher_info->iv_length;
	uint8_t zeroiv[gmac_iv_length] __attribute__((aligned(8)));
	memset(zeroiv, 0, gmac_iv_length);

	if (!session->gmac_cipher->crypt(
		    session->gmac_cipher_state, &H, &ZERO_BLOCK, sizeof(fastd_block128_t), zeroiv)) {
		session->cipher->free(session->cipher_state);
		session->gmac_cipher->free(session->gmac_cipher_state);
		free(session);

		return NULL;
	}

	session->ghash = fastd_mac_get(method->ghash_info);
	session->ghash_state = session->ghash->init(H.b, GHASH_SHIFT_SIZE);

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
		session->gmac_cipher->free(session->gmac_cipher_state);
		session->ghash->free(session->ghash_state);

		free(session);
	}
}

/** Encrypts and authenticates a packet */
static bool method_encrypt(
	UNUSED fastd_peer_t *peer, fastd_method_session_state_t *session, fastd_buffer_t *out, fastd_buffer_t in) {
	*out = fastd_buffer_alloc(sizeof(fastd_block128_t) + in.len, COMMON_HEADROOM);

	int n_blocks = block_count(in.len, sizeof(fastd_block128_t));

	const fastd_block128_t *inblocks = in.data;
	fastd_block128_t *outblocks = out->data;
	fastd_block128_t tag;

	uint8_t gmac_nonce[session->method->gmac_cipher_info->iv_length] __attribute__((aligned(8)));
	fastd_method_expand_nonce(gmac_nonce, session->common.send_nonce, sizeof(gmac_nonce));

	uint8_t nonce[session->method->cipher_info->iv_length ?: 1] __attribute__((aligned(8)));
	fastd_method_expand_nonce(nonce, session->common.send_nonce, session->method->cipher_info->iv_length);

	if (!session->gmac_cipher->crypt(
		    session->gmac_cipher_state, outblocks, &ZERO_BLOCK, sizeof(fastd_block128_t), gmac_nonce))
		goto fail;

	if (!session->cipher->crypt(
		    session->cipher_state, outblocks + 1, inblocks, n_blocks * sizeof(fastd_block128_t), nonce))
		goto fail;

	fastd_buffer_zero_pad(*out);

	if (!session->ghash->digest(session->ghash_state, &tag, outblocks + 1, out->len - sizeof(fastd_block128_t)))
		goto fail;

	block_xor_a(&outblocks[0], &tag);

	fastd_buffer_free(in);

	fastd_method_put_common_header(out, session->common.send_nonce, 0);
	fastd_method_increment_nonce(&session->common);

	return true;

fail:
	fastd_buffer_free(*out);
	return false;
}

/** Verifies and decrypts a packet */
static bool method_decrypt(
	fastd_peer_t *peer, fastd_method_session_state_t *session, fastd_buffer_t *out, fastd_buffer_t in,
	bool *reordered) {
	if (in.len < COMMON_HEADBYTES + sizeof(fastd_block128_t))
		return false;

	if (!method_session_is_valid(session))
		return false;

	fastd_buffer_view_t in_view = fastd_buffer_get_view(&in);

	uint8_t in_nonce[COMMON_NONCEBYTES];
	uint8_t flags;
	int64_t age;
	if (!fastd_method_handle_common_header(&session->common, &in_view, in_nonce, &flags, &age))
		return false;

	if (flags)
		return false;

	uint8_t nonce[session->method->cipher_info->iv_length ?: 1] __attribute__((aligned(8)));
	fastd_method_expand_nonce(nonce, in_nonce, session->method->cipher_info->iv_length);

	uint8_t gmac_nonce[session->method->gmac_cipher_info->iv_length] __attribute__((aligned(8)));
	fastd_method_expand_nonce(gmac_nonce, in_nonce, sizeof(gmac_nonce));

	*out = fastd_buffer_alloc(in_view.len, 0);

	int n_blocks = block_count(in_view.len, sizeof(fastd_block128_t));

	const fastd_block128_t *inblocks = in_view.data;
	fastd_block128_t *outblocks = out->data;
	fastd_block128_t tag;

	if (!session->gmac_cipher->crypt(
		    session->gmac_cipher_state, outblocks, inblocks, sizeof(fastd_block128_t), gmac_nonce))
		goto fail;

	if (!session->cipher->crypt(
		    session->cipher_state, outblocks + 1, inblocks + 1, (n_blocks - 1) * sizeof(fastd_block128_t),
		    nonce))
		goto fail;

	if (!session->ghash->digest(session->ghash_state, &tag, inblocks + 1, in_view.len - sizeof(fastd_block128_t)))
		goto fail;

	if (!block_equal(&tag, &outblocks[0]))
		goto fail;

	fastd_buffer_pull(out, sizeof(fastd_block128_t));

	fastd_tristate_t reorder_check = fastd_method_reorder_check(peer, &session->common, in_nonce, age);
	if (reorder_check.set)
		*reordered = reorder_check.state;
	else
		out->len = 0;

	fastd_buffer_free(in);

	return true;

fail:
	fastd_buffer_free(*out);
	return false;
}


/** The composed-gmac method provider */
const fastd_method_provider_t fastd_method_composed_gmac = {
	.overhead = COMMON_HEADBYTES + sizeof(fastd_block128_t),
	.encrypt_headroom = 0,
	.decrypt_headroom = 0,

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
