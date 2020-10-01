// SPDX-License-Identifier: BSD-2-Clause
/*
  Copyright (c) 2012-2016, Matthias Schiffer <mschiffer@universe-factory.net>
  All rights reserved.
*/

/**
   \file

   composed-umac method provider

   composed-umac combines any cipher (or null) with UMAC, while another cipher is
   used to generate the UHASH keys. Combining the null cipher with UMAC allows creating
   unencrypted, authenticated-only methods.
*/


#include "../../crypto.h"
#include "../../method.h"
#include "../common.h"


/** A block of zeros */
static const fastd_block128_t ZERO_BLOCK = {};


/** A specific method provided by this provider */
struct fastd_method {
	const fastd_cipher_info_t *cipher_info;      /**< The cipher used for encryption */
	const fastd_cipher_info_t *umac_cipher_info; /**< The cipher used for authenticaton */
	const fastd_mac_info_t *uhash_info;          /**< UHASH */
};

/** The method-specific session state */
struct fastd_method_session_state {
	fastd_method_common_t common; /**< The common method state */

	const fastd_method_t *method; /**< The specific method used */

	const fastd_cipher_t *cipher;       /**< The cipher implementation used for encryption */
	fastd_cipher_state_t *cipher_state; /**< The cipher state for encryption */

	const fastd_cipher_t *umac_cipher;       /**< The cipher implementation used for authentication */
	fastd_cipher_state_t *umac_cipher_state; /**< The cipher state for authentication */

	const fastd_mac_t *uhash;       /**< The UHASH implementation */
	fastd_mac_state_t *uhash_state; /**< The UHASH state */
};


/** Instanciates a method using a name of the pattern "<cipher>+<cipher>+umac" (or "<cipher>+<cipher>-umac" for block
 * ciphers in counter mode, e.g. null+aes128-umac instead of null+aes128-ctr+umac) */
static bool method_create_by_name(const char *name, fastd_method_t **method) {
	fastd_method_t m;

	m.uhash_info = fastd_mac_info_get_by_name("uhash");
	if (!m.uhash_info)
		return false;

	size_t len = strlen(name);
	char cipher_name[len];

	if (len >= 5 && !strcmp(name + len - 5, "+umac")) {
		memcpy(cipher_name, name, len - 5);
		cipher_name[len - 5] = 0;
	} else {
		return false;
	}

	char *umac_cipher_name = strchr(cipher_name, '+');

	if (!umac_cipher_name)
		return false;

	*umac_cipher_name = 0;
	umac_cipher_name++;

	m.cipher_info = fastd_cipher_info_get_by_name(cipher_name);
	if (!m.cipher_info)
		return false;

	if (m.cipher_info->iv_length && m.cipher_info->iv_length <= COMMON_NONCEBYTES)
		return false;

	m.umac_cipher_info = fastd_cipher_info_get_by_name(umac_cipher_name);
	if (!m.umac_cipher_info)
		return false;

	if (m.umac_cipher_info->iv_length <= COMMON_NONCEBYTES)
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
	return method->cipher_info->key_length + method->umac_cipher_info->key_length + method->uhash_info->key_length;
}

/** Initializes a session */
static fastd_method_session_state_t *
method_session_init(fastd_peer_t *peer, const fastd_method_t *method, const uint8_t *secret, bool initiator) {
	fastd_method_session_state_t *session = fastd_new(fastd_method_session_state_t);

	fastd_method_common_init(&session->common, peer, initiator);
	session->method = method;

	session->cipher = fastd_cipher_get(method->cipher_info);
	session->cipher_state = session->cipher->init(secret, 0);

	session->umac_cipher = fastd_cipher_get(method->umac_cipher_info);
	session->umac_cipher_state = session->umac_cipher->init(secret + method->cipher_info->key_length, 0);

	session->uhash = fastd_mac_get(method->uhash_info);
	session->uhash_state = session->uhash->init(
		secret + method->cipher_info->key_length + method->umac_cipher_info->key_length, 0);

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
		session->umac_cipher->free(session->umac_cipher_state);
		session->uhash->free(session->uhash_state);

		free(session);
	}
}

/** Encrypts and authenticates a packet */
static fastd_buffer_t *method_encrypt(fastd_method_session_state_t *session, fastd_buffer_t *in) {
	fastd_buffer_t *out = fastd_buffer_alloc(sizeof(fastd_block128_t) + in->len, COMMON_HEADROOM);

	int n_blocks = block_count(in->len, sizeof(fastd_block128_t));

	const fastd_block128_t *inblocks = in->data;
	fastd_block128_t *outblocks = out->data;
	fastd_block128_t tag;

	uint8_t umac_nonce[session->method->umac_cipher_info->iv_length] __attribute__((aligned(8)));
	fastd_method_expand_nonce(umac_nonce, session->common.send_nonce, sizeof(umac_nonce));

	uint8_t nonce[session->method->cipher_info->iv_length ?: 1] __attribute__((aligned(8)));
	fastd_method_expand_nonce(nonce, session->common.send_nonce, session->method->cipher_info->iv_length);

	if (!session->umac_cipher->crypt(
		    session->umac_cipher_state, outblocks, &ZERO_BLOCK, sizeof(fastd_block128_t), umac_nonce))
		goto fail;

	if (!session->cipher->crypt(
		    session->cipher_state, outblocks + 1, inblocks, n_blocks * sizeof(fastd_block128_t), nonce))
		goto fail;

	fastd_buffer_zero_pad(out);

	if (!session->uhash->digest(session->uhash_state, &tag, outblocks + 1, out->len - sizeof(fastd_block128_t)))
		goto fail;

	block_xor_a(&outblocks[0], &tag);

	fastd_buffer_free(in);

	fastd_method_put_common_header(out, session->common.send_nonce, 0);
	fastd_method_increment_nonce(&session->common);

	return out;

fail:
	fastd_buffer_free(out);
	return NULL;
}

/** Verifies and decrypts a packet */
static fastd_buffer_t *method_decrypt(fastd_method_session_state_t *session, fastd_buffer_t *in, bool *reordered) {
	if (in->len < COMMON_HEADBYTES + sizeof(fastd_block128_t))
		return NULL;

	if (!method_session_is_valid(session))
		return NULL;

	fastd_buffer_view_t in_view = fastd_buffer_get_view(in);

	uint8_t in_nonce[COMMON_NONCEBYTES];
	uint8_t flags;
	int64_t age;
	if (!fastd_method_handle_common_header(&session->common, &in_view, in_nonce, &flags, &age))
		return NULL;

	if (flags)
		return NULL;

	uint8_t nonce[session->method->cipher_info->iv_length ?: 1] __attribute__((aligned(8)));
	fastd_method_expand_nonce(nonce, in_nonce, session->method->cipher_info->iv_length);

	uint8_t umac_nonce[session->method->umac_cipher_info->iv_length] __attribute__((aligned(8)));
	fastd_method_expand_nonce(umac_nonce, in_nonce, sizeof(umac_nonce));

	fastd_buffer_t *out =
		fastd_buffer_alloc(in_view.len, ssub_size_t(conf.encrypt_headroom, sizeof(fastd_block128_t)));

	int n_blocks = block_count(in_view.len, sizeof(fastd_block128_t));

	const fastd_block128_t *inblocks = in_view.data;
	fastd_block128_t *outblocks = out->data;
	fastd_block128_t tag;

	if (!session->umac_cipher->crypt(
		    session->umac_cipher_state, outblocks, inblocks, sizeof(fastd_block128_t), umac_nonce))
		goto fail;

	if (!session->cipher->crypt(
		    session->cipher_state, outblocks + 1, inblocks + 1, (n_blocks - 1) * sizeof(fastd_block128_t),
		    nonce))
		goto fail;

	if (!session->uhash->digest(session->uhash_state, &tag, inblocks + 1, in_view.len - sizeof(fastd_block128_t)))
		goto fail;

	if (!block_equal(&tag, &outblocks[0]))
		goto fail;

	fastd_buffer_pull(out, sizeof(fastd_block128_t));

	fastd_tristate_t reorder_check = fastd_method_reorder_check(&session->common, in_nonce, age);
	if (reorder_check.set)
		*reordered = reorder_check.state;
	else
		out->len = 0;

	fastd_buffer_free(in);

	return out;

fail:
	fastd_buffer_free(out);
	return NULL;
}


/** The composed-umac method provider */
const fastd_method_provider_t fastd_method_composed_umac = {
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
