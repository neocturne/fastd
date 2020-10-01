// SPDX-License-Identifier: BSD-2-Clause
/*
  Copyright (c) 2012-2016, Matthias Schiffer <mschiffer@universe-factory.net>
  All rights reserved.
*/

/**
   \file

   cipher-test method provider (testing and benchmarking only)

   The cipher-test method provider performs encryption only and can be used to test
   and benchmark cipher implementations.
*/


#include "../../crypto.h"
#include "../../method.h"
#include "../common.h"


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


/** Instanciates a method using a name of the pattern "<cipher>+cipher-test" */
static bool method_create_by_name(const char *name, fastd_method_t **method) {
	fastd_method_t m;

	size_t len = strlen(name);
	if (len < 12)
		return false;

	if (strcmp(name + len - 12, "+cipher-test"))
		return false;

	char cipher_name[len - 11];
	memcpy(cipher_name, name, len - 12);
	cipher_name[len - 12] = 0;

	m.cipher_info = fastd_cipher_info_get_by_name(cipher_name);
	if (!m.cipher_info)
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
method_session_init(fastd_peer_t *peer, const fastd_method_t *method, const uint8_t *secret, bool initiator) {
	fastd_method_session_state_t *session = fastd_new(fastd_method_session_state_t);

	fastd_method_common_init(&session->common, peer, initiator);
	session->method = method;
	session->cipher = fastd_cipher_get(method->cipher_info);
	session->cipher_state = session->cipher->init(secret, 0);

	pr_warn("using cipher-test method with %P; this method must be used for testing and benchmarks only", peer);

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


/** Encrypts a packet and adds the common method header */
static fastd_buffer_t *method_encrypt(fastd_method_session_state_t *session, fastd_buffer_t *in) {
	fastd_buffer_t *out = fastd_buffer_alloc(in->len, COMMON_HEADROOM);

	uint8_t nonce[session->method->cipher_info->iv_length ?: 1] __attribute__((aligned(8)));
	fastd_method_expand_nonce(nonce, session->common.send_nonce, sizeof(nonce));

	int n_blocks = block_count(in->len, sizeof(fastd_block128_t));

	const fastd_block128_t *inblocks = in->data;
	fastd_block128_t *outblocks = out->data;

	if (!session->cipher->crypt(
		    session->cipher_state, outblocks, inblocks, n_blocks * sizeof(fastd_block128_t), nonce))
		goto fail;

	fastd_buffer_free(in);

	fastd_method_put_common_header(out, session->common.send_nonce, 0);
	fastd_method_increment_nonce(&session->common);

	return out;

fail:
	fastd_buffer_free(out);
	return NULL;
}

/** Decrypts a packet */
static fastd_buffer_t *method_decrypt(fastd_method_session_state_t *session, fastd_buffer_t *in, bool *reordered) {
	if (in->len < COMMON_HEADBYTES)
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
	fastd_method_expand_nonce(nonce, in_nonce, sizeof(nonce));

	fastd_buffer_t *out = fastd_buffer_alloc(in_view.len, conf.encrypt_headroom);

	int n_blocks = block_count(in_view.len, sizeof(fastd_block128_t));

	const fastd_block128_t *inblocks = in_view.data;
	fastd_block128_t *outblocks = out->data;

	if (!session->cipher->crypt(
		    session->cipher_state, outblocks, inblocks, n_blocks * sizeof(fastd_block128_t), nonce))
		goto fail;

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


/** The cipher-test method provider */
const fastd_method_provider_t fastd_method_cipher_test = {
	.overhead = COMMON_HEADBYTES,
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
