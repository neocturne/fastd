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

   generic-umac method provider

   generic-umac can combine any stream cipher with the UMAC authentication.
*/


#include "../../crypto.h"
#include "../../method.h"
#include "../common.h"


/** A specific method provided by this provider */
struct fastd_method {
	const fastd_cipher_info_t *cipher_info;		/**< The cipher used */
	const fastd_mac_info_t *uhash_info;		/**< UHASH */
};

/** The method-specific session state */
struct fastd_method_session_state {
	fastd_method_common_t common;			/**< The common method state */

	const fastd_method_t *method;			/**< The specific method used */

	const fastd_cipher_t *cipher;			/**< The cipher implementation used */
	fastd_cipher_state_t *cipher_state;		/**< The cipher state */

	const fastd_mac_t *uhash;			/**< The UHASH implementation */
	fastd_mac_state_t *uhash_state;			/**< The UHASH state */
};


/** Instanciates a method using a name of the pattern "<cipher>+umac" */
static bool method_create_by_name(const char *name, fastd_method_t **method) {
	fastd_method_t m;

	m.uhash_info = fastd_mac_info_get_by_name("uhash");
	if (!m.uhash_info)
		return false;

	size_t len = strlen(name);
	char cipher_name[len+1];

	if (len >= 5 && !strcmp(name+len-5, "+umac")) {
		memcpy(cipher_name, name, len-5);
		cipher_name[len-5] = 0;
	}
	else {
		return false;
	}

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
	return method->cipher_info->key_length + method->uhash_info->key_length;
}

/** Initializes a session */
static fastd_method_session_state_t * method_session_init(const fastd_method_t *method, const uint8_t *secret, bool initiator) {
	fastd_method_session_state_t *session = fastd_new(fastd_method_session_state_t);

	fastd_method_common_init(&session->common, initiator);
	session->method = method;

	session->cipher = fastd_cipher_get(method->cipher_info);
	session->cipher_state = session->cipher->init(secret);

	session->uhash = fastd_mac_get(method->uhash_info);
	session->uhash_state = session->uhash->init(secret + method->cipher_info->key_length);

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
		session->uhash->free(session->uhash_state);

		free(session);
	}
}

/** Encrypts and authenticates a packet */
static bool method_encrypt(UNUSED fastd_peer_t *peer, fastd_method_session_state_t *session, fastd_buffer_t *out, fastd_buffer_t in) {
	size_t tail_len = in.len ? alignto(in.len, 2 * sizeof(fastd_block128_t))-in.len : (2 * sizeof(fastd_block128_t));

	fastd_buffer_pull_head_zero(&in, sizeof(fastd_block128_t));

	*out = fastd_buffer_alloc(in.len, alignto(COMMON_HEADBYTES, 16), tail_len);

	uint8_t nonce[session->method->cipher_info->iv_length] __attribute__((aligned(8)));
	fastd_method_expand_nonce(nonce, session->common.send_nonce, sizeof(nonce));

	int n_blocks = block_count(in.len, sizeof(fastd_block128_t));

	fastd_block128_t *inblocks = in.data;
	fastd_block128_t *outblocks = out->data;
	fastd_block128_t tag;

	bool ok = session->cipher->crypt(session->cipher_state, outblocks, inblocks, n_blocks*sizeof(fastd_block128_t), nonce);

	if (ok) {
		if (tail_len)
			memset(out->data+out->len, 0, tail_len);

		ok = session->uhash->digest(session->uhash_state, &tag, outblocks+1, out->len - sizeof(fastd_block128_t));
	}

	if (!ok) {
		fastd_buffer_free(*out);
		return false;
	}

	xor_a(&outblocks[0], &tag);

	fastd_buffer_free(in);

	fastd_method_put_common_header(out, session->common.send_nonce, 0);
	fastd_method_increment_nonce(&session->common);

	return true;
}

/** Verifies and decrypts a packet */
static bool method_decrypt(fastd_peer_t *peer, fastd_method_session_state_t *session, fastd_buffer_t *out, fastd_buffer_t in, bool *reordered) {
	if (in.len < COMMON_HEADBYTES+sizeof(fastd_block128_t))
		return false;

	if (!method_session_is_valid(session))
		return false;

	uint8_t in_nonce[COMMON_NONCEBYTES];
	uint8_t flags;
	int64_t age;
	if (!fastd_method_handle_common_header(&session->common, &in, in_nonce, &flags, &age))
		return false;

	if (flags)
		return false;

	uint8_t nonce[session->method->cipher_info->iv_length] __attribute__((aligned(8)));
	fastd_method_expand_nonce(nonce, in_nonce, sizeof(nonce));

	size_t in_len = in.len - sizeof(fastd_block128_t);
	size_t tail_len = in_len ? alignto(in_len, 2 * sizeof(fastd_block128_t))-in_len : (2 * sizeof(fastd_block128_t));
	*out = fastd_buffer_alloc(in.len, 0, tail_len);

	int n_blocks = block_count(in.len, sizeof(fastd_block128_t));

	fastd_block128_t *inblocks = in.data;
	fastd_block128_t *outblocks = out->data;
	fastd_block128_t tag;

	if (tail_len)
		memset(in.data+in.len, 0, tail_len);

	bool ok = session->cipher->crypt(session->cipher_state, outblocks, inblocks, n_blocks*sizeof(fastd_block128_t), nonce);

	if (ok)
		ok = session->uhash->digest(session->uhash_state, &tag, inblocks+1, in_len);

	if (!ok || !block_equal(&tag, &outblocks[0])) {
		fastd_buffer_free(*out);
		return false;
	}

	fastd_buffer_free(in);

	fastd_buffer_push_head(out, sizeof(fastd_block128_t));

	fastd_tristate_t reorder_check = fastd_method_reorder_check(peer, &session->common, in_nonce, age);
	if (reorder_check.set) {
		*reordered = reorder_check.state;
	}
	else {
		fastd_buffer_free(*out);
		*out = fastd_buffer_alloc(0, 0, 0);
	}

	return true;
}


/** The generic-umac method provider */
const fastd_method_provider_t fastd_method_generic_umac = {
	.max_overhead = COMMON_HEADBYTES + sizeof(fastd_block128_t),
	.min_encrypt_head_space = sizeof(fastd_block128_t),
	.min_decrypt_head_space = 0,
	.min_encrypt_tail_space = sizeof(fastd_block128_t)-1,
	.min_decrypt_tail_space = 2*sizeof(fastd_block128_t),

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
