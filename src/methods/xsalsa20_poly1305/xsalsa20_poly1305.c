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

   The xsalsa20-poly1305 method provider (deprecated)

   This provider is included for compatiblity reasons as pre-v11
   xsalsa20-poly1305 was the recommended method. In new setups salsa20+poly1305
   provided by the generic-poly1305 provider should be used as a replacement.
*/


#include "../../crypto.h"
#include "../../method.h"
#include "../common.h"

#include <crypto_secretbox_xsalsa20poly1305.h>


/** The session state */
struct fastd_method_session_state {
	fastd_method_common_t common;		/**< The common method state */

	uint8_t key[crypto_secretbox_xsalsa20poly1305_KEYBYTES] __attribute__((aligned(8))); /**< The encryption key */
};


/** Matches the method name "xsalsa20-poly1305" */
static bool method_create_by_name(const char *name, UNUSED fastd_method_t **method) {
	return !strcmp(name, "xsalsa20-poly1305");
}

/** Does nothing as this provider has only a single method */
static void method_destroy(UNUSED fastd_method_t *method) {
}

/** Returns the key length used by xsalsa20-poly1305 */
static size_t method_key_length(UNUSED const fastd_method_t *method) {
	return crypto_secretbox_xsalsa20poly1305_KEYBYTES;
}

/** Initializes the session state */
static fastd_method_session_state_t * method_session_init(UNUSED const fastd_method_t *method, const uint8_t *secret, bool initiator) {
	fastd_method_session_state_t *session = fastd_new(fastd_method_session_state_t);

	fastd_method_common_init(&session->common, initiator);

	memcpy(session->key, secret, crypto_secretbox_xsalsa20poly1305_KEYBYTES);

	return session;
}

/** Initializes the session state (pre-v11 compat handshake) */
static fastd_method_session_state_t * method_session_init_compat(const fastd_method_t *method, const uint8_t *secret, size_t length, bool initiator) {
	if (length < crypto_secretbox_xsalsa20poly1305_KEYBYTES)
		exit_bug("xsalsa20-poly1305: tried to init with short secret");

	return method_session_init(method, secret, initiator);
}

/** Checks if a session is currently valid */
static bool method_session_is_valid(fastd_method_session_state_t *session) {
	return (session && fastd_method_session_common_is_valid(&session->common));
}

/** Checks if this side is the initiator of the session */
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
	if(session) {
		secure_memzero(session, sizeof(fastd_method_session_state_t));
		free(session);
	}
}


/**
   Copies a nonce of length COMMON_NONCEBYTES to a buffer, reversing its byte order

   To maintain compability with pre-v11 versions, which used a little-endian nonce,
   the xsalsa20-poly1305 keeps using the old nonce format.
*/
static inline void memcpy_nonce(uint8_t *dst, const uint8_t *src) {
	size_t i;
	for (i = 0; i < COMMON_NONCEBYTES; i++)
		dst[i] = src[COMMON_NONCEBYTES-i-1];
}

/** Adds the xsalsa20-poly1305 header to the head of a packet */
static inline void put_header(fastd_buffer_t *buffer, const uint8_t nonce[COMMON_NONCEBYTES], uint8_t flags) {
	fastd_buffer_pull_head_from(buffer, &flags, 1);

	fastd_buffer_pull_head(buffer, COMMON_NONCEBYTES);
	memcpy_nonce(buffer->data, nonce);
}

/** Removes the xsalsa20-poly1305 header from the head of a packet */
static inline void take_header(fastd_buffer_t *buffer, uint8_t nonce[COMMON_NONCEBYTES], uint8_t *flags) {
	memcpy_nonce(nonce, buffer->data);
	fastd_buffer_push_head(buffer, COMMON_NONCEBYTES);

	fastd_buffer_push_head_to(buffer, flags, 1);
}

/** Removes and handles the xsalsa20-poly1305 header from the head of a packet */
static inline bool handle_header(const fastd_method_common_t *session, fastd_buffer_t *buffer, uint8_t nonce[COMMON_NONCEBYTES], uint8_t *flags, int64_t *age) {
	take_header(buffer, nonce, flags);
	return fastd_method_is_nonce_valid(session, nonce, age);
}


/** Performs encryption and authentication of a packet */
static bool method_encrypt(UNUSED fastd_peer_t *peer, fastd_method_session_state_t *session, fastd_buffer_t *out, fastd_buffer_t in) {
	fastd_buffer_pull_head_zero(&in, crypto_secretbox_xsalsa20poly1305_ZEROBYTES);

	*out = fastd_buffer_alloc(in.len, 0, 0);

	uint8_t nonce[crypto_secretbox_xsalsa20poly1305_NONCEBYTES] __attribute__((aligned(8))) = {};
	memcpy_nonce(nonce, session->common.send_nonce);

	crypto_secretbox_xsalsa20poly1305(out->data, in.data, in.len, nonce, session->key);

	fastd_buffer_free(in);

	fastd_buffer_push_head(out, crypto_secretbox_xsalsa20poly1305_BOXZEROBYTES);
	put_header(out, session->common.send_nonce, 0);
	fastd_method_increment_nonce(&session->common);

	return true;
}

/** Performs validation and decryption of a packet */
static bool method_decrypt(fastd_peer_t *peer, fastd_method_session_state_t *session, fastd_buffer_t *out, fastd_buffer_t in, bool *reordered) {
	if (in.len < COMMON_HEADBYTES)
		return false;

	if (!method_session_is_valid(session))
		return false;

	uint8_t in_nonce[COMMON_NONCEBYTES];
	uint8_t flags;
	int64_t age;
	if (!handle_header(&session->common, &in, in_nonce, &flags, &age))
		return false;

	if (flags)
		return false;

	uint8_t nonce[crypto_secretbox_xsalsa20poly1305_NONCEBYTES] __attribute__((aligned(8))) = {};
	memcpy_nonce(nonce, in_nonce);

	fastd_buffer_pull_head_zero(&in, crypto_secretbox_xsalsa20poly1305_BOXZEROBYTES);

	*out = fastd_buffer_alloc(in.len, 0, 0);

	if (crypto_secretbox_xsalsa20poly1305_open(out->data, in.data, in.len, nonce, session->key) != 0) {
		fastd_buffer_free(*out);

		/* restore input buffer */
		fastd_buffer_push_head(&in, crypto_secretbox_xsalsa20poly1305_BOXZEROBYTES);
		put_header(&in, in_nonce, 0);
		return false;
	}

	fastd_buffer_free(in);

	fastd_tristate_t reorder_check = fastd_method_reorder_check(peer, &session->common, in_nonce, age);
	if (reorder_check.set) {
		*reordered = reorder_check.state;
	}
	else {
		fastd_buffer_free(*out);
		*out = fastd_buffer_alloc(crypto_secretbox_xsalsa20poly1305_ZEROBYTES, 0, 0);
	}

	fastd_buffer_push_head(out, crypto_secretbox_xsalsa20poly1305_ZEROBYTES);

	return true;
}


/** The xsalsa20-poly1305 method provider */
const fastd_method_provider_t fastd_method_xsalsa20_poly1305 = {

	.max_overhead = COMMON_HEADBYTES + crypto_secretbox_xsalsa20poly1305_ZEROBYTES - crypto_secretbox_xsalsa20poly1305_BOXZEROBYTES,
	.min_encrypt_head_space = crypto_secretbox_xsalsa20poly1305_ZEROBYTES,
	.min_decrypt_head_space = crypto_secretbox_xsalsa20poly1305_BOXZEROBYTES - COMMON_HEADBYTES,
	.min_encrypt_tail_space = 0,
	.min_decrypt_tail_space = 0,

	.create_by_name = method_create_by_name,
	.destroy = method_destroy,

	.key_length = method_key_length,

	.session_init = method_session_init,
	.session_init_compat = method_session_init_compat,
	.session_is_valid = method_session_is_valid,
	.session_is_initiator = method_session_is_initiator,
	.session_want_refresh = method_session_want_refresh,
	.session_superseded = method_session_superseded,
	.session_free = method_session_free,

	.encrypt = method_encrypt,
	.decrypt = method_decrypt,
};
