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


#include "../../crypto.h"
#include "../../method.h"
#include "../common.h"

#include <crypto_secretbox_xsalsa20poly1305.h>


struct fastd_method_session_state {
	fastd_method_common_t common;

	data_t key[crypto_secretbox_xsalsa20poly1305_KEYBYTES];
};


static bool method_create_by_name(const char *name, fastd_method_t **method UNUSED) {
	return !strcmp(name, "xsalsa20-poly1305");
}

static void method_destroy(fastd_method_t *method UNUSED) {
}

static size_t method_key_length(fastd_context_t *ctx UNUSED, const fastd_method_t *method UNUSED) {
	return crypto_secretbox_xsalsa20poly1305_KEYBYTES;
}

static fastd_method_session_state_t* method_session_init(fastd_context_t *ctx, const fastd_method_t *method UNUSED, const uint8_t *secret, bool initiator) {
	fastd_method_session_state_t *session = malloc(sizeof(fastd_method_session_state_t));

	fastd_method_common_init(ctx, &session->common, initiator);

	memcpy(session->key, secret, crypto_secretbox_xsalsa20poly1305_KEYBYTES);

	return session;
}

static fastd_method_session_state_t* method_session_init_compat(fastd_context_t *ctx, const fastd_method_t *method, const uint8_t *secret, size_t length, bool initiator) {
	if (length < crypto_secretbox_xsalsa20poly1305_KEYBYTES)
		exit_bug(ctx, "xsalsa20-poly1305: tried to init with short secret");

	return method_session_init(ctx, method, secret, initiator);
}

static bool method_session_is_valid(fastd_context_t *ctx, fastd_method_session_state_t *session) {
	return (session && fastd_method_session_common_is_valid(ctx, &session->common));
}

static bool method_session_is_initiator(fastd_context_t *ctx UNUSED, fastd_method_session_state_t *session) {
	return fastd_method_session_common_is_initiator(&session->common);
}

static bool method_session_want_refresh(fastd_context_t *ctx, fastd_method_session_state_t *session) {
	return fastd_method_session_common_want_refresh(ctx, &session->common);
}

static void method_session_superseded(fastd_context_t *ctx, fastd_method_session_state_t *session) {
	fastd_method_session_common_superseded(ctx, &session->common);
}

static void method_session_free(fastd_context_t *ctx UNUSED, fastd_method_session_state_t *session) {
	if(session) {
		secure_memzero(session, sizeof(fastd_method_session_state_t));
		free(session);
	}
}


static inline void memcpy_nonce(uint8_t *dst, const uint8_t *src) {
	size_t i;
	for (i = 0; i < COMMON_NONCEBYTES; i++)
		dst[i] = src[COMMON_NONCEBYTES-i-1];
}

static inline void put_header(fastd_context_t *ctx, fastd_buffer_t *buffer, const uint8_t nonce[COMMON_NONCEBYTES], uint8_t flags) {
	fastd_buffer_pull_head_from(ctx, buffer, &flags, 1);

	fastd_buffer_pull_head(ctx, buffer, COMMON_NONCEBYTES);
	memcpy_nonce(buffer->data, nonce);
}

static inline void take_header(fastd_context_t *ctx, fastd_buffer_t *buffer, uint8_t nonce[COMMON_NONCEBYTES], uint8_t *flags) {
	memcpy_nonce(nonce, buffer->data  );
	fastd_buffer_push_head(ctx, buffer, COMMON_NONCEBYTES);

	fastd_buffer_push_head_to(ctx, buffer, flags, 1);
}

static inline bool handle_header(fastd_context_t *ctx, const fastd_method_common_t *session, fastd_buffer_t *buffer, uint8_t nonce[COMMON_NONCEBYTES], uint8_t *flags, int64_t *age) {
	take_header(ctx, buffer, nonce, flags);
	return fastd_method_is_nonce_valid(ctx, session, nonce, age);
}


static bool method_encrypt(fastd_context_t *ctx, fastd_peer_t *peer UNUSED, fastd_method_session_state_t *session, fastd_buffer_t *out, fastd_buffer_t in) {
	fastd_buffer_pull_head_zero(ctx, &in, crypto_secretbox_xsalsa20poly1305_ZEROBYTES);

	*out = fastd_buffer_alloc(ctx, in.len, 0, 0);

	data_t nonce[crypto_secretbox_xsalsa20poly1305_NONCEBYTES] = {};
	memcpy_nonce(nonce, session->common.send_nonce);

	crypto_secretbox_xsalsa20poly1305(out->data, in.data, in.len, nonce, session->key);

	fastd_buffer_free(in);

	fastd_buffer_push_head(ctx, out, crypto_secretbox_xsalsa20poly1305_BOXZEROBYTES);
	put_header(ctx, out, session->common.send_nonce, 0);
	fastd_method_increment_nonce(&session->common);

	return true;
}

static bool method_decrypt(fastd_context_t *ctx, fastd_peer_t *peer, fastd_method_session_state_t *session, fastd_buffer_t *out, fastd_buffer_t in) {
	if (in.len < COMMON_HEADBYTES)
		return false;

	if (!method_session_is_valid(ctx, session))
		return false;

	uint8_t in_nonce[COMMON_NONCEBYTES];
	uint8_t flags;
	int64_t age;
	if (!handle_header(ctx, &session->common, &in, in_nonce, &flags, &age))
		return false;

	if (flags)
		return false;

	data_t nonce[crypto_secretbox_xsalsa20poly1305_NONCEBYTES] = {};
	memcpy_nonce(nonce, in_nonce);

	fastd_buffer_pull_head_zero(ctx, &in, crypto_secretbox_xsalsa20poly1305_BOXZEROBYTES);

	*out = fastd_buffer_alloc(ctx, in.len, 0, 0);

	if (crypto_secretbox_xsalsa20poly1305_open(out->data, in.data, in.len, nonce, session->key) != 0) {
		fastd_buffer_free(*out);

		/* restore input buffer */
		fastd_buffer_push_head(ctx, &in, crypto_secretbox_xsalsa20poly1305_BOXZEROBYTES);
		put_header(ctx, &in, in_nonce, 0);
		return false;
	}

	fastd_buffer_free(in);

	if (!fastd_method_reorder_check(ctx, peer, &session->common, in_nonce, age)) {
		fastd_buffer_free(*out);
		*out = fastd_buffer_alloc(ctx, crypto_secretbox_xsalsa20poly1305_ZEROBYTES, 0, 0);
	}

	fastd_buffer_push_head(ctx, out, crypto_secretbox_xsalsa20poly1305_ZEROBYTES);

	return true;
}


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
