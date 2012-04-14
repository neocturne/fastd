/*
  Copyright (c) 2012, Matthias Schiffer <mschiffer@universe-factory.net>
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
#include <crypto_secretbox_xsalsa20poly1305.h>


#define NONCEBYTES 7


struct _fastd_method_session_state {
	struct timespec valid_till;
	struct timespec refresh_after;

	uint8_t key[crypto_secretbox_xsalsa20poly1305_KEYBYTES];

	uint8_t send_nonce[NONCEBYTES];
	uint8_t receive_nonce[NONCEBYTES];
};


static inline void increment_nonce(uint8_t nonce[NONCEBYTES]) {
	nonce[0] += 2;

	if (nonce[0] == 0 || nonce[0] == 1) {
		int i;
		for (i = 1; i < NONCEBYTES; i++) {
			nonce[i]++;
			if (nonce[i] != 0)
				break;
		}
	}
}

static inline bool is_nonce_valid(const uint8_t nonce[NONCEBYTES], const uint8_t old_nonce[NONCEBYTES]) {
	if ((nonce[0] & 1) != (old_nonce[0] & 1))
		return false;

	int i;
	for (i = NONCEBYTES-1; i >= 0; i--) {
		if (nonce[i] > old_nonce[i])
			return true;
		if (nonce[i] < old_nonce[i])
			return false;
	}

	return false;
}

static size_t method_max_packet_size(fastd_context *ctx) {
	return (fastd_max_packet_size(ctx) + NONCEBYTES + crypto_secretbox_xsalsa20poly1305_ZEROBYTES - crypto_secretbox_xsalsa20poly1305_BOXZEROBYTES);
}

static size_t method_min_encrypt_head_space(fastd_context *ctx) {
	return crypto_secretbox_xsalsa20poly1305_ZEROBYTES;
}

static size_t method_min_decrypt_head_space(fastd_context *ctx) {
	return (crypto_secretbox_xsalsa20poly1305_BOXZEROBYTES - NONCEBYTES);
}

static fastd_method_session_state* method_session_init(fastd_context *ctx, uint8_t *secret, size_t length, bool initiator) {
	int i;

	if (length < crypto_secretbox_xsalsa20poly1305_KEYBYTES)
		exit_bug(ctx, "xsalsa20-poly1305: tried to init with short secret");
	
	fastd_method_session_state *session = malloc(sizeof(fastd_method_session_state));

	session->valid_till = ctx->now;
	session->valid_till.tv_sec += ctx->conf->key_valid;

	session->refresh_after = ctx->now;
	session->refresh_after.tv_sec += ctx->conf->key_refresh;

	memcpy(session->key, secret, crypto_secretbox_xsalsa20poly1305_KEYBYTES);

	session->send_nonce[0] = initiator ? 3 : 2;
	session->receive_nonce[0] = initiator ? 0 : 1;

	for (i = 1; i < NONCEBYTES; i++) {
		session->send_nonce[i] = 0;
		session->receive_nonce[i] = 0;
	}

	return session;
}

static bool method_session_is_valid(fastd_context *ctx, fastd_method_session_state *session) {
	return (session && timespec_after(&session->valid_till, &ctx->now));
}

static bool method_session_is_initiator(fastd_context *ctx, fastd_method_session_state *session) {
	return (session->send_nonce[0] & 1);
}

static bool method_session_want_refresh(fastd_context *ctx, fastd_method_session_state *session) {
	return (method_session_is_initiator(ctx, session) && timespec_after(&ctx->now, &session->refresh_after));
}

static void method_session_free(fastd_context *ctx, fastd_method_session_state *session) {
	if(session) {
		memset(session, 0, sizeof(fastd_method_session_state));
		free(session);
	}
}

static bool method_encrypt(fastd_context *ctx, fastd_method_session_state *session, fastd_buffer *out, fastd_buffer in) {
	fastd_buffer_pull_head(&in, crypto_secretbox_xsalsa20poly1305_ZEROBYTES);
	memset(in.data, 0, crypto_secretbox_xsalsa20poly1305_ZEROBYTES);

	*out = fastd_buffer_alloc(in.len, 0, 0);

	uint8_t nonce[crypto_secretbox_xsalsa20poly1305_NONCEBYTES];
	memcpy(nonce, session->send_nonce, NONCEBYTES);
	memset(nonce+NONCEBYTES, 0, crypto_secretbox_xsalsa20poly1305_NONCEBYTES-NONCEBYTES);

	crypto_secretbox_xsalsa20poly1305(out->data, in.data, in.len, nonce, session->key);

	fastd_buffer_free(in);

	fastd_buffer_push_head(out, crypto_secretbox_xsalsa20poly1305_BOXZEROBYTES-NONCEBYTES);
	memcpy(out->data, session->send_nonce, NONCEBYTES);

	increment_nonce(session->send_nonce);

	return true;
}

static bool method_decrypt(fastd_context *ctx, fastd_method_session_state *session, fastd_buffer *out, fastd_buffer in) {
	if (in.len < NONCEBYTES)
		return false;

	if (!method_session_is_valid(ctx, session))
		return false;

	uint8_t nonce[crypto_secretbox_xsalsa20poly1305_NONCEBYTES];
	memcpy(nonce, in.data, NONCEBYTES);
	memset(nonce+NONCEBYTES, 0, crypto_secretbox_xsalsa20poly1305_NONCEBYTES-NONCEBYTES);

	if (!is_nonce_valid(nonce, session->receive_nonce))
		return false;
	
	fastd_buffer_pull_head(&in, crypto_secretbox_xsalsa20poly1305_BOXZEROBYTES-NONCEBYTES);
	memset(in.data, 0, crypto_secretbox_xsalsa20poly1305_BOXZEROBYTES);

	*out = fastd_buffer_alloc(in.len, 0, 0);

	if (crypto_secretbox_xsalsa20poly1305_open(out->data, in.data, in.len, nonce, session->key) != 0) {
		fastd_buffer_free(*out);

		/* restore input buffer */
		fastd_buffer_push_head(&in, crypto_secretbox_xsalsa20poly1305_BOXZEROBYTES-NONCEBYTES);
		memcpy(in.data, nonce, NONCEBYTES);
		return false;
	}

	fastd_buffer_free(in);

	fastd_buffer_push_head(out, crypto_secretbox_xsalsa20poly1305_ZEROBYTES);

	memcpy(session->receive_nonce, nonce, NONCEBYTES);

	return true;
}

const fastd_method fastd_method_xsalsa20_poly1305 = {
	.name = "xsalsa20-poly1305",

	.max_packet_size = method_max_packet_size,
	.min_encrypt_head_space = method_min_encrypt_head_space,
	.min_decrypt_head_space = method_min_decrypt_head_space,

	.session_init = method_session_init,
	.session_is_valid = method_session_is_valid,
	.session_is_initiator = method_session_is_initiator,
	.session_want_refresh = method_session_want_refresh,
	.session_free = method_session_free,

	.encrypt = method_encrypt,
	.decrypt = method_decrypt,
};
