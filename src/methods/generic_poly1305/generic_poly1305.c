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


#include "../../fastd.h"
#include "../common.h"

#include <crypto_onetimeauth_poly1305.h>


#define AUTHBLOCKS (block_count(crypto_onetimeauth_poly1305_KEYBYTES, sizeof(fastd_block128_t)))


struct fastd_method_session_state {
	fastd_method_common_t common;

	const fastd_cipher_t *cipher;
	const fastd_cipher_context_t *cipher_ctx;
	fastd_cipher_state_t *cipher_state;
	size_t ivlen;
};


static bool cipher_get(fastd_context_t *ctx, const char *name, const fastd_cipher_t **cipher, const fastd_cipher_context_t **cctx) {
	size_t len = strlen(name);

	if (len < 9)
		return false;

	if (strcmp(name+len-9, "+poly1305"))
		return false;

	char cipher_name[len-8];
	memcpy(cipher_name, name, len-9);
	cipher_name[len-9] = 0;

	if (ctx) {
		*cipher = fastd_cipher_get_by_name(ctx, cipher_name, cctx);
		return *cipher;
	}
	else {
		return fastd_cipher_available(cipher_name);
	}
}


static bool method_provides(const char *name) {
	return cipher_get(NULL, name, NULL, NULL);
}

static size_t method_max_packet_size(fastd_context_t *ctx) {
	return (fastd_max_packet_size(ctx) + COMMON_HEADBYTES + crypto_onetimeauth_poly1305_BYTES);
}

static size_t method_min_encrypt_head_space(fastd_context_t *ctx UNUSED) {
	return AUTHBLOCKS*sizeof(fastd_block128_t);
}

static size_t method_min_decrypt_head_space(fastd_context_t *ctx UNUSED) {
	return AUTHBLOCKS*sizeof(fastd_block128_t) - crypto_onetimeauth_poly1305_BYTES;
}

static size_t method_min_tail_space(fastd_context_t *ctx UNUSED) {
	return (sizeof(fastd_block128_t)-1);
}


static size_t method_key_length(fastd_context_t *ctx, const char *name) {
	const fastd_cipher_t *cipher = NULL;
	const fastd_cipher_context_t *cctx;
	if (!cipher_get(ctx, name, &cipher, &cctx))
		exit_bug(ctx, "generic-poly1305: can't get cipher key length");

	return cipher->key_length(ctx, cctx);
}

static fastd_method_session_state_t* method_session_init(fastd_context_t *ctx, const char *name, const uint8_t *secret, bool initiator) {
	fastd_method_session_state_t *session = malloc(sizeof(fastd_method_session_state_t));

	fastd_method_common_init(ctx, &session->common, initiator);

	if (!cipher_get(ctx, name, &session->cipher, &session->cipher_ctx))
		exit_bug(ctx, "generic-poly1305: can't instanciate cipher");

	session->cipher_state = session->cipher->init_state(ctx, session->cipher_ctx, secret);

	session->ivlen = session->cipher->iv_length(ctx, session->cipher_state);
	if (session->ivlen <= COMMON_NONCEBYTES)
		exit_bug(ctx, "generic-poly1305: iv_length to small");

	return session;
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

static void method_session_free(fastd_context_t *ctx, fastd_method_session_state_t *session) {
	if (session) {
		session->cipher->free_state(ctx, session->cipher_state);
		free(session);
	}
}

static bool method_encrypt(fastd_context_t *ctx, fastd_peer_t *peer UNUSED, fastd_method_session_state_t *session, fastd_buffer_t *out, fastd_buffer_t in) {
	fastd_buffer_pull_head(ctx, &in, AUTHBLOCKS*sizeof(fastd_block128_t));
	memset(in.data, 0, AUTHBLOCKS*sizeof(fastd_block128_t));

	size_t tail_len = alignto(in.len, sizeof(fastd_block128_t))-in.len;
	*out = fastd_buffer_alloc(ctx, in.len, alignto(COMMON_HEADBYTES, 16), sizeof(fastd_block128_t)+tail_len);

	if (tail_len)
		memset(in.data+in.len, 0, tail_len);

	uint8_t nonce[session->ivlen];
	memset(nonce, 0, session->ivlen);
	memcpy(nonce, session->common.send_nonce, COMMON_NONCEBYTES);
	nonce[session->ivlen-1] = 1;

	int n_blocks = block_count(in.len, sizeof(fastd_block128_t));

	fastd_block128_t *inblocks = in.data;
	fastd_block128_t *outblocks = out->data;
	uint8_t tag[crypto_onetimeauth_poly1305_BYTES];

	bool ok = session->cipher->crypt(ctx, session->cipher_state, outblocks, inblocks, n_blocks*sizeof(fastd_block128_t), nonce);

	if (!ok) {
		/* restore original buffer */
		fastd_buffer_push_head(ctx, &in, AUTHBLOCKS*sizeof(fastd_block128_t));
		fastd_buffer_free(*out);
		return false;
	}

	crypto_onetimeauth_poly1305(tag, (const uint8_t*)(outblocks+AUTHBLOCKS), in.len - AUTHBLOCKS*sizeof(fastd_block128_t), (const uint8_t*)outblocks);

	fastd_buffer_push_head(ctx, out, AUTHBLOCKS*sizeof(fastd_block128_t) - crypto_onetimeauth_poly1305_BYTES);
	memcpy(out->data, tag, crypto_onetimeauth_poly1305_BYTES);

	fastd_buffer_free(in);

	fastd_buffer_pull_head(ctx, out, COMMON_HEADBYTES);

	memcpy(out->data, session->common.send_nonce, COMMON_NONCEBYTES);
	fastd_method_increment_nonce(&session->common);

	((uint8_t*)out->data)[COMMON_NONCEBYTES] = 0; /* flags */

	return true;
}

static bool method_decrypt(fastd_context_t *ctx, fastd_peer_t *peer, fastd_method_session_state_t *session, fastd_buffer_t *out, fastd_buffer_t in) {
	if (in.len < COMMON_HEADBYTES+crypto_onetimeauth_poly1305_BYTES)
		return false;

	if (!method_session_is_valid(ctx, session))
		return false;

	if (((const uint8_t*)in.data)[COMMON_NONCEBYTES]) /* flags */
		return false;

	uint8_t nonce[session->ivlen];
	memset(nonce, 0, session->ivlen);
	memcpy(nonce, in.data, COMMON_NONCEBYTES);
	nonce[session->ivlen-1] = 1;

	int64_t age;
	if (!fastd_method_is_nonce_valid(ctx, &session->common, nonce, &age))
		return false;

	fastd_buffer_push_head(ctx, &in, COMMON_HEADBYTES);

	uint8_t tag[crypto_onetimeauth_poly1305_BYTES];
	memcpy(tag, in.data, crypto_onetimeauth_poly1305_BYTES);

	fastd_buffer_pull_head(ctx, &in, AUTHBLOCKS*sizeof(fastd_block128_t) - crypto_onetimeauth_poly1305_BYTES);
	memset(in.data, 0, AUTHBLOCKS*sizeof(fastd_block128_t));

	size_t tail_len = alignto(in.len, sizeof(fastd_block128_t))-in.len;
	*out = fastd_buffer_alloc(ctx, in.len, 0, tail_len);

	int n_blocks = block_count(in.len, sizeof(fastd_block128_t));
	fastd_block128_t *inblocks = in.data;
	fastd_block128_t *outblocks = out->data;

	bool ok = session->cipher->crypt(ctx, session->cipher_state, outblocks, inblocks, n_blocks*sizeof(fastd_block128_t), nonce);

	if (ok) {
		if (tail_len)
			memset(in.data+in.len, 0, tail_len);

		ok = (crypto_onetimeauth_poly1305_verify(tag, in.data+AUTHBLOCKS*sizeof(fastd_block128_t), in.len - AUTHBLOCKS*sizeof(fastd_block128_t), out->data) == 0);
	}

	if (!ok) {
		fastd_buffer_free(*out);

		/* restore input buffer */
		fastd_buffer_push_head(ctx, &in, AUTHBLOCKS*sizeof(fastd_block128_t) - crypto_onetimeauth_poly1305_BYTES);
		memcpy(in.data, tag, crypto_onetimeauth_poly1305_BYTES);
		fastd_buffer_pull_head(ctx, &in, COMMON_HEADBYTES);
		memcpy(in.data, nonce, COMMON_NONCEBYTES);
		((uint8_t*)in.data)[COMMON_NONCEBYTES] = 0;

		return false;
	}

	fastd_buffer_free(in);

	fastd_buffer_push_head(ctx, out, AUTHBLOCKS*sizeof(fastd_block128_t));

	if (!fastd_method_reorder_check(ctx, peer, &session->common, nonce, age)) {
		fastd_buffer_free(*out);
		*out = fastd_buffer_alloc(ctx, 0, 0, 0);
	}

	return true;
}

const fastd_method_t fastd_method_generic_poly1305 = {
	.provides = method_provides,

	.max_packet_size = method_max_packet_size,
	.min_encrypt_head_space = method_min_encrypt_head_space,
	.min_decrypt_head_space = method_min_decrypt_head_space,
	.min_encrypt_tail_space = method_min_tail_space,
	.min_decrypt_tail_space = method_min_tail_space,

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
