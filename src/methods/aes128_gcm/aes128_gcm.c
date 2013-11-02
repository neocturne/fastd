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
#include "../../crypto.h"
#include "../common.h"


struct fastd_method_session_state {
	fastd_method_common_t common;

	const fastd_cipher_t *aes128_ctr;
	fastd_cipher_context_t *aes128_ctr_ctx;
	fastd_cipher_state_t *aes128_ctr_state;

	fastd_crypto_ghash_state_t *cstate_ghash;
};


static size_t method_max_packet_size(fastd_context_t *ctx) {
	return (fastd_max_packet_size(ctx) + COMMON_NONCEBYTES + sizeof(fastd_block128_t));
}


static size_t method_min_encrypt_head_space(fastd_context_t *ctx UNUSED) {
	return sizeof(fastd_block128_t);
}

static size_t method_min_decrypt_head_space(fastd_context_t *ctx UNUSED) {
	return 0;
}

static size_t method_min_encrypt_tail_space(fastd_context_t *ctx UNUSED) {
	return (sizeof(fastd_block128_t)-1);
}

static size_t method_min_decrypt_tail_space(fastd_context_t *ctx UNUSED) {
	return (2*sizeof(fastd_block128_t)-1);
}


static size_t method_key_length(fastd_context_t *ctx UNUSED) {
	return sizeof(fastd_block128_t);
}

static fastd_method_session_state_t* method_session_init(fastd_context_t *ctx, const uint8_t *secret, bool initiator) {
	fastd_method_session_state_t *session = malloc(sizeof(fastd_method_session_state_t));

	fastd_method_common_init(ctx, &session->common, initiator);

	session->aes128_ctr = fastd_cipher_get_by_name(ctx, "aes128-ctr", &session->aes128_ctr_ctx);
	if (!session->aes128_ctr)
		exit_bug(ctx, "aes128-gcm: can't instanciate aes128-ctr");

	session->aes128_ctr_state = session->aes128_ctr->init_state(ctx, session->aes128_ctr_ctx, secret);

	static const fastd_block128_t zeroblock = {};
	fastd_block128_t H;

	session->aes128_ctr->crypt(ctx, session->aes128_ctr_state, &H, &zeroblock, sizeof(fastd_block128_t), &zeroblock);

	session->cstate_ghash = ctx->conf->crypto_ghash->set_h(ctx, ctx->crypto_ghash, &H);

	return session;
}

static fastd_method_session_state_t* method_session_init_compat(fastd_context_t *ctx, const uint8_t *secret, size_t length, bool initiator) {
	if (length < sizeof(fastd_block128_t))
		exit_bug(ctx, "aes128-gcm: tried to init with short secret");

	return method_session_init(ctx, secret, initiator);
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
		session->aes128_ctr->free_state(ctx, session->aes128_ctr_state);
		ctx->conf->crypto_ghash->free_state(ctx, session->cstate_ghash);

		secure_memzero(session, sizeof(fastd_method_session_state_t));
		free(session);
	}
}

static inline void put_size(fastd_block128_t *out, size_t len) {
	memset(out, 0, sizeof(fastd_block128_t)-5);
	out->b[sizeof(fastd_block128_t)-5] = len >> 29;
	out->b[sizeof(fastd_block128_t)-4] = len >> 21;
	out->b[sizeof(fastd_block128_t)-3] = len >> 13;
	out->b[sizeof(fastd_block128_t)-2] = len >> 5;
	out->b[sizeof(fastd_block128_t)-1] = len << 3;
}

static bool method_encrypt(fastd_context_t *ctx, fastd_peer_t *peer UNUSED, fastd_method_session_state_t *session, fastd_buffer_t *out, fastd_buffer_t in) {
	fastd_buffer_pull_head(ctx, &in, sizeof(fastd_block128_t));
	memset(in.data, 0, sizeof(fastd_block128_t));

	size_t tail_len = alignto(in.len, sizeof(fastd_block128_t))-in.len;
	*out = fastd_buffer_alloc(ctx, in.len, alignto(COMMON_NONCEBYTES, 16), sizeof(fastd_block128_t)+tail_len);

	if (tail_len)
		memset(in.data+in.len, 0, tail_len);

	fastd_block128_t nonce;
	memcpy(nonce.b, session->common.send_nonce, COMMON_NONCEBYTES);
	memset(nonce.b+COMMON_NONCEBYTES, 0, sizeof(fastd_block128_t)-COMMON_NONCEBYTES-1);
	nonce.b[sizeof(fastd_block128_t)-1] = 1;

	int n_blocks = (in.len+sizeof(fastd_block128_t)-1)/sizeof(fastd_block128_t);

	fastd_block128_t *inblocks = in.data;
	fastd_block128_t *outblocks = out->data;
	fastd_block128_t sig;

	bool ok = session->aes128_ctr->crypt(ctx, session->aes128_ctr_state, outblocks, inblocks, n_blocks*sizeof(fastd_block128_t), &nonce);

	if (ok) {
		if (tail_len)
			memset(out->data+out->len, 0, tail_len);

		put_size(&outblocks[n_blocks], in.len-sizeof(fastd_block128_t));

		ok = ctx->conf->crypto_ghash->hash(ctx, session->cstate_ghash, &sig, outblocks+1, n_blocks);
	}

	if (!ok) {
		/* restore original buffer */
		fastd_buffer_push_head(ctx, &in, sizeof(fastd_block128_t));
		fastd_buffer_free(*out);
		return false;
	}

	xor_a(&outblocks[0], &sig);

	fastd_buffer_free(in);

	fastd_buffer_pull_head(ctx, out, COMMON_NONCEBYTES);
	memcpy(out->data, session->common.send_nonce, COMMON_NONCEBYTES);
	fastd_method_increment_nonce(&session->common);

	return true;
}

static bool method_decrypt(fastd_context_t *ctx, fastd_peer_t *peer, fastd_method_session_state_t *session, fastd_buffer_t *out, fastd_buffer_t in) {
	if (in.len < COMMON_NONCEBYTES+sizeof(fastd_block128_t))
		return false;

	if (!method_session_is_valid(ctx, session))
		return false;

	fastd_block128_t nonce;
	memcpy(nonce.b, in.data, COMMON_NONCEBYTES);
	memset(nonce.b+COMMON_NONCEBYTES, 0, sizeof(fastd_block128_t)-COMMON_NONCEBYTES-1);
	nonce.b[sizeof(fastd_block128_t)-1] = 1;

	int64_t age;
	if (!fastd_method_is_nonce_valid(ctx, &session->common, nonce.b, &age))
		return false;

	fastd_buffer_push_head(ctx, &in, COMMON_NONCEBYTES);

	size_t tail_len = alignto(in.len, sizeof(fastd_block128_t))-in.len;
	*out = fastd_buffer_alloc(ctx, in.len, 0, tail_len);

	int n_blocks = (in.len+sizeof(fastd_block128_t)-1)/sizeof(fastd_block128_t);

	fastd_block128_t *inblocks = in.data;
	fastd_block128_t *outblocks = out->data;
	fastd_block128_t sig;

	bool ok = session->aes128_ctr->crypt(ctx, session->aes128_ctr_state, outblocks, inblocks, n_blocks*sizeof(fastd_block128_t), &nonce);

	if (ok) {
		if (tail_len)
			memset(in.data+in.len, 0, tail_len);

		put_size(&inblocks[n_blocks], in.len-sizeof(fastd_block128_t));

		ok = ctx->conf->crypto_ghash->hash(ctx, session->cstate_ghash, &sig, inblocks+1, n_blocks);
	}

	if (!ok || memcmp(&sig, &outblocks[0], sizeof(fastd_block128_t)) != 0) {
		fastd_buffer_free(*out);
		return false;
	}

	fastd_buffer_free(in);

	fastd_buffer_push_head(ctx, out, sizeof(fastd_block128_t));

	if (!fastd_method_reorder_check(ctx, peer, &session->common, nonce.b, age)) {
		fastd_buffer_free(*out);
		*out = fastd_buffer_alloc(ctx, 0, 0, 0);
	}

	return true;
}

const fastd_method_t fastd_method_aes128_gcm = {
	.name = "aes128-gcm",

	.max_packet_size = method_max_packet_size,
	.min_encrypt_head_space = method_min_encrypt_head_space,
	.min_decrypt_head_space = method_min_decrypt_head_space,
	.min_encrypt_tail_space = method_min_encrypt_tail_space,
	.min_decrypt_tail_space = method_min_decrypt_tail_space,

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
