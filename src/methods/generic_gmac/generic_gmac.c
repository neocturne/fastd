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


struct fastd_method {
	const fastd_cipher_info_t *cipher_info;
	const fastd_mac_info_t *ghash_info;
};

struct fastd_method_session_state {
	fastd_method_common_t common;

	const fastd_method_t *method;

	const fastd_cipher_t *cipher;
	fastd_cipher_state_t *cipher_state;

	const fastd_mac_t *ghash;
	fastd_mac_state_t *ghash_state;
};


static bool method_create_by_name(const char *name, fastd_method_t **method) {
	fastd_method_t m;

	m.ghash_info = fastd_mac_info_get_by_name("ghash");
	if (!m.ghash_info)
		return false;

	size_t len = strlen(name);
	char cipher_name[len+1];

	if (len >= 4 && !strcmp(name+len-4, "-gcm")) {
		memcpy(cipher_name, name, len-3);
		strncpy(cipher_name+len-3, "ctr", 4);
	}
	else if (len >= 5 && !strcmp(name+len-5, "+gmac")) {
		if (len >= 9 && !strcmp(name+len-9, "-ctr+gmac"))
			return false;

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

	*method = malloc(sizeof(fastd_method_t));
	**method = m;

	return true;
}

static void method_destroy(fastd_method_t *method) {
	free(method);
}

static size_t method_key_length(fastd_context_t *ctx UNUSED, const fastd_method_t *method) {
	return method->cipher_info->key_length;
}

static fastd_method_session_state_t* method_session_init(fastd_context_t *ctx, const fastd_method_t *method, const uint8_t *secret, bool initiator) {
	fastd_method_session_state_t *session = malloc(sizeof(fastd_method_session_state_t));

	fastd_method_common_init(ctx, &session->common, initiator);
	session->method = method;

	session->cipher = fastd_cipher_get(ctx, method->cipher_info);
	session->cipher_state = session->cipher->init(secret);

	static const fastd_block128_t zeroblock = {};
	fastd_block128_t H;

	size_t iv_length = method->cipher_info->iv_length;
	data_t zeroiv[iv_length];
	memset(zeroiv, 0, iv_length);

	if (!session->cipher->crypt(session->cipher_state, &H, &zeroblock, sizeof(fastd_block128_t), zeroiv)) {
		session->cipher->free(session->cipher_state);
		free(session);
		return NULL;
	}

	session->ghash = fastd_mac_get(ctx, method->ghash_info);
	session->ghash_state = session->ghash->init(H.b);

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

static void method_session_free(fastd_context_t *ctx UNUSED, fastd_method_session_state_t *session) {
	if (session) {
		session->cipher->free(session->cipher_state);
		session->ghash->free(session->ghash_state);

		free(session);
	}
}

static inline void put_size(fastd_block128_t *out, size_t len) {
	memset(out, 0, sizeof(fastd_block128_t));
	out->b[11] = len >> 29;
	out->b[12] = len >> 21;
	out->b[13] = len >> 13;
	out->b[14] = len >> 5;
	out->b[15] = len << 3;
}

static bool method_encrypt(fastd_context_t *ctx, fastd_peer_t *peer UNUSED, fastd_method_session_state_t *session, fastd_buffer_t *out, fastd_buffer_t in) {
	fastd_buffer_pull_head_zero(ctx, &in, sizeof(fastd_block128_t));

	size_t tail_len = alignto(in.len, sizeof(fastd_block128_t))-in.len;
	*out = fastd_buffer_alloc(ctx, in.len, alignto(COMMON_HEADBYTES, 16), sizeof(fastd_block128_t)+tail_len);

	if (tail_len)
		memset(in.data+in.len, 0, tail_len);

	data_t nonce[session->method->cipher_info->iv_length];
	fastd_method_expand_nonce(nonce, session->common.send_nonce, sizeof(nonce));

	int n_blocks = block_count(in.len, sizeof(fastd_block128_t));

	fastd_block128_t *inblocks = in.data;
	fastd_block128_t *outblocks = out->data;
	fastd_block128_t tag;

	bool ok = session->cipher->crypt(session->cipher_state, outblocks, inblocks, n_blocks*sizeof(fastd_block128_t), nonce);

	if (ok) {
		if (tail_len)
			memset(out->data+out->len, 0, tail_len);

		put_size(&outblocks[n_blocks], in.len-sizeof(fastd_block128_t));

		ok = session->ghash->hash(session->ghash_state, &tag, outblocks+1, n_blocks);
	}

	if (!ok) {
		fastd_buffer_free(*out);
		return false;
	}

	xor_a(&outblocks[0], &tag);

	fastd_buffer_free(in);

	fastd_method_put_common_header(ctx, out, session->common.send_nonce, 0);
	fastd_method_increment_nonce(&session->common);

	return true;
}

static bool method_decrypt(fastd_context_t *ctx, fastd_peer_t *peer, fastd_method_session_state_t *session, fastd_buffer_t *out, fastd_buffer_t in) {
	if (in.len < COMMON_HEADBYTES+sizeof(fastd_block128_t))
		return false;

	if (!method_session_is_valid(ctx, session))
		return false;

	uint8_t in_nonce[COMMON_NONCEBYTES];
	uint8_t flags;
	int64_t age;
	if (!fastd_method_handle_common_header(ctx, &session->common, &in, in_nonce, &flags, &age))
		return false;

	if (flags)
		return false;

	data_t nonce[session->method->cipher_info->iv_length];
	fastd_method_expand_nonce(nonce, in_nonce, sizeof(nonce));

	size_t tail_len = alignto(in.len, sizeof(fastd_block128_t))-in.len;
	*out = fastd_buffer_alloc(ctx, in.len, 0, tail_len);

	int n_blocks = block_count(in.len, sizeof(fastd_block128_t));

	fastd_block128_t *inblocks = in.data;
	fastd_block128_t *outblocks = out->data;
	fastd_block128_t tag;

	bool ok = session->cipher->crypt(session->cipher_state, outblocks, inblocks, n_blocks*sizeof(fastd_block128_t), nonce);

	if (ok) {
		if (tail_len)
			memset(in.data+in.len, 0, tail_len);

		put_size(&inblocks[n_blocks], in.len-sizeof(fastd_block128_t));

		ok = session->ghash->hash(session->ghash_state, &tag, inblocks+1, n_blocks);
	}

	if (!ok || memcmp(&tag, &outblocks[0], sizeof(fastd_block128_t)) != 0) {
		fastd_buffer_free(*out);
		return false;
	}

	fastd_buffer_free(in);

	fastd_buffer_push_head(ctx, out, sizeof(fastd_block128_t));

	if (!fastd_method_reorder_check(ctx, peer, &session->common, in_nonce, age)) {
		fastd_buffer_free(*out);
		*out = fastd_buffer_alloc(ctx, 0, 0, 0);
	}

	return true;
}

const fastd_method_provider_t fastd_method_generic_gmac = {
	.max_overhead = COMMON_HEADBYTES + sizeof(fastd_block128_t),
	.min_encrypt_head_space = sizeof(fastd_block128_t),
	.min_decrypt_head_space = 0,
	.min_encrypt_tail_space = sizeof(fastd_block128_t)-1,
	.min_decrypt_tail_space = 2*sizeof(fastd_block128_t)-1,

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
