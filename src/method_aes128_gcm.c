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
#include "crypto.h"

#include <unistd.h>


#define KEYBYTES 16
#define NONCEBYTES 7

struct _fastd_method_session_state {
	struct timespec valid_till;
	struct timespec refresh_after;

	uint8_t send_nonce[NONCEBYTES];
	uint8_t receive_nonce[NONCEBYTES];

	struct timespec receive_last;
	uint64_t receive_reorder_seen;

	fastd_crypto_aes128ctr_state *cstate_aes128ctr;
	fastd_crypto_ghash_state *cstate_ghash;
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

static inline bool is_nonce_valid(const uint8_t nonce[NONCEBYTES], const uint8_t old_nonce[NONCEBYTES], int64_t *age) {
	if ((nonce[0] & 1) != (old_nonce[0] & 1))
		return false;

	int i;
	*age = 0;

	for (i = NONCEBYTES-1; i >= 0; i--) {
		*age *= 256;
		*age += old_nonce[i]-nonce[i];
	}

	*age /= 2;
	return true;
}

static size_t method_max_packet_size(fastd_context *ctx) {
	return (fastd_max_packet_size(ctx) + NONCEBYTES + sizeof(fastd_block128));
}


static size_t method_min_encrypt_head_space(fastd_context *ctx) {
	return sizeof(fastd_block128);
}

static size_t method_min_decrypt_head_space(fastd_context *ctx) {
	return 0;
}

static size_t method_min_encrypt_tail_space(fastd_context *ctx) {
	return (sizeof(fastd_block128)-1);
}

static size_t method_min_decrypt_tail_space(fastd_context *ctx) {
	return (2*sizeof(fastd_block128)-1);
}


static fastd_method_session_state* method_session_init(fastd_context *ctx, uint8_t *secret, size_t length, bool initiator) {
	int i;

	if (length < KEYBYTES)
		exit_bug(ctx, "aes128-gcm: tried to init with short secret");

	fastd_method_session_state *session = malloc(sizeof(fastd_method_session_state));

	session->valid_till = ctx->now;
	session->valid_till.tv_sec += ctx->conf->key_valid;

	session->refresh_after = ctx->now;
	session->refresh_after.tv_sec += ctx->conf->key_refresh;

	fastd_block128 key;
	memcpy(key.b, secret, sizeof(fastd_block128));
	session->cstate_aes128ctr = ctx->conf->crypto_aes128ctr->set_key(ctx, ctx->crypto_aes128ctr, &key);

	static const fastd_block128 zeroblock = {};
	fastd_block128 H;

	ctx->conf->crypto_aes128ctr->crypt(ctx, session->cstate_aes128ctr, &H, &zeroblock, sizeof(fastd_block128), &zeroblock);

	session->cstate_ghash = ctx->conf->crypto_ghash->set_h(ctx, ctx->crypto_ghash, &H);

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
	return timespec_after(&ctx->now, &session->refresh_after);
}

static void method_session_free(fastd_context *ctx, fastd_method_session_state *session) {
	if(session) {
		ctx->conf->crypto_aes128ctr->free_state(ctx, session->cstate_aes128ctr);
		ctx->conf->crypto_ghash->free_state(ctx, session->cstate_ghash);

		memset(session, 0, sizeof(fastd_method_session_state));
		free(session);
	}
}

static inline void put_size(fastd_block128 *out, size_t len) {
	memset(out, 0, sizeof(fastd_block128)-5);
	out->b[sizeof(fastd_block128)-5] = len >> 29;
	out->b[sizeof(fastd_block128)-4] = len >> 21;
	out->b[sizeof(fastd_block128)-3] = len >> 13;
	out->b[sizeof(fastd_block128)-2] = len >> 5;
	out->b[sizeof(fastd_block128)-1] = len << 3;
}

static bool method_encrypt(fastd_context *ctx, fastd_peer *peer, fastd_method_session_state *session, fastd_buffer *out, fastd_buffer in) {
	fastd_buffer_pull_head(&in, sizeof(fastd_block128));
	memset(in.data, 0, sizeof(fastd_block128));

	size_t tail_len = alignto(in.len, sizeof(fastd_block128))-in.len;
	*out = fastd_buffer_alloc(in.len, alignto(NONCEBYTES, 16), sizeof(fastd_block128)+tail_len);

	if (tail_len)
		memset(in.data+in.len, 0, tail_len);

	fastd_block128 nonce;
	memcpy(nonce.b, session->send_nonce, NONCEBYTES);
	memset(nonce.b+NONCEBYTES, 0, sizeof(fastd_block128)-NONCEBYTES-1);
	nonce.b[sizeof(fastd_block128)-1] = 1;

	int n_blocks = (in.len+sizeof(fastd_block128)-1)/sizeof(fastd_block128);

	fastd_block128 *inblocks = in.data;
	fastd_block128 *outblocks = out->data;
	fastd_block128 sig;

	bool ok = ctx->conf->crypto_aes128ctr->crypt(ctx, session->cstate_aes128ctr, outblocks, inblocks, n_blocks*sizeof(fastd_block128), &nonce);

	if (ok) {
		if (tail_len)
			memset(out->data+out->len, 0, tail_len);

		put_size(&outblocks[n_blocks], in.len-sizeof(fastd_block128));

		ok = ctx->conf->crypto_ghash->hash(ctx, session->cstate_ghash, &sig, outblocks+1, n_blocks);
	}

	if (!ok) {
		/* restore original buffer */
		fastd_buffer_push_head(&in, sizeof(fastd_block128));
		fastd_buffer_free(*out);
		return false;
	}

	xor_a(&outblocks[0], &sig);

	fastd_buffer_free(in);

	fastd_buffer_pull_head(out, NONCEBYTES);
	memcpy(out->data, session->send_nonce, NONCEBYTES);
	increment_nonce(session->send_nonce);

	return true;
}

static bool method_decrypt(fastd_context *ctx, fastd_peer *peer, fastd_method_session_state *session, fastd_buffer *out, fastd_buffer in) {
	if (in.len < NONCEBYTES+sizeof(fastd_block128))
		return false;

	if (!method_session_is_valid(ctx, session))
		return false;

	fastd_block128 nonce;
	memcpy(nonce.b, in.data, NONCEBYTES);
	memset(nonce.b+NONCEBYTES, 0, sizeof(fastd_block128)-NONCEBYTES-1);
	nonce.b[sizeof(fastd_block128)-1] = 1;

	int64_t age;
	if (!is_nonce_valid(nonce.b, session->receive_nonce, &age))
		return false;

	if (age >= 0) {
		if (timespec_diff(&ctx->now, &session->receive_last) > ctx->conf->reorder_time*1000)
			return false;

		if (age > ctx->conf->reorder_count)
			return false;
	}

	fastd_buffer_push_head(&in, NONCEBYTES);

	size_t tail_len = alignto(in.len, sizeof(fastd_block128))-in.len;
	*out = fastd_buffer_alloc(in.len, 0, tail_len);

	int n_blocks = (in.len+sizeof(fastd_block128)-1)/sizeof(fastd_block128);

	fastd_block128 *inblocks = in.data;
	fastd_block128 *outblocks = out->data;
	fastd_block128 sig;

	bool ok = ctx->conf->crypto_aes128ctr->crypt(ctx, session->cstate_aes128ctr, outblocks, inblocks, n_blocks*sizeof(fastd_block128), &nonce);

	if (ok) {
		if (tail_len)
			memset(in.data+in.len, 0, tail_len);

		put_size(&inblocks[n_blocks], in.len-sizeof(fastd_block128));

		ok = ctx->conf->crypto_ghash->hash(ctx, session->cstate_ghash, &sig, inblocks+1, n_blocks);
	}

	if (!ok || memcmp(&sig, &outblocks[0], sizeof(fastd_block128)) != 0) {
		fastd_buffer_free(*out);

		/* restore input buffer */
		fastd_buffer_pull_head(&in, NONCEBYTES);

		return false;
	}

	fastd_buffer_free(in);

	fastd_buffer_push_head(out, sizeof(fastd_block128));

	if (age < 0) {
		session->receive_reorder_seen >>= age;
		session->receive_reorder_seen |= (1 >> (age+1));
		memcpy(session->receive_nonce, nonce.b, NONCEBYTES);
		session->receive_last = ctx->now;
	}
	else if (age == 0 || session->receive_reorder_seen & (1 << (age-1))) {
		pr_debug(ctx, "dropping duplicate packet from %P (age %u)", peer, (unsigned)age);
		fastd_buffer_free(*out);
		*out = fastd_buffer_alloc(0, 0, 0);
	}
	else {
		pr_debug(ctx, "accepting reordered packet from %P (age %u)", peer, (unsigned)age);
		session->receive_reorder_seen |= (1 << (age-1));
	}

	return true;
}

const fastd_method fastd_method_aes128_gcm = {
	.name = "aes128-gcm",

	.max_packet_size = method_max_packet_size,
	.min_encrypt_head_space = method_min_encrypt_head_space,
	.min_decrypt_head_space = method_min_decrypt_head_space,
	.min_encrypt_tail_space = method_min_encrypt_tail_space,
	.min_decrypt_tail_space = method_min_decrypt_tail_space,

	.session_init = method_session_init,
	.session_is_valid = method_session_is_valid,
	.session_is_initiator = method_session_is_initiator,
	.session_want_refresh = method_session_want_refresh,
	.session_free = method_session_free,

	.encrypt = method_encrypt,
	.decrypt = method_decrypt,
};
