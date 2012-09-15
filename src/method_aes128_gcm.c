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
#include <crypto_stream_aes128ctr.h>


#define NONCEBYTES 7
#define BLOCKBYTES 16
#define BLOCKQWORDS (BLOCKBYTES/8)


typedef union _block_t {
	uint8_t b[BLOCKBYTES];
	uint64_t qw[BLOCKQWORDS];
} block_t;

struct _fastd_method_session_state {
	struct timespec valid_till;
	struct timespec refresh_after;

	uint8_t d[crypto_stream_aes128ctr_BEFORENMBYTES];
	block_t H[32][16];

	uint8_t send_nonce[NONCEBYTES];
	uint8_t receive_nonce[NONCEBYTES];

	struct timespec receive_last;
	uint64_t receive_reorder_seen;
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
	return (fastd_max_packet_size(ctx) + NONCEBYTES + BLOCKBYTES);
}


static size_t method_min_head_space(fastd_context *ctx) {
	return 0;
}

static size_t method_min_encrypt_tail_space(fastd_context *ctx) {
	return (BLOCKBYTES-1);
}

static size_t method_min_decrypt_tail_space(fastd_context *ctx) {
	return (2*BLOCKBYTES-1);
}


static const block_t r = { .b = {0xe1} };

static inline uint8_t shr(block_t *out, const block_t *in, int n) {
	int i;
	uint8_t c = 0;

	for (i = 0; i < BLOCKBYTES; i++) {
		uint8_t c2 = in->b[i] << (8-n);
		out->b[i] = (in->b[i] >> n) | c;
		c = c2;
	}

	return (c >> (8-n));
}

static inline void xor(block_t *x, const block_t *a, const block_t *b) {
	x->qw[0] = a->qw[0] ^ b->qw[0];
	x->qw[1] = a->qw[1] ^ b->qw[1];
}

static inline void xor_a(block_t *x, const block_t *a) {
	xor(x, x, a);
}

static fastd_method_session_state* method_session_init(fastd_context *ctx, uint8_t *secret, size_t length, bool initiator) {
	int i;

	if (length < crypto_stream_aes128ctr_KEYBYTES)
		exit_bug(ctx, "aes128-gcm: tried to init with short secret");

	fastd_method_session_state *session = malloc(sizeof(fastd_method_session_state));

	session->valid_till = ctx->now;
	session->valid_till.tv_sec += ctx->conf->key_valid;

	session->refresh_after = ctx->now;
	session->refresh_after.tv_sec += ctx->conf->key_refresh;

	crypto_stream_aes128ctr_beforenm(session->d, secret);

	static const uint8_t zerononce[crypto_stream_aes128ctr_NONCEBYTES] = {};

	block_t Hbase[4];
	crypto_stream_aes128ctr_afternm(Hbase[0].b, BLOCKBYTES, zerononce, session->d);

	block_t Rbase[4];
	Rbase[0] = r;

	for (i = 1; i < 4; i++) {
		uint8_t carry = shr(&Hbase[i], &Hbase[i-1], 1);
		if (carry)
			xor_a(&Hbase[i], &r);

		shr(&Rbase[i], &Rbase[i-1], 1);
	}

	block_t R[16];
	memset(session->H, 0, sizeof(session->H));
	memset(R, 0, sizeof(R));

	for (i = 0; i < 16; i++) {
		int j;
		for (j = 0; j < 4; j++) {
			if (i & (8 >> j)) {
				xor_a(&session->H[0][i], &Hbase[j]);
				xor_a(&R[i], &Rbase[j]);
			}
		}
	}

	for (i = 1; i < 32; i++) {
		int j;

		for (j = 0; j < 16; j++) {
			uint8_t carry = shr(&session->H[i][j], &session->H[i-1][j], 4);
			xor_a(&session->H[i][j], &R[carry]);
		}
	}

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
		memset(session, 0, sizeof(fastd_method_session_state));
		free(session);
	}
}

static void mulH_a(block_t *x, fastd_method_session_state *session) {
	block_t out = {};

	int i;
	for (i = 0; i < 16; i++) {
		xor_a(&out, &session->H[2*i][x->b[i]>>4]);
		xor_a(&out, &session->H[2*i+1][x->b[i]&0xf]);
	}

	*x = out;
}

static inline void xor_blocks(block_t *out, const block_t *in1, const block_t *in2, size_t n_blocks) {
	int i;
	for (i = 0; i < n_blocks; i++)
		xor(&out[i], &in1[i], &in2[i]);
}

static inline void put_size(block_t *out, size_t len) {
	memset(out, 0, BLOCKBYTES-5);
	out->b[BLOCKBYTES-5] = len >> 29;
	out->b[BLOCKBYTES-4] = len >> 21;
	out->b[BLOCKBYTES-3] = len >> 13;
	out->b[BLOCKBYTES-2] = len >> 5;
	out->b[BLOCKBYTES-1] = len << 3;
}

static inline void ghash(block_t *out, const block_t *blocks, size_t n_blocks, fastd_method_session_state *session) {
	memset(out, 0, sizeof(block_t));

	int i;
	for (i = 0; i < n_blocks; i++) {
		xor_a(out, &blocks[i]);
		mulH_a(out, session);
	}
}

static bool method_encrypt(fastd_context *ctx, fastd_peer *peer, fastd_method_session_state *session, fastd_buffer *out, fastd_buffer in) {
	size_t tail_len = ALIGN(in.len, BLOCKBYTES)-in.len;
	*out = fastd_buffer_alloc(in.len, ALIGN(NONCEBYTES+BLOCKBYTES, 8), BLOCKBYTES+tail_len);

	if (tail_len)
		memset(in.data+in.len, 0, tail_len);

	uint8_t nonce[crypto_stream_aes128ctr_NONCEBYTES];
	memcpy(nonce, session->send_nonce, NONCEBYTES);
	memset(nonce+NONCEBYTES, 0, crypto_stream_aes128ctr_NONCEBYTES-NONCEBYTES-1);
	nonce[crypto_stream_aes128ctr_NONCEBYTES-1] = 1;

	int n_blocks = (in.len+BLOCKBYTES-1)/BLOCKBYTES;

	block_t stream[n_blocks+1];
	crypto_stream_aes128ctr_afternm((uint8_t*)stream, sizeof(stream), nonce, session->d);

	block_t *inblocks = in.data;
	block_t *outblocks = out->data;

	xor_blocks(outblocks, inblocks, stream+1, n_blocks);

	if (tail_len)
		memset(out->data+out->len, 0, tail_len);

	put_size(&outblocks[n_blocks], in.len);

	block_t *sig = outblocks-1;
	ghash(sig, outblocks, n_blocks+1, session);
	xor_a(sig, &stream[0]);

	fastd_buffer_free(in);

	fastd_buffer_pull_head(out, NONCEBYTES+BLOCKBYTES);
	memcpy(out->data, session->send_nonce, NONCEBYTES);
	increment_nonce(session->send_nonce);

	return true;
}

static bool method_decrypt(fastd_context *ctx, fastd_peer *peer, fastd_method_session_state *session, fastd_buffer *out, fastd_buffer in) {
	if (in.len < NONCEBYTES+BLOCKBYTES)
		return false;

	if (!method_session_is_valid(ctx, session))
		return false;

	uint8_t nonce[crypto_stream_aes128ctr_NONCEBYTES];
	memcpy(nonce, in.data, NONCEBYTES);
	memset(nonce+NONCEBYTES, 0, crypto_stream_aes128ctr_NONCEBYTES-NONCEBYTES-1);
	nonce[crypto_stream_aes128ctr_NONCEBYTES-1] = 1;

	int64_t age;
	if (!is_nonce_valid(nonce, session->receive_nonce, &age))
		return false;

	if (age >= 0) {
		if (timespec_diff(&ctx->now, &session->receive_last) > ctx->conf->reorder_time*1000)
			return false;

		if (age > ctx->conf->reorder_count)
			return false;
	}

	fastd_buffer_push_head(&in, NONCEBYTES+BLOCKBYTES);

	size_t tail_len = ALIGN(in.len, BLOCKBYTES)-in.len;
	*out = fastd_buffer_alloc(in.len, 0, tail_len);

	int n_blocks = (in.len+BLOCKBYTES-1)/BLOCKBYTES;

	block_t stream[n_blocks+1];
	crypto_stream_aes128ctr_afternm((uint8_t*)stream, sizeof(stream), nonce, session->d);

	block_t *inblocks = in.data;
	block_t *outblocks = out->data;

	if (tail_len)
		memset(in.data+in.len, 0, tail_len);

	put_size(&inblocks[n_blocks], in.len);

	block_t sig;
	ghash(&sig, inblocks, n_blocks+1, session);
	xor_a(&sig, &stream[0]);

	if (memcmp(&sig, inblocks-1, BLOCKBYTES) != 0) {
		fastd_buffer_free(*out);

		/* restore input buffer */
		fastd_buffer_pull_head(&in, NONCEBYTES+BLOCKBYTES);

		return false;
	}

	xor_blocks(outblocks, inblocks, stream+1, n_blocks);

	fastd_buffer_free(in);

	if (age < 0) {
		session->receive_reorder_seen >>= age;
		session->receive_reorder_seen |= (1 >> (age+1));
		memcpy(session->receive_nonce, nonce, NONCEBYTES);
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
	.min_encrypt_head_space = method_min_head_space,
	.min_decrypt_head_space = method_min_head_space,
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
