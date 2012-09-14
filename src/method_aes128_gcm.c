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


static size_t method_min_encrypt_head_space(fastd_context *ctx) {
	return 0;
}

static size_t method_min_decrypt_head_space(fastd_context *ctx) {
	return 0;
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

static inline void xor(uint8_t *x, const uint8_t *a, const uint8_t *b, unsigned int l) {
	int i;
	for (i = 0; i < l; i++)
		x[i] = a[i] ^ b[i];
}

static inline void xor_block(block_t *x, const block_t *a) {
	x->qw[0] ^= a->qw[0];
	x->qw[1] ^= a->qw[1];
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

	uint8_t zerononce[crypto_stream_aes128ctr_NONCEBYTES];
	memset(zerononce, 0, crypto_stream_aes128ctr_NONCEBYTES);

	block_t Hbase[4];
	crypto_stream_aes128ctr_afternm(Hbase[0].b, BLOCKBYTES, zerononce, session->d);

	block_t Rbase[4];
	Rbase[0] = r;

	for (i = 1; i < 4; i++) {
		uint8_t carry = shr(&Hbase[i], &Hbase[i-1], 1);
		if (carry)
			xor_block(&Hbase[i], &r);

		shr(&Rbase[i], &Rbase[i-1], 1);
	}

	block_t R[16];
	memset(session->H, 0, sizeof(session->H));
	memset(R, 0, sizeof(R));

	for (i = 0; i < 16; i++) {
		int j;
		for (j = 0; j < 4; j++) {
			if (i & (8 >> j)) {
				xor_block(&session->H[0][i], &Hbase[j]);
				xor_block(&R[i], &Rbase[j]);
			}
		}
	}

	for (i = 1; i < 32; i++) {
		int j;

		for (j = 0; j < 16; j++) {
			uint8_t carry = shr(&session->H[i][j], &session->H[i-1][j], 4);
			xor_block(&session->H[i][j], &R[carry]);
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

static void mulH(uint8_t out[BLOCKBYTES], const uint8_t in[BLOCKBYTES], fastd_method_session_state *session) {
	block_t out2;
	memset(&out2, 0, BLOCKBYTES);

	int i;
	for (i = 0; i < 16; i++) {
		xor_block(&out2, &session->H[2*i][in[i]>>4]);
		xor_block(&out2, &session->H[2*i+1][in[i]&0xf]);
	}

	memcpy(out, &out2, BLOCKBYTES);
}

#define BLOCKPTR(buf, i) (((uint8_t*)(buf))+(i)*BLOCKBYTES)

static bool method_encrypt(fastd_context *ctx, fastd_peer *peer, fastd_method_session_state *session, fastd_buffer *out, fastd_buffer in) {
	*out = fastd_buffer_alloc(in.len, NONCEBYTES+BLOCKBYTES, 0);
	uint8_t *sig = ((uint8_t*)out->data) - BLOCKBYTES;

	memset(sig, 0, BLOCKBYTES);

	uint8_t nonce[crypto_stream_aes128ctr_NONCEBYTES];
	memcpy(nonce, session->send_nonce, NONCEBYTES);
	memset(nonce+NONCEBYTES, 0, crypto_stream_aes128ctr_NONCEBYTES-NONCEBYTES-1);
	nonce[crypto_stream_aes128ctr_NONCEBYTES-1] = 1;

	uint8_t stream[in.len+BLOCKBYTES];
	crypto_stream_aes128ctr_afternm(stream, in.len+BLOCKBYTES, nonce, session->d);

	int blocks = (in.len+BLOCKBYTES-1)/BLOCKBYTES;

	int i;
	for (i = 0; i < blocks; i++) {
		int len = BLOCKBYTES;
		if (i == blocks-1)
			len = in.len - i*BLOCKBYTES;

		xor(BLOCKPTR(out->data, i), BLOCKPTR(in.data, i), BLOCKPTR(stream, i+1), len);

		xor(sig, sig, BLOCKPTR(out->data, i), len);
		mulH(sig, sig, session);
	}

	sig[BLOCKBYTES-5] ^= (in.len >> 29) & 0xff;
	sig[BLOCKBYTES-4] ^= (in.len >> 21) & 0xff;
	sig[BLOCKBYTES-3] ^= (in.len >> 13) & 0xff;
	sig[BLOCKBYTES-2] ^= (in.len >> 5) & 0xff;
	sig[BLOCKBYTES-1] ^= (in.len << 3) & 0xff;
	mulH(sig, sig, session);

	xor(sig, sig, stream, BLOCKBYTES);

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

	*out = fastd_buffer_alloc(in.len, 0, 0);

	uint8_t sig[BLOCKBYTES];
	memset(sig, 0, BLOCKBYTES);

	uint8_t stream[in.len+BLOCKBYTES];
	crypto_stream_aes128ctr_afternm(stream, in.len+BLOCKBYTES, nonce, session->d);

	int blocks = (in.len+BLOCKBYTES-1)/BLOCKBYTES;

	int i;
	for (i = 0; i < blocks; i++) {
		int len = BLOCKBYTES;
		if (i == blocks-1)
			len = in.len - i*BLOCKBYTES;

		xor(BLOCKPTR(out->data, i), BLOCKPTR(in.data, i), BLOCKPTR(stream, i+1), len);

		xor(sig, sig, BLOCKPTR(in.data, i), len);
		mulH(sig, sig, session);
	}

	sig[BLOCKBYTES-5] ^= (in.len >> 29) & 0xff;
	sig[BLOCKBYTES-4] ^= (in.len >> 21) & 0xff;
	sig[BLOCKBYTES-3] ^= (in.len >> 13) & 0xff;
	sig[BLOCKBYTES-2] ^= (in.len >> 5) & 0xff;
	sig[BLOCKBYTES-1] ^= (in.len << 3) & 0xff;
	mulH(sig, sig, session);

	xor(sig, sig, stream, BLOCKBYTES);

	fastd_buffer_pull_head(&in, BLOCKBYTES);

	if (memcmp(sig, in.data, BLOCKBYTES) != 0) {
		fastd_buffer_free(*out);

		/* restore input buffer */
		fastd_buffer_pull_head(&in, NONCEBYTES);

		return false;
	}

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
