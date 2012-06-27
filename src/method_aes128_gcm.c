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


struct _fastd_method_session_state {
	struct timespec valid_till;
	struct timespec refresh_after;

	uint8_t d[crypto_stream_aes128ctr_BEFORENMBYTES];
	uint8_t H[BLOCKBYTES];

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
	crypto_stream_aes128ctr_afternm(session->H, BLOCKBYTES, zerononce, session->d);

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

static void sel(uint8_t *out, const uint8_t *r, const uint8_t *s, unsigned int l, unsigned int b) {
        unsigned int j;
        unsigned int t;
        uint8_t bminus1;

        bminus1 = b - 1;
        for (j = 0; j < l; ++j) {
                t = bminus1 & (r[j] ^ s[j]);
                out[j] = s[j] ^ t;
        }
}

static inline void xor(uint8_t *x, const uint8_t *a, const uint8_t *b, unsigned int l) {
	int i;
	for (i = 0; i < l; i++)
		x[i] = a[i] ^ b[i];
}

static inline void shl1(uint8_t *x, unsigned int l) {
	int i;
	uint8_t c = 0;

	for (i = 0; i < l; i++) {
		uint8_t c2 = x[i] >> 7;
		x[i] = (x[i] << 1) | c;
		c = c2;
	}
}

static inline void shr1(uint8_t *x, unsigned int l) {
	int i;
	uint8_t c = 0;

	for (i = l-1; i >= 0; i--) {
		uint8_t c2 = x[i] & 1;
		x[i] = (x[i] >> 1) | (c << 7);
		c = c2;
	}
}

static const uint8_t p[BLOCKBYTES] = {0x87};

static void mul(uint8_t out[BLOCKBYTES], const uint8_t a[BLOCKBYTES], const uint8_t b[BLOCKBYTES]) {
	uint8_t out2[2*BLOCKBYTES];
	uint8_t zero[2*BLOCKBYTES];
	uint8_t a2[2*BLOCKBYTES];
	uint8_t b2[BLOCKBYTES];

	memset(out2, 0, 2*BLOCKBYTES);
	memset(zero, 0, 2*BLOCKBYTES);

	memcpy(a2, a, BLOCKBYTES);
	memset(a2+BLOCKBYTES, 0, BLOCKBYTES);

	memcpy(b2, b, BLOCKBYTES);

	int i;
	for (i = 0; i < 8*BLOCKBYTES; i++) {
		uint8_t tmp[2*BLOCKBYTES];

		sel(tmp, zero, a2, 2*BLOCKBYTES, b2[0]&1);
		xor(out2, out2, tmp, 2*BLOCKBYTES);

		shl1(a2, 2*BLOCKBYTES);
		shr1(b2, BLOCKBYTES);
	}

	uint8_t out3[BLOCKBYTES+1];
	memcpy(out3, out2, BLOCKBYTES);
	out3[BLOCKBYTES] = 0;

	uint8_t p2[BLOCKBYTES+1];
	memcpy(p2, p, BLOCKBYTES);
	p2[BLOCKBYTES] = 0;

	for (i = 0; i < 8*BLOCKBYTES; i++) {
		uint8_t tmp[BLOCKBYTES+1];

		sel(tmp, zero, p2, BLOCKBYTES+1, out2[BLOCKBYTES]&1);
		xor(out3, out3, tmp, BLOCKBYTES+1);

		shl1(p2, BLOCKBYTES+1);
		shr1(out2+BLOCKBYTES, BLOCKBYTES);
	}

	memcpy(out, out3, BLOCKBYTES);
	memcpy(p2, p, BLOCKBYTES);

	for (i = 0; i < 8; i++) {
		uint8_t tmp[2];

		sel(tmp, zero, p2, 2, out3[BLOCKBYTES]&1);
		xor(out, out, tmp, 2);

		shl1(p2, BLOCKBYTES);
		out3[BLOCKBYTES] >>= 1;
	}
}

#define BLOCKPTR(buf, i) (((uint8_t*)(buf))+i*BLOCKBYTES)

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
		mul(sig, sig, session->H);
	}

	sig[BLOCKBYTES-8] ^= (in.len >> 53) & 0xff;
	sig[BLOCKBYTES-7] ^= (in.len >> 45) & 0xff;
	sig[BLOCKBYTES-6] ^= (in.len >> 37) & 0xff;
	sig[BLOCKBYTES-5] ^= (in.len >> 29) & 0xff;
	sig[BLOCKBYTES-4] ^= (in.len >> 21) & 0xff;
	sig[BLOCKBYTES-3] ^= (in.len >> 13) & 0xff;
	sig[BLOCKBYTES-2] ^= (in.len >> 5) & 0xff;
	sig[BLOCKBYTES-1] ^= (in.len << 3) & 0xff;
	mul(sig, sig, session->H);

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
		mul(sig, sig, session->H);
	}

	sig[BLOCKBYTES-8] ^= (in.len >> 53) & 0xff;
	sig[BLOCKBYTES-7] ^= (in.len >> 45) & 0xff;
	sig[BLOCKBYTES-6] ^= (in.len >> 37) & 0xff;
	sig[BLOCKBYTES-5] ^= (in.len >> 29) & 0xff;
	sig[BLOCKBYTES-4] ^= (in.len >> 21) & 0xff;
	sig[BLOCKBYTES-3] ^= (in.len >> 13) & 0xff;
	sig[BLOCKBYTES-2] ^= (in.len >> 5) & 0xff;
	sig[BLOCKBYTES-1] ^= (in.len << 3) & 0xff;
	mul(sig, sig, session->H);

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
