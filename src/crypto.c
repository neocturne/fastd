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


#ifdef USE_CRYPTO_AES128CTR
#ifdef WITH_CRYPTO_AES128CTR_NACL

#include <crypto_stream_aes128ctr.h>


struct _fastd_crypto_aes128ctr_state {
	fastd_buffer d;
};


static fastd_crypto_aes128ctr_context* aes128ctr_init(fastd_context *ctx) {
	return (fastd_crypto_aes128ctr_context*)1;
}

static fastd_crypto_aes128ctr_state* aes128ctr_set_key(fastd_context *ctx, const fastd_crypto_aes128ctr_context *cctx, const fastd_block128 *key) {
	fastd_crypto_aes128ctr_state *cstate = malloc(sizeof(fastd_crypto_aes128ctr_state));

	cstate->d = fastd_buffer_alloc(crypto_stream_aes128ctr_BEFORENMBYTES, 0, 0);
	crypto_stream_aes128ctr_beforenm(cstate->d.data, key->b);

	return cstate;
}

static bool aes128ctr_crypt(fastd_context *ctx, const fastd_crypto_aes128ctr_state *cstate, fastd_block128 *out, const fastd_block128 *in, size_t len, const fastd_block128 *iv) {
	crypto_stream_aes128ctr_xor_afternm(out->b, in->b, len, iv->b, cstate->d.data);
	return true;
}

static void aes128ctr_free_state(fastd_context *ctx, fastd_crypto_aes128ctr_state *cstate) {
	if (cstate) {
		fastd_buffer_free(cstate->d);
		free(cstate);
	}
}

static void aes128ctr_free(fastd_context *ctx, fastd_crypto_aes128ctr_context *cctx) {
}

fastd_crypto_aes128ctr fastd_crypto_aes128ctr_nacl = {
	.name = "nacl",

	.init = aes128ctr_init,
	.set_key = aes128ctr_set_key,
	.crypt = aes128ctr_crypt,

	.free_state = aes128ctr_free_state,
	.free = aes128ctr_free,
};

#endif
#endif

#ifdef USE_CRYPTO_GHASH
#ifdef WITH_CRYPTO_GHASH_BUILTIN

struct _fastd_crypto_ghash_state {
	fastd_block128 H[32][16];
};


static const fastd_block128 r = { .b = {0xe1} };


static inline uint8_t shr(fastd_block128 *out, const fastd_block128 *in, int n) {
	int i;
	uint8_t c = 0;

	for (i = 0; i < sizeof(fastd_block128); i++) {
		uint8_t c2 = in->b[i] << (8-n);
		out->b[i] = (in->b[i] >> n) | c;
		c = c2;
	}

	return (c >> (8-n));
}

static inline void mulH_a(fastd_block128 *x, const fastd_crypto_ghash_state *cstate) {
	fastd_block128 out = {};

	int i;
	for (i = 0; i < 16; i++) {
		xor_a(&out, &cstate->H[2*i][x->b[i]>>4]);
		xor_a(&out, &cstate->H[2*i+1][x->b[i]&0xf]);
	}

	*x = out;
}


static fastd_crypto_ghash_context* ghash_init(fastd_context *ctx) {
	return (fastd_crypto_ghash_context*)1;
}

static fastd_crypto_ghash_state* ghash_set_h(fastd_context *ctx, const fastd_crypto_ghash_context *cctx, const fastd_block128 *h) {
	fastd_crypto_ghash_state *cstate = malloc(sizeof(fastd_crypto_ghash_state));

	fastd_block128 Hbase[4];
	fastd_block128 Rbase[4];

	Hbase[0] = *h;
	Rbase[0] = r;

	int i;
	for (i = 1; i < 4; i++) {
		uint8_t carry = shr(&Hbase[i], &Hbase[i-1], 1);
		if (carry)
			xor_a(&Hbase[i], &r);

		shr(&Rbase[i], &Rbase[i-1], 1);
	}

	fastd_block128 R[16];
	memset(cstate->H, 0, sizeof(cstate->H));
	memset(R, 0, sizeof(R));

	for (i = 0; i < 16; i++) {
		int j;
		for (j = 0; j < 4; j++) {
			if (i & (8 >> j)) {
				xor_a(&cstate->H[0][i], &Hbase[j]);
				xor_a(&R[i], &Rbase[j]);
			}
		}
	}

	for (i = 1; i < 32; i++) {
		int j;

		for (j = 0; j < 16; j++) {
			uint8_t carry = shr(&cstate->H[i][j], &cstate->H[i-1][j], 4);
			xor_a(&cstate->H[i][j], &R[carry]);
		}
	}

	return cstate;
}

static bool ghash_hash(fastd_context *ctx, const fastd_crypto_ghash_state *cstate, fastd_block128 *out, const fastd_block128 *in, size_t n_blocks) {
	memset(out, 0, sizeof(fastd_block128));

	int i;
	for (i = 0; i < n_blocks; i++) {
		xor_a(out, &in[i]);
		mulH_a(out, cstate);
	}

	return true;
}

static void ghash_free_state(fastd_context *ctx, fastd_crypto_ghash_state *cstate) {
	free(cstate);
}

static void ghash_free(fastd_context *ctx, fastd_crypto_ghash_context *cctx) {
}

fastd_crypto_ghash fastd_crypto_ghash_builtin = {
	.name = "builtin",

	.init = ghash_init,
	.set_h = ghash_set_h,
	.hash = ghash_hash,

	.free_state = ghash_free_state,
	.free = ghash_free,
};

#endif
#endif
