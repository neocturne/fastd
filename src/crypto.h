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


#ifndef _FASTD_CRYPTO_H_
#define _FASTD_CRYPTO_H_

#include "types.h"

#include <stdint.h>


typedef union _fastd_block128 {
	uint8_t b[16];
	uint64_t qw[2];
} __attribute__((aligned(16))) fastd_block128;


#ifdef USE_CRYPTO_AES128CTR
struct _fastd_crypto_aes128ctr {
	const char *name;

	fastd_crypto_aes128ctr_context* (*init)(fastd_context *ctx);
	fastd_crypto_aes128ctr_state* (*set_key)(fastd_context *ctx, const fastd_crypto_aes128ctr_context *cctx, const fastd_block128 *key);
	bool (*crypt)(fastd_context *ctx, const fastd_crypto_aes128ctr_state *cstate, fastd_block128 *out, const fastd_block128 *in, size_t len, const fastd_block128 *iv);

	void (*free_state)(fastd_context *ctx, fastd_crypto_aes128ctr_state *cstate);
	void (*free)(fastd_context *ctx, fastd_crypto_aes128ctr_context *cctx);
};
#endif

#ifdef USE_CRYPTO_GHASH
struct _fastd_crypto_ghash {
	const char *name;

	fastd_crypto_ghash_context* (*init)(fastd_context *ctx);
	fastd_crypto_ghash_state* (*set_h)(fastd_context *ctx, const fastd_crypto_ghash_context *cctx, const fastd_block128 *h);
	bool (*hash)(fastd_context *ctx, const fastd_crypto_ghash_state *cstate, fastd_block128 *out, const fastd_block128 *in, size_t n_blocks);

	void (*free_state)(fastd_context *ctx, fastd_crypto_ghash_state *cstate);
	void (*free)(fastd_context *ctx, fastd_crypto_ghash_context *cctx);
};
#endif


static inline void xor(fastd_block128 *x, const fastd_block128 *a, const fastd_block128 *b) {
	x->qw[0] = a->qw[0] ^ b->qw[0];
	x->qw[1] = a->qw[1] ^ b->qw[1];
}

static inline void xor_a(fastd_block128 *x, const fastd_block128 *a) {
	xor(x, x, a);
}

#endif /* _FASTD_CRYPTO_H_ */
