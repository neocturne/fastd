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


#include "../../../../fastd.h"
#include <crypto_stream_aes128ctr.h>


struct __attribute__((aligned(16))) fastd_cipher_state {
	uint8_t d[crypto_stream_aes128ctr_BEFORENMBYTES] __attribute__((aligned(16)));
};


static fastd_cipher_context_t* aes128_ctr_initialize(fastd_context_t *ctx UNUSED) {
	return NULL;
}

static size_t aes128_ctr_key_length(fastd_context_t *ctx UNUSED, const fastd_cipher_context_t *cctx UNUSED) {
	return 16;
}

static fastd_cipher_state_t* aes128_ctr_init_state(fastd_context_t *ctx, const fastd_cipher_context_t *cctx UNUSED, const uint8_t *key) {
	fastd_block128_t k;
	memcpy(k.b, key, sizeof(fastd_block128_t));

	fastd_cipher_state_t *state;
	int err = posix_memalign((void**)&state, 16, sizeof(fastd_cipher_state_t));
	if (err)
		exit_error(ctx, "posix_memalign: %s", strerror(err));

	crypto_stream_aes128ctr_beforenm(state->d, k.b);

	return state;
}

static size_t aes128_ctr_iv_length(fastd_context_t *ctx UNUSED, const fastd_cipher_state_t *state UNUSED) {
	return 16;
}

static bool aes128_ctr_crypt(fastd_context_t *ctx UNUSED, const fastd_cipher_state_t *state, fastd_block128_t *out, const fastd_block128_t *in, size_t len, const uint8_t *iv) {
	crypto_stream_aes128ctr_xor_afternm(out->b, in->b, len, iv, state->d);
	return true;
}

static void aes128_ctr_free_state(fastd_context_t *ctx UNUSED, fastd_cipher_state_t *state) {
	if (state) {
		secure_memzero(state, sizeof(*state));
		free(state);
	}
}

static void aes128_ctr_free(fastd_context_t *ctx UNUSED, fastd_cipher_context_t *cctx UNUSED) {
}

const fastd_cipher_t fastd_cipher_aes128_ctr_nacl = {
	.name = "nacl",

	.initialize = aes128_ctr_initialize,

	.key_length = aes128_ctr_key_length,
	.init_state = aes128_ctr_init_state,

	.iv_length = aes128_ctr_iv_length,
	.crypt = aes128_ctr_crypt,

	.free_state = aes128_ctr_free_state,
	.free = aes128_ctr_free,
};
