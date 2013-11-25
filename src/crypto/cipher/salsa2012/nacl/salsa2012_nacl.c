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


#include "../../../../crypto.h"
#include <crypto_stream_salsa2012.h>


struct __attribute__((aligned(16))) fastd_cipher_state {
	uint8_t key[crypto_stream_salsa2012_KEYBYTES];
};


static fastd_cipher_context_t* salsa2012_initialize(fastd_context_t *ctx UNUSED) {
	return NULL;
}

static fastd_cipher_state_t* salsa2012_init_state(fastd_context_t *ctx UNUSED, const fastd_cipher_context_t *cctx UNUSED, const uint8_t *key) {
	fastd_cipher_state_t *state = malloc(sizeof(fastd_cipher_state_t));
	memcpy(state->key, key, crypto_stream_salsa2012_KEYBYTES);

	return state;
}

static bool salsa2012_crypt(fastd_context_t *ctx UNUSED, const fastd_cipher_state_t *state, fastd_block128_t *out, const fastd_block128_t *in, size_t len, const uint8_t *iv) {
	crypto_stream_salsa2012_xor(out->b, in->b, len, iv, state->key);
	return true;
}

static void salsa2012_free_state(fastd_context_t *ctx UNUSED, fastd_cipher_state_t *state) {
	if (state) {
		secure_memzero(state, sizeof(*state));
		free(state);
	}
}

static void salsa2012_free(fastd_context_t *ctx UNUSED, fastd_cipher_context_t *cctx UNUSED) {
}

const fastd_cipher_t fastd_cipher_salsa2012_nacl = {
	.name = "nacl",
	.key_length = crypto_stream_salsa2012_KEYBYTES,
	.iv_length = crypto_stream_salsa2012_NONCEBYTES,

	.initialize = salsa2012_initialize,
	.init_state = salsa2012_init_state,

	.crypt = salsa2012_crypt,

	.free_state = salsa2012_free_state,
	.free = salsa2012_free,
};
