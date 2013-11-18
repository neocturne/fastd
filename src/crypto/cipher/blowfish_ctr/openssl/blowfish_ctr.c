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

#include <openssl/blowfish.h>


struct fastd_cipher_state {
	BF_KEY key;
};


static fastd_cipher_context_t* blowfish_ctr_initialize(fastd_context_t *ctx UNUSED) {
	return NULL;
}

static size_t blowfish_ctr_key_length(fastd_context_t *ctx UNUSED, const fastd_cipher_context_t *cctx UNUSED) {
	return 56;
}

static inline void bf_ntohl(uint32_t *v, size_t len) {
	size_t i;
	for (i = 0; i < len; i++)
		v[i] = ntohl(v[i]);
}

static inline void bf_htonl(uint32_t *v, size_t len) {
	size_t i;
	for (i = 0; i < len; i++)
		v[i] = htonl(v[i]);
}
static fastd_cipher_state_t* blowfish_ctr_init_state(fastd_context_t *ctx UNUSED, const fastd_cipher_context_t *cctx UNUSED, const uint8_t *key) {
	fastd_cipher_state_t *state = malloc(sizeof(fastd_cipher_state_t));
	BF_set_key(&state->key, 56, (const unsigned char*)key);

	return state;
}

static size_t blowfish_ctr_iv_length(fastd_context_t *ctx UNUSED, const fastd_cipher_state_t *state UNUSED) {
	return 8;
}

static bool blowfish_ctr_crypt(fastd_context_t *ctx UNUSED, const fastd_cipher_state_t *state, fastd_block128_t *out, const fastd_block128_t *in, size_t len, const uint8_t *iv) {
	uint32_t ctr[2];

	fastd_block128_t block;
	uint32_t* block4 = (uint32_t*)&block;

	memcpy(ctr, iv, sizeof(ctr));
	bf_ntohl(ctr, 2);

	size_t i;
	for(i = 0; i < len; i += 16) {
		memcpy(block4, ctr, sizeof(ctr));
		BF_encrypt((BF_LONG*)block4, &state->key);
		ctr[1]++;

		memcpy(block4+2, ctr, sizeof(ctr));
		BF_encrypt((BF_LONG*)block4+2, &state->key);
		ctr[1]++;

		bf_htonl(block4, 4);
		xor(out++, in++, &block);
	}

	return true;
}

static void blowfish_ctr_free_state(fastd_context_t *ctx UNUSED, fastd_cipher_state_t *state) {
	if (state) {
		secure_memzero(state, sizeof(*state));
		free(state);
	}
}

static void blowfish_ctr_free(fastd_context_t *ctx UNUSED, fastd_cipher_context_t *cctx UNUSED) {
}

const fastd_cipher_t fastd_cipher_blowfish_ctr_openssl = {
	.name = "openssl",

	.initialize = blowfish_ctr_initialize,

	.key_length = blowfish_ctr_key_length,
	.init_state = blowfish_ctr_init_state,

	.iv_length = blowfish_ctr_iv_length,
	.crypt = blowfish_ctr_crypt,

	.free_state = blowfish_ctr_free_state,
	.free = blowfish_ctr_free,
};
