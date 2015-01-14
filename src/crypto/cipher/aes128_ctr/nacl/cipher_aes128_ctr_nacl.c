/*
  Copyright (c) 2012-2015, Matthias Schiffer <mschiffer@universe-factory.net>
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

/**
   \file

   The aes128-ctr implementation from NaCl
*/


#include "../../../../crypto.h"
#include "../../../../alloc.h"

#include <crypto_stream_aes128ctr.h>


/** The cipher state */
struct __attribute__((aligned(16))) fastd_cipher_state {
	uint8_t d[crypto_stream_aes128ctr_BEFORENMBYTES] __attribute__((aligned(16))); /**< The unpacked AES key */
};


/** Initializes the cipher state */
static fastd_cipher_state_t * aes128_ctr_init(const uint8_t *key) {
	fastd_block128_t k;
	memcpy(k.b, key, sizeof(fastd_block128_t));

	fastd_cipher_state_t *state = fastd_new_aligned(fastd_cipher_state_t, 16);
	crypto_stream_aes128ctr_beforenm(state->d, k.b);

	return state;
}

/** XORs data with the aes128-ctr cipher stream */
static bool aes128_ctr_crypt(const fastd_cipher_state_t *state, fastd_block128_t *out, const fastd_block128_t *in, size_t len, const uint8_t *iv) {
	crypto_stream_aes128ctr_xor_afternm(out->b, in->b, len, iv, state->d);
	return true;
}

/** Frees the cipher state */
static void aes128_ctr_free(fastd_cipher_state_t *state) {
	if (state) {
		secure_memzero(state, sizeof(*state));
		free(state);
	}
}


/** The nacl aes128-ctr implementation */
const fastd_cipher_t fastd_cipher_aes128_ctr_nacl = {
	.init = aes128_ctr_init,
	.crypt = aes128_ctr_crypt,
	.free = aes128_ctr_free,
};
