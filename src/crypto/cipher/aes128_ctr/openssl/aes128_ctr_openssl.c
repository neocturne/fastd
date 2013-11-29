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
#include <openssl/evp.h>


struct fastd_cipher_state {
	EVP_CIPHER_CTX *aes;
};


static fastd_cipher_state_t* aes128_ctr_init(fastd_context_t *ctx UNUSED, const uint8_t *key) {
	fastd_cipher_state_t *state = malloc(sizeof(fastd_cipher_state_t));

	state->aes = EVP_CIPHER_CTX_new();
	EVP_EncryptInit(state->aes, EVP_aes_128_ctr(), (const unsigned char*)key, NULL);

	return state;
}

static bool aes128_ctr_crypt(fastd_context_t *ctx UNUSED, const fastd_cipher_state_t *state, fastd_block128_t *out, const fastd_block128_t *in, size_t len, const uint8_t *iv) {
	int clen, clen2;

	if (!EVP_EncryptInit(state->aes, NULL, NULL, iv))
		return false;

	if (!EVP_EncryptUpdate(state->aes, (unsigned char*)out, &clen, (const unsigned char*)in, len))
		return false;

	if (!EVP_EncryptFinal(state->aes, ((unsigned char*)out) + clen, &clen2))
		return false;

	if ((size_t)(clen+clen2) != len)
		return false;

	return true;
}

static void aes128_ctr_free(fastd_context_t *ctx UNUSED, fastd_cipher_state_t *state) {
	if (state) {
		EVP_CIPHER_CTX_free(state->aes);
		free(state);
	}
}

const fastd_cipher_t fastd_cipher_aes128_ctr_openssl = {
	.available = fastd_true,

	.init = aes128_ctr_init,
	.crypt = aes128_ctr_crypt,
	.free = aes128_ctr_free,
};
