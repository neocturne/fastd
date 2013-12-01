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

/*
  The assembly implementations were written by D. J. Bernstein and are
  Public Domain. For more information see http://cr.yp.to/snuffle.html
*/

#include "../../../../crypto.h"
#include "../../../../cpuid.h"


#define KEYBYTES 32


#ifdef __x86_64__
#define crypto_stream_salsa20_xor crypto_stream_salsa20_amd64_xmm6_xor
#endif

#ifdef __i386__
#define crypto_stream_salsa20_xor crypto_stream_salsa20_x86_xmm5_xor
#endif


int crypto_stream_salsa20_xor(unsigned char *c, const unsigned char *m, unsigned long long mlen, const unsigned char *n, const unsigned char *k);


struct fastd_cipher_state {
	uint8_t key[KEYBYTES];
};


static bool salsa20_available(void) {
	return fastd_cpuid() & CPUID_SSE2;
}

static fastd_cipher_state_t* salsa20_init(const uint8_t *key) {
	fastd_cipher_state_t *state = malloc(sizeof(fastd_cipher_state_t));
	memcpy(state->key, key, KEYBYTES);

	return state;
}

static bool salsa20_crypt(const fastd_cipher_state_t *state, fastd_block128_t *out, const fastd_block128_t *in, size_t len, const uint8_t *iv) {
	crypto_stream_salsa20_xor(out->b, in->b, len, iv, state->key);
	return true;
}

static void salsa20_free(fastd_cipher_state_t *state) {
	if (state) {
		secure_memzero(state, sizeof(*state));
		free(state);
	}
}

const fastd_cipher_t fastd_cipher_salsa20_xmm = {
	.available = salsa20_available,

	.init = salsa20_init,
	.crypt = salsa20_crypt,
	.free = salsa20_free,
};
