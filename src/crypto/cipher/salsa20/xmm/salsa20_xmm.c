// SPDX-License-Identifier: BSD-2-Clause
/*
  Copyright (c) 2012-2016, Matthias Schiffer <mschiffer@universe-factory.net>
  All rights reserved.
*/

/**
   \file

   The XMM Salsa20 implementation for SSE2-capable x86 systems

   The assembly implementations were written by D. J. Bernstein and are
   Public Domain. For more information see http://cr.yp.to/snuffle.html
*/


#include "../../../../alloc.h"
#include "../../../../cpuid.h"
#include "../../../../crypto.h"


/** The length of the key used by Salsa20 */
#define KEYBYTES 32


/** The actual Salsa20 assembly implementation */
int fastd_salsa20_xmm_xor(
	unsigned char *c, const unsigned char *m, unsigned long long mlen, const unsigned char *n,
	const unsigned char *k);


/** The cipher state */
struct fastd_cipher_state {
	uint8_t key[KEYBYTES]; /**< The encryption key */
};


/** Checks if the runtime platform supports SSE2 */
static bool salsa20_available(void) {
	return fastd_cpuid() & CPUID_SSE2;
}

/** Initializes the cipher state */
static fastd_cipher_state_t *salsa20_init(const uint8_t *key) {
	fastd_cipher_state_t *state = fastd_new(fastd_cipher_state_t);
	memcpy(state->key, key, KEYBYTES);

	return state;
}

/** XORs data with the Salsa20 cipher stream */
static bool salsa20_crypt(
	const fastd_cipher_state_t *state, fastd_block128_t *out, const fastd_block128_t *in, size_t len,
	const uint8_t *iv) {
	fastd_salsa20_xmm_xor(out->b, in->b, len, iv, state->key);
	return true;
}

/** Frees the cipher state */
static void salsa20_free(fastd_cipher_state_t *state) {
	if (state) {
		secure_memzero(state, sizeof(*state));
		free(state);
	}
}


/** The xmm salsa20 implementation */
const fastd_cipher_t fastd_cipher_salsa20_xmm = {
	.available = salsa20_available,

	.init = salsa20_init,
	.crypt = salsa20_crypt,
	.free = salsa20_free,
};
