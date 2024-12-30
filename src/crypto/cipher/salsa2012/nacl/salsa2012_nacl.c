// SPDX-License-Identifier: BSD-2-Clause
/*
  Copyright (c) Matthias Schiffer <mschiffer@universe-factory.net>
  All rights reserved.
*/

/**
   \file

   The Salsa20/12 implementation from NaCl
*/


#include "../../../../alloc.h"
#include "../../../../crypto.h"

#ifdef HAVE_LIBSODIUM
#include <sodium/crypto_stream_salsa2012.h>
#else
#include <nacl/crypto_stream_salsa2012.h>
#endif

#include <assert.h>


/** The cipher state */
struct fastd_cipher_state {
	uint8_t key[crypto_stream_salsa2012_KEYBYTES]; /**< The encryption key */
};


/** Initializes the cipher state */
static fastd_cipher_state_t *salsa2012_init(const uint8_t *key, UNUSED int flags) {
	assert(flags == 0);

	fastd_cipher_state_t *state = fastd_new(fastd_cipher_state_t);
	memcpy(state->key, key, crypto_stream_salsa2012_KEYBYTES);

	return state;
}

/** XORs data with the Salsa20/12 cipher stream */
static bool salsa2012_crypt(
	const fastd_cipher_state_t *state, fastd_block128_t *out, const fastd_block128_t *in, size_t len,
	const uint8_t *iv) {
	crypto_stream_salsa2012_xor(out->b, in->b, len, iv, state->key);
	return true;
}

/** Frees the cipher state */
static void salsa2012_free(fastd_cipher_state_t *state) {
	if (state) {
		secure_memzero(state, sizeof(*state));
		free(state);
	}
}


/** The nacl salsa2012 implementation */
const fastd_cipher_t fastd_cipher_salsa2012_nacl = {
	.init = salsa2012_init,
	.crypt = salsa2012_crypt,
	.free = salsa2012_free,
};
