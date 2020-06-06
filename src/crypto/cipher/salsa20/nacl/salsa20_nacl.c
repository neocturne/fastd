// SPDX-License-Identifier: BSD-2-Clause
/*
  Copyright (c) 2012-2016, Matthias Schiffer <mschiffer@universe-factory.net>
  All rights reserved.
*/

/**
   \file

   The Salsa20 implementation from NaCl
*/


#include "../../../../alloc.h"
#include "../../../../crypto.h"

#ifdef HAVE_LIBSODIUM
#include <sodium/crypto_stream_salsa20.h>
#else
#include <nacl/crypto_stream_salsa20.h>
#endif


/** The cipher state */
struct fastd_cipher_state {
	uint8_t key[crypto_stream_salsa20_KEYBYTES]; /**< The encryption key */
};


/** Initializes the cipher state */
static fastd_cipher_state_t *salsa20_init(const uint8_t *key) {
	fastd_cipher_state_t *state = fastd_new(fastd_cipher_state_t);
	memcpy(state->key, key, crypto_stream_salsa20_KEYBYTES);

	return state;
}

/** XORs data with the Salsa20 cipher stream */
static bool salsa20_crypt(
	const fastd_cipher_state_t *state, fastd_block128_t *out, const fastd_block128_t *in, size_t len,
	const uint8_t *iv) {
	crypto_stream_salsa20_xor(out->b, in->b, len, iv, state->key);
	return true;
}

/** Frees the cipher state */
static void salsa20_free(fastd_cipher_state_t *state) {
	if (state) {
		secure_memzero(state, sizeof(*state));
		free(state);
	}
}


/** The nacl salsa20 implementation */
const fastd_cipher_t fastd_cipher_salsa20_nacl = {
	.init = salsa20_init,
	.crypt = salsa20_crypt,
	.free = salsa20_free,
};
