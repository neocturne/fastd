// SPDX-License-Identifier: BSD-2-Clause
/*
  Copyright (c) Matthias Schiffer <mschiffer@universe-factory.net>
  All rights reserved.
*/

/**
   \file

   The aes128-ctr implementation from OpenSSL
*/


#include "../../../../alloc.h"
#include "../../../../crypto.h"

#include <assert.h>

#include <openssl/evp.h>


/** The cipher state containing the OpenSSL cipher context */
struct fastd_cipher_state {
	EVP_CIPHER_CTX *aes; /**< The OpenSSL cipher context */
};


/** Initializes the cipher state */
static fastd_cipher_state_t *aes128_ctr_init(const uint8_t *key, UNUSED int flags) {
	assert(flags == 0);

	fastd_cipher_state_t *state = fastd_new(fastd_cipher_state_t);

	state->aes = EVP_CIPHER_CTX_new();
	EVP_EncryptInit_ex(state->aes, EVP_aes_128_ctr(), NULL, (const unsigned char *)key, NULL);

	return state;
}

/** XORs data with the aes128-ctr cipher stream */
static bool aes128_ctr_crypt(
	const fastd_cipher_state_t *state, fastd_block128_t *out, const fastd_block128_t *in, size_t len,
	const uint8_t *iv) {
	int clen, clen2;

	if (!EVP_EncryptInit_ex(state->aes, NULL, NULL, NULL, iv))
		return false;

	if (!EVP_EncryptUpdate(state->aes, (unsigned char *)out, &clen, (const unsigned char *)in, len))
		return false;

	if (!EVP_EncryptFinal(state->aes, ((unsigned char *)out) + clen, &clen2))
		return false;

	if ((size_t)(clen + clen2) != len)
		return false;

	return true;
}

/** Frees the cipher state */
static void aes128_ctr_free(fastd_cipher_state_t *state) {
	if (state) {
		EVP_CIPHER_CTX_free(state->aes);
		free(state);
	}
}


/** The openssl aes128-ctr implementation */
const fastd_cipher_t fastd_cipher_aes128_ctr_openssl = {
	.init = aes128_ctr_init,
	.crypt = aes128_ctr_crypt,
	.free = aes128_ctr_free,
};
