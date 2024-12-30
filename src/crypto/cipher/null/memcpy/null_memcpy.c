// SPDX-License-Identifier: BSD-2-Clause
/*
  Copyright (c) Matthias Schiffer <mschiffer@universe-factory.net>
  All rights reserved.
*/

/**
   \file

   The memcpy null implementation
*/


#include "../../../../crypto.h"

#include <assert.h>


/** Doesn't do anything as the null cipher doesn't use any state */
static fastd_cipher_state_t *null_init(UNUSED const uint8_t *key, UNUSED int flags) {
	assert(flags == 0);

	return NULL;
}

/** Just copies the input data to the output */
static bool null_memcpy(
	UNUSED const fastd_cipher_state_t *state, fastd_block128_t *out, const fastd_block128_t *in, size_t len,
	UNUSED const uint8_t *iv) {
	memcpy(out, in, len);
	return true;
}

/** Doesn't do anything as the null cipher doesn't use any state */
static void null_free(UNUSED fastd_cipher_state_t *state) {}

/** The memcpy null implementation */
const fastd_cipher_t fastd_cipher_null_memcpy = {
	.init = null_init,
	.crypt = null_memcpy,
	.free = null_free,
};
