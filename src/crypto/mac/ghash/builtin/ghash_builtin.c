// SPDX-License-Identifier: BSD-2-Clause
/*
  Copyright (c) 2012-2016, Matthias Schiffer <mschiffer@universe-factory.net>
  All rights reserved.
*/

/**
   \file

   Portable, table-based GHASH implementation
*/


#include "../../../../alloc.h"
#include "../../../../crypto.h"


/** MAC state used by this GHASH implmentation */
struct fastd_mac_state {
	fastd_block128_t H[32][16]; /**< Lookup table unpacked from the hash key */
};


/** Lower 128 bit of the modulus \f$ x^{128} + x^7 + x^2 + x + 1 \f$ */
static const fastd_block128_t r = { .b = { 0xe1 } };


/** Right shift of a 128bit integer by up to 8 bytes */
static inline uint8_t shr(fastd_block128_t *out, const fastd_block128_t *in, int n) {
	size_t i;
	uint8_t c = 0;

	for (i = 0; i < sizeof(fastd_block128_t); i++) {
		uint8_t c2 = in->b[i] << (8 - n);
		out->b[i] = (in->b[i] >> n) | c;
		c = c2;
	}

	return (c >> (8 - n));
}

/** Galois field multiplication of a 128bit integer with H */
static inline void mulH_a(fastd_block128_t *x, const fastd_mac_state_t *cstate) {
	fastd_block128_t out = {};

	size_t i;
	for (i = 0; i < 16; i++) {
		block_xor_a(&out, &cstate->H[2 * i][x->b[i] >> 4]);
		block_xor_a(&out, &cstate->H[2 * i + 1][x->b[i] & 0xf]);
	}

	*x = out;
}


/** Initializes the MAC state with the unpacked key data */
static fastd_mac_state_t *ghash_init(const uint8_t *key) {
	fastd_mac_state_t *state = fastd_new_aligned(fastd_mac_state_t, 16);

	fastd_block128_t Hbase[4];
	fastd_block128_t Rbase[4];

	memcpy(&Hbase[0], key, sizeof(fastd_block128_t));
	Rbase[0] = r;

	size_t i;
	for (i = 1; i < 4; i++) {
		uint8_t carry = shr(&Hbase[i], &Hbase[i - 1], 1);
		if (carry)
			block_xor_a(&Hbase[i], &r);

		shr(&Rbase[i], &Rbase[i - 1], 1);
	}

	fastd_block128_t R[16];
	memset(state->H, 0, sizeof(state->H));
	memset(R, 0, sizeof(R));

	for (i = 0; i < 16; i++) {
		int j;
		for (j = 0; j < 4; j++) {
			if (i & (8 >> j)) {
				block_xor_a(&state->H[0][i], &Hbase[j]);
				block_xor_a(&R[i], &Rbase[j]);
			}
		}
	}

	for (i = 1; i < 32; i++) {
		int j;

		for (j = 0; j < 16; j++) {
			uint8_t carry = shr(&state->H[i][j], &state->H[i - 1][j], 4);
			block_xor_a(&state->H[i][j], &R[carry]);
		}
	}

	return state;
}

/** Calculates the GHASH of the supplied blocks */
static bool
ghash_digest(const fastd_mac_state_t *state, fastd_block128_t *out, const fastd_block128_t *in, size_t length) {
	if (length % sizeof(fastd_block128_t))
		exit_bug("ghash_digest (builtin): invalid length");

	size_t n_blocks = length / sizeof(fastd_block128_t);

	memset(out, 0, sizeof(fastd_block128_t));

	size_t i;
	for (i = 0; i < n_blocks; i++) {
		block_xor_a(out, &in[i]);
		mulH_a(out, state);
	}

	return true;
}

/** Frees the MAC state */
static void ghash_free(fastd_mac_state_t *state) {
	if (state) {
		secure_memzero(state, sizeof(*state));
		free(state);
	}
}

/** The builtin GHASH implementation */
const fastd_mac_t fastd_mac_ghash_builtin = {
	.init = ghash_init,
	.digest = ghash_digest,
	.free = ghash_free,
};
