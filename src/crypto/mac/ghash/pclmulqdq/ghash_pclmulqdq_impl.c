// SPDX-License-Identifier: BSD-2-Clause
/*
  Copyright (c) Matthias Schiffer <mschiffer@universe-factory.net>
  All rights reserved.
*/

/**
   \file

   PCLMULQDQ-based GHASH implementation for newer x86 systems: implementation
*/


#include "../ghash.h"

#include "../../../../alloc.h"
#include "../../../../util.h"
#include "ghash_pclmulqdq.h"

#include <assert.h>

#include <emmintrin.h>
#include <tmmintrin.h>
#include <wmmintrin.h>


/** An union allowing easy access to a block as a SIMD vector and a fastd_block128_t */
typedef union vecblock {
	__m128i v;          /**< __m128i access */
	fastd_block128_t b; /**< fastd_block128_t access */
} vecblock_t;

/** The MAC state used by this GHASH implementation */
struct fastd_mac_state {
	vecblock_t H; /**< The hash key used by GHASH */
	bool shift_size;
};


/** Left shift on a 128bit integer */
static inline __m128i shl(__m128i v, int a) {
	__m128i tmpl = _mm_slli_epi64(v, a);
	__m128i tmpr = _mm_srli_epi64(v, 64 - a);
	tmpr = _mm_slli_si128(tmpr, 8);

	return _mm_xor_si128(tmpl, tmpr);
}

/** Right shift on a 128bit integer */
static inline __m128i shr(__m128i v, int a) {
	__m128i tmpr = _mm_srli_epi64(v, a);
	__m128i tmpl = _mm_slli_epi64(v, 64 - a);
	tmpl = _mm_srli_si128(tmpl, 8);

	return _mm_xor_si128(tmpr, tmpl);
}

/** _mm_shuffle_epi8 parameter to reverse the bytes of a __m128i */
static const __v16qi BYTESWAP_SHUFFLE = { 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0 };

/** Reverses the order of the bytes of a __m128i */
static inline __m128i byteswap(__m128i v) {
	return _mm_shuffle_epi8(v, (__m128i)BYTESWAP_SHUFFLE);
}


/** Initializes the state used by this GHASH implementation */
fastd_mac_state_t *fastd_ghash_pclmulqdq_init(const uint8_t *key, int flags) {
	assert((flags & ~GHASH_MASK) == 0);

	fastd_mac_state_t *state = fastd_new_aligned(fastd_mac_state_t, 16);

	state->shift_size = flags & GHASH_SHIFT_SIZE;

	memcpy(&state->H, key, sizeof(__m128i));
	state->H.v = byteswap(state->H.v);

	return state;
}

/** Frees the state used by this GHASH implementation */
void fastd_ghash_pclmulqdq_free(fastd_mac_state_t *state) {
	if (state) {
		secure_memzero(state, sizeof(*state));
		free(state);
	}
}

/** Performs a carryless multiplication of two 128bit integers modulo \f$ x^{128} + x^7 + x^2 + x + 1 \f$ */
static __m128i gmul(__m128i v, __m128i h) {
	/* multiply */
	__m128i z0, z1, z2, tmp;
	z0 = _mm_clmulepi64_si128(v, h, 0x11);
	z2 = _mm_clmulepi64_si128(v, h, 0x00);

	__m128i tmpv = _mm_srli_si128(v, 8);
	tmpv = _mm_xor_si128(tmpv, v);

	__m128i tmph = _mm_srli_si128(h, 8);
	tmph = _mm_xor_si128(tmph, h);

	z1 = _mm_clmulepi64_si128(tmpv, tmph, 0x00);
	z1 = _mm_xor_si128(z1, z0);
	z1 = _mm_xor_si128(z1, z2);

	tmp = _mm_srli_si128(z1, 8);
	__m128i pl = _mm_xor_si128(z0, tmp);

	tmp = _mm_slli_si128(z1, 8);
	__m128i ph = _mm_xor_si128(z2, tmp);

	tmp = _mm_srli_epi64(ph, 63);
	tmp = _mm_srli_si128(tmp, 8);

	pl = shl(pl, 1);
	pl = _mm_xor_si128(pl, tmp);

	ph = shl(ph, 1);

	/* reduce */
	__m128i b, c;
	b = c = _mm_slli_si128(ph, 8);

	b = _mm_slli_epi64(b, 62);
	c = _mm_slli_epi64(c, 57);

	tmp = _mm_xor_si128(b, c);
	__m128i d = _mm_xor_si128(ph, tmp);

	__m128i e = shr(d, 1);
	__m128i f = shr(d, 2);
	__m128i g = shr(d, 7);

	pl = _mm_xor_si128(pl, d);
	pl = _mm_xor_si128(pl, e);
	pl = _mm_xor_si128(pl, f);
	pl = _mm_xor_si128(pl, g);

	return pl;
}


static __m128i make_size(size_t len, bool shift) {
	if (len >= (1U << 29))
		exit_bug("ghash: oversized input");

	uint32_t size = htobe32((uint32_t)len << 3);

	vecblock_t ret = {};
	if (shift)
		ret.b.dw[1] = size;
	else
		ret.b.dw[3] = size;

	return ret.v;
}

/** Calculates the GHASH of the supplied input blocks */
bool fastd_ghash_pclmulqdq_digest(
	const fastd_mac_state_t *state, fastd_block128_t *out, const fastd_block128_t *in, size_t length) {
	size_t n_blocks = block_count(length, sizeof(fastd_block128_t));

	vecblock_t v = { .v = _mm_setzero_si128() };

	size_t i;
	for (i = 0; i < n_blocks; i++) {
		__m128i b = ((vecblock_t)in[i]).v;
		v.v = _mm_xor_si128(v.v, byteswap(b));
		v.v = gmul(v.v, state->H.v);
	}

	v.v = _mm_xor_si128(v.v, byteswap(make_size(length, state->shift_size)));
	v.v = gmul(v.v, state->H.v);

	v.v = byteswap(v.v);
	*out = v.b;

	return true;
}
