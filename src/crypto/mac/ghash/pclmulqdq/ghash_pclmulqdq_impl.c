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


#include "ghash_pclmulqdq.h"
#include <wmmintrin.h>
#include <emmintrin.h>
#include <tmmintrin.h>


typedef union _vecblock {
	__m128i v;
	fastd_block128_t b;
} vecblock;

static inline __m128i shl(__m128i v, int a) {
	__m128i tmpl = _mm_slli_epi64(v, a);
	__m128i tmpr = _mm_srli_epi64(v, 64-a);
	tmpr = _mm_slli_si128(tmpr, 8);

	return _mm_xor_si128(tmpl, tmpr);
}

static inline __m128i shr(__m128i v, int a) {
	__m128i tmpr = _mm_srli_epi64(v, a);
	__m128i tmpl = _mm_slli_epi64(v, 64-a);
	tmpl = _mm_srli_si128(tmpl, 8);

	return _mm_xor_si128(tmpr, tmpl);
}

static const __v16qi BYTESWAP_SHUFFLE = {15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0};

static inline __m128i byteswap(__m128i v) {
	return _mm_shuffle_epi8(v, (__m128i)BYTESWAP_SHUFFLE);
}


fastd_mac_state_t* fastd_ghash_pclmulqdq_init_state(fastd_context_t *ctx UNUSED, const fastd_mac_context_t *mctx UNUSED, const uint8_t *key) {
	fastd_mac_state_t *state = malloc(sizeof(fastd_mac_state_t));

	vecblock h;
	memcpy(&h, key, sizeof(__m128i));

	h.v = byteswap(h.v);
	state->H = h.b;

	return state;
}

static __m128i gmul(__m128i v, __m128i h) {
	/* multiply */
	__m128i z0, z1, z2, tmp;
	z0 = _mm_clmulepi64_si128(v, h, 0x11);
	z2 = _mm_clmulepi64_si128(v, h, 0x00);

	__m128i tmpv = _mm_srli_si128(v, 8);
	tmpv = _mm_xor_si128(tmpv, v);

	__m128i tmph = _mm_srli_si128(h, 8);
	tmph = _mm_xor_si128(tmph, h);

	z1 = __builtin_ia32_pclmulqdq128(tmpv, tmph, 0x00);
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


bool fastd_ghash_pclmulqdq_hash(fastd_context_t *ctx UNUSED, const fastd_mac_state_t *state, fastd_block128_t *out, const fastd_block128_t *in, size_t n_blocks) {
	const __m128i *inv = (const __m128i*)in;

	__m128i h = ((vecblock*)&state->H)->v;
	__m128i v = _mm_setzero_si128();

	size_t i;
	for (i = 0; i < n_blocks; i++) {
		__m128i b = inv[i];
		v = _mm_xor_si128(v, byteswap(b));
		v = gmul(v, h);
	}

	((vecblock*)out)->v = byteswap(v);

	return true;
}
