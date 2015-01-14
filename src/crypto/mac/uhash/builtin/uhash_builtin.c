/*
  Copyright (c) 2012-2015, Matthias Schiffer <mschiffer@universe-factory.net>
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

/**
   \file

   Builtin UHASH implementation
*/


#include "../../../../crypto.h"
#include "../../../../alloc.h"
#include "../../../../util.h"
#include "../../../../log.h"


/** MAC state used by this UHASH implmentation */
struct fastd_mac_state {
	uint32_t L1Key[256+3*4];	/**< The keys used by the L1-HASH */
	uint64_t L2Key[12];		/**< The keys used by the L2-HASH */
	uint64_t L3Key1[32];		/**< The first keys used by the L3-HASH */
	uint32_t L3Key2[4];		/**< The second keys used by the L3-HASH */
};


/** An unsigned 64bit integer, split into two 32bit parts */
typedef struct uint32_2 {
	uint32_t h;			/**< The high half */
	uint32_t l;			/**< The low half */
} uint32_2_t;

/** An unsigned 128bit integer, split into two 64bit parts */
typedef struct uint64_2 {
	uint64_t h;			/**< The high half */
	uint64_t l;			/**< The low half */
} uint64_2_t;

/** Four unsigned 64bit integers */
typedef struct uint64_4 {
	uint64_t v[4];			/**< The values */
} uint64_4_t;


/** Splits a 64bit interger into its 32bit halves */
static inline uint32_2_t split64(uint64_t x) {
	return (uint32_2_t){.h = x >> 32, .l = x};
}

/** Joins two 32bit halves into a 64bit integer */
static inline uint64_t join64(uint32_t h, uint32_t l) {
	return ((uint64_t)h << 32) | l;
}

/** Multiplies two 32bit integers to a 64bit value */
static inline uint64_t mul64(uint32_t a, uint32_t b) {
	return (uint64_t)a * b;
}

/** Returns \a a if s is 0 and \a b if s is 1 in a manner safe against timing side channels */
static inline uint64_t sel(uint64_t a, uint64_t b, unsigned int s) {
	uint64_t s1 = (uint64_t)s - 1;

	return b ^ (s1 & (a ^ b));
}

/** Reduces a 64bit integer by a modulus of \f$ p_{36} = 2^{36}-5 \f$ */
static inline uint64_t mod_p36(uint64_t a) {
	const uint64_t mask = 0x0000000fffffffffull;

	uint64_t a1 = (a & mask) + 5 * (a >> 36);
	uint64_t a2 = a1 + 5;

	return sel(a1, a2 & mask, a2 >> 36);
}


/** Initializes the MAC state with the unpacked key data */
static fastd_mac_state_t * uhash_init(const uint8_t *key) {
	fastd_mac_state_t *state = fastd_new(fastd_mac_state_t);

	const uint32_t *key32 = (const uint32_t *)key;
	size_t i;

	for (i = 0; i < array_size(state->L1Key); i++)
		state->L1Key[i] = be32toh(*(key32++));

	for (i = 0; i < array_size(state->L2Key); i++) {
		uint32_t h = be32toh(*(key32++)) & 0x01ffffff;
		uint32_t l = be32toh(*(key32++)) & 0x01ffffff;
		state->L2Key[i] = join64(h, l);
	}

	for (i = 0; i < array_size(state->L3Key1); i++) {
		uint32_t h = be32toh(*(key32++));
		uint32_t l = be32toh(*(key32++));
		state->L3Key1[i] = mod_p36(join64(h, l));
	}

	for (i = 0; i < array_size(state->L3Key2); i++)
		state->L3Key2[i] = be32toh(*(key32++));

	return state;
}


/**
   The UHASH NH function

   The four iterations are interleaved to improve cache locality.
*/
static uint64_4_t nh(const uint32_t *K, const uint32_t *M, size_t length) {
	uint64_4_t Y = {{8 * length, 8 * length, 8 * length, 8 * length}};

	size_t i, j;
	for (i = 0; i < max_size_t(block_count(length, 4), 1); i += 8) {
		uint32_t b[8];

		for (j = 0; j < 8; j++)
			b[j] = le32toh(M[i+j]);

		for (j = 0; j < 4; j++) {
			Y.v[j] += mul64(b[0] + K[i+4*j+0], b[4] + K[i+4*j+4]);
			Y.v[j] += mul64(b[1] + K[i+4*j+1], b[5] + K[i+4*j+5]);
			Y.v[j] += mul64(b[2] + K[i+4*j+2], b[6] + K[i+4*j+6]);
			Y.v[j] += mul64(b[3] + K[i+4*j+3], b[7] + K[i+4*j+7]);
		}
	}

	return Y;
}

/**
   The L1-HASH function (with all four iterations interleaved)

   The message must be padded with zeros to a positive multiple of 32 bytes.
*/
static void l1hash(uint64_4_t *Y, const uint32_t *K, const fastd_block128_t *message, size_t length) {
	size_t blocks = max_size_t(block_count(length, 1024), 1), i;

	for (i = 0; i < blocks; i++) {
		size_t blocklen = min_size_t(length, 1024);
		Y[i] = nh(K, (message+64*i)->dw, blocklen);
		length -= 1024;
	}
}

/**
   Multiplies two 64bit integers to a 128bit value

   This optimized implementation will only work correctly if none of the 64bit
   intermediate values overflow. This is given by the limited space of the L2 keys.
*/
static inline uint64_2_t mul128(uint32_2_t a, uint32_2_t b) {
	uint32_2_t lo = split64(mul64(a.l, b.l));
	uint32_2_t mid = split64(mul64(a.l, b.h) + mul64(a.h, b.l) + lo.h);
	uint64_t hi = mul64(a.h, b.h) + mid.h;

	return (uint64_2_t) {
		.h = hi,
		.l = join64(mid.l, lo.l),
	};
}

/**
   Adds two 64bit intergers modulo \f$ p_{64} = 2^{64}-59 \f$

   \a a must be smaller than \f$ p_{64} \f$.
*/
static inline uint64_t add_p64(uint64_t a, uint64_t b) {
	uint64_t c1 = a + b;
	a += 59;
	uint64_t c2 = a + b;

	unsigned int s = ((a & b) | ((a | b) & ~c2)) >> 63;

	return sel(c1, c2, s);
}

/**
   Multiplies two 64bit intergers modulo \f$ p_{64} = 2^{64}-59 \f$

   This function is optimized for the limited L2 key space, it won't work
   correctly with greater numbers.
*/
static inline uint64_t mul_p64(uint64_t a, uint64_t b) {
	uint64_2_t m = mul128(split64(a), split64(b));

	return add_p64(m.h * 59, m.l);
}

/** One L2-HASH multiply-add step */
static inline uint64_t l2add(uint64_t Y, uint64_t K, uint64_t m) {
	const uint64_t marker = 0xffffffffffffffc4ull;

	uint64_t Y1, Y2;

	Y = mul_p64(Y, K);

	Y1 = add_p64(Y, marker);
	Y1 = mul_p64(Y1, K);
	Y1 = add_p64(Y1, m - 59);

	Y2 = add_p64(Y, m);

	unsigned int s = ((m >> 32) + 1) >> 32;
	return sel(Y2, Y1, s);
}

/**
   The L2-HASH function (with all four iterations interleaved)

   Handling for block counts greater than \f$ 2^{14} \f$, i.e. messages with more
   than \f$ 2^{24} \f$ bytes, is not implemented.
*/
static uint64_4_t l2hash(const uint64_t *K, const uint64_4_t *M, size_t count) {
	if (count > 0x4000)
		exit_bug("uhash (builtin): l2hash: message too long");

	uint64_4_t y = {{1, 1, 1, 1}};

	size_t i, j;
	for (i = 0; i < count; i++) {
		for (j = 0; j < 4; j++)
			y.v[j] = l2add(y.v[j], K[3*j], M[i].v[j]);
	}

	return y;
}

/** The L3-HASH function */
static uint32_t l3hash(const uint64_t *K1, uint32_t K2, uint64_t M) {
	uint64_t y = 0;

	size_t i;
	for (i = 4; i < 8; i++) {
		uint16_t m = M >> (16 * (3 - i%4));
		y += m * K1[i];
	}

	return mod_p36(y) ^ K2;
}

/** Calculates the UHASH of the supplied blocks */
static bool uhash_digest(const fastd_mac_state_t *state, fastd_block128_t *out, const fastd_block128_t *in, size_t length) {
	size_t blocks = max_size_t(block_count(length, 1024), 1);
	size_t i;

	uint64_4_t A[blocks];
	l1hash(A, state->L1Key, in, length);

	uint64_4_t B;
	if (blocks <= 1)
		B = A[0];
	else
		B = l2hash(state->L2Key, A, blocks);

	for (i = 0; i < 4; i++) {
		const uint64_t *L3Key1 = state->L3Key1 + 8*i;
		uint32_t L3Key2 = state->L3Key2[i];

		uint32_t c = l3hash(L3Key1, L3Key2, B.v[i]);
		out->dw[i] = htobe32(c);
	}

	return true;
}

/** Frees the MAC state */
static void uhash_free(fastd_mac_state_t *state) {
	if (state) {
		secure_memzero(state, sizeof(*state));
		free(state);
	}
}

/** The builtin UHASH implementation */
const fastd_mac_t fastd_mac_uhash_builtin = {
	.init = uhash_init,
	.digest = uhash_digest,
	.free = uhash_free,
};
