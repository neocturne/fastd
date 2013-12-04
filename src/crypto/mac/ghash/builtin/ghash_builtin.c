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


#include "../../../../crypto.h"


struct fastd_mac_state {
	fastd_block128_t H[32][16];
};


static const fastd_block128_t r = { .b = {0xe1} };


static inline uint8_t shr(fastd_block128_t *out, const fastd_block128_t *in, int n) {
	size_t i;
	uint8_t c = 0;

	for (i = 0; i < sizeof(fastd_block128_t); i++) {
		uint8_t c2 = in->b[i] << (8-n);
		out->b[i] = (in->b[i] >> n) | c;
		c = c2;
	}

	return (c >> (8-n));
}

static inline void mulH_a(fastd_block128_t *x, const fastd_mac_state_t *cstate) {
	fastd_block128_t out = {};

	int i;
	for (i = 0; i < 16; i++) {
		xor_a(&out, &cstate->H[2*i][x->b[i]>>4]);
		xor_a(&out, &cstate->H[2*i+1][x->b[i]&0xf]);
	}

	*x = out;
}


static fastd_mac_state_t* ghash_init(const uint8_t *key) {
	fastd_mac_state_t *state;
	if (posix_memalign((void**)&state, 16, sizeof(fastd_mac_state_t)))
		abort();

	fastd_block128_t Hbase[4];
	fastd_block128_t Rbase[4];

	memcpy(&Hbase[0], key, sizeof(fastd_block128_t));
	Rbase[0] = r;

	int i;
	for (i = 1; i < 4; i++) {
		uint8_t carry = shr(&Hbase[i], &Hbase[i-1], 1);
		if (carry)
			xor_a(&Hbase[i], &r);

		shr(&Rbase[i], &Rbase[i-1], 1);
	}

	fastd_block128_t R[16];
	memset(state->H, 0, sizeof(state->H));
	memset(R, 0, sizeof(R));

	for (i = 0; i < 16; i++) {
		int j;
		for (j = 0; j < 4; j++) {
			if (i & (8 >> j)) {
				xor_a(&state->H[0][i], &Hbase[j]);
				xor_a(&R[i], &Rbase[j]);
			}
		}
	}

	for (i = 1; i < 32; i++) {
		int j;

		for (j = 0; j < 16; j++) {
			uint8_t carry = shr(&state->H[i][j], &state->H[i-1][j], 4);
			xor_a(&state->H[i][j], &R[carry]);
		}
	}

	return state;
}

static bool ghash_hash(const fastd_mac_state_t *state, fastd_block128_t *out, const fastd_block128_t *in, size_t n_blocks) {
	memset(out, 0, sizeof(fastd_block128_t));

	size_t i;
	for (i = 0; i < n_blocks; i++) {
		xor_a(out, &in[i]);
		mulH_a(out, state);
	}

	return true;
}

static void ghash_free(fastd_mac_state_t *state) {
	if (state) {
		secure_memzero(state, sizeof(*state));
		free(state);
	}
}

const fastd_mac_t fastd_mac_ghash_builtin = {
	.available = fastd_true,

	.init = ghash_init,
	.hash = ghash_hash,
	.free = ghash_free,
};
