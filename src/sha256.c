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


#include "sha256.h"

#include <stdarg.h>
#include <stdbool.h>
#include <string.h>

#include <arpa/inet.h>


static inline uint32_t rotr(uint32_t x, int r) {
	return (x >> r) | (x << (32-r));
}

void fastd_sha256_blocks(uint8_t out[FASTD_SHA256_HASH_BYTES], ...) {
	static const uint32_t k[64] = {
		0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
		0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
		0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
		0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
		0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
		0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
		0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
		0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
	};

	uint32_t h[8] = {
		0x6a09e667,
		0xbb67ae85,
		0x3c6ef372,
		0xa54ff53a,
		0x510e527f,
		0x9b05688c,
		0x1f83d9ab,
		0x5be0cd19
	};
	unsigned count = 0, i;
	va_list ap;
	const uint32_t *in1, *in2;

	va_start(ap, out);

	do {
		uint32_t w[64], v[8];

		in1 = va_arg(ap, const uint32_t*);

		if (in1) {
			count++;
			in2 = va_arg(ap, const uint32_t*);

			if (in2)
				count++;
		}
		else {
			in2 = NULL;
		}

		if (in1) {
			for (i = 0; i < 8; i++)
				w[i] = ntohl(in1[i]);
		}
		else {
			w[0] = 0x80000000;
			memset(w+1, 0, 7*sizeof(uint32_t));
		}

		if (in2) {
			for (i = 0; i < 8; i++)
				w[i+8] = ntohl(in2[i]);
		}
		else {
			w[8] = in1 ? 0x80000000 : 0;
			memset(w+9, 0, 6*sizeof(uint32_t));
			w[15] = count << 8;
		}

		for (i = 16; i < 64; i++) {
			uint32_t s0 = rotr(w[i-15], 7) ^ rotr(w[i-15], 18) ^ (w[i-15] >> 3);
			uint32_t s1 = rotr(w[i-2], 17) ^ rotr(w[i-2], 19) ^ (w[i-2] >> 10);
			w[i] = w[i-16] + s0 + w[i-7] + s1;
		}

		memcpy(v, h, sizeof(v));

		for (i = 0; i < 64; i++) {
			uint32_t s1 = rotr(v[4], 6) ^ rotr(v[4], 11) ^ rotr(v[4], 25);
			uint32_t ch = (v[4] & v[5]) ^ ((~v[4]) & v[6]);
			uint32_t temp1 = v[7] + s1 + ch + k[i] + w[i];
			uint32_t s0 = rotr(v[0], 2) ^ rotr(v[0], 13) ^ rotr(v[0], 22);
			uint32_t maj = (v[0] & v[1]) ^ (v[0] & v[2]) ^ (v[1] & v[2]);
			uint32_t temp2 = s0 + maj;

			v[7] = v[6];
			v[6] = v[5];
			v[5] = v[4];
			v[4] = v[3] + temp1;
			v[3] = v[2];
			v[2] = v[1];
			v[1] = v[0];
			v[0] = temp1 + temp2;
		}

		for (i = 0; i < 8; i++)
			h[i] += v[i];

	} while (in1 && in2);

	va_end(ap);

	uint32_t *out32 = (uint32_t*)out;
	for (i = 0; i < 8; i++)
		out32[i] = htonl(h[i]);
}
