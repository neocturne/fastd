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

   Small SHA256 and HMAC-SHA256 implementation
*/


#include "sha256.h"
#include "crypto.h"

#include <stdarg.h>
#include <string.h>

#include <arpa/inet.h>


/** right-rotation of a 32bit value */
static inline uint32_t rotr(uint32_t x, int r) {
	return (x >> r) | (x << (32-r));
}

/**
   Copies a (potentially incomplete) input block, while switching from big endian to CPU byte order

   After the last byte, a one-bit is added, as SHA256 defines.
*/
static inline void copy_words(uint32_t w[8], const uint32_t *in, ssize_t *left) {
	size_t i;
	for (i = 0; i < 8; i++) {
		if (*left >= 4) {
			w[i] = ntohl(in[i]);
		}
		else if (*left > 0) {
			uint32_t tmp = 0;
			memcpy(&tmp, &in[i], *left);
			w[i] = ntohl(tmp) | (0x80000000 >> (*left * 8));
		}
		else if (*left == 0) {
			w[i] = 0x80000000;
		}
		else {
			w[i] = 0;
		}

		*left -= 4;
	}
}

/** Hashes a list of input blocks */
static void sha256_list(uint32_t out[FASTD_SHA256_HASH_WORDS], const uint32_t *const *in, size_t len) {
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
	ssize_t left = len;
	size_t i;

	while (left >= -8) {
		uint32_t w[64], v[8];

		copy_words(w, *(in++), &left);
		copy_words(w+8, *(in++), &left);

		if (left < -8)
			w[15] = len << 3;

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
	}

	for (i = 0; i < 8; i++)
		out[i] = htonl(h[i]);
}

/** Hashes a NULL-terminated va_list of complete input blocks */
static void sha256_blocks_va(uint32_t out[FASTD_SHA256_HASH_WORDS], va_list ap) {
	size_t count = 0;
	va_list ap2;

	va_copy(ap2, ap);
	while (va_arg(ap2, const uint32_t *))
		count++;
	va_end(ap2);

	const uint32_t *blocks[count];

	size_t i = 0;
	const uint32_t *block;
	while ((block = va_arg(ap, const uint32_t *)) != NULL)
		blocks[i++] = block;

	sha256_list(out, blocks, count*FASTD_SHA256_BLOCK_BYTES);
}

/** Hashes complete input blocks (argument list must by NULL-terminated) */
void fastd_sha256_blocks(fastd_sha256_t *out, ...) {
	va_list ap;

	va_start(ap, out);
	sha256_blocks_va(out->w, ap);
	va_end(ap);
}

/** Hashes a buffer of arbitraty length (must by 32bit-aligned) */
void fastd_sha256(fastd_sha256_t *out, const uint32_t *in, size_t len) {
	size_t i, count = (len+FASTD_SHA256_BLOCK_BYTES-1) / FASTD_SHA256_BLOCK_BYTES;
	const uint32_t *blocks[count];

	for (i = 0; i < count; i++)
		blocks[i] = in + i*FASTD_SHA256_BLOCK_WORDS;

	sha256_list(out->w, blocks, len);
}

/** Computes the HMAC-SHA256 of a list of (potentially incomplete) input blocks */
static void hmacsha256_list(fastd_sha256_t *out, const uint32_t key[FASTD_HMACSHA256_KEY_WORDS], const uint32_t *const *in, size_t len) {
	static const uint32_t ipad2[8] = {
		0x36363636,
		0x36363636,
		0x36363636,
		0x36363636,
		0x36363636,
		0x36363636,
		0x36363636,
		0x36363636,
	};
	static const uint32_t opad2[8] = {
		0x5c5c5c5c,
		0x5c5c5c5c,
		0x5c5c5c5c,
		0x5c5c5c5c,
		0x5c5c5c5c,
		0x5c5c5c5c,
		0x5c5c5c5c,
		0x5c5c5c5c,
	};

	size_t i, count = (len+FASTD_SHA256_BLOCK_BYTES-1) / FASTD_SHA256_BLOCK_BYTES;
	const uint32_t *blocks[count+2];
	uint32_t ipad[8], opad[8];

	for (i = 0; i < 8; i++) {
		ipad[i] = key[i] ^ 0x36363636;
		opad[i] = key[i] ^ 0x5c5c5c5c;
	}

	blocks[0] = ipad;
	blocks[1] = ipad2;

	for (i = 0; i < count; i++)
		blocks[i+2] = in[i];

	uint32_t temp[8];
	sha256_list(temp, blocks, len + 2*FASTD_SHA256_BLOCK_BYTES);
	fastd_sha256_blocks(out, opad, opad2, temp, NULL);
}

/** Computes the HMAC-SHA256 of a list of NULL-terminated va_list of input blocks */
static void hmacsha256_blocks_va(fastd_sha256_t *out, const uint32_t key[FASTD_HMACSHA256_KEY_WORDS], va_list ap) {
	size_t count = 0;
	va_list ap2;

	va_copy(ap2, ap);
	while (va_arg(ap2, const uint32_t *))
		count++;
	va_end(ap2);

	const uint32_t *blocks[count];

	size_t i = 0;
	const uint32_t *block;
	while ((block = va_arg(ap, const uint32_t *)) != NULL)
		blocks[i++] = block;

	hmacsha256_list(out, key, blocks, count*FASTD_SHA256_BLOCK_BYTES);
}


/** Computes the HMAC-SHA256 of the complete blocks given as arguments (the argument list must be NULL-terminated) */
void fastd_hmacsha256_blocks(fastd_sha256_t *out, const uint32_t key[FASTD_HMACSHA256_KEY_WORDS], ...) {
	va_list ap;

	va_start(ap, key);
	hmacsha256_blocks_va(out, key, ap);
	va_end(ap);
}

/** Verifies the HMAC-SHA256 of the complete blocks given as arguments (the argument list must be NULL-terminated) */
bool fastd_hmacsha256_blocks_verify(const uint8_t mac[FASTD_SHA256_HASH_BYTES], const uint32_t key[FASTD_HMACSHA256_KEY_WORDS], ...) {
	va_list ap;
	fastd_sha256_t out;

	va_start(ap, key);
	hmacsha256_blocks_va(&out, key, ap);
	va_end(ap);

	return secure_memequal(out.b, mac, FASTD_SHA256_HASH_BYTES);
}

/** Computes the HMAC-SHA256 of an arbitraty input buffer */
void fastd_hmacsha256(fastd_sha256_t *out, const uint32_t key[FASTD_HMACSHA256_KEY_WORDS], const uint32_t *in, size_t len) {
	size_t i, count = (len+FASTD_SHA256_BLOCK_BYTES-1) / FASTD_SHA256_BLOCK_BYTES;
	const uint32_t *blocks[count];

	for (i = 0; i < count; i++)
		blocks[i] = in + i*FASTD_SHA256_BLOCK_WORDS;

	hmacsha256_list(out, key, blocks, len);
}

/** Verifies the HMAC-SHA256 of an arbitraty input buffer */
bool fastd_hmacsha256_verify(const uint8_t mac[FASTD_SHA256_HASH_BYTES], const uint32_t key[FASTD_HMACSHA256_KEY_WORDS], const uint32_t *in, size_t len) {
	fastd_sha256_t out;

	fastd_hmacsha256(&out, key, in, len);
	return secure_memequal(out.b, mac, FASTD_SHA256_HASH_BYTES);
}
