// SPDX-License-Identifier: BSD-2-Clause
/*
  Copyright (c) Matthias Schiffer <mschiffer@universe-factory.net>
  All rights reserved.
*/

/**
   \file

   An implementation of the HMAC-based Key Derivation Function (RFC 5869) using HMAC-SHA256
*/


#include "hkdf_sha256.h"

#include <string.h>


/** The HKDF-SHA256 expansion function */
void fastd_hkdf_sha256_expand(
	fastd_sha256_t *out, size_t blocks, const fastd_sha256_t *prk, const uint8_t *info, size_t infolen) {
	if (!blocks)
		return;

	size_t len = sizeof(fastd_sha256_t) + infolen + 1;
	uint32_t buf[(len + 3) / 4];

	memset(buf, 0, FASTD_SHA256_HASH_BYTES);
	memcpy(buf + FASTD_SHA256_HASH_WORDS, info, infolen);
	((uint8_t *)buf)[len - 1] = 0x01;

	fastd_hmacsha256(out, prk->w, buf + FASTD_SHA256_HASH_WORDS, infolen + 1);

	while (--blocks) {
		memcpy(buf, out, FASTD_SHA256_HASH_BYTES);
		out++;
		((uint8_t *)buf)[len - 1]++;

		fastd_hmacsha256(out, prk->w, buf, len);
	}
}
