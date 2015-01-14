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

   An implementation of the HMAC-based Key Derivation Function (RFC 5869) using HMAC-SHA256
*/


#include "hkdf_sha256.h"

#include <string.h>


/** The HKDF-SHA256 expansion function */
void fastd_hkdf_sha256_expand(fastd_sha256_t *out, size_t blocks, const fastd_sha256_t *prk, const uint8_t *info, size_t infolen) {
	if (!blocks)
		return;

	size_t len = sizeof(fastd_sha256_t) + infolen + 1;
	uint32_t buf[(len+3)/4];

	memset(buf, 0, FASTD_SHA256_HASH_BYTES);
	memcpy(buf+FASTD_SHA256_HASH_WORDS, info, infolen);
	((uint8_t *)buf)[len-1] = 0x01;

	fastd_hmacsha256(out, prk->w, buf+FASTD_SHA256_HASH_WORDS, infolen + 1);

	while (--blocks) {
		memcpy(buf, out, FASTD_SHA256_HASH_BYTES);
		out++;
		((uint8_t *)buf)[len-1]++;

		fastd_hmacsha256(out, prk->w, buf, len);
	}
}
