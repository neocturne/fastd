// SPDX-License-Identifier: BSD-2-Clause
/*
  Copyright (c) Matthias Schiffer <mschiffer@universe-factory.net>
  All rights reserved.
*/

/**
   \file

   An implementation of the HMAC-based Key Derivation Function (RFC 5869) using HMAC-SHA256
*/


#pragma once

#include "sha256.h"
#include "types.h"


/** The HKDF-SHA256 extraction function (which is just HMAC-SHA256) */
static inline void fastd_hkdf_sha256_extract(
	fastd_sha256_t *out, const uint32_t salt[FASTD_HMACSHA256_KEY_WORDS], const uint32_t *in, size_t len) {
	fastd_hmacsha256(out, salt, in, len);
}

void fastd_hkdf_sha256_expand(
	fastd_sha256_t *out, size_t blocks, const fastd_sha256_t *prk, const uint8_t *info, size_t infolen);
