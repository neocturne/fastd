// SPDX-License-Identifier: BSD-2-Clause
/*
  Copyright (c) 2012-2016, Matthias Schiffer <mschiffer@universe-factory.net>
  All rights reserved.
*/

/**
   \file

   Small SHA256 and HMAC-SHA256 implementation
*/


#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>


/** 32bit words per SHA256 hash */
#define FASTD_SHA256_HASH_WORDS 8
/** 32bit words per input block */
#define FASTD_SHA256_BLOCK_WORDS 8

/** 32bit words per HMAC-SHA256 key */
#define FASTD_HMACSHA256_KEY_WORDS 8

/** bytes per SHA256 hash */
#define FASTD_SHA256_HASH_BYTES (4 * FASTD_SHA256_HASH_WORDS)
/** bytes per input block */
#define FASTD_SHA256_BLOCK_BYTES (4 * FASTD_SHA256_BLOCK_WORDS)

/** bytes per HMAC-SHA256 key */
#define FASTD_HMACSHA256_KEY_BYTES (4 * FASTD_HMACSHA256_KEY_WORDS)


/** A SHA256 hash output */
typedef union fastd_sha256 {
	uint32_t w[FASTD_SHA256_HASH_WORDS]; /**< 32bit-word-wise access */
	uint8_t b[FASTD_SHA256_HASH_BYTES];  /**< bytewise access */
} fastd_sha256_t;


void fastd_sha256_blocks(fastd_sha256_t *out, ...);
void fastd_sha256(fastd_sha256_t *out, const uint32_t *in, size_t len);

void fastd_hmacsha256_blocks(fastd_sha256_t *out, const uint32_t key[FASTD_HMACSHA256_KEY_WORDS], ...);
bool fastd_hmacsha256_blocks_verify(
	const uint8_t mac[FASTD_SHA256_HASH_BYTES], const uint32_t key[FASTD_HMACSHA256_KEY_WORDS], ...);
void fastd_hmacsha256(
	fastd_sha256_t *out, const uint32_t key[FASTD_HMACSHA256_KEY_WORDS], const uint32_t *in, size_t len);
bool fastd_hmacsha256_verify(
	const uint8_t mac[FASTD_SHA256_HASH_BYTES], const uint32_t key[FASTD_HMACSHA256_KEY_WORDS], const uint32_t *in,
	size_t len);
