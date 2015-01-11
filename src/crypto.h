/*
  Copyright (c) 2012-2014, Matthias Schiffer <mschiffer@universe-factory.net>
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

   Cyptographic algorithm API and utilities
*/


#pragma once

#include "types.h"

#include <stdlib.h>
#include <string.h>


/** Contains information about a cipher algorithm */
struct fastd_cipher_info {
	size_t key_length;		/**< The key length used by the cipher */
	size_t iv_length;		/**< The initialization vector length used by the cipher */
};

/** A stream cipher implementation */
struct fastd_cipher {
	/**< Checks if the algorithm is available on the platform used. If NULL, the algorithm is always available. */
	bool (*available)(void);

	/** Initializes a cipher context with the given key */
	fastd_cipher_state_t * (*init)(const uint8_t *key);
	/** Encrypts or decrypts data */
	bool (*crypt)(const fastd_cipher_state_t *state, fastd_block128_t *out, const fastd_block128_t *in, size_t len, const uint8_t *iv);
	/** Frees a cipher context */
	void (*free)(fastd_cipher_state_t *state);
};


/** Contains information about a message authentication code algorithm */
struct fastd_mac_info {
	size_t key_length;		/**< The key length used by the MAC */
};

/** A MAC implementation */
struct fastd_mac {
	/**< Checks if the algorithm is available on the platform used. If NULL, the algorithm is always available. */
	bool (*available)(void);

	/** Initializes a MAC context with the given key */
	fastd_mac_state_t * (*init)(const uint8_t *key);
	/** Computes the MAC of data blocks */
	bool (*digest)(const fastd_mac_state_t *state, fastd_block128_t *out, const fastd_block128_t *in, size_t length);
	/** Frees a MAC context */
	void (*free)(fastd_mac_state_t *state);
};


/** Initializes the list of cipher implementations */
void fastd_cipher_init(void);

/** Configures a cipher to use a specific implementation */
bool fastd_cipher_config(const char *name, const char *impl);


/** Returns information about the cipher with the specified name if there is an implementation available */
const fastd_cipher_info_t * fastd_cipher_info_get_by_name(const char *name);

/** Returns the chosen cipher implementation for a given cipher */
const fastd_cipher_t * fastd_cipher_get(const fastd_cipher_info_t *info);


/** Initializes the list of MAC implementations */
void fastd_mac_init(void);

/** Configures a MAC to use a specific implementation */
bool fastd_mac_config(const char *name, const char *impl);


/** Returns information about the MAC with the specified name if there is an implementation available */
const fastd_mac_info_t * fastd_mac_info_get_by_name(const char *name);

/** Returns the chosen MAC implementation for a given cipher */
const fastd_mac_t * fastd_mac_get(const fastd_mac_info_t *info);


/** Sets a range of memory to zero, ensuring the operation can't be optimized out by the compiler */
static inline void secure_memzero(void *s, size_t n) {
	memset(s, 0, n);
	__asm__ volatile("" : : "m"(s));
}

/** Checks if two blocks of memory are equal in constant time */
static inline bool secure_memequal(const void *s1, const void *s2, size_t n) {
	uint8_t v = 0;
	const uint8_t *i1 = s1, *i2 = s2;
	size_t i;

	for (i = 0; i < n; i++)
		v |= i1[i] ^ i2[i];

	return (v == 0);
}

/** Checks if two 128bit blocks are equal in constant time */
static inline bool block_equal(const fastd_block128_t *a, const fastd_block128_t *b) {
	uint32_t v = 0;

	v |= a->dw[0] ^ b->dw[0];
	v |= a->dw[1] ^ b->dw[1];
	v |= a->dw[2] ^ b->dw[2];
	v |= a->dw[3] ^ b->dw[3];

	return (v == 0);
}

/** XORs two blocks of data */
static inline void xor(fastd_block128_t *x, const fastd_block128_t *a, const fastd_block128_t *b) {
	x->qw[0] = a->qw[0] ^ b->qw[0];
	x->qw[1] = a->qw[1] ^ b->qw[1];
}

/** XORs one block of data into another */
static inline void xor_a(fastd_block128_t *x, const fastd_block128_t *a) {
	xor(x, x, a);
}
