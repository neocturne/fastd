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


#pragma once

#include "types.h"

#include <stdlib.h>
#include <string.h>


struct fastd_cipher_info {
	size_t key_length;
	size_t iv_length;
};

struct fastd_cipher {
	bool (*available)(void);

	fastd_cipher_state_t* (*init)(const uint8_t *key);
	bool (*crypt)(const fastd_cipher_state_t *state, fastd_block128_t *out, const fastd_block128_t *in, size_t len, const uint8_t *iv);
	void (*free)(fastd_cipher_state_t *state);
};


struct fastd_mac_info {
	size_t key_length;
};

struct fastd_mac {
	bool (*available)(void);

	fastd_mac_state_t* (*init)(const uint8_t *key);
	bool (*hash)(const fastd_mac_state_t *state, fastd_block128_t *out, const fastd_block128_t *in, size_t n_blocks);
	void (*free)(fastd_mac_state_t *state);
};


const fastd_cipher_t** fastd_cipher_config_alloc(void);
void fastd_cipher_config_free(const fastd_cipher_t **cipher_conf);
bool fastd_cipher_config(const fastd_cipher_t **cipher_conf, const char *name, const char *impl);

const fastd_cipher_info_t* fastd_cipher_info_get_by_name(const char *name);
const fastd_cipher_t* fastd_cipher_get(const fastd_cipher_info_t *info);

const fastd_mac_t** fastd_mac_config_alloc(void);
void fastd_mac_config_free(const fastd_mac_t **mac_conf);
bool fastd_mac_config(const fastd_mac_t **mac_conf, const char *name, const char *impl);

const fastd_mac_info_t* fastd_mac_info_get_by_name(const char *name);
const fastd_mac_t* fastd_mac_get(const fastd_mac_info_t *info);


static inline void secure_memzero(void *s, size_t n) {
	memset(s, 0, n);
	__asm__ volatile("" : : "m"(s));
}

static inline void xor(fastd_block128_t *x, const fastd_block128_t *a, const fastd_block128_t *b) {
	x->qw[0] = a->qw[0] ^ b->qw[0];
	x->qw[1] = a->qw[1] ^ b->qw[1];
}

static inline void xor_a(fastd_block128_t *x, const fastd_block128_t *a) {
	xor(x, x, a);
}

static inline bool fastd_true(void) {
	return true;
}
