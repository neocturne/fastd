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


#ifndef _FASTD_CRYPTO_H_
#define _FASTD_CRYPTO_H_

#include "fastd.h"


struct fastd_cipher_info {
	size_t key_length;
	size_t iv_length;
};

struct fastd_cipher {
	bool (*available)(void);

	fastd_cipher_context_t* (*initialize)(fastd_context_t *ctx);
	fastd_cipher_state_t* (*init_state)(fastd_context_t *ctx, const fastd_cipher_context_t *cctx, const uint8_t *key);

	bool (*crypt)(fastd_context_t *ctx, const fastd_cipher_state_t *state, fastd_block128_t *out, const fastd_block128_t *in, size_t len, const uint8_t *iv);

	void (*free_state)(fastd_context_t *ctx, fastd_cipher_state_t *state);
	void (*free)(fastd_context_t *ctx, fastd_cipher_context_t *cctx);
};


struct fastd_mac_info {
	size_t key_length;
};

struct fastd_mac {
	bool (*available)(void);

	fastd_mac_context_t* (*initialize)(fastd_context_t *ctx);
	fastd_mac_state_t* (*init_state)(fastd_context_t *ctx, const fastd_mac_context_t *mctx, const uint8_t *key);

	bool (*hash)(fastd_context_t *ctx, const fastd_mac_state_t *state, fastd_block128_t *out, const fastd_block128_t *in, size_t n_blocks);

	void (*free_state)(fastd_context_t *ctx, fastd_mac_state_t *state);
	void (*free)(fastd_context_t *ctx, fastd_mac_context_t *mctx);
};


void fastd_cipher_init(fastd_context_t *ctx);
void fastd_cipher_free(fastd_context_t *ctx);
const fastd_cipher_info_t* fastd_cipher_info_get_by_name(const char *name);
const fastd_cipher_t* fastd_cipher_get_by_name(fastd_context_t *ctx, const char *name, const fastd_cipher_info_t **info, const fastd_cipher_context_t **cctx);

void fastd_mac_init(fastd_context_t *ctx);
void fastd_mac_free(fastd_context_t *ctx);
const fastd_mac_info_t* fastd_mac_info_get_by_name(const char *name);
const fastd_mac_t* fastd_mac_get_by_name(fastd_context_t *ctx, const char *name, const fastd_mac_info_t **info, const fastd_mac_context_t **cctx);

#endif /* _FASTD_CRYPTO_H_ */
