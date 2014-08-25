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

   Portable, table-based HMAC-SHA1 implementation
*/


#include "../../../../alloc.h"
#include "../../../../crypto.h"

#include <openssl/evp.h>


/** The MAC state containing the OpenSSL digest context */
struct fastd_mac_state {
	EVP_PKEY *pkey;			/**< The OpenSSL private key */
	EVP_MD_CTX *digest;		/**< The OpenSSL digest context */
};


/** Initializes the MAC state with the unpacked key data */
static fastd_mac_state_t * hmac_sha1_init(const uint8_t *key) {
	fastd_mac_state_t *state = fastd_new(fastd_mac_state_t);

	state->digest = EVP_MD_CTX_create();
	if (!state->digest)
		exit_error("EVP_MD_CTX_create");

	state->pkey = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, key, 64);
	if (!state->pkey)
		exit_error("EVP_PKEY_new_mac_key");

	return state;
}

/** Calculates the HMAC-SHA1 of the supplied blocks */
static bool hmac_sha1_digest(const fastd_mac_state_t *state, fastd_block128_t *out, const fastd_block128_t *in, size_t length) {
	if (!EVP_DigestSignInit(state->digest, NULL, EVP_sha1(), NULL, state->pkey))
		return false;

	if (!EVP_DigestSignUpdate(state->digest, (const unsigned char *)in, length))
		return false;

	unsigned char digest[EVP_MAX_MD_SIZE];
	size_t digestlen = 0;

	if (!EVP_DigestSignFinal(state->digest, digest, &digestlen))
		return false;

	if (digestlen != 20)
		exit_bug("EVP_DigestSignFinal: invalid HMAC-SHA1 length");

	memcpy(out, digest, sizeof(fastd_block128_t));

	return true;
}

/** Frees the MAC state */
static void hmac_sha1_free(fastd_mac_state_t *state) {
	if (state) {
		EVP_MD_CTX_destroy(state->digest);
		EVP_PKEY_free(state->pkey);
		free(state);
	}
}

/** The OpenSSL-based HMAC-SHA1 implementation */
const fastd_mac_t fastd_mac_hmac_sha1_openssl = {
	.init = hmac_sha1_init,
	.digest = hmac_sha1_digest,
	.free = hmac_sha1_free,
};
