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

   The memcpy null implementation
*/


#include "../../../../crypto.h"


/** Doesn't do anything as the null cipher doesn't use any state */
static fastd_cipher_state_t * null_init(UNUSED const uint8_t *key) {
	return NULL;
}

/** Just copies the input data to the output */
static bool null_memcpy(UNUSED const fastd_cipher_state_t *state, fastd_block128_t *out, const fastd_block128_t *in, size_t len, UNUSED const uint8_t *iv) {
	memcpy(out, in, len);
	return true;
}

/** Doesn't do anything as the null cipher doesn't use any state */
static void null_free(UNUSED fastd_cipher_state_t *state) {
}

/** The memcpy null implementation */
const fastd_cipher_t fastd_cipher_null_memcpy = {
	.init = null_init,
	.crypt = null_memcpy,
	.free = null_free,
};
