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


#include "ghash_pclmulqdq.h"
#include "../../../../cpuid.h"


static bool ghash_available(void) {
	static const uint64_t REQ = CPUID_FXSR|CPUID_SSSE3|CPUID_PCLMULQDQ;

	return ((fastd_cpuid()&REQ) == REQ);
}

static fastd_mac_context_t* ghash_initialize(fastd_context_t *ctx UNUSED) {
	return NULL;
}

static void ghash_free_state(fastd_context_t *ctx UNUSED, fastd_mac_state_t *state) {
	if (state) {
		secure_memzero(state, sizeof(*state));
		free(state);
	}
}

static void ghash_free(fastd_context_t *ctx UNUSED, fastd_mac_context_t *mctx UNUSED) {
}

const fastd_mac_t fastd_mac_ghash_pclmulqdq = {
	.available = ghash_available,

	.initialize = ghash_initialize,
	.init_state = fastd_ghash_pclmulqdq_init_state,

	.hash = fastd_ghash_pclmulqdq_hash,

	.free_state = ghash_free_state,
	.free = ghash_free,
};
