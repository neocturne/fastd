/*
  Copyright (c) 2012, Matthias Schiffer <mschiffer@universe-factory.net>
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


#include "fastd.h"


static size_t method_max_packet_size(fastd_context_t *ctx) {
	return fastd_max_packet_size(ctx);
}

static size_t method_min_head_tail_space(fastd_context_t *ctx) {
	return 0;
}

static fastd_method_session_state_t* method_session_init(fastd_context_t *ctx, uint8_t *secret, size_t length, bool initiator) {
	if (initiator)
		return (fastd_method_session_state_t*)1;
	else
		return (fastd_method_session_state_t*)2;
}

static bool method_session_is_valid(fastd_context_t *ctx, fastd_method_session_state_t *session) {
	return session;
}

static bool method_session_is_initiator(fastd_context_t *ctx, fastd_method_session_state_t *session) {
	return (session == (fastd_method_session_state_t*)1);
}

static bool method_session_want_refresh(fastd_context_t *ctx, fastd_method_session_state_t *session) {
	return false;
}

static void method_session_free(fastd_context_t *ctx, fastd_method_session_state_t *session) {
}

static bool method_passthrough(fastd_context_t *ctx, fastd_peer_t *peer, fastd_method_session_state_t *session, fastd_buffer_t *out, fastd_buffer_t in) {
	*out = in;
	return true;
}

const fastd_method_t fastd_method_null = {
	.name = "null",

	.max_packet_size = method_max_packet_size,
	.min_encrypt_head_space = method_min_head_tail_space,
	.min_decrypt_head_space = method_min_head_tail_space,
	.min_encrypt_tail_space = method_min_head_tail_space,
	.min_decrypt_tail_space = method_min_head_tail_space,

	.session_init = method_session_init,
	.session_is_valid = method_session_is_valid,
	.session_is_initiator = method_session_is_initiator,
	.session_want_refresh = method_session_want_refresh,
	.session_free = method_session_free,

	.encrypt = method_passthrough,
	.decrypt = method_passthrough,
};
