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


#include "../../method.h"


struct fastd_method_session_state {
	bool valid;
	bool initiator;
};


static bool method_create_by_name(const char *name, fastd_method_t **method UNUSED) {
	return !strcmp(name, "null");
}

static void method_destroy(fastd_method_t *method UNUSED) {
}

static size_t method_key_length(fastd_context_t *ctx UNUSED, const fastd_method_t *method UNUSED) {
	return 0;
}

static fastd_method_session_state_t* method_session_init(fastd_context_t *ctx UNUSED, const fastd_method_t *method UNUSED, const uint8_t *secret UNUSED, bool initiator) {
	fastd_method_session_state_t *session = malloc(sizeof(fastd_method_session_state_t));

	session->valid = true;
	session->initiator = initiator;

	return session;
}

static fastd_method_session_state_t* method_session_init_compat(fastd_context_t *ctx, const fastd_method_t *method, const uint8_t *secret, size_t length UNUSED, bool initiator) {
	return method_session_init(ctx, method, secret, initiator);
}

static bool method_session_is_valid(fastd_context_t *ctx UNUSED, fastd_method_session_state_t *session) {
	return (session && session->valid);
}

static bool method_session_is_initiator(fastd_context_t *ctx UNUSED, fastd_method_session_state_t *session) {
	return (session->initiator);
}

static bool method_session_want_refresh(fastd_context_t *ctx UNUSED, fastd_method_session_state_t *session UNUSED) {
	return false;
}

static void method_session_superseded(fastd_context_t *ctx UNUSED, fastd_method_session_state_t *session) {
	session->valid = false;
}

static void method_session_free(fastd_context_t *ctx UNUSED, fastd_method_session_state_t *session) {
	free(session);
}

static bool method_passthrough(fastd_context_t *ctx UNUSED, fastd_peer_t *peer UNUSED, fastd_method_session_state_t *session UNUSED, fastd_buffer_t *out, fastd_buffer_t in) {
	*out = in;
	return true;
}

const fastd_method_provider_t fastd_method_null = {
	.max_overhead = 0,
	.min_encrypt_head_space = 0,
	.min_decrypt_head_space = 0,
	.min_encrypt_tail_space = 0,
	.min_decrypt_tail_space = 0,

	.create_by_name = method_create_by_name,
	.destroy = method_destroy,

	.key_length = method_key_length,

	.session_init = method_session_init,
	.session_init_compat = method_session_init_compat,
	.session_is_valid = method_session_is_valid,
	.session_is_initiator = method_session_is_initiator,
	.session_want_refresh = method_session_want_refresh,
	.session_superseded = method_session_superseded,
	.session_free = method_session_free,

	.encrypt = method_passthrough,
	.decrypt = method_passthrough,
};
