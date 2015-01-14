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

   The null method not providing any encryption or authenticaton
*/

#include "../../method.h"


/** The session state */
struct fastd_method_session_state {
	bool valid;			/**< true if the session has not been invalidated */
	bool initiator;			/**< true if this side is the initiator of the session */
};


/** Returns true if the name is "null" */
static bool method_create_by_name(const char *name, UNUSED fastd_method_t **method) {
	return !strcmp(name, "null");
}

/** Does nothing as the null provider provides only a single method */
static void method_destroy(UNUSED fastd_method_t *method) {
}

/** Returns 0 */
static size_t method_key_length(UNUSED const fastd_method_t *method) {
	return 0;
}

/** Initiates a new null session */
static fastd_method_session_state_t * method_session_init(UNUSED const fastd_method_t *method, UNUSED const uint8_t *secret, bool initiator) {
	fastd_method_session_state_t *session = fastd_new(fastd_method_session_state_t);

	session->valid = true;
	session->initiator = initiator;

	return session;
}

/** Initiates a new null session (pre-v11 compat handshake) */
static fastd_method_session_state_t * method_session_init_compat(const fastd_method_t *method, const uint8_t *secret, UNUSED size_t length, bool initiator) {
	return method_session_init(method, secret, initiator);
}

/** Checks if the session is valid */
static bool method_session_is_valid(fastd_method_session_state_t *session) {
	return (session && session->valid);
}

/** Checks if this side is the initiator of the session */
static bool method_session_is_initiator(fastd_method_session_state_t *session) {
	return (session->initiator);
}

/** Returns false */
static bool method_session_want_refresh(UNUSED fastd_method_session_state_t *session) {
	return false;
}

/**
   Marks the session as invalid

   The session in invalidated without any delay to prevent packets of the new session being
   mistaken to be valid for the old session
*/
static void method_session_superseded(fastd_method_session_state_t *session) {
	session->valid = false;
}

/** Frees the session state */
static void method_session_free(fastd_method_session_state_t *session) {
	free(session);
}

/** Just returns the input buffer as the output */
static bool method_encrypt(UNUSED fastd_peer_t *peer, UNUSED fastd_method_session_state_t *session, fastd_buffer_t *out, fastd_buffer_t in) {
	*out = in;
	return true;
}

/** Just returns the input buffer as the output */
static bool method_decrypt(UNUSED fastd_peer_t *peer, UNUSED fastd_method_session_state_t *session, fastd_buffer_t *out, fastd_buffer_t in, UNUSED bool *reordered) {
	*out = in;
	return true;
}


/** The null method provider */
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

	.encrypt = method_encrypt,
	.decrypt = method_decrypt,
};
