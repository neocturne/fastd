// SPDX-License-Identifier: BSD-2-Clause
/*
  Copyright (c) 2012-2020, Matthias Schiffer <mschiffer@universe-factory.net>
  All rights reserved.
*/

/**
   \file

   The null method not providing any encryption or authenticaton
*/

#include "../../method.h"


/** The session state */
struct fastd_method_session_state {
	bool valid;     /**< true if the session has not been invalidated */
	bool initiator; /**< true if this side is the initiator of the session */
};


/** Returns true if the name is "null" */
static bool method_create_by_name(const char *name, UNUSED fastd_method_t **method) {
	return !strcmp(name, "null");
}

/** Does nothing as the null provider provides only a single method */
static void method_destroy(UNUSED fastd_method_t *method) {}

/** Returns 0 */
static size_t method_key_length(UNUSED const fastd_method_t *method) {
	return 0;
}

/** Initiates a new null session */
static fastd_method_session_state_t *method_session_init(
	UNUSED fastd_peer_t *peer, UNUSED const fastd_method_t *method, UNUSED const uint8_t *secret, bool initiator) {
	fastd_method_session_state_t *session = fastd_new(fastd_method_session_state_t);

	session->valid = true;
	session->initiator = initiator;

	return session;
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
static fastd_buffer_t *method_encrypt(UNUSED fastd_method_session_state_t *session, fastd_buffer_t *in) {
	const uint8_t packet_type = PACKET_DATA;
	fastd_buffer_push_from(in, &packet_type, 1);

	return in;
}

/** Just returns the input buffer as the output */
static fastd_buffer_t *
method_decrypt(UNUSED fastd_method_session_state_t *session, fastd_buffer_t *in, UNUSED bool *reordered) {
	fastd_buffer_pull(in, 1);

	return in;
}


/** The null method provider */
const fastd_method_provider_t fastd_method_null = {
	.overhead = 1,
	.encrypt_headroom = 1,
	.decrypt_headroom = 0,

	.create_by_name = method_create_by_name,
	.destroy = method_destroy,

	.key_length = method_key_length,

	.session_init = method_session_init,
	.session_is_valid = method_session_is_valid,
	.session_is_initiator = method_session_is_initiator,
	.session_want_refresh = method_session_want_refresh,
	.session_superseded = method_session_superseded,
	.session_free = method_session_free,

	.encrypt = method_encrypt,
	.decrypt = method_decrypt,
};
