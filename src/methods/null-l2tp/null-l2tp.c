// SPDX-License-Identifier: BSD-2-Clause
/*
  Copyright (c) 2021, Matthias Schiffer <mschiffer@universe-factory.net>
  All rights reserved.
*/

/**
   \file

   The null method not providing any encryption or authenticaton, using the
   L2TP packet format
*/

#include "../../method.h"

/** The session state */
struct fastd_method_session_state {
	unsigned flags; /**< Session flags */
	bool valid;     /**< true if the session has not been invalidated */
};

/** The L2TP Session header over UDP */
typedef struct method_l2tp_header {
	uint8_t packet_type;
	uint8_t flags_ver;
	uint8_t rsv[2];
	uint32_t session_id;
} method_l2tp_header_t;

#define FASTD_L2TP_VER_MASK 0xf


/** Returns true if the name is "null@l2tp" */
static bool method_create_by_name(const char *name, UNUSED fastd_method_t **method) {
	return !strcmp(name, "null@l2tp");
}

/** Does nothing as the null-l2tp provider provides only a single method */
static void method_destroy(UNUSED fastd_method_t *method) {}

/** Returns 0 */
static size_t method_key_length(UNUSED const fastd_method_t *method) {
	return 0;
}

/** Initiates a new null@l2tp session */
static fastd_method_session_state_t *method_session_init(
	UNUSED fastd_peer_t *peer, UNUSED const fastd_method_t *method, UNUSED const uint8_t *secret,
	unsigned session_flags) {
	fastd_method_session_state_t *session = fastd_new(fastd_method_session_state_t);

	session->flags = session_flags;
	session->valid = true;

	return session;
}

/** Checks if the session is valid */
static bool method_session_is_valid(fastd_method_session_state_t *session) {
	return (session && session->valid);
}

/** Checks if this side is the initiator of the session */
static bool method_session_is_initiator(fastd_method_session_state_t *session) {
	return (session->flags & FASTD_SESSION_INITIATOR);
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
	method_l2tp_header_t header = {
		.packet_type = PACKET_DATA,
		.flags_ver = 3,
		.session_id = htobe32(1),
	};

	/* This is a keepalive; prepend a control header so it always ends up in userspace */
	if (in->len == 0) {
		fastd_buffer_free(in);

		const fastd_control_packet_t control_header = {
			.packet_type = PACKET_CONTROL,
			.flags_ver = PACKET_L2TP_VERSION,
			.length = htobe16(sizeof(control_header)),
		};

		fastd_buffer_t *out = fastd_buffer_alloc(0, sizeof(control_header) + sizeof(header));
		fastd_buffer_push_from(out, &header, sizeof(header));
		fastd_buffer_push_from(out, &control_header, sizeof(control_header));
		return out;
	}

	fastd_buffer_push_from(in, &header, sizeof(header));

	return in;
}

/** Just returns the input buffer as the output */
static fastd_buffer_t *
method_decrypt(UNUSED fastd_method_session_state_t *session, fastd_buffer_t *in, UNUSED bool *reordered) {
	method_l2tp_header_t header;
	if (in->len < sizeof(header))
		return NULL;

	fastd_buffer_view_t in_view = fastd_buffer_get_view(in);
	fastd_buffer_view_pull_to(&in_view, &header, sizeof(header));

	if ((header.flags_ver & FASTD_L2TP_VER_MASK) != 3)
		return NULL;

	if (header.packet_type & PACKET_L2TP_T)
		return NULL;

	if (header.session_id != htobe32(1))
		return NULL;

	fastd_buffer_pull(in, sizeof(header));
	return in;
}


/** The null@l2tp method provider */
const fastd_method_provider_t fastd_method_null_l2tp = {
	.flags = METHOD_FORCE_KEEPALIVE,

	.overhead = sizeof(struct method_l2tp_header),
	.encrypt_headroom = sizeof(struct method_l2tp_header),
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
