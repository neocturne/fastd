// SPDX-License-Identifier: BSD-2-Clause
/*
  Copyright (c) 2012-2020, Matthias Schiffer <mschiffer@universe-factory.net>
  All rights reserved.
*/

/**
   \file

   Management of encryption methods
*/


#pragma once

#include "fastd.h"


/** Information about a single encryption method */
struct fastd_method_info {
	const char *name;                        /**< The method name */
	const fastd_method_provider_t *provider; /**< The provider of the method */
	fastd_method_t *method;                  /**< Provider-specific method data */
};

/** Describes a method provider (an implementation of a class of encryption methods) */
struct fastd_method_provider {
	size_t overhead;         /**< The maximum number of bytes of overhead the methods may add */
	size_t encrypt_headroom; /**< The minimum head space needed for encrytion */
	size_t decrypt_headroom; /**< The minimum head space needed for decryption */

	/** Tries to create a method with the given name */
	bool (*create_by_name)(const char *name, fastd_method_t **method);
	/** Frees the resources allocated for a method */
	void (*destroy)(fastd_method_t *method);

	/** Returns the key length used by a method */
	size_t (*key_length)(const fastd_method_t *method);

	/** Initiates a session */
	fastd_method_session_state_t *(*session_init)(
		const fastd_method_t *method, const uint8_t *secret, bool initiator);
	/** Closes a session */
	void (*session_free)(fastd_method_session_state_t *session);

	/** Determines if a session is currently valid */
	bool (*session_is_valid)(fastd_method_session_state_t *session);
	/** Determines if this fastd instance is the intiator of a given session */
	bool (*session_is_initiator)(fastd_method_session_state_t *session);
	/** Checks if this side wants to refresh the session, negotiating a new session key */
	bool (*session_want_refresh)(fastd_method_session_state_t *session);
	/** Marks a session as superseded after a refresh */
	void (*session_superseded)(fastd_method_session_state_t *session);

	/** Encrypts a packet for a given session, adding method-specific headers */
	bool (*encrypt)(
		fastd_peer_t *peer, fastd_method_session_state_t *session, fastd_buffer_t **outp, fastd_buffer_t *in);
	/** Decrypts a packet for a given session, stripping method-specific headers */
	bool (*decrypt)(
		fastd_peer_t *peer, fastd_method_session_state_t *session, fastd_buffer_t **outp, fastd_buffer_t *in,
		bool *reordered);
};


/** Searches for a provider providing a method and instanciates it */
bool fastd_method_create_by_name(const char *name, const fastd_method_provider_t **provider, fastd_method_t **method);


/** Finds the fastd_method_info_t for a configured method */
static inline const fastd_method_info_t *fastd_method_get_by_name(const char *name) {
	size_t i;
	for (i = 0; conf.methods[i].name; i++) {
		if (!strcmp(conf.methods[i].name, name))
			return &conf.methods[i];
	}

	return NULL;
}
