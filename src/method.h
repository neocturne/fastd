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

   Management of encryption methods
*/


#pragma once

#include "fastd.h"


/** Information about a single encryption method */
struct fastd_method_info {
	const char *name;				/**< The method name */
	const fastd_method_provider_t *provider;	/**< The provider of the method */
	fastd_method_t *method;				/**< Provider-specific method data */
};

/** Describes a method provider (an implementation of a class of encryption methods) */
struct fastd_method_provider {
	size_t max_overhead;				/**< The maximum number of bytes of overhead the methods may add */
	size_t min_encrypt_head_space;			/**< The minimum head space needed for encrytion */
	size_t min_decrypt_head_space;			/**< The minimum head space needed for decryption */
	size_t min_encrypt_tail_space;			/**< The minimum tail space needed for encryption */
	size_t min_decrypt_tail_space;			/**< The minimum tail space needed for decryption */

	/** Tries to create a method with the given name */
	bool (*create_by_name)(const char *name, fastd_method_t **method);
	/** Frees the resources allocated for a method */
	void (*destroy)(fastd_method_t *method);

	/** Returns the key length used by a method */
	size_t (*key_length)(const fastd_method_t *method);

	/** Initiates a session */
	fastd_method_session_state_t * (*session_init)(const fastd_method_t *method, const uint8_t *secret, bool initiator);
	/** Initiates a session in pre-v11 compatiblity mode */
	fastd_method_session_state_t * (*session_init_compat)(const fastd_method_t *method, const uint8_t *secret, size_t length, bool initiator);
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
	bool (*encrypt)(fastd_peer_t *peer, fastd_method_session_state_t *session, fastd_buffer_t *out, fastd_buffer_t in);
	/** Decrypts a packet for a given session, stripping method-specific headers */
	bool (*decrypt)(fastd_peer_t *peer, fastd_method_session_state_t *session, fastd_buffer_t *out, fastd_buffer_t in, bool *reordered);
};


/** Searches for a provider providing a method and instanciates it */
bool fastd_method_create_by_name(const char *name, const fastd_method_provider_t **provider, fastd_method_t **method);


/** Finds the fastd_method_info_t for a configured method */
static inline const fastd_method_info_t * fastd_method_get_by_name(const char *name) {
	size_t i;
	for (i = 0; conf.methods[i].name; i++) {
		if (!strcmp(conf.methods[i].name, name))
			return &conf.methods[i];
	}

	return NULL;
}
