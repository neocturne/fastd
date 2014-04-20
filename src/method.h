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


#pragma once

#include "fastd.h"


struct fastd_method_info {
	const char *name;
	const fastd_method_provider_t *provider;
	fastd_method_t *method;
};

struct fastd_method_provider {
	size_t max_overhead;
	size_t min_encrypt_head_space;
	size_t min_decrypt_head_space;
	size_t min_encrypt_tail_space;
	size_t min_decrypt_tail_space;

	bool (*create_by_name)(const char *name, fastd_method_t **method);
	void (*destroy)(fastd_method_t *method);

	size_t (*key_length)(const fastd_method_t *method);

	fastd_method_session_state_t* (*session_init)(const fastd_method_t *method, const uint8_t *secret, bool initiator);
	fastd_method_session_state_t* (*session_init_compat)(const fastd_method_t *method, const uint8_t *secret, size_t length, bool initiator);
	bool (*session_is_valid)(fastd_method_session_state_t *session);
	bool (*session_is_initiator)(fastd_method_session_state_t *session);
	bool (*session_want_refresh)(fastd_method_session_state_t *session);
	void (*session_superseded)(fastd_method_session_state_t *session);
	void (*session_free)(fastd_method_session_state_t *session);

	bool (*encrypt)(fastd_peer_t *peer, fastd_method_session_state_t *session, fastd_buffer_t *out, fastd_buffer_t in);
	bool (*decrypt)(fastd_peer_t *peer, fastd_method_session_state_t *session, fastd_buffer_t *out, fastd_buffer_t in);
};


bool fastd_method_create_by_name(const char *name, const fastd_method_provider_t **provider, fastd_method_t **method);


static inline const fastd_method_info_t* fastd_method_get_by_name(const char *name) {
	size_t i;
	for (i = 0; conf.methods[i].name; i++) {
		if (!strcmp(conf.methods[i].name, name))
			return &conf.methods[i];
	}

	return NULL;
}
