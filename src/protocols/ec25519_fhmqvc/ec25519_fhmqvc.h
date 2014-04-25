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

#include "../../fastd.h"
#include "../../method.h"
#include "../../peer.h"
#include "../../sha256.h"

#include <libuecc/ecc.h>


#define PUBLICKEYBYTES 32
#define SECRETKEYBYTES 32


typedef union aligned_int256 {
	ecc_int256_t int256;
	uint32_t u32[8];
	uint8_t u8[32];
} aligned_int256_t;

typedef struct keypair {
	ecc_int256_t secret;
	aligned_int256_t public;
} keypair_t;

struct fastd_protocol_config {
	keypair_t key;
};

struct fastd_protocol_peer_config {
	aligned_int256_t public_key;
};

typedef struct protocol_session {
	bool handshakes_cleaned;
	bool refreshing;

	const fastd_method_info_t *method;
	fastd_method_session_state_t *method_state;
} protocol_session_t;

struct fastd_protocol_peer_state {
	protocol_session_t old_session;
	protocol_session_t session;

	uint64_t last_serial;

	/* handshake cache */
	uint64_t last_handshake_serial;
	aligned_int256_t peer_handshake_key;
	aligned_int256_t sigma;
	fastd_sha256_t shared_handshake_key;
	fastd_sha256_t shared_handshake_key_compat;
};


bool fastd_protocol_ec25519_fhmqvc_peer_check(fastd_peer_config_t *peer_conf);
bool fastd_protocol_ec25519_fhmqvc_peer_check_temporary(fastd_peer_t *peer);

void fastd_protocol_ec25519_fhmqvc_maintenance(void);
void fastd_protocol_ec25519_fhmqvc_init_peer_state(fastd_peer_t *peer);
void fastd_protocol_ec25519_fhmqvc_reset_peer_state(fastd_peer_t *peer);
void fastd_protocol_ec25519_fhmqvc_free_peer_state(fastd_peer_t *peer);

void fastd_protocol_ec25519_fhmqvc_handshake_init(fastd_socket_t *sock, const fastd_peer_address_t *local_addr, const fastd_peer_address_t *remote_addr, fastd_peer_t *peer);
void fastd_protocol_ec25519_fhmqvc_handshake_handle(fastd_socket_t *sock, const fastd_peer_address_t *local_addr, const fastd_peer_address_t *remote_addr, fastd_peer_t *peer, const fastd_handshake_t *handshake, const fastd_method_info_t *method);
void fastd_protocol_ec25519_fhmqvc_handle_verify_return(fastd_peer_t *peer, fastd_socket_t *sock, const fastd_peer_address_t *local_addr, const fastd_peer_address_t *remote_addr, const fastd_method_info_t *method, const void *protocol_data, bool ok);

void fastd_protocol_ec25519_fhmqvc_send_empty(fastd_peer_t *peer, protocol_session_t *session);

void fastd_protocol_ec25519_fhmqvc_generate_key(void);
void fastd_protocol_ec25519_fhmqvc_show_key(void);
void fastd_protocol_ec25519_fhmqvc_set_shell_env(fastd_shell_env_t *env, const fastd_peer_t *peer);
bool fastd_protocol_ec25519_fhmqvc_describe_peer(const fastd_peer_t *peer, char *buf, size_t len);


static inline void hexdump(char out[65], const unsigned char d[32]) {
	size_t i;
	for (i = 0; i < 32; i++)
		snprintf(out+2*i, 3, "%02x", d[i]);
}


static inline bool is_session_valid(const protocol_session_t *session) {
	return (session->method && session->method->provider->session_is_valid(session->method_state));
}
