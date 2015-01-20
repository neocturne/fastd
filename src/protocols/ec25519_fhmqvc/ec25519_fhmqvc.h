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

   ec25519-fhmqvc protocol: general definitions
*/


#pragma once

#include "../../fastd.h"
#include "../../method.h"
#include "../../peer.h"
#include "../../sha256.h"

#include <libuecc/ecc.h>


/** The length of a \em ec25519-fhmqvc public key */
#define PUBLICKEYBYTES 32

/** The length of a \em ec25519-fhmqvc private key */
#define SECRETKEYBYTES 32


/** A \e libuecc int256, aligned to 32bit, so it can be used as input to the SHA256 functions */
typedef union aligned_int256 {
	ecc_int256_t int256;			/**< ecc_int256_t access */
	uint32_t u32[8];			/**< 32bit-wise access */
	uint8_t u8[32];				/**< byte-wise access */
} aligned_int256_t;

/** A keypair */
typedef struct keypair {
	ecc_int256_t secret;			/**< The secret key */
	aligned_int256_t public;		/**< The public key */
} keypair_t;

/** The protocol-specific configuration */
struct fastd_protocol_config {
	keypair_t key;				/**< The own keypair */
};

/** A peer's public key */
struct fastd_protocol_key {
	aligned_int256_t key;			/**< The peer's public key */
	ecc_25519_work_t unpacked;		/**< The peer's public key (unpacked) */
};


/** Session state */
typedef struct protocol_session {
	/**
	   Stores if remaining handshakes have been unqueued after session establishment.

	   After a session has been established, further scheduled handshakes aren't unqueued
	   before it has been ensured the other side has established the session as well.
	*/
	bool handshakes_cleaned;
	bool refreshing;			/**< true if a session refresh has been triggered by the local side */

	const fastd_method_info_t *method;	/**< The used crypto method */
	fastd_method_session_state_t *method_state; /**< The method-specific state */
} protocol_session_t;

/** Protocol-specific peer state */
struct fastd_protocol_peer_state {
	protocol_session_t old_session;		/**< An old, not yet invalidated session */
	protocol_session_t session;		/**< The newest session */

	uint64_t last_serial;			/**< The serial number of the ephemeral keypair used for the last session establishment */

	/* handshake cache */
	uint64_t last_handshake_serial;		/**< The serial number of the ephemeral keypair used in the last handshake */
	aligned_int256_t peer_handshake_key;	/**< The peer's ephemeral public key used in the last handshake */
	aligned_int256_t sigma;			/**< The value of sigma used in the last handshake */
	fastd_sha256_t shared_handshake_key;	/**< The shared handshake key used in the last handshake */
	fastd_sha256_t shared_handshake_key_compat; /**< The shared handshake key used in the last handshake (pre-v11 compatiblity protocol) */
};


void fastd_protocol_ec25519_fhmqvc_maintenance(void);
void fastd_protocol_ec25519_fhmqvc_init_peer_state(fastd_peer_t *peer);
void fastd_protocol_ec25519_fhmqvc_reset_peer_state(fastd_peer_t *peer);
void fastd_protocol_ec25519_fhmqvc_free_peer_state(fastd_peer_t *peer);

void fastd_protocol_ec25519_fhmqvc_handshake_init(fastd_socket_t *sock, const fastd_peer_address_t *local_addr, const fastd_peer_address_t *remote_addr, fastd_peer_t *peer);
void fastd_protocol_ec25519_fhmqvc_handshake_handle(fastd_socket_t *sock, const fastd_peer_address_t *local_addr, const fastd_peer_address_t *remote_addr, fastd_peer_t *peer, const fastd_handshake_t *handshake);

#ifdef WITH_DYNAMIC_PEERS
void fastd_protocol_ec25519_fhmqvc_handle_verify_return(fastd_peer_t *peer, fastd_socket_t *sock, const fastd_peer_address_t *local_addr, const fastd_peer_address_t *remote_addr, const fastd_method_info_t *method, const void *protocol_data, bool ok);
#endif

void fastd_protocol_ec25519_fhmqvc_send_empty(fastd_peer_t *peer, protocol_session_t *session);

fastd_peer_t * fastd_protocol_ec25519_fhmqvc_find_peer(const fastd_protocol_key_t *key);

void fastd_protocol_ec25519_fhmqvc_generate_key(void);
void fastd_protocol_ec25519_fhmqvc_show_key(void);

void fastd_protocol_ec25519_fhmqvc_set_shell_env(fastd_shell_env_t *env, const fastd_peer_t *peer);
bool fastd_protocol_ec25519_fhmqvc_describe_peer(const fastd_peer_t *peer, char *buf, size_t len);


/** Converts a 32 byte value to a hexadecimal string representation */
static inline void hexdump(char out[65], const unsigned char d[32]) {
	size_t i;
	for (i = 0; i < 32; i++)
		snprintf(out+2*i, 3, "%02x", d[i]);
}

/** Checks if a session is currently valid */
static inline bool is_session_valid(const protocol_session_t *session) {
	return (session->method && session->method->provider->session_is_valid(session->method_state));
}


/** Divides a secret key by 8 (for some optimizations) */
static inline bool divide_key(ecc_int256_t *key) {
	uint8_t c = 0, c2;
	ssize_t i;

	for (i = 31; i >= 0; i--) {
		c2 = key->p[i] << 5;
		key->p[i] = (key->p[i] >> 3) | c;
		c = c2;
	}

	return (c == 0);
}

/** Multiplies a point by 8 */
static inline void octuple_point(ecc_25519_work_t *p) {
	ecc_25519_work_t work;
	ecc_25519_double(&work, p);
	ecc_25519_double(&work, &work);
	ecc_25519_double(p, &work);
}
