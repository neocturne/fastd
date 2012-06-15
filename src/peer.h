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


#ifndef _FASTD_PEER_H_
#define _FASTD_PEER_H_

#include "fastd.h"


struct _fastd_peer {
	fastd_peer *next;

	const fastd_peer_config *config;

	fastd_peer_address address;

	bool established;

	struct timespec last_resolve;
	struct timespec last_resolve_return;
	struct timespec seen;

	struct timespec last_handshake;
	fastd_peer_address last_handshake_address;

	struct timespec last_handshake_response;
	fastd_peer_address last_handshake_response_address;

	fastd_protocol_peer_state *protocol_state;
};

struct _fastd_peer_config {
	fastd_peer_config *next;

	const char *config_source_dir;

	bool enabled;
	char *name;

	char *hostname;
	fastd_peer_address address;
	bool dynamic_float;
	char *key;

	fastd_protocol_peer_config *protocol_config;
};

struct _fastd_peer_eth_addr {
	fastd_eth_addr addr;
	fastd_peer *peer;
	struct timespec seen;
};


bool fastd_peer_address_equal(const fastd_peer_address *addr1, const fastd_peer_address *addr2);

fastd_peer_config* fastd_peer_config_new(fastd_context *ctx, fastd_config *conf);
void fastd_peer_config_free(fastd_peer_config *peer);
void fastd_peer_config_delete(fastd_context *ctx, fastd_config *conf);
void fastd_peer_config_purge(fastd_context *ctx, fastd_peer_config *conf);
bool fastd_peer_config_equal(const fastd_peer_config *peer1, const fastd_peer_config *peer2);

void fastd_peer_reset(fastd_context *ctx, fastd_peer *peer);
void fastd_peer_delete(fastd_context *ctx, fastd_peer *peer);
fastd_peer* fastd_peer_add(fastd_context *ctx, fastd_peer_config *conf);
void fastd_peer_set_established(fastd_context *ctx, fastd_peer *peer);
bool fastd_peer_claim_address(fastd_context *ctx, fastd_peer *peer, const fastd_peer_address *addr);

const fastd_eth_addr* fastd_get_source_address(const fastd_context *ctx, fastd_buffer buffer);
const fastd_eth_addr* fastd_get_dest_address(const fastd_context *ctx, fastd_buffer buffer);

static inline bool fastd_peer_config_is_floating(const fastd_peer_config *config) {
	return ((config->hostname == NULL && config->address.sa.sa_family == AF_UNSPEC) || config->dynamic_float);
}

static inline bool fastd_peer_config_is_dynamic(const fastd_peer_config *config) {
	return (config->hostname != NULL);
}

bool fastd_peer_config_matches_dynamic(const fastd_peer_config *config, const fastd_peer_address *addr);

static inline bool fastd_peer_is_floating(const fastd_peer *peer) {
	return fastd_peer_config_is_floating(peer->config);
}

static inline bool fastd_peer_is_dynamic(const fastd_peer *peer) {
	return fastd_peer_config_is_dynamic(peer->config);
}

static inline bool fastd_peer_is_established(const fastd_peer *peer) {
	return peer->established;
}

static inline void fastd_peer_seen(fastd_context *ctx, fastd_peer *peer) {
	peer->seen = ctx->now;
}

static inline bool fastd_eth_addr_is_unicast(const fastd_eth_addr *addr) {
	return ((addr->data[0] & 1) == 0);
}

void fastd_peer_eth_addr_add(fastd_context *ctx, fastd_peer *peer, const fastd_eth_addr *addr);
void fastd_peer_eth_addr_cleanup(fastd_context *ctx);
fastd_peer* fastd_peer_find_by_eth_addr(fastd_context *ctx, const fastd_eth_addr *addr);

#endif /* _FASTD_PEER_H_ */
