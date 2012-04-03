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


union _fastd_peer_address {
	struct sockaddr sa;
	struct sockaddr_in in;
	struct sockaddr_in6 in6;
};

struct _fastd_peer {
	fastd_peer *next;

	const fastd_peer_config *config;

	fastd_peer_address address;

	fastd_peer_state state;
	uint8_t last_req_id;

	struct timespec seen;

	fastd_protocol_peer_state *protocol_state;
};

struct _fastd_peer_config {
	fastd_peer_config *next;

	char *config_source_dir;

	bool enabled;
	char *name;

	fastd_peer_address address;
	char *key;

	fastd_protocol_peer_config *protocol_config;
};

struct _fastd_peer_eth_addr {
	fastd_eth_addr addr;
	fastd_peer *peer;
	struct timespec seen;
};


fastd_peer_config* fastd_peer_config_new(fastd_context *ctx, fastd_config *conf);
void fastd_peer_config_delete(fastd_context *ctx, fastd_config *conf);

void fastd_peer_reset(fastd_context *ctx, fastd_peer *peer);
fastd_peer* fastd_peer_add(fastd_context *ctx, fastd_peer_config *conf);
fastd_peer* fastd_peer_add_temp(fastd_context *ctx, const fastd_peer_address *address);
fastd_peer* fastd_peer_set_established_merge(fastd_context *ctx, fastd_peer *perm_peer, fastd_peer *temp_peer);
void fastd_peer_set_established(fastd_context *ctx, fastd_peer *peer);

const fastd_eth_addr* fastd_get_source_address(const fastd_context *ctx, fastd_buffer buffer);
const fastd_eth_addr* fastd_get_dest_address(const fastd_context *ctx, fastd_buffer buffer);

static inline bool fastd_peer_config_is_floating(const fastd_peer_config *config) {
	return (config->address.sa.sa_family == AF_UNSPEC);
}

static inline bool fastd_peer_is_floating(const fastd_peer *peer) {
	return (peer->config && fastd_peer_config_is_floating(peer->config));
}

static inline bool fastd_peer_is_temporary(const fastd_peer *peer) {
	return (peer->state == STATE_TEMP);
}

static inline bool fastd_peer_is_established(const fastd_peer *peer) {
	return (peer->state == STATE_ESTABLISHED);
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
