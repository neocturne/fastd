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


struct fastd_peer {
	uint64_t id;

	const fastd_peer_config_t *config;
	fastd_peer_group_t *group;

	fastd_socket_t *sock;
	fastd_peer_address_t local_address;
	fastd_peer_address_t address;

	fastd_peer_state_t state;
	struct timespec timeout;
	struct timespec keepalive_timeout;

	VECTOR(fastd_remote_t) remotes;
	ssize_t next_remote;

	struct timespec next_handshake;
	fastd_dlist_head_t handshake_entry;

	struct timespec last_handshake_timeout;
	fastd_peer_address_t last_handshake_address;

	struct timespec last_handshake_response_timeout;
	fastd_peer_address_t last_handshake_response_address;

	struct timespec establish_handshake_timeout;

	fastd_protocol_peer_config_t *protocol_config;
	fastd_protocol_peer_state_t *protocol_state;
};

struct fastd_peer_config {
	fastd_peer_config_t *next;

	const char *config_source_dir;

	bool enabled;
	char *name;

	fastd_remote_config_t *remotes;
	char *key;
	bool floating;
	const fastd_peer_group_config_t *group;

	fastd_protocol_peer_config_t *protocol_config;
};

struct fastd_peer_eth_addr {
	fastd_eth_addr_t addr;
	fastd_peer_t *peer;
	struct timespec timeout;
};

struct fastd_remote {
	fastd_remote_config_t *config;

	size_t n_addresses;
	size_t current_address;
	fastd_peer_address_t *addresses;

	struct timespec last_resolve_timeout;
};

struct fastd_remote_config {
	fastd_remote_config_t *next;

	char *hostname;
	fastd_peer_address_t address;
};


bool fastd_peer_address_equal(const fastd_peer_address_t *addr1, const fastd_peer_address_t *addr2);
void fastd_peer_address_simplify(fastd_peer_address_t *addr);
void fastd_peer_address_widen(fastd_peer_address_t *addr);

static inline uint16_t fastd_peer_address_get_port(const fastd_peer_address_t *addr) {
	switch (addr->sa.sa_family) {
	case AF_INET:
		return addr->in.sin_port;

	case AF_INET6:
		return addr->in6.sin6_port;

	default:
		return 0;
	}
}

fastd_peer_config_t* fastd_peer_config_new(void);
void fastd_peer_config_free(fastd_peer_config_t *peer);
void fastd_peer_config_delete(void);
void fastd_peer_config_purge(fastd_peer_config_t *config);
bool fastd_peer_config_equal(const fastd_peer_config_t *peer1, const fastd_peer_config_t *peer2);

void fastd_peer_reset(fastd_peer_t *peer);
void fastd_peer_delete(fastd_peer_t *peer);
fastd_peer_t* fastd_peer_add(fastd_peer_config_t *peer_conf);
bool fastd_peer_verify_temporary(fastd_peer_t *peer, const fastd_peer_address_t *local_addr, const fastd_peer_address_t *peer_addr);
void fastd_peer_enable_temporary(fastd_peer_t *peer);
void fastd_peer_set_established(fastd_peer_t *peer);
bool fastd_peer_may_connect(fastd_peer_t *peer);
void fastd_peer_handle_resolve(fastd_peer_t *peer, fastd_remote_t *remote, size_t n_addresses, const fastd_peer_address_t *addresses);
bool fastd_peer_owns_address(const fastd_peer_t *peer, const fastd_peer_address_t *addr);
bool fastd_peer_matches_address(const fastd_peer_t *peer, const fastd_peer_address_t *addr);
bool fastd_peer_claim_address(fastd_peer_t *peer, fastd_socket_t *sock, const fastd_peer_address_t *local_addr, const fastd_peer_address_t *remote_addr, bool force);
void fastd_peer_reset_socket(fastd_peer_t *peer);
void fastd_peer_schedule_handshake(fastd_peer_t *peer, int delay);
fastd_peer_t* fastd_peer_find_by_id(uint64_t id);

void fastd_peer_set_shell_env(fastd_shell_env_t *env, const fastd_peer_t *peer, const fastd_peer_address_t *local_addr, const fastd_peer_address_t *peer_addr);
void fastd_peer_exec_shell_command(const fastd_shell_command_t *command, const fastd_peer_t *peer, const fastd_peer_address_t *local_addr, const fastd_peer_address_t *peer_addr);

static inline void fastd_peer_schedule_handshake_default(fastd_peer_t *peer) {
	fastd_peer_schedule_handshake(peer, fastd_rand(17500, 22500));
}

static inline void fastd_peer_unschedule_handshake(fastd_peer_t *peer) {
	fastd_dlist_remove(&peer->handshake_entry);
}

static inline bool fastd_peer_handshake_scheduled(fastd_peer_t *peer) {
	return fastd_dlist_linked(&peer->handshake_entry);
}

static inline bool fastd_peer_config_is_floating(const fastd_peer_config_t *config) {
	return (!config->remotes || config->floating);
}

bool fastd_remote_matches_dynamic(const fastd_remote_config_t *remote, const fastd_peer_address_t *addr);

static inline bool fastd_peer_is_floating(const fastd_peer_t *peer) {
	return peer->config ? fastd_peer_config_is_floating(peer->config) : true;
}

static inline bool fastd_peer_is_temporary(const fastd_peer_t *peer) {
	return (!peer->config);
}

static inline fastd_remote_t * fastd_peer_get_next_remote(fastd_peer_t *peer) {
	if (peer->next_remote < 0)
	     return NULL;

	return &VECTOR_INDEX(peer->remotes, peer->next_remote);
}

static inline bool fastd_peer_is_established(const fastd_peer_t *peer) {
	switch(peer->state) {
	case STATE_ESTABLISHED:
		return true;

	default:
		return false;
	}
}

static inline bool fastd_remote_is_dynamic(const fastd_remote_t *remote) {
	return remote->config->hostname;
}

static inline void fastd_peer_seen(fastd_peer_t *peer) {
	peer->timeout = fastd_in_seconds(conf.peer_stale_time);
}

static inline bool fastd_peer_is_socket_dynamic(const fastd_peer_t *peer) {
	return (!peer->sock || !peer->sock->addr);
}

static inline bool fastd_eth_addr_is_unicast(fastd_eth_addr_t addr) {
	return ((addr.data[0] & 1) == 0);
}

void fastd_peer_eth_addr_add(fastd_peer_t *peer, fastd_eth_addr_t addr);
fastd_peer_t* fastd_peer_find_by_eth_addr(fastd_eth_addr_t addr);

void fastd_peer_handle_handshake_queue(void);
void fastd_peer_maintenance(void);
