// SPDX-License-Identifier: BSD-2-Clause
/*
  Copyright (c) Matthias Schiffer <mschiffer@universe-factory.net>
  All rights reserved.
*/

/**
   \file

   Structures and functions for peer management
*/


#pragma once

#include "fastd.h"


/** The state of a peer */
typedef enum fastd_peer_state {
	STATE_INACTIVE = 0, /**< The peer is not active at the moment */
	STATE_PASSIVE,      /**< The peer is waiting for incoming connections */
	STATE_RESOLVING,    /**< The peer is currently resolving its first remote */
	STATE_HANDSHAKE,    /**< The peer has tried to perform a handshake */
	STATE_ESTABLISHED,  /**< The peer has established a connection */
} fastd_peer_state_t;

/** The config state of a peer */
typedef enum fastd_peer_config_state {
	CONFIG_NEW = 0,  /**< The peer is configured statically, but has not been enabled yet */
	CONFIG_STATIC,   /**< The peer is configured statically */
	CONFIG_DISABLED, /**< The peer is configured statically, but has been disabled because of a configuration error
			  */
#ifdef WITH_DYNAMIC_PEERS
	CONFIG_DYNAMIC, /**< The peer is configured dynamically (using a on-verify handler) */
#endif
} fastd_peer_config_state_t;

/** A peer's configuration and state */
struct fastd_peer {
	/* The following fields are more or less static configuration: */

	uint64_t id; /**< A unique ID assigned to each peer */

	char *name;                      /**< The peer's name */
	const fastd_peer_group_t *group; /**< The peer group the peer belongs to */
	const char *config_source_dir;   /**< The directory this peer's configuration was loaded from */

	VECTOR(fastd_remote_t) remotes; /**< The vector of the peer's remotes */
	bool floating;                  /**< Specifies if the peer has any floating remotes */

	fastd_peer_config_state_t config_state; /**< Specifies the way this peer was configured and if it is enabled */

	fastd_protocol_key_t *key;                   /**< The peer's public key */
	fastd_protocol_peer_state_t *protocol_state; /**< Protocol-specific peer state */

	char *ifname; /**< Peer-specific interface name */
	uint16_t mtu; /**< Peer-specific interface MTU */

	/* Starting here, more dynamic fields follow: */

	fastd_iface_t *iface; /**< The interface this peer is associated with */
	/** The socket used by the peer. This can either be a common bound socket or a
	    dynamic, unbound socket that is used exclusively by this peer */
	fastd_socket_t *sock;
	const fastd_offload_t *offload;       /**< Datapath kernel offloading provider */
	fastd_offload_state_t *offload_state; /**< Datapath kernel offloading - provider-specific state */
	fastd_peer_address_t local_address;   /**< The local address used to communicate with this peer */
	fastd_peer_address_t address;         /**< The peers current address */

	fastd_peer_address_t last_handshake_address;          /**< The address the last handshake was sent to */
	fastd_peer_address_t last_handshake_response_address; /**< The address the last handshake was received from */
	ssize_t next_remote;                                  /**< An index into the field remotes or -1 */

	fastd_peer_state_t state; /**< The peer's state */

	fastd_task_t task; /**< Task queue entry for periodic maintenance tasks */

	fastd_timeout_t next_handshake;         /**< The time of the next handshake */
	fastd_timeout_t last_handshake_timeout; /**< No handshakes are sent to the peer until this timeout has occured
						   to avoid flooding the peer */
	fastd_timeout_t last_handshake_response_timeout; /**< All handshakes from last_handshake_address will be ignored
							    until this timeout has occured */
	fastd_timeout_t establish_handshake_timeout; /**< A timeout during which all handshakes for this peer will be
							ignored after a new connection has been established */
	int64_t established;                         /**< The time this peer connection has been established */

	fastd_timeout_t reset_timeout;     /**< The timeout after which the peer is reset */
	fastd_timeout_t keepalive_timeout; /**< The timeout after which a keepalive is sent to the peer */

	fastd_stats_t stats; /**< Traffic statistics */

#ifdef WITH_DYNAMIC_PEERS
	fastd_timeout_t verify_timeout; /**< Specifies the minimum time after which on-verify may be run again */
	fastd_timeout_t
		verify_valid_timeout; /**< Specifies how long a peer stays valid after a successful on-verify run */
#endif
};


/** An entry for a MAC address seen at another peer */
struct fastd_peer_eth_addr {
	fastd_eth_addr_t addr;   /**< The MAC address */
	fastd_peer_t *peer;      /**< The corresponding peer */
	fastd_timeout_t timeout; /**< Timeout after which the address entry will be purged */
};

/** A remote entry */
struct fastd_remote {
	char *hostname;               /**< The hostname or NULL */
	fastd_peer_address_t address; /**< The address; if hostname is set only sin.sin_port is used */

	size_t n_addresses;              /**< The size of the \e addresses array */
	size_t current_address;          /**< The index of the remote the next handshake will be sent to */
	fastd_peer_address_t *addresses; /**< The IP addresses the remote was resolved to */

	fastd_timeout_t last_resolve_timeout; /**< Timeout before the remote must not be resolved again */
};


bool fastd_peer_address_equal(const fastd_peer_address_t *addr1, const fastd_peer_address_t *addr2);
void fastd_peer_address_simplify(fastd_peer_address_t *addr);
void fastd_peer_address_widen(fastd_peer_address_t *addr);

bool fastd_peer_add(fastd_peer_t *peer);
void fastd_peer_reset(fastd_peer_t *peer);
void fastd_peer_delete(fastd_peer_t *peer);
void fastd_peer_free(fastd_peer_t *peer);
bool fastd_peer_set_established(fastd_peer_t *peer, const fastd_offload_t *offload);
bool fastd_peer_may_connect(fastd_peer_t *peer);
void fastd_peer_handle_resolve(
	fastd_peer_t *peer, fastd_remote_t *remote, size_t n_addresses, const fastd_peer_address_t *addresses);
bool fastd_peer_owns_address(const fastd_peer_t *peer, const fastd_peer_address_t *addr);
bool fastd_peer_matches_address(const fastd_peer_t *peer, const fastd_peer_address_t *addr);
bool fastd_peer_claim_address(
	fastd_peer_t *peer, fastd_socket_t *sock, const fastd_peer_address_t *local_addr,
	const fastd_peer_address_t *remote_addr, bool force);
void fastd_peer_reset_socket(fastd_peer_t *peer);
void fastd_peer_schedule_handshake(fastd_peer_t *peer, int delay);
fastd_peer_t *fastd_peer_find_by_id(uint64_t id);

void fastd_peer_set_shell_env(
	fastd_shell_env_t *env, const fastd_peer_t *peer, const fastd_peer_address_t *local_addr,
	const fastd_peer_address_t *peer_addr);
void fastd_peer_exec_shell_command(
	const fastd_shell_command_t *command, const fastd_peer_t *peer, const fastd_peer_address_t *local_addr,
	const fastd_peer_address_t *peer_addr, bool sync);

void fastd_peer_eth_addr_add(fastd_peer_t *peer, fastd_eth_addr_t addr);
bool fastd_peer_find_by_eth_addr(const fastd_eth_addr_t addr, fastd_peer_t **peer);

void fastd_peer_handle_task(fastd_task_t *task);
void fastd_peer_eth_addr_cleanup(void);
void fastd_peer_reset_all(void);


/** Returns the port of a fastd_peer_address_t (in network byte order) */
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

/** Returns a random value in the range DEFAULT_HANDSHAKE_INTERVAL +/- DEFAULT_HANDSHAKE_JITTER */
static inline int fastd_peer_handshake_default_rand(void) {
	return fastd_rand(
		DEFAULT_HANDSHAKE_INTERVAL - DEFAULT_HANDSHAKE_JITTER,
		DEFAULT_HANDSHAKE_INTERVAL + DEFAULT_HANDSHAKE_JITTER);
}

/** Schedules a handshake with the default delay and jitter */
static inline void fastd_peer_schedule_handshake_default(fastd_peer_t *peer) {
	fastd_peer_schedule_handshake(peer, fastd_peer_handshake_default_rand());
}

/** Cancels a scheduled handshake */
static inline void fastd_peer_unschedule_handshake(fastd_peer_t *peer) {
	peer->next_handshake = FASTD_TIMEOUT_INV;
}

#ifdef WITH_DYNAMIC_PEERS
/** Call to signal that there is currently an asychronous on-verify command running for the peer */
static inline void fastd_peer_set_verifying(fastd_peer_t *peer) {
	peer->verify_timeout = ctx.now + MIN_VERIFY_INTERVAL;

	fastd_timeout_advance(&peer->reset_timeout, peer->verify_timeout);
}

/** Marks the peer verification as successful or failed */
static inline void fastd_peer_set_verified(fastd_peer_t *peer, bool ok) {
	peer->verify_valid_timeout = ctx.now + (ok ? VERIFY_VALID_TIME : 0);

	fastd_timeout_advance(&peer->reset_timeout, peer->verify_valid_timeout);
}
#endif

/** Checks if there's a handshake queued for the peer */
static inline bool fastd_peer_handshake_scheduled(fastd_peer_t *peer) {
	return (peer->next_handshake != FASTD_TIMEOUT_INV);
}

/** Checks if a peer is floating (is has at least one floating remote or no remotes at all) */
static inline bool fastd_peer_is_floating(const fastd_peer_t *peer) {
	return (!VECTOR_LEN(peer->remotes) || peer->floating);
}

/** Checks if a peer is not statically configured, but added after a on-verify run */
static inline bool fastd_peer_is_dynamic(UNUSED const fastd_peer_t *peer) {
#ifdef WITH_DYNAMIC_PEERS
	return peer->config_state == CONFIG_DYNAMIC;
#else
	return false;
#endif
}

/** Checks if a peer is enabled */
static inline bool fastd_peer_is_enabled(const fastd_peer_t *peer) {
	switch (peer->config_state) {
	case CONFIG_STATIC:
#ifdef WITH_DYNAMIC_PEERS
	case CONFIG_DYNAMIC:
#endif
		return true;
	default:
		return false;
	}
}

/** Returns the currently active remote entry */
static inline fastd_remote_t *fastd_peer_get_next_remote(fastd_peer_t *peer) {
	if (peer->next_remote < 0)
		return NULL;

	return &VECTOR_INDEX(peer->remotes, peer->next_remote);
}

/** Checks if the peer currently has an established connection */
static inline bool fastd_peer_is_established(const fastd_peer_t *peer) {
	switch (peer->state) {
	case STATE_ESTABLISHED:
		return true;

	default:
		return false;
	}
}

/** Signals that a valid packet was received from the peer */
static inline void fastd_peer_seen(fastd_peer_t *peer) {
	peer->reset_timeout = ctx.now + PEER_STALE_TIME;
}

/** Resets the keepalive timeout */
static inline void fastd_peer_clear_keepalive(fastd_peer_t *peer) {
	peer->keepalive_timeout = ctx.now + KEEPALIVE_TIMEOUT;
}

/** Checks if a peer uses dynamic sockets (which means that each connection attempt uses a new socket) */
static inline bool fastd_peer_is_socket_dynamic(const fastd_peer_t *peer) {
	return (!peer->sock || !peer->sock->addr);
}

/** Returns the MTU to use for a peer */
static inline uint16_t fastd_peer_get_mtu(const fastd_peer_t *peer) {
	if (conf.mode == MODE_TAP)
		return conf.mtu;

	if (peer && peer->mtu)
		return peer->mtu;

	return conf.mtu;
}

/** Checks if a MAC address is a normal unicast address */
static inline bool fastd_eth_addr_is_unicast(fastd_eth_addr_t addr) {
	return ((addr.data[0] & 1) == 0);
}

/** Adds statistics for a single packet of a given size */
static inline void fastd_stats_add(UNUSED fastd_peer_t *peer, UNUSED fastd_stat_type_t stat, UNUSED size_t bytes) {
#ifdef WITH_STATUS_SOCKET
	if (!bytes)
		return;

	ctx.stats.packets[stat]++;
	ctx.stats.bytes[stat] += bytes;

	peer->stats.packets[stat]++;
	peer->stats.bytes[stat] += bytes;
#endif
}
