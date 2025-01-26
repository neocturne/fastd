// SPDX-License-Identifier: BSD-2-Clause
/*
  Copyright (c) 2012-2016, Matthias Schiffer <mschiffer@universe-factory.net>
  All rights reserved.
*/

/**
   \file

   Implementations of functions for peer management
*/

#include "peer.h"
#include "handshake.h"
#include "offload/offload.h"
#include "peer_group.h"
#include "peer_hashtable.h"
#include "polling.h"

#include <arpa/inet.h>
#include <sys/wait.h>


/** Adds address and port of an fastd_peer_address_t to \e env */
static void fastd_peer_set_shell_env_addr(
	fastd_shell_env_t *env, const fastd_peer_address_t *addr, const char *address_var, const char *port_var) {
	/* both INET6_ADDRSTRLEN and IFNAMSIZ already include space for the zero termination, so there is no need to add
	 * space for the '%' here. */
	char buf[INET6_ADDRSTRLEN + IFNAMSIZ];

	switch (addr ? addr->sa.sa_family : AF_UNSPEC) {
	case AF_INET:
		inet_ntop(AF_INET, &addr->in.sin_addr, buf, sizeof(buf));
		fastd_shell_env_set(env, address_var, buf);

		snprintf(buf, sizeof(buf), "%u", ntohs(addr->in.sin_port));
		fastd_shell_env_set(env, port_var, buf);

		return;

	case AF_INET6:
		inet_ntop(AF_INET6, &addr->in6.sin6_addr, buf, sizeof(buf));

		if (IN6_IS_ADDR_LINKLOCAL(&addr->in6.sin6_addr)) {
			if (if_indextoname(addr->in6.sin6_scope_id, buf + strlen(buf) + 1))
				buf[strlen(buf)] = '%';
		}

		fastd_shell_env_set(env, address_var, buf);

		snprintf(buf, sizeof(buf), "%u", ntohs(addr->in6.sin6_port));
		fastd_shell_env_set(env, port_var, buf);

		return;
	}

	fastd_shell_env_set(env, address_var, NULL);
	fastd_shell_env_set(env, port_var, NULL);
}


/** Adds peer-specific fields to \e env */
void fastd_peer_set_shell_env(
	fastd_shell_env_t *env, const fastd_peer_t *peer, const fastd_peer_address_t *local_addr,
	const fastd_peer_address_t *peer_addr) {

	fastd_shell_env_set(env, "PEER_NAME", peer ? peer->name : NULL);

	const char *ifname = NULL;
	uint16_t mtu = 0;
	if (peer) {
		if (peer->offload) {
			peer->offload->get_iface(peer->offload_state, &ifname, &mtu);
		} else if (peer->iface) {
			ifname = peer->iface->name;
			mtu = peer->iface->mtu;
		}
	}
	fastd_shell_env_set_iface(env, ifname, mtu);

	fastd_peer_set_shell_env_addr(env, local_addr, "LOCAL_ADDRESS", "LOCAL_PORT");
	fastd_peer_set_shell_env_addr(env, peer_addr, "PEER_ADDRESS", "PEER_PORT");

	conf.protocol->set_shell_env(env, peer);
}

/** Executes a shell command, providing peer-specific enviroment fields */
void fastd_peer_exec_shell_command(
	const fastd_shell_command_t *command, const fastd_peer_t *peer, const fastd_peer_address_t *local_addr,
	const fastd_peer_address_t *peer_addr, bool sync) {
	fastd_shell_env_t *env = fastd_shell_env_alloc();
	fastd_peer_set_shell_env(env, peer, local_addr, peer_addr);

	if (sync)
		fastd_shell_command_exec_sync(command, env, NULL);
	else
		fastd_shell_command_exec(command, env);

	fastd_shell_env_free(env);
}

/** Calls the on-up command */
static inline void on_up(const fastd_peer_t *peer, bool sync) {
	const fastd_shell_command_t *on_up = fastd_peer_group_lookup_peer_shell_command(peer, on_up);
	fastd_peer_exec_shell_command(on_up, peer, NULL, NULL, sync);
}

/** Calls the on-down command */
static inline void on_down(const fastd_peer_t *peer, bool sync) {
	const fastd_shell_command_t *on_down = fastd_peer_group_lookup_peer_shell_command(peer, on_down);
	fastd_peer_exec_shell_command(on_down, peer, NULL, NULL, sync);
}

/** Executes the on-establish command for a peer */
static inline void on_establish(const fastd_peer_t *peer) {
	const fastd_shell_command_t *on_establish = fastd_peer_group_lookup_peer_shell_command(peer, on_establish);
	fastd_peer_exec_shell_command(on_establish, peer, &peer->local_address, &peer->address, false);
}

/** Executes the on-disestablish command for a peer */
static inline void on_disestablish(const fastd_peer_t *peer) {
	const fastd_shell_command_t *on_disestablish =
		fastd_peer_group_lookup_peer_shell_command(peer, on_disestablish);
	fastd_peer_exec_shell_command(on_disestablish, peer, &peer->local_address, &peer->address, false);
}

/** Compares two peers by their peer ID */
static int peer_id_cmp(fastd_peer_t *const *a, fastd_peer_t *const *b) {
	if ((*a)->id == (*b)->id)
		return 0;
	else if ((*a)->id < (*b)->id)
		return -1;
	else
		return 1;
}

/** Finds the entry for a peer with a specified ID in the array \e ctx.peers */
static fastd_peer_t **peer_p_find_by_id(uint64_t id) {
	fastd_peer_t key = { .id = id };
	fastd_peer_t *const keyp = &key;

	return VECTOR_BSEARCH(&keyp, ctx.peers, peer_id_cmp);
}

/** Finds the index of a peer with a specified ID in the array \e ctx.peers */
static size_t peer_index_find_by_id(uint64_t id) {
	fastd_peer_t **ret = peer_p_find_by_id(id);

	if (!ret)
		exit_bug("peer_index_find_by_id: not found");

	return ret - VECTOR_DATA(ctx.peers);
}

/** Finds the index of a peer in the array \e ctx.peers */
static inline size_t peer_index(fastd_peer_t *peer) {
	return peer_index_find_by_id(peer->id);
}

/** Finds a peer with a specified ID */
fastd_peer_t *fastd_peer_find_by_id(uint64_t id) {
	fastd_peer_t **ret = peer_p_find_by_id(id);

	if (ret)
		return *ret;
	else
		return NULL;
}

/** Closes and frees a peer's dynamic socket */
static inline void free_socket(fastd_peer_t *peer) {
	if (!peer->sock)
		return;

	if (fastd_peer_is_socket_dynamic(peer)) {
		if (peer->sock->peer != peer)
			exit_bug("dynamic peer socket mismatch");

		fastd_socket_close(peer->sock);
		free(peer->sock);
	}

	peer->sock = NULL;
}

/** Checks if a peer group has any contraints which might cause connection attempts to be rejected */
static inline bool has_group_config_constraints(const fastd_peer_group_t *group) {
	for (; group; group = group->parent) {
		if (group->max_connections >= 0)
			return true;
	}

	return false;
}

/**
   Resets a peer's socket

   If the peer's old socket is dynamic, it is closed. Then either a new dynamic socket is opened
   or a default socket is used.
*/
void fastd_peer_reset_socket(fastd_peer_t *peer) {
	if (peer->address.sa.sa_family == AF_UNSPEC) {
		free_socket(peer);
		return;
	}

	if (!fastd_peer_is_socket_dynamic(peer))
		return;

	pr_debug("resetting socket for peer %P", peer);

	free_socket(peer);

	switch (peer->address.sa.sa_family) {
	case AF_INET:
		if (ctx.sock_default_v4)
			peer->sock = ctx.sock_default_v4;
		else
			peer->sock = fastd_socket_open(peer, AF_INET);
		break;

	case AF_INET6:
		if (ctx.sock_default_v6)
			peer->sock = ctx.sock_default_v6;
		else
			peer->sock = fastd_socket_open(peer, AF_INET6);
	}
}

/** Schedules the peer maintenance task (or removes the scheduled task if there's nothing to do) */
static void schedule_peer_task(fastd_peer_t *peer) {
	fastd_timeout_t timeout = fastd_timeout_min(
		peer->reset_timeout, fastd_timeout_min(peer->keepalive_timeout, peer->next_handshake));

	if (timeout == FASTD_TIMEOUT_INV) {
		pr_debug2("Removing scheduled task for %P", peer);
		fastd_task_unschedule(&peer->task);
	} else if (fastd_task_timeout(&peer->task) > timeout) {
		pr_debug2("Replacing scheduled task for %P", peer);
		fastd_task_unschedule(&peer->task);
		fastd_task_schedule(&peer->task, TASK_TYPE_PEER, timeout);
	} else {
		pr_debug2("Keeping scheduled task for %P", peer);
	}
}

/** Sets the timeout for the next handshake without actually rescheduling */
static void set_next_handshake(fastd_peer_t *peer, int delay) {
	peer->next_handshake = ctx.now + delay;
}

/** Sets the timeout for the next handshake to the default delay and jitter without actually rescheduling */
static void set_next_handshake_default(fastd_peer_t *peer) {
	set_next_handshake(peer, fastd_peer_handshake_default_rand());
}

/**
   Schedules a handshake after the given delay

   @param peer	the peer
   @param delay	the delay in milliseconds
*/
void fastd_peer_schedule_handshake(fastd_peer_t *peer, int delay) {
	set_next_handshake(peer, delay);
	schedule_peer_task(peer);
}

/** Checks if the peer group \e group1 lies in \e group2 */
static inline bool is_group_in(const fastd_peer_group_t *group1, const fastd_peer_group_t *group2) {
	while (group1) {
		if (group1 == group2)
			return true;

		group1 = group1->parent;
	}

	return false;
}

/** Checks if a peer lies in a peer group */
static bool is_peer_in_group(const fastd_peer_t *peer, const fastd_peer_group_t *group) {
	return is_group_in(peer->group, group);
}

/**
   Resets a peer (internal function)

   Disestablished the current connection with the peer (if any) and drops any scheduled handshake.

   After a call to reset_peer a peer must be deleted by delete_peer or re-initialized by setup_peer.
*/
static void reset_peer(fastd_peer_t *peer) {
	if (fastd_peer_is_established(peer)) {
		on_disestablish(peer);
		pr_info("connection with %P disestablished.", peer);
	}

	free_socket(peer);

	conf.protocol->reset_peer_state(peer);

	size_t i, deleted = 0;
	for (i = 0; i < VECTOR_LEN(ctx.eth_addrs); i++) {
		if (VECTOR_INDEX(ctx.eth_addrs, i).peer == peer) {
			deleted++;
		} else if (deleted) {
			VECTOR_INDEX(ctx.eth_addrs, i - deleted) = VECTOR_INDEX(ctx.eth_addrs, i);
		}
	}

	VECTOR_RESIZE(ctx.eth_addrs, VECTOR_LEN(ctx.eth_addrs) - deleted);

	fastd_task_unschedule(&peer->task);

	fastd_peer_hashtable_remove(peer);

	memset(&peer->stats, 0, sizeof(peer->stats));

	peer->address.sa.sa_family = AF_UNSPEC;
	peer->local_address.sa.sa_family = AF_UNSPEC;
	peer->state = STATE_INACTIVE;

	if (peer->offload) {
		on_down(peer, false);
		peer->offload->free_session(peer->offload_state);
		peer->offload = NULL;
	}

	if (!conf.iface_persist || peer->config_state == CONFIG_DISABLED || fastd_peer_is_dynamic(peer)) {
		if (peer->iface && peer->iface->peer) {
			on_down(peer, false);
			fastd_iface_close(peer->iface);
		}

		peer->iface = NULL;
	}
}

/**
   Starts the first handshake with a newly setup peer

   If a peer group has a peer limit the handshakes will be delayed between 0 and 3 seconds
   make the choice of peers random (it will be biased by the latency, which might or might not be
   what a user wants)
*/
static void init_handshake(fastd_peer_t *peer) {
	unsigned delay = 0;
	if (has_group_config_constraints(peer->group))
		delay = fastd_rand(0, 3000);

	peer->state = STATE_HANDSHAKE;

	fastd_peer_schedule_handshake(peer, delay);
}

/** Handles an asynchronous DNS resolve response */
void fastd_peer_handle_resolve(
	fastd_peer_t *peer, fastd_remote_t *remote, size_t n_addresses, const fastd_peer_address_t *addresses) {
	free(remote->addresses);
	remote->addresses = fastd_new_array(n_addresses, fastd_peer_address_t);
	memcpy(remote->addresses, addresses, n_addresses * sizeof(fastd_peer_address_t));

	remote->n_addresses = n_addresses;
	remote->current_address = 0;

	if (peer->state == STATE_RESOLVING)
		init_handshake(peer);
}

/** Initializes a peer */
static void setup_peer(fastd_peer_t *peer) {
	if (VECTOR_LEN(peer->remotes) == 0) {
		peer->next_remote = -1;
	} else {
		size_t i;
		for (i = 0; i < VECTOR_LEN(peer->remotes); i++) {
			fastd_remote_t *remote = &VECTOR_INDEX(peer->remotes, i);

			remote->last_resolve_timeout = ctx.now;

			if (!remote->hostname) {
				remote->n_addresses = 1;
				remote->addresses = &remote->address;
			}
		}

		peer->next_remote = 0;
	}

	peer->last_handshake_timeout = ctx.now;
	peer->last_handshake_address.sa.sa_family = AF_UNSPEC;

	peer->last_handshake_response_timeout = ctx.now;
	peer->last_handshake_response_address.sa.sa_family = AF_UNSPEC;

	peer->establish_handshake_timeout = ctx.now;

#ifdef WITH_DYNAMIC_PEERS
	peer->verify_timeout = ctx.now;
	peer->verify_valid_timeout = ctx.now;
#endif

	peer->next_handshake = FASTD_TIMEOUT_INV;
	peer->reset_timeout = FASTD_TIMEOUT_INV;
	peer->keepalive_timeout = FASTD_TIMEOUT_INV;

	if (fastd_peer_is_dynamic(peer))
		peer->reset_timeout = ctx.now;

	if (!fastd_peer_is_enabled(peer))
		/* Keep the peer in STATE_INACTIVE */
		return;

	if (ctx.iface) {
		peer->iface = ctx.iface;
	} else if (conf.iface_persist && !peer->iface && !fastd_peer_is_dynamic(peer)) {
		peer->iface = fastd_iface_open(peer);
		if (peer->iface)
			on_up(peer, true);
		else if (!peer->config_source_dir)
			/* Fail for statically configured peers;
			   an error message has already been printed by fastd_iface_open() */
			exit(1);
	}

	fastd_remote_t *next_remote = fastd_peer_get_next_remote(peer);
	if (next_remote) {
		next_remote->current_address = 0;

		if (next_remote->hostname) {
			peer->state = STATE_RESOLVING;
			fastd_resolve_peer(peer, next_remote);
			set_next_handshake_default(peer);
		} else {
			init_handshake(peer);
		}
	} else {
		peer->state = STATE_PASSIVE;
	}

	schedule_peer_task(peer);
}

/**
   Frees a peer

   If the peer has already been added to the peer list,
   use fastd_peer_delete() instead.
*/
void fastd_peer_free(fastd_peer_t *peer) {
	free(peer->key);

	size_t i;
	for (i = 0; i < VECTOR_LEN(peer->remotes); i++) {
		fastd_remote_t *remote = &VECTOR_INDEX(peer->remotes, i);

		if (remote->hostname) {
			free(remote->addresses);
			free(remote->hostname);
		}
	}

	VECTOR_FREE(peer->remotes);

	free(peer->ifname);
	free(peer->name);
	free(peer);
}

/** Deletes a peer */
static void delete_peer(fastd_peer_t *peer) {
	if (fastd_peer_is_dynamic(peer) || peer->config_source_dir)
		pr_verbose("deleting peer %P", peer);

	size_t i = peer_index(peer);
	VECTOR_DELETE(ctx.peers, i);

	conf.protocol->free_peer_state(peer);

	if (peer->iface && peer->iface->peer) {
		on_down(peer, true);
		fastd_iface_close(peer->iface);
	}

	fastd_peer_free(peer);
}


/** Checks if two fastd_peer_address_t are equal */
bool fastd_peer_address_equal(const fastd_peer_address_t *addr1, const fastd_peer_address_t *addr2) {
	if (addr1->sa.sa_family != addr2->sa.sa_family)
		return false;

	switch (addr1->sa.sa_family) {
	case AF_UNSPEC:
		break;

	case AF_INET:
		if (addr1->in.sin_addr.s_addr != addr2->in.sin_addr.s_addr)
			return false;
		if (addr1->in.sin_port != addr2->in.sin_port)
			return false;
		break;

	case AF_INET6:
		if (!IN6_ARE_ADDR_EQUAL(&addr1->in6.sin6_addr, &addr2->in6.sin6_addr))
			return false;
		if (addr1->in6.sin6_port != addr2->in6.sin6_port)
			return false;
		if (IN6_IS_ADDR_LINKLOCAL(&addr1->in6.sin6_addr)) {
			if (addr1->in6.sin6_scope_id != addr2->in6.sin6_scope_id)
				return false;
		}
	}

	return true;
}

/** If \e addr is a v4-mapped IPv6 address, it is converted to an IPv4 address */
void fastd_peer_address_simplify(fastd_peer_address_t *addr) {
	if (addr->sa.sa_family == AF_INET6 && IN6_IS_ADDR_V4MAPPED(&addr->in6.sin6_addr)) {
		struct sockaddr_in6 mapped = addr->in6;

		memset(addr, 0, sizeof(fastd_peer_address_t));
		addr->in.sin_family = AF_INET;
		addr->in.sin_port = mapped.sin6_port;
		memcpy(&addr->in.sin_addr.s_addr, &mapped.sin6_addr.s6_addr[12], 4);
	}
}

/** If \e addr is an IPv4 address, it is converted to a v4-mapped IPv6 address */
void fastd_peer_address_widen(fastd_peer_address_t *addr) {
	if (addr->sa.sa_family == AF_INET) {
		struct sockaddr_in addr4 = addr->in;

		memset(addr, 0, sizeof(fastd_peer_address_t));
		addr->in6.sin6_family = AF_INET6;
		addr->in6.sin6_port = addr4.sin_port;
		addr->in6.sin6_addr.s6_addr[10] = 0xff;
		addr->in6.sin6_addr.s6_addr[11] = 0xff;
		memcpy(&addr->in6.sin6_addr.s6_addr[12], &addr4.sin_addr.s_addr, 4);
	}
}


/** Resets a peer's address to the unspecified address */
static inline void reset_peer_address(fastd_peer_t *peer) {
	if (fastd_peer_is_established(peer)) {
		fastd_peer_reset(peer);
	} else {
		fastd_peer_hashtable_remove(peer);
		peer->address.sa.sa_family = AF_UNSPEC;
	}
}

/** Checks if an address is statically configured for a peer */
bool fastd_peer_owns_address(const fastd_peer_t *peer, const fastd_peer_address_t *addr) {
	if (fastd_peer_is_floating(peer))
		return false;

	size_t i;
	for (i = 0; i < VECTOR_LEN(peer->remotes); i++) {
		fastd_remote_t *remote = &VECTOR_INDEX(peer->remotes, i);

		if (remote->hostname)
			continue;

		if (fastd_peer_address_equal(&remote->address, addr))
			return true;
	}

	return false;
}

/** Checks if an address matches any of the configured or resolved remotes of a peer */
bool fastd_peer_matches_address(const fastd_peer_t *peer, const fastd_peer_address_t *addr) {
	if (fastd_peer_is_floating(peer))
		return true;

	size_t i, j;
	for (i = 0; i < VECTOR_LEN(peer->remotes); i++) {
		fastd_remote_t *remote = &VECTOR_INDEX(peer->remotes, i);

		for (j = 0; j < remote->n_addresses; j++) {
			if (fastd_peer_address_equal(&remote->addresses[j], addr))
				return true;
		}
	}

	return false;
}

/**
   Tries to claim an address for a peer

   Each remote address (+ port) can by used by only one peer at a time.

   If it is tried to claim an address that is currently used by another peer, the claim will fail unless
   \e force is set. The claim will fail even with \e force set if the other peer has statically configured the address
   in question.
 */
bool fastd_peer_claim_address(
	fastd_peer_t *new_peer, fastd_socket_t *sock, const fastd_peer_address_t *local_addr,
	const fastd_peer_address_t *remote_addr, bool force) {
	if (remote_addr->sa.sa_family == AF_UNSPEC) {
		if (fastd_peer_is_established(new_peer))
			fastd_peer_reset(new_peer);
	} else {
		size_t i;
		for (i = 0; i < VECTOR_LEN(ctx.peers); i++) {
			fastd_peer_t *peer = VECTOR_INDEX(ctx.peers, i);

			if (peer == new_peer)
				continue;

			if (!fastd_peer_is_enabled(peer))
				continue;

			if (fastd_peer_owns_address(peer, remote_addr)) {
				reset_peer_address(new_peer);
				return false;
			}

			if (fastd_peer_address_equal(&peer->address, remote_addr)) {
				if (!force && fastd_peer_is_established(peer)) {
					reset_peer_address(new_peer);
					return false;
				}

				reset_peer_address(peer);
				break;
			}
		}
	}

	fastd_peer_hashtable_remove(new_peer);
	new_peer->address = *remote_addr;
	fastd_peer_hashtable_insert(new_peer);

	if (sock && sock->addr && sock != new_peer->sock) {
		free_socket(new_peer);
		new_peer->sock = sock;
	}

	if (local_addr)
		new_peer->local_address = *local_addr;

	return true;
}

/** Resets and re-initializes a peer */
void fastd_peer_reset(fastd_peer_t *peer) {
	if (peer->state != STATE_INACTIVE) {
		pr_debug("resetting peer %P", peer);
		reset_peer(peer);
	}

	setup_peer(peer);
}

/** Deletes a peer */
void fastd_peer_delete(fastd_peer_t *peer) {
	reset_peer(peer);
	delete_peer(peer);
}

/** Counts how many peers in the given peer group have established a connection */
static inline size_t count_established_group_peers(const fastd_peer_group_t *group) {
	size_t i, ret = 0;
	for (i = 0; i < VECTOR_LEN(ctx.peers); i++) {
		fastd_peer_t *peer = VECTOR_INDEX(ctx.peers, i);

		if (fastd_peer_is_established(peer) && is_peer_in_group(peer, group))
			ret++;
	}

	return ret;
}

/** Checks if a peer may currently establish a connection */
bool fastd_peer_may_connect(fastd_peer_t *peer) {
	if (fastd_peer_is_established(peer))
		return true;

	const fastd_peer_group_t *group;

	for (group = peer->group; group; group = group->parent) {
		if (group->max_connections < 0)
			continue;

		if (count_established_group_peers(group) >= (size_t)group->max_connections)
			return false;
	}

	return true;
}

/** Checks if two peer configurations are equivalent (exept for the name) */
static inline bool peer_configs_equal(const fastd_peer_t *peer1, const fastd_peer_t *peer2) {
	if (peer1->group != peer2->group)
		return false;

	if (peer1->floating != peer2->floating)
		return false;

	if (VECTOR_LEN(peer1->remotes) != VECTOR_LEN(peer2->remotes))
		return false;

	if (!strequal(peer1->ifname, peer2->ifname))
		return false;

	size_t i;
	for (i = 0; i < VECTOR_LEN(peer1->remotes); i++) {
		const fastd_remote_t *remote1 = &VECTOR_INDEX(peer1->remotes, i),
				     *remote2 = &VECTOR_INDEX(peer2->remotes, i);

		if (!fastd_peer_address_equal(&remote1->address, &remote2->address))
			return false;

		if (!strequal(remote1->hostname, remote2->hostname))
			return false;
	}

	return true;
}

/** Adds a new peer */
bool fastd_peer_add(fastd_peer_t *peer) {
	if (!peer->key) {
		pr_warn("no valid key configured for peer %P", peer);
		goto error;
	}

	fastd_peer_t *other = conf.protocol->find_peer(peer->key);
	if (other) {
		if (peer->config_state != CONFIG_NEW)
			exit_bug("tried to replace with active peer");

		switch (other->config_state) {
		case CONFIG_NEW:
		case CONFIG_DISABLED:
			pr_warn("duplicate key used by peers %P and %P, disabling both", peer, other);
			other->config_state = CONFIG_DISABLED;
			goto error;

		case CONFIG_STATIC:
			if (!strequal(other->name, peer->name))
				pr_verbose("peer %P has been renamed to %P", other, peer);

			if (peer_configs_equal(other, peer)) {
				free(other->name);
				other->name = peer->name;
				peer->name = NULL;

				fastd_peer_free(peer);

				pr_verbose("peer %P is unchanged", other);
				other->config_state = CONFIG_NEW;

				return true;
			} else {
				pr_verbose("peer %P has changed", peer);
			}

			fastd_peer_delete(other);
			break;

#ifdef WITH_DYNAMIC_PEERS
		case CONFIG_DYNAMIC:
			pr_verbose("dynamic peer %P is now configured as %P", other, peer);
			fastd_peer_delete(other);
#endif
		}
	}

	peer->id = ctx.next_peer_id++;

	VECTOR_ADD(ctx.peers, peer);

	conf.protocol->init_peer_state(peer);

	if (fastd_peer_is_dynamic(peer) || peer->config_source_dir)
		pr_verbose("adding peer %P", peer);

	return true;

error:
	fastd_peer_free(peer);
	return false;
}

/** Prints a debug message when no handshake could be sent because the current remote didn't resolve successfully */
static inline void no_valid_address_debug(const fastd_peer_t *peer) {
	pr_debug("not sending a handshake to %P (no valid address resolved)", peer);
}

/** Sends a new handshake to the current address of the given remote of a peer */
static void send_handshake(fastd_peer_t *peer, fastd_remote_t *next_remote) {
	if (!fastd_peer_is_established(peer)) {
		if (!next_remote->n_addresses) {
			no_valid_address_debug(peer);
			return;
		}

		fastd_peer_claim_address(
			peer, NULL, NULL, &next_remote->addresses[next_remote->current_address], false);
		fastd_peer_reset_socket(peer);
	}

	if (!peer->sock)
		return;

	if (peer->address.sa.sa_family == AF_UNSPEC) {
		no_valid_address_debug(peer);
		return;
	}

	if (!fastd_timed_out(peer->last_handshake_timeout) &&
	    fastd_peer_address_equal(&peer->address, &peer->last_handshake_address)) {
		pr_debug("not sending a handshake to %P as we sent one a short time ago", peer);
		return;
	}

	peer->last_handshake_timeout = ctx.now + MIN_HANDSHAKE_INTERVAL;
	peer->last_handshake_address = peer->address;
	conf.protocol->handshake_init(peer->sock, &peer->local_address, &peer->address, peer, FLAG_INITIAL);
}

/** Marks a peer as established */
bool fastd_peer_set_established(fastd_peer_t *peer, const fastd_offload_t *offload) {
	if (peer->offload) {
		bool need_reset;

		if (peer->offload == offload)
			need_reset = !peer->offload->update_session(peer, peer->offload_state);
		else
			need_reset = true;

		if (need_reset) {
			on_down(peer, false);
			peer->offload->free_session(peer->offload_state);
			peer->offload = NULL;
		}
	}

	if (offload && !peer->offload) {
		if (peer->iface && peer->iface->peer) {
			on_down(peer, false);
			fastd_iface_close(peer->iface);
		}
		peer->iface = NULL;

		peer->offload_state = offload->init_session(peer);
		if (!peer->offload_state)
			return false;

		peer->offload = offload;
		on_up(peer, false);
	}

	if (!peer->iface && !peer->offload) {
		peer->iface = fastd_iface_open(peer);
		if (!peer->iface)
			return false;

		on_up(peer, false);
	}

	if (fastd_peer_is_established(peer))
		return true;

	peer->state = STATE_ESTABLISHED;
	peer->established = ctx.now;
	fastd_peer_seen(peer);
	fastd_peer_clear_keepalive(peer);
	fastd_receive_unknown_purge(peer->address);

	schedule_peer_task(peer);

	on_establish(peer);
	pr_info("connection with %P established.", peer);

	return true;
}

/** Compares two MAC addresses */
static inline int eth_addr_cmp(const fastd_eth_addr_t *addr1, const fastd_eth_addr_t *addr2) {
	return memcmp(addr1->data, addr2->data, sizeof(fastd_eth_addr_t));
}

/** Compares two fastd_peer_eth_addr_t entries by their MAC addresses */
static int peer_eth_addr_cmp(const fastd_peer_eth_addr_t *addr1, const fastd_peer_eth_addr_t *addr2) {
	return eth_addr_cmp(&addr1->addr, &addr2->addr);
}

/** Adds a MAC address to the sorted list of addresses associated with a peer (or updates the timeout of an existing
 * entry) */
void fastd_peer_eth_addr_add(fastd_peer_t *peer, fastd_eth_addr_t addr) {
	size_t min = 0, max = VECTOR_LEN(ctx.eth_addrs);

	if (peer && !fastd_peer_is_established(peer))
		exit_bug("tried to learn ethernet address on non-established peer");

	while (max > min) {
		size_t cur = min + (max - min) / 2;
		int cmp = eth_addr_cmp(&addr, &VECTOR_INDEX(ctx.eth_addrs, cur).addr);

		if (cmp == 0) {
			VECTOR_INDEX(ctx.eth_addrs, cur).peer = peer;
			VECTOR_INDEX(ctx.eth_addrs, cur).timeout = ctx.now + ETH_ADDR_STALE_TIME;
			return; /* We're done here. */
		} else if (cmp < 0) {
			max = cur;
		} else {
			min = cur + 1;
		}
	}

	VECTOR_INSERT(ctx.eth_addrs, ((fastd_peer_eth_addr_t){ addr, peer, ctx.now + ETH_ADDR_STALE_TIME }), min);

	if (peer)
		pr_debug("learned new MAC address %E on peer %P", &addr, peer);
	else
		pr_debug("learned new local MAC address %E", &addr);
}

/** Finds the peer that is associated with a given MAC address */
bool fastd_peer_find_by_eth_addr(const fastd_eth_addr_t addr, fastd_peer_t **peer) {
	const fastd_peer_eth_addr_t key = { .addr = addr };
	fastd_peer_eth_addr_t *peer_eth_addr = VECTOR_BSEARCH(&key, ctx.eth_addrs, peer_eth_addr_cmp);

	if (!peer_eth_addr)
		return false;

	*peer = peer_eth_addr->peer;
	return true;
}

/** Sends a handshake to one peer, if a scheduled handshake is due */
static void handle_task_handshake(fastd_peer_t *peer) {
	set_next_handshake_default(peer);

	if (!fastd_peer_may_connect(peer)) {
		if (peer->next_remote != -1) {
			pr_debug("temporarily disabling handshakes with %P", peer);
			peer->next_remote = -1;
		}

		return;
	}

	fastd_remote_t *next_remote = fastd_peer_get_next_remote(peer);

	if (next_remote || fastd_peer_is_established(peer)) {
		send_handshake(peer, next_remote);

		if (fastd_peer_is_established(peer))
			return;

		peer->state = STATE_HANDSHAKE;

		if (++next_remote->current_address < next_remote->n_addresses)
			return;

		peer->next_remote++;
	}

	if (peer->next_remote < 0 || (size_t)peer->next_remote >= VECTOR_LEN(peer->remotes))
		peer->next_remote = 0;

	next_remote = fastd_peer_get_next_remote(peer);
	next_remote->current_address = 0;

	if (next_remote->hostname)
		fastd_resolve_peer(peer, next_remote);
}

/**
   Performs maintenance tasks for a peer

   \li If no data was received from the peer for some time, it is reset.
   \li If no data was sent to the peer for some time, a keepalive is sent.
 */
void fastd_peer_handle_task(fastd_task_t *task) {
	fastd_peer_t *peer = container_of(task, fastd_peer_t, task);

	/* check for peer timeout */
	if (fastd_timed_out(peer->reset_timeout)) {
		if (fastd_peer_is_dynamic(peer))
			fastd_peer_delete(peer);
		else
			fastd_peer_reset(peer);

		return;
	}

	/* check for keepalive timeout */
	if (fastd_timed_out(peer->keepalive_timeout)) {
		pr_debug2("sending keepalive to %P", peer);
		conf.protocol->send(peer, fastd_buffer_alloc(0, conf.encrypt_headroom));
		fastd_peer_clear_keepalive(peer);
	}

	if (fastd_timed_out(peer->next_handshake))
		handle_task_handshake(peer);

	schedule_peer_task(peer);
}

/** Removes all time-outed MAC addresses from \e ctx.eth_addrs */
void fastd_peer_eth_addr_cleanup(void) {
	size_t i, deleted = 0;

	for (i = 0; i < VECTOR_LEN(ctx.eth_addrs); i++) {
		if (fastd_timed_out(VECTOR_INDEX(ctx.eth_addrs, i).timeout)) {
			deleted++;
			pr_debug(
				"MAC address %E not seen for more than %u seconds, removing",
				&VECTOR_INDEX(ctx.eth_addrs, i).addr, ETH_ADDR_STALE_TIME / 1000);
		} else if (deleted) {
			VECTOR_INDEX(ctx.eth_addrs, i - deleted) = VECTOR_INDEX(ctx.eth_addrs, i);
		}
	}

	VECTOR_RESIZE(ctx.eth_addrs, VECTOR_LEN(ctx.eth_addrs) - deleted);
}

/** Resets all peers */
void fastd_peer_reset_all(void) {
	size_t i;
	for (i = 0; i < VECTOR_LEN(ctx.peers);) {
		fastd_peer_t *peer = VECTOR_INDEX(ctx.peers, i);

		if (fastd_peer_is_dynamic(peer)) {
			fastd_peer_delete(peer);
		} else {
			fastd_peer_reset(peer);
			i++;
		}
	}
}
