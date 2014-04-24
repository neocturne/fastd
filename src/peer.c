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


#include "peer.h"
#include "peer_hashtable.h"
#include "poll.h"

#include <arpa/inet.h>
#include <sys/wait.h>


static inline void on_establish(const fastd_peer_t *peer) {
	fastd_shell_command_exec(&conf.on_establish, peer, &peer->local_address, &peer->address);
}

static inline void on_disestablish(const fastd_peer_t *peer) {
	fastd_shell_command_exec(&conf.on_disestablish, peer, &peer->local_address, &peer->address);
}

static inline void free_socket(fastd_peer_t *peer) {
	if (peer->sock) {
		if (fastd_peer_is_socket_dynamic(peer)) {
			if (peer->sock->peer != peer)
				exit_bug("dynamic peer socket mismatch");

			fastd_socket_close(peer->sock);
			free(peer->sock);
			peer->sock = NULL;

			size_t i;
			for (i = 0; i < VECTOR_LEN(ctx.peers); i++) {
				if (VECTOR_INDEX(ctx.peers, i) == peer) {
					fastd_poll_set_fd_peer(i);
					break;
				}
			}
		}
		else {
			peer->sock = NULL;
		}
	}
}

static inline bool has_group_config_constraints(const fastd_peer_group_config_t *group) {
	for (; group; group = group->parent) {
		if (group->max_connections >= 0)
			return true;
	}

	return false;
}

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

	if (!peer->sock || !fastd_peer_is_socket_dynamic(peer))
		return;

	size_t i;
	for (i = 0; i < VECTOR_LEN(ctx.peers); i++) {
		if (VECTOR_INDEX(ctx.peers, i) == peer) {
			fastd_poll_set_fd_peer(i);
			break;
		}
	}
}

void fastd_peer_schedule_handshake(fastd_peer_t *peer, int delay) {
	fastd_peer_unschedule_handshake(peer);

	peer->next_handshake = ctx.now;

	peer->next_handshake.tv_sec += delay/1000;
	peer->next_handshake.tv_nsec += (delay%1000)*1e6;

	if (peer->next_handshake.tv_nsec > 1e9) {
		peer->next_handshake.tv_sec++;
		peer->next_handshake.tv_nsec -= 1e9;
	}

	fastd_dlist_head_t *list;
	for (list = &ctx.handshake_queue; list->next; list = list->next) {
		fastd_peer_t *entry = container_of(list->next, fastd_peer_t, handshake_entry);

		if (timespec_after(&entry->next_handshake, &peer->next_handshake))
			break;
	}

	fastd_dlist_insert(list, &peer->handshake_entry);
}

static int peer_id_cmp(fastd_peer_t *const *a, fastd_peer_t *const *b) {
	if ((*a)->id == (*b)->id)
		return 0;
	else if ((*a)->id < (*b)->id)
		return -1;
	else
		return 1;
}

fastd_peer_t* fastd_peer_find_by_id(uint64_t id) {
	fastd_peer_t key = {.id = id};
	fastd_peer_t *const keyp = &key;

	fastd_peer_t **ret = VECTOR_BSEARCH(&keyp, ctx.peers, peer_id_cmp);

	if (ret)
		return *ret;
	else
		return NULL;

}

static inline fastd_peer_group_t* find_peer_group(fastd_peer_group_t *group, const fastd_peer_group_config_t *config) {
	if (group->conf == config)
		return group;

	fastd_peer_group_t *child;
	for (child = group->children; child; child = child->next) {
		fastd_peer_group_t *ret = find_peer_group(child, config);

		if (ret)
			return ret;
	}

	return NULL;
}

static inline bool is_group_in(fastd_peer_group_t *group1, fastd_peer_group_t *group2) {
	while (group1) {
		if (group1 == group2)
			return true;

		group1 = group1->parent;
	}

	return false;
}

static bool is_peer_in_group(fastd_peer_t *peer, fastd_peer_group_t *group) {
	return is_group_in(peer->group, group);
}

static void reset_peer(fastd_peer_t *peer) {
	if (fastd_peer_is_established(peer))
		on_disestablish(peer);

	free_socket(peer);

	memset(&peer->local_address, 0, sizeof(peer->local_address));

	conf.protocol->reset_peer_state(peer);

	size_t i, deleted = 0;
	for (i = 0; i < VECTOR_LEN(ctx.eth_addrs); i++) {
		if (VECTOR_INDEX(ctx.eth_addrs, i).peer == peer) {
			deleted++;
		}
		else if (deleted) {
			VECTOR_INDEX(ctx.eth_addrs, i-deleted) = VECTOR_INDEX(ctx.eth_addrs, i);
		}
	}

	VECTOR_RESIZE(ctx.eth_addrs, VECTOR_LEN(ctx.eth_addrs)-deleted);

	fastd_peer_unschedule_handshake(peer);
}

static void init_handshake(fastd_peer_t *peer) {
	unsigned delay = 0;
	if (has_group_config_constraints(peer->group->conf))
		delay = fastd_rand(0, 3000);

	if (!fastd_peer_is_established(peer))
		peer->state = STATE_HANDSHAKE;

	fastd_peer_schedule_handshake(peer, delay);
}

void fastd_peer_handle_resolve(fastd_peer_t *peer, fastd_remote_t *remote, size_t n_addresses, const fastd_peer_address_t *addresses) {
	remote->resolving = false;

	free(remote->addresses);
	remote->addresses = malloc(n_addresses*sizeof(fastd_peer_address_t));
	memcpy(remote->addresses, addresses, n_addresses*sizeof(fastd_peer_address_t));

	remote->n_addresses = n_addresses;
	remote->current_address = 0;

	if (peer->state == STATE_RESOLVING)
		init_handshake(peer);
}

static void setup_peer(fastd_peer_t *peer) {
	peer->address.sa.sa_family = AF_UNSPEC;
	peer->local_address.sa.sa_family = AF_UNSPEC;

	peer->state = STATE_INIT;

	fastd_remote_t *remote;
	for (remote = peer->remotes; remote; remote = remote->next) {
		remote->last_resolve_timeout = ctx.now;
		remote->resolving = false;
	}

	peer->next_remote = peer->remotes;

	peer->last_handshake_timeout = ctx.now;
	peer->last_handshake_address.sa.sa_family = AF_UNSPEC;

	peer->last_handshake_response_timeout = ctx.now;
	peer->last_handshake_response_address.sa.sa_family = AF_UNSPEC;

	peer->establish_handshake_timeout = ctx.now;

	if (!peer->protocol_state)
		conf.protocol->init_peer_state(peer);

	if (peer->next_remote) {
		peer->next_remote->current_address = 0;

		if (fastd_remote_is_dynamic(peer->next_remote)) {
			peer->state = STATE_RESOLVING;
			fastd_resolve_peer(peer, peer->next_remote);
		}
		else  {
			init_handshake(peer);
		}
	}
}

static void delete_peer(fastd_peer_t *peer) {
	pr_debug("deleting peer %P", peer);

	size_t i;
	for (i = 0; i < VECTOR_LEN(ctx.peers); i++) {
		if (VECTOR_INDEX(ctx.peers, i) == peer) {
			VECTOR_DELETE(ctx.peers, i);
			fastd_poll_delete_peer(i);
			break;
		}
	}

	fastd_peer_hashtable_remove(peer);

	conf.protocol->free_peer_state(peer);

	if (!peer->config)
		free(peer->protocol_config);

	while (peer->remotes) {
		fastd_remote_t *remote = peer->remotes;
		peer->remotes = remote->next;

		fastd_remote_unref(remote);
	}

	free(peer);
}


fastd_peer_config_t* fastd_peer_config_new(void) {
	fastd_peer_config_t *peer = calloc(1, sizeof(fastd_peer_config_t));

	peer->group = conf.peer_group;

	peer->next = conf.peers;
	conf.peers = peer;

	return peer;
}

void fastd_peer_config_free(fastd_peer_config_t *peer) {
	while (peer->remotes) {
		fastd_remote_config_t *remote = peer->remotes;
		peer->remotes = remote->next;

		free(remote->hostname);
		free(remote);
	}

	free(peer->name);
	free(peer->key);
	free(peer->protocol_config);
	free(peer);
}

void fastd_peer_config_delete(void) {
	fastd_peer_config_t *peer = conf.peers, *next = peer->next;
	fastd_peer_config_free(peer);
	conf.peers = next;
}

void fastd_peer_config_purge(fastd_peer_config_t *config) {
	size_t i;
	for (i = 0; i < VECTOR_LEN(ctx.peers); i++) {
		fastd_peer_t *peer = VECTOR_INDEX(ctx.peers, i);

		if (peer->config == config) {
			fastd_peer_delete(peer);
			break;
		}
	}

	fastd_peer_config_free(config);
}

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

void fastd_peer_address_simplify(fastd_peer_address_t *addr) {
	if (addr->sa.sa_family == AF_INET6 && IN6_IS_ADDR_V4MAPPED(&addr->in6.sin6_addr)) {
		struct sockaddr_in6 mapped = addr->in6;

		memset(addr, 0, sizeof(fastd_peer_address_t));
		addr->in.sin_family = AF_INET;
		addr->in.sin_port = mapped.sin6_port;
		memcpy(&addr->in.sin_addr.s_addr, &mapped.sin6_addr.s6_addr[12], 4);
	}
}

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


static inline void reset_peer_address(fastd_peer_t *peer) {
	if (fastd_peer_is_established(peer))
		fastd_peer_reset(peer);

	fastd_peer_hashtable_remove(peer);
	memset(&peer->address, 0, sizeof(fastd_peer_address_t));
}

bool fastd_peer_owns_address(const fastd_peer_t *peer, const fastd_peer_address_t *addr) {
	if (fastd_peer_is_floating(peer))
		return false;

	fastd_remote_config_t *remote;
	for (remote = peer->config->remotes; remote; remote = remote->next) {
		if (remote->hostname)
			continue;

		if (fastd_peer_address_equal(&remote->address, addr))
			return true;
	}

	return false;
}

bool fastd_peer_matches_address(const fastd_peer_t *peer, const fastd_peer_address_t *addr) {
	if (fastd_peer_is_floating(peer))
		return true;

	fastd_remote_t *remote;
	for (remote = peer->remotes; remote; remote = remote->next) {
		size_t i;
		for (i = 0; i < remote->n_addresses; i++) {
			if (fastd_peer_address_equal(&remote->addresses[i], addr))
				return true;
		}
	}

	return false;
}

bool fastd_peer_claim_address(fastd_peer_t *new_peer, fastd_socket_t *sock, const fastd_peer_address_t *local_addr, const fastd_peer_address_t *remote_addr, bool force) {
	if (remote_addr->sa.sa_family == AF_UNSPEC) {
		if (fastd_peer_is_established(new_peer))
			fastd_peer_reset(new_peer);
	}
	else {
		size_t i;
		for (i = 0; i < VECTOR_LEN(ctx.peers); i++) {
			fastd_peer_t *peer = VECTOR_INDEX(ctx.peers, i);

			if (peer == new_peer)
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

	if (remote_addr->sa.sa_family != AF_UNSPEC)
		fastd_peer_hashtable_insert(new_peer);

	if (sock && sock->addr && sock != new_peer->sock) {
		free_socket(new_peer);
		new_peer->sock = sock;
	}

	if (local_addr)
		new_peer->local_address = *local_addr;

	return true;
}

static bool remote_configs_equal(const fastd_remote_config_t *remote1, const fastd_remote_config_t *remote2) {
	if (!remote1 && !remote2)
		return true;

	if (!remote1 || !remote2)
		return false;

	if (!fastd_peer_address_equal(&remote1->address, &remote2->address))
		return false;

	if (!strequal(remote1->hostname, remote2->hostname))
		return false;

	return remote_configs_equal(remote1->next, remote2->next);
}

bool fastd_peer_config_equal(const fastd_peer_config_t *peer1, const fastd_peer_config_t *peer2) {
	if (peer1->group != peer2->group)
		return false;

	if(peer1->floating != peer2->floating)
		return false;

	if (!remote_configs_equal(peer1->remotes, peer2->remotes))
		return false;

	if (!strequal(peer1->key, peer2->key))
		return false;

	return true;
}

void fastd_peer_reset(fastd_peer_t *peer) {
	pr_debug("resetting peer %P", peer);

	reset_peer(peer);
	setup_peer(peer);
}

void fastd_peer_delete(fastd_peer_t *peer) {
	reset_peer(peer);
	delete_peer(peer);
}

static inline size_t count_established_group_peers(fastd_peer_group_t *group) {
	size_t i, ret = 0;
	for (i = 0; i < VECTOR_LEN(ctx.peers); i++) {
		fastd_peer_t *peer = VECTOR_INDEX(ctx.peers, i);

		if (fastd_peer_is_established(peer) && is_peer_in_group(peer, group))
			ret++;
	}

	return ret;
}

bool fastd_peer_may_connect(fastd_peer_t *peer) {
	if (fastd_peer_is_established(peer))
		return true;

	fastd_peer_group_t *group;

	for (group = peer->group; group; group = group->parent) {
		if (group->conf->max_connections < 0)
			continue;

		if (count_established_group_peers(group) >= (size_t)group->conf->max_connections)
			return false;
	}

	return true;
}

fastd_peer_t* fastd_peer_add(fastd_peer_config_t *peer_conf) {
	fastd_peer_t *peer = calloc(1, sizeof(fastd_peer_t));

	peer->id = ctx.next_peer_id++;

	if (peer_conf) {
		peer->config = peer_conf;
		peer->group = find_peer_group(ctx.peer_group, peer_conf->group);
		peer->protocol_config = peer_conf->protocol_config;

		fastd_remote_t **remote = &peer->remotes;
		fastd_remote_config_t *remote_config = peer_conf->remotes;

		while (remote_config) {
			*remote = calloc(1, sizeof(fastd_remote_t));
			(*remote)->ref = 1;
			(*remote)->config = remote_config;

			if (!remote_config->hostname) {
				(*remote)->n_addresses = 1;
				(*remote)->addresses = malloc(sizeof(fastd_peer_address_t));
				(*remote)->addresses[0] = remote_config->address;
			}

			remote = &(*remote)->next;
			remote_config = remote_config->next;
		}

		pr_verbose("adding peer %P (group `%s')", peer, peer->group->conf->name);
	}
	else {
		if (!fastd_shell_command_isset(&conf.on_verify))
			exit_bug("tried to add temporary peer without on-verify command");

		peer->group = ctx.peer_group;

		fastd_peer_seen(peer);

		pr_debug("adding temporary peer");
	}

	setup_peer(peer);

	VECTOR_ADD(ctx.peers, peer);
	fastd_poll_add_peer();

	return peer;
}

bool fastd_peer_verify_temporary(fastd_peer_t *peer, const fastd_peer_address_t *local_addr, const fastd_peer_address_t *peer_addr) {
	if (!fastd_shell_command_isset(&conf.on_verify))
		exit_bug("tried to verify temporary peer without on-verify command");

	/* TODO: async not supported yet */

	int ret;
	if (!fastd_shell_command_exec_sync(&conf.on_verify, peer, local_addr, peer_addr, &ret))
		return false;

	if (WIFSIGNALED(ret)) {
		pr_error("verify command exited with signal %i", WTERMSIG(ret));
		return false;
	}
	else if (WEXITSTATUS(ret)) {
		pr_debug("verify command exited with status %i", WEXITSTATUS(ret));
		return false;
	}

	return true;
}

void fastd_peer_enable_temporary(fastd_peer_t *peer) {
	if (peer->config)
		exit_bug("trying to re-enable non-temporary peer");

	VECTOR_ADD(ctx.peers, peer);
	fastd_poll_add_peer();
}

void fastd_peer_set_established(fastd_peer_t *peer) {
	if (fastd_peer_is_established(peer))
		return;

	peer->state = STATE_ESTABLISHED;
	on_establish(peer);
	pr_info("connection with %P established.", peer);
}

fastd_eth_addr_t fastd_get_source_address(const fastd_buffer_t buffer) {
	fastd_eth_addr_t ret;

	switch (conf.mode) {
	case MODE_TAP:
		memcpy(&ret, buffer.data+offsetof(struct ethhdr, h_source), ETH_ALEN);
		return ret;
	default:
		exit_bug("invalid mode");
	}
}

fastd_eth_addr_t fastd_get_dest_address(const fastd_buffer_t buffer) {
	fastd_eth_addr_t ret;
	switch (conf.mode) {
	case MODE_TAP:
		memcpy(&ret, buffer.data+offsetof(struct ethhdr, h_dest), ETH_ALEN);
		return ret;
	default:
		exit_bug("invalid mode");
	}
}

bool fastd_remote_matches_dynamic(const fastd_remote_config_t *remote, const fastd_peer_address_t *addr) {
	if (!remote->hostname)
		return false;

	if (remote->address.sa.sa_family != AF_UNSPEC &&
	    remote->address.sa.sa_family != addr->sa.sa_family)
		return false;

	if (addr->sa.sa_family == AF_INET6) {
		if (remote->address.in.sin_port != addr->in6.sin6_port)
			return false;
	}
	else {
		if (remote->address.in.sin_port != addr->in.sin_port)
			return false;
	}

	return true;
}

static inline int eth_addr_cmp(const fastd_eth_addr_t *addr1, const fastd_eth_addr_t *addr2) {
	return memcmp(addr1->data, addr2->data, ETH_ALEN);
}

static int peer_eth_addr_cmp(const fastd_peer_eth_addr_t *addr1, const fastd_peer_eth_addr_t *addr2) {
	return eth_addr_cmp(&addr1->addr, &addr2->addr);
}

void fastd_peer_eth_addr_add(fastd_peer_t *peer, fastd_eth_addr_t addr) {
	int min = 0, max = VECTOR_LEN(ctx.eth_addrs);

	if (!fastd_peer_is_established(peer))
		exit_bug("tried to learn ethernet address on non-established peer");

	while (max > min) {
		int cur = (min+max)/2;
		int cmp = eth_addr_cmp(&addr, &VECTOR_INDEX(ctx.eth_addrs, cur).addr);

		if (cmp == 0) {
			VECTOR_INDEX(ctx.eth_addrs, cur).peer = peer;
			VECTOR_INDEX(ctx.eth_addrs, cur).timeout = fastd_in_seconds(conf.eth_addr_stale_time);
			return; /* We're done here. */
		}
		else if (cmp < 0) {
			max = cur;
		}
		else {
			min = cur+1;
		}
	}

	VECTOR_INSERT(ctx.eth_addrs, ((fastd_peer_eth_addr_t) {addr, peer, fastd_in_seconds(conf.eth_addr_stale_time)}), min);

	pr_debug("learned new MAC address %E on peer %P", &addr, peer);
}

void fastd_peer_eth_addr_cleanup(void) {
	size_t i, deleted = 0;

	for (i = 0; i < VECTOR_LEN(ctx.eth_addrs); i++) {
		if (fastd_timed_out(&VECTOR_INDEX(ctx.eth_addrs, i).timeout)) {
			deleted++;
			pr_debug("MAC address %E not seen for more than %u seconds, removing",
				 &VECTOR_INDEX(ctx.eth_addrs, i).addr, conf.eth_addr_stale_time);
		}
		else if (deleted) {
			VECTOR_INDEX(ctx.eth_addrs, i-deleted) = VECTOR_INDEX(ctx.eth_addrs, i);
		}
	}

	VECTOR_RESIZE(ctx.eth_addrs, VECTOR_LEN(ctx.eth_addrs)-deleted);
}

fastd_peer_t* fastd_peer_find_by_eth_addr(const fastd_eth_addr_t addr) {
	const fastd_peer_eth_addr_t key = {.addr = addr};
	fastd_peer_eth_addr_t *peer_eth_addr = VECTOR_BSEARCH(&key, ctx.eth_addrs, peer_eth_addr_cmp);

	if (peer_eth_addr)
		return peer_eth_addr->peer;
	else
		return NULL;
}
