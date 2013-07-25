/*
  Copyright (c) 2012-2013, Matthias Schiffer <mschiffer@universe-factory.net>
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


#define _GNU_SOURCE

#include "peer.h"
#include "task.h"

#include <arpa/inet.h>


static inline void on_establish(fastd_context_t *ctx, const fastd_peer_t *peer) {
	if (!ctx->conf->on_establish)
		return;

	fastd_shell_exec(ctx, ctx->conf->on_establish, ctx->conf->on_establish_dir, peer, &peer->local_address, &peer->address, NULL);
}

static inline void on_disestablish(fastd_context_t *ctx, const fastd_peer_t *peer) {
	if (!ctx->conf->on_disestablish)
		return;

	fastd_shell_exec(ctx, ctx->conf->on_disestablish, ctx->conf->on_disestablish_dir, peer, &peer->local_address, &peer->address, NULL);
}

static inline void free_socket(fastd_context_t *ctx, fastd_peer_t *peer) {
	if (peer->sock) {
		if (fastd_peer_is_socket_dynamic(peer)) {
			if (peer->sock->peer != peer)
				exit_bug(ctx, "dynamic peer socket mismatch");

			fastd_socket_close(ctx, peer->sock);
			free(peer->sock);
		}
		peer->sock = NULL;
	}
}

static inline bool has_group_config_constraints(const fastd_peer_group_config_t *group) {
	for (; group; group = group->parent) {
		if (group->max_connections)
			return true;
	}

	return false;
}

void fastd_peer_reset_socket(fastd_context_t *ctx, fastd_peer_t *peer) {
	if (peer->address.sa.sa_family == AF_UNSPEC) {
		free_socket(ctx, peer);
		return;
	}

	if (!fastd_peer_is_socket_dynamic(peer))
		return;

	pr_debug(ctx, "resetting socket for peer %P", peer);

	free_socket(ctx, peer);

	switch (peer->address.sa.sa_family) {
	case AF_INET:
		if (ctx->sock_default_v4)
			peer->sock = ctx->sock_default_v4;
		else
			peer->sock = fastd_socket_open(ctx, peer, AF_INET);
		break;

	case AF_INET6:
		if (ctx->sock_default_v6)
			peer->sock = ctx->sock_default_v6;
		else
			peer->sock = fastd_socket_open(ctx, peer, AF_INET6);
	}
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

static void reset_peer(fastd_context_t *ctx, fastd_peer_t *peer) {
	if (fastd_peer_is_established(peer))
		on_disestablish(ctx, peer);

	free_socket(ctx, peer);

	memset(&peer->local_address, 0, sizeof(peer->local_address));

	ctx->conf->protocol->reset_peer_state(ctx, peer);

	int i, deleted = 0;
	for (i = 0; i < ctx->n_eth_addr; i++) {
		if (ctx->eth_addr[i].peer == peer) {
			deleted++;
		}
		else if (deleted) {
			ctx->eth_addr[i-deleted] = ctx->eth_addr[i];
		}
	}

	ctx->n_eth_addr -= deleted;

	fastd_task_delete_peer(ctx, peer);
}

static void init_handshake(fastd_context_t *ctx, fastd_peer_t *peer) {
	unsigned delay = 0;
	if (has_group_config_constraints(peer->group->conf))
		delay = fastd_rand(ctx, 0, 3000);

	if (!fastd_peer_is_established(peer))
		peer->state = STATE_HANDSHAKE;

	fastd_task_schedule_handshake(ctx, peer, delay);
}

void fastd_peer_handle_resolve(fastd_context_t *ctx, fastd_peer_t *peer, fastd_remote_t *remote, const fastd_peer_address_t *address) {
	remote->last_resolve_return = ctx->now;
	remote->address = *address;

	if (peer->state == STATE_RESOLVING)
		init_handshake(ctx, peer);
}

static void setup_peer(fastd_context_t *ctx, fastd_peer_t *peer) {
	peer->address.sa.sa_family = AF_UNSPEC;
	peer->local_address.sa.sa_family = AF_UNSPEC;

	peer->state = STATE_INIT;

	fastd_remote_t *remote;
	for (remote = peer->remotes; remote; remote = remote->next) {
		remote->last_resolve = (struct timespec){0, 0};
		remote->last_resolve_return = (struct timespec){0, 0};
	}

	peer->next_remote = peer->remotes;

	peer->last_handshake = (struct timespec){0, 0};
	peer->last_handshake_address.sa.sa_family = AF_UNSPEC;

	peer->last_handshake_response = (struct timespec){0, 0};
	peer->last_handshake_response_address.sa.sa_family = AF_UNSPEC;

	if (!peer->protocol_state)
		ctx->conf->protocol->init_peer_state(ctx, peer);

	if(peer->next_remote) {
		if (fastd_remote_is_dynamic(peer->next_remote)) {
			peer->state = STATE_RESOLVING;
			fastd_resolve_peer(ctx, peer, peer->next_remote);
		}
		else  {
			init_handshake(ctx, peer);
		}
	}
}

static void delete_peer(fastd_context_t *ctx, fastd_peer_t *peer) {
	pr_debug(ctx, "deleting peer %P", peer);

	fastd_peer_t **cur_peer;
	for (cur_peer = &ctx->peers; *cur_peer; cur_peer = &(*cur_peer)->next) {
		if ((*cur_peer) == peer) {
			*cur_peer = peer->next;
			ctx->n_peers--;
			break;
		}
	}
	if (!*cur_peer) {
		for (cur_peer = &ctx->peers_temp; *cur_peer; cur_peer = &(*cur_peer)->next) {
			if ((*cur_peer) == peer) {
				*cur_peer = peer->next;
				break;
			}
		}
	}

	ctx->conf->protocol->free_peer_state(ctx, peer);

	if (!peer->config)
		free(peer->protocol_config);

	while (peer->remotes) {
		fastd_remote_t *remote = peer->remotes;
		peer->remotes = remote->next;

		fastd_remote_unref(remote);
	}

	free(peer);
}


fastd_peer_config_t* fastd_peer_config_new(fastd_context_t *ctx, fastd_config_t *conf) {
	fastd_peer_config_t *peer = calloc(1, sizeof(fastd_peer_config_t));

	peer->group = conf->peer_group;

	peer->next = conf->peers;
	conf->peers = peer;

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

void fastd_peer_config_delete(fastd_context_t *ctx, fastd_config_t *conf) {
	fastd_peer_config_t *peer = conf->peers, *next = peer->next;
	fastd_peer_config_free(peer);
	conf->peers = next;
}

void fastd_peer_config_purge(fastd_context_t *ctx, fastd_peer_config_t *conf) {
	fastd_peer_t *peer, *next;
	for (peer = ctx->peers; peer; peer = next) {
		next = peer->next;

		if (peer->config == conf)
			fastd_peer_delete(ctx, peer);
	}

	fastd_peer_config_free(conf);
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


static inline void reset_peer_address(fastd_context_t *ctx, fastd_peer_t *peer) {
	if (fastd_peer_is_established(peer))
		fastd_peer_reset(ctx, peer);

	memset(&peer->address, 0, sizeof(fastd_peer_address_t));
}

bool fastd_peer_owns_address(fastd_context_t *ctx, const fastd_peer_t *peer, const fastd_peer_address_t *addr) {
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

bool fastd_peer_matches_address(fastd_context_t *ctx, const fastd_peer_t *peer, const fastd_peer_address_t *addr) {
	if (fastd_peer_is_floating(peer))
		return true;

	fastd_remote_t *remote;
	for (remote = peer->remotes; remote; remote = remote->next) {
		if (fastd_peer_address_equal(&remote->address, addr))
			return true;
	}

	return false;
}

bool fastd_peer_claim_address(fastd_context_t *ctx, fastd_peer_t *new_peer, fastd_socket_t *sock, const fastd_peer_address_t *local_addr, const fastd_peer_address_t *remote_addr) {
	if (remote_addr->sa.sa_family == AF_UNSPEC) {
		if (fastd_peer_is_established(new_peer))
			fastd_peer_reset(ctx, new_peer);
	}
	else {
		fastd_peer_t *peer;
		for (peer = ctx->peers; peer; peer = peer->next) {
			if (peer == new_peer)
				continue;

			if (fastd_peer_owns_address(ctx, peer, remote_addr)) {
				reset_peer_address(ctx, new_peer);
				return false;
			}

			if (fastd_peer_address_equal(&peer->address, remote_addr)) {
				if (fastd_peer_is_established(peer))
					return false;

				reset_peer_address(ctx, peer);
				break;
			}
		}
	}

	new_peer->address = *remote_addr;
	if (sock && sock->addr && sock != new_peer->sock) {
		free_socket(ctx, new_peer);
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

void fastd_peer_reset(fastd_context_t *ctx, fastd_peer_t *peer) {
	pr_debug(ctx, "resetting peer %P", peer);

	reset_peer(ctx, peer);
	setup_peer(ctx, peer);
}

void fastd_peer_delete(fastd_context_t *ctx, fastd_peer_t *peer) {
	reset_peer(ctx, peer);
	delete_peer(ctx, peer);
}

static inline unsigned count_established_group_peers(fastd_context_t *ctx, fastd_peer_group_t *group) {
	unsigned ret = 0;
	fastd_peer_t *peer;
	for (peer = ctx->peers; peer; peer = peer->next) {
		if (fastd_peer_is_established(peer) && is_peer_in_group(peer, group))
			ret++;
	}

	return ret;
}

bool fastd_peer_may_connect(fastd_context_t *ctx, fastd_peer_t *peer) {
	if (fastd_peer_is_established(peer))
		return true;

	fastd_peer_group_t *group;

	for (group = peer->group; group; group = group->parent) {
		if (group->conf->max_connections < 0)
			continue;

		if (count_established_group_peers(ctx, group) >= group->conf->max_connections)
			return false;
	}

	return true;
}

fastd_peer_t* fastd_peer_add(fastd_context_t *ctx, fastd_peer_config_t *peer_conf) {
	fastd_peer_t *peer = calloc(1, sizeof(fastd_peer_t));

	peer->next = ctx->peers;
	ctx->peers = peer;

	peer->config = peer_conf;
	peer->group = find_peer_group(ctx->peer_group, peer_conf->group);
	peer->protocol_config = peer_conf->protocol_config;

	fastd_remote_t **remote = &peer->remotes;
	fastd_remote_config_t *remote_config = peer_conf->remotes;

	while (remote_config) {
		*remote = calloc(1, sizeof(fastd_remote_t));
		(*remote)->ref = 1;
		(*remote)->config = remote_config;

		if (!remote_config->hostname)
			(*remote)->address = remote_config->address;

		remote = &(*remote)->next;
		remote_config = remote_config->next;
	}

	pr_verbose(ctx, "adding peer %P (group `%s')", peer, peer->group->conf->name);

	setup_peer(ctx, peer);

	ctx->n_peers++;

	return peer;
}

fastd_peer_t* fastd_peer_add_temporary(fastd_context_t *ctx) {
	if (!ctx->conf->on_verify)
		exit_bug(ctx, "tried to add temporary peer without on-verify command");

	fastd_peer_t *peer = calloc(1, sizeof(fastd_peer_t));

	peer->next = ctx->peers_temp;
	ctx->peers_temp = peer;

	peer->group = ctx->peer_group;
	peer->seen = ctx->now;

	pr_debug(ctx, "adding temporary peer");

	setup_peer(ctx, peer);

	return peer;
}

bool fastd_peer_verify_temporary(fastd_context_t *ctx, fastd_peer_t *peer, const fastd_peer_address_t *local_addr, const fastd_peer_address_t *peer_addr) {
	if (!ctx->conf->on_verify)
		exit_bug(ctx, "tried to verify temporary peer without on-verify command");

	int ret;
	if (!fastd_shell_exec(ctx, ctx->conf->on_verify, ctx->conf->on_verify_dir, peer, local_addr, peer_addr, &ret))
		return false;

	if (WIFSIGNALED(ret)) {
		pr_error(ctx, "verify command exited with signal %i", WTERMSIG(ret));
		return false;
	}
	else if (WEXITSTATUS(ret)) {
		pr_debug(ctx, "verify command exited with status %i", WEXITSTATUS(ret));
		return false;
	}

	return true;
}

void fastd_peer_enable_temporary(fastd_context_t *ctx, fastd_peer_t *peer) {
	if (peer->config)
		exit_bug(ctx, "trying to re-enable non-temporary peer");

	peer->next = ctx->peers;
	ctx->peers = peer;
	ctx->n_peers++;
}

void fastd_peer_set_established(fastd_context_t *ctx, fastd_peer_t *peer) {
	if (fastd_peer_is_established(peer))
		return;

	peer->state = STATE_ESTABLISHED;
	on_establish(ctx, peer);
	pr_info(ctx, "connection with %P established.", peer);
}

const fastd_eth_addr_t* fastd_get_source_address(const fastd_context_t *ctx, fastd_buffer_t buffer) {
	switch (ctx->conf->mode) {
	case MODE_TAP:
		return (fastd_eth_addr_t*)&((struct ethhdr*)buffer.data)->h_source;
	default:
		exit_bug(ctx, "invalid mode");
	}
}

const fastd_eth_addr_t* fastd_get_dest_address(const fastd_context_t *ctx, fastd_buffer_t buffer) {
	switch (ctx->conf->mode) {
	case MODE_TAP:
		return (fastd_eth_addr_t*)&((struct ethhdr*)buffer.data)->h_dest;
	default:
		exit_bug(ctx, "invalid mode");
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

static inline int fastd_eth_addr_cmp(const fastd_eth_addr_t *addr1, const fastd_eth_addr_t *addr2) {
	return memcmp(addr1->data, addr2->data, ETH_ALEN);
}

static inline int fastd_peer_eth_addr_cmp(const fastd_peer_eth_addr_t *addr1, const fastd_peer_eth_addr_t *addr2) {
	return fastd_eth_addr_cmp(&addr1->addr, &addr2->addr);
}

static inline fastd_peer_eth_addr_t* peer_get_by_addr(fastd_context_t *ctx, const fastd_eth_addr_t *addr) {
	return bsearch(container_of(addr, fastd_peer_eth_addr_t, addr), ctx->eth_addr, ctx->n_eth_addr, sizeof(fastd_peer_eth_addr_t),
		       (int (*)(const void *, const void *))fastd_peer_eth_addr_cmp);
}

void fastd_peer_eth_addr_add(fastd_context_t *ctx, fastd_peer_t *peer, const fastd_eth_addr_t *addr) {
	int min = 0, max = ctx->n_eth_addr;

	while (max > min) {
		int cur = (min+max)/2;
		int cmp = fastd_eth_addr_cmp(addr, &ctx->eth_addr[cur].addr);

		if (cmp == 0) {
			ctx->eth_addr[cur].peer = peer;
			ctx->eth_addr[cur].seen = ctx->now;
			return; /* We're done here. */
		}
		else if (cmp < 0) {
			max = cur;
		}
		else {
			min = cur+1;
		}
	}

	ctx->n_eth_addr++;
	if (ctx->n_eth_addr > ctx->eth_addr_size) {
		if (ctx->eth_addr_size == 0)
			ctx->eth_addr_size = 16;
		else
			ctx->eth_addr_size *= 2;

		ctx->eth_addr = realloc(ctx->eth_addr, ctx->eth_addr_size*sizeof(fastd_peer_eth_addr_t));
	}

	int i;
	for (i = ctx->n_eth_addr-1; i > min; i--)
		ctx->eth_addr[i] = ctx->eth_addr[i-1];

	ctx->eth_addr[min] = (fastd_peer_eth_addr_t){ *addr, peer, ctx->now };

	pr_debug(ctx, "learned new MAC address %E on peer %P", addr, peer);
}

void fastd_peer_eth_addr_cleanup(fastd_context_t *ctx) {
	int i, deleted = 0;

	for (i = 0; i < ctx->n_eth_addr; i++) {
		if (timespec_diff(&ctx->now, &ctx->eth_addr[i].seen) > ctx->conf->eth_addr_stale_time*1000) {
			deleted++;
			pr_debug(ctx, "MAC address %E not seen for more than %u seconds, removing",
				 &ctx->eth_addr[i].addr, ctx->conf->eth_addr_stale_time);
		}
		else if (deleted) {
			ctx->eth_addr[i-deleted] = ctx->eth_addr[i];
		}
	}

	ctx->n_eth_addr -= deleted;
}

fastd_peer_t* fastd_peer_find_by_eth_addr(fastd_context_t *ctx, const fastd_eth_addr_t *addr) {
	fastd_peer_eth_addr_t *peer_eth_addr = peer_get_by_addr(ctx, addr);

	if (peer_eth_addr)
		return peer_eth_addr->peer;
	else
		return NULL;
}
