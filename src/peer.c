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


#define _GNU_SOURCE

#include "peer.h"
#include "task.h"

#include <arpa/inet.h>


static void on_establish(fastd_context *ctx, fastd_peer *peer) {
	if (!ctx->conf->on_establish)
		return;

	char *cwd = get_current_dir_name();

	if(!chdir(ctx->conf->on_establish_dir)) {
		setenv("INTERFACE", ctx->ifname, 1);

		char buf[INET6_ADDRSTRLEN];

		if (peer->config && peer->config->name)
			setenv("PEER_NAME", peer->config->name, 1);
		else
			unsetenv("PEER_NAME");

		switch(peer->address.sa.sa_family) {
		case AF_INET:
			inet_ntop(AF_INET, &peer->address.in.sin_addr, buf, sizeof(buf));
			setenv("PEER_ADDRESS", buf, 1);

			snprintf(buf, sizeof(buf), "%u", ntohs(peer->address.in.sin_port));
			setenv("PEER_PORT", buf, 1);

			break;

		case AF_INET6:
			inet_ntop(AF_INET6, &peer->address.in6.sin6_addr, buf, sizeof(buf));
			setenv("PEER_ADDRESS", buf, 1);

			snprintf(buf, sizeof(buf), "%u", ntohs(peer->address.in6.sin6_port));
			setenv("PEER_PORT", buf, 1);

			break;

		default:
			unsetenv("PEER_ADDRESS");
			unsetenv("PEER_PORT");
		}

		int ret = system(ctx->conf->on_establish);

		if (WIFSIGNALED(ret))
			pr_error(ctx, "on-establish command exited with signal %i", WTERMSIG(ret));
		else if(ret)
			pr_warn(ctx, "on-establish command exited with status %i", WEXITSTATUS(ret));

		if(chdir(cwd))
			pr_error(ctx, "can't chdir to `%s': %s", cwd, strerror(errno));
	}
	else {
		pr_error(ctx, "can't chdir to `%s': %s", ctx->conf->on_establish_dir, strerror(errno));
	}

	free(cwd);
}

static void on_disestablish(fastd_context *ctx, fastd_peer *peer) {
	if (!ctx->conf->on_disestablish)
		return;

	char *cwd = get_current_dir_name();

	if(!chdir(ctx->conf->on_disestablish_dir)) {
		setenv("INTERFACE", ctx->ifname, 1);

		char buf[INET6_ADDRSTRLEN];

		if (peer->config && peer->config->name)
			setenv("PEER_NAME", peer->config->name, 1);
		else
			unsetenv("PEER_NAME");

		switch(peer->address.sa.sa_family) {
		case AF_INET:
			inet_ntop(AF_INET, &peer->address.in.sin_addr, buf, sizeof(buf));
			setenv("PEER_ADDRESS", buf, 1);

			snprintf(buf, sizeof(buf), "%u", ntohs(peer->address.in.sin_port));
			setenv("PEER_PORT", buf, 1);

			break;

		case AF_INET6:
			inet_ntop(AF_INET6, &peer->address.in6.sin6_addr, buf, sizeof(buf));
			setenv("PEER_ADDRESS", buf, 1);

			snprintf(buf, sizeof(buf), "%u", ntohs(peer->address.in6.sin6_port));
			setenv("PEER_PORT", buf, 1);

			break;

		default:
			unsetenv("PEER_ADDRESS");
			unsetenv("PEER_PORT");
		}

		int ret = system(ctx->conf->on_disestablish);

		if (WIFSIGNALED(ret))
			pr_error(ctx, "on-disestablish command exited with signal %i", WTERMSIG(ret));
		else if(ret)
			pr_warn(ctx, "on-disestablish command exited with status %i", WEXITSTATUS(ret));

		if(chdir(cwd))
			pr_error(ctx, "can't chdir to `%s': %s", cwd, strerror(errno));
	}
	else {
		pr_error(ctx, "can't chdir to `%s': %s", ctx->conf->on_disestablish_dir, strerror(errno));
	}

	free(cwd);
}

static inline void free_socket(fastd_context *ctx, fastd_peer *peer) {
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

static bool has_group_config_constraints(const fastd_peer_group_config *group) {
	for (; group; group = group->parent) {
		if (group->max_connections)
			return true;
	}

	return false;
}

void fastd_peer_reset_socket(fastd_context *ctx, fastd_peer *peer) {
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

static inline fastd_peer_group* find_peer_group(fastd_peer_group *group, const fastd_peer_group_config *config) {
	if (group->conf == config)
		return group;

	fastd_peer_group *child;
	for (child = group->children; child; child = child->next) {
		fastd_peer_group *ret = find_peer_group(child, config);

		if (ret)
			return ret;
	}

	return NULL;
}

static inline bool is_group_in(fastd_peer_group *group1, fastd_peer_group *group2) {
	while (group1) {
		if (group1 == group2)
			return true;

		group1 = group1->parent;
	}

	return false;
}

static bool is_peer_in_group(fastd_peer *peer, fastd_peer_group *group) {
	return is_group_in(peer->group, group);
}

static void reset_peer(fastd_context *ctx, fastd_peer *peer) {
	if (peer->established)
		on_disestablish(ctx, peer);

	free_socket(ctx, peer);

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

static void setup_peer(fastd_context *ctx, fastd_peer *peer) {
	if (peer->config->hostname)
		peer->address.sa.sa_family = AF_UNSPEC;
	else
		peer->address = peer->config->address;

	peer->established = false;

	peer->last_resolve = (struct timespec){0, 0};
	peer->last_resolve_return = (struct timespec){0, 0};
	peer->seen = (struct timespec){0, 0};

	peer->last_handshake = (struct timespec){0, 0};
	peer->last_handshake_address.sa.sa_family = AF_UNSPEC;

	peer->last_handshake_response = (struct timespec){0, 0};
	peer->last_handshake_response_address.sa.sa_family = AF_UNSPEC;

	if (!peer->protocol_state)
		ctx->conf->protocol->init_peer_state(ctx, peer);

	if (!fastd_peer_is_floating(peer) || fastd_peer_is_dynamic(peer)) {
		unsigned delay = 0;
		if (has_group_config_constraints(peer->group->conf))
			delay = fastd_rand(ctx, 0, 3000);

		fastd_task_schedule_handshake(ctx, peer, delay);
	}
}

static void delete_peer(fastd_context *ctx, fastd_peer *peer) {
	pr_debug(ctx, "deleting peer %P", peer);

	fastd_peer **cur_peer;
	for (cur_peer = &ctx->peers; *cur_peer; cur_peer = &(*cur_peer)->next) {
		if ((*cur_peer) == peer) {
			*cur_peer = peer->next;
			break;
		}
	}

	ctx->conf->protocol->free_peer_state(ctx, peer);
	free(peer);
	ctx->n_peers--;
}


fastd_peer_config* fastd_peer_config_new(fastd_context *ctx, fastd_config *conf) {
	fastd_peer_config *peer = malloc(sizeof(fastd_peer_config));
	peer->enabled = true;

	peer->hostname = NULL;
	memset(&peer->address, 0, sizeof(fastd_peer_address));
	peer->dynamic_float = false;

	peer->config_source_dir = NULL;

	peer->name = NULL;
	peer->key = NULL;
	peer->group = conf->peer_group;
	peer->protocol_config = NULL;

	peer->next = conf->peers;
	conf->peers = peer;

	return peer;
}

void fastd_peer_config_free(fastd_peer_config *peer) {
	free(peer->name);
	free(peer->hostname);
	free(peer->key);
	free(peer->protocol_config);
	free(peer);
}

void fastd_peer_config_delete(fastd_context *ctx, fastd_config *conf) {
	fastd_peer_config *peer = conf->peers, *next = peer->next;
	fastd_peer_config_free(peer);
	conf->peers = next;
}

void fastd_peer_config_purge(fastd_context *ctx, fastd_peer_config *conf) {
	fastd_peer *peer, *next;
	for (peer = ctx->peers; peer; peer = next) {
		next = peer->next;

		if (peer->config == conf)
			fastd_peer_delete(ctx, peer);
	}

	fastd_peer_config_free(conf);
}

bool fastd_peer_address_equal(const fastd_peer_address *addr1, const fastd_peer_address *addr2) {
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
	}

	return true;
}

void fastd_peer_address_simplify(fastd_peer_address *addr) {
	if (addr->sa.sa_family == AF_INET6 && IN6_IS_ADDR_V4MAPPED(&addr->in6.sin6_addr)) {
		struct sockaddr_in6 mapped = addr->in6;

		memset(addr, 0, sizeof(fastd_peer_address));
		addr->in.sin_family = AF_INET;
		addr->in.sin_port = mapped.sin6_port;
		memcpy(&addr->in.sin_addr.s_addr, &mapped.sin6_addr.s6_addr[12], 4);
	}
}


bool fastd_peer_claim_address(fastd_context *ctx, fastd_peer *new_peer, fastd_socket *sock, const fastd_peer_address *addr) {
	if (addr->sa.sa_family == AF_UNSPEC) {
		if (fastd_peer_is_established(new_peer))
			fastd_peer_reset(ctx, new_peer);
	}
	else {
		fastd_peer *peer;
		for (peer = ctx->peers; peer; peer = peer->next) {
			if (!fastd_peer_address_equal(&peer->address, addr))
				continue;

			if (peer == new_peer)
				break;

			if (!fastd_peer_is_floating(peer)) {
				if (fastd_peer_is_established(new_peer))
					fastd_peer_reset(ctx, new_peer);

				memset(&new_peer->address, 0, sizeof(fastd_peer_address));
				return false;
			}

			if (fastd_peer_is_established(peer))
				fastd_peer_reset(ctx, peer);

			memset(&peer->address, 0, sizeof(fastd_peer_address));
			break;
		}
	}

	new_peer->address = *addr;
	if (sock && sock->addr && sock != new_peer->sock) {
		free_socket(ctx, new_peer);
		new_peer->sock = sock;
	}

	return true;
}

bool fastd_peer_config_equal(const fastd_peer_config *peer1, const fastd_peer_config *peer2) {
	if (peer1->group != peer2->group)
		return false;

	if (!strequal(peer1->hostname, peer2->hostname))
		return false;

	if(peer1->dynamic_float != peer2->dynamic_float)
		return false;

	if (!fastd_peer_address_equal(&peer1->address, &peer2->address))
		return false;

	if (!strequal(peer1->key, peer2->key))
		return false;

	return true;
}

void fastd_peer_reset(fastd_context *ctx, fastd_peer *peer) {
	pr_debug(ctx, "resetting peer %P", peer);

	reset_peer(ctx, peer);
	setup_peer(ctx, peer);
}

void fastd_peer_delete(fastd_context *ctx, fastd_peer *peer) {
	reset_peer(ctx, peer);
	delete_peer(ctx, peer);
}

static inline unsigned count_established_group_peers(fastd_context *ctx, fastd_peer_group *group) {
	unsigned ret = 0;
	fastd_peer *peer;
	for (peer = ctx->peers; peer; peer = peer->next) {
		if (fastd_peer_is_established(peer) && is_peer_in_group(peer, group))
			ret++;
	}

	return ret;
}

bool fastd_peer_may_connect(fastd_context *ctx, fastd_peer *peer) {
	if (fastd_peer_is_established(peer))
		return true;

	fastd_peer_group *group;

	for (group = peer->group; group; group = group->parent) {
		if (!group->conf->max_connections)
			continue;

		if (count_established_group_peers(ctx, group) >= group->conf->max_connections)
			return false;
	}

	return true;
}

fastd_peer* fastd_peer_add(fastd_context *ctx, fastd_peer_config *peer_conf) {
	fastd_peer *peer = malloc(sizeof(fastd_peer));

	peer->next = ctx->peers;
	ctx->peers = peer;

	peer->config = peer_conf;
	peer->group = find_peer_group(ctx->peer_group, peer_conf->group);
	peer->protocol_state = NULL;
	peer->sock = NULL;
	setup_peer(ctx, peer);

	pr_verbose(ctx, "adding peer %P (group `%s')", peer, peer->group->conf->name);
	ctx->n_peers++;

	return peer;
}

void fastd_peer_set_established(fastd_context *ctx, fastd_peer *peer) {
	if (!peer->established) {
		peer->established = true;
		on_establish(ctx, peer);
		pr_info(ctx, "connection with %P established.", peer);
	}

	return;
}

const fastd_eth_addr* fastd_get_source_address(const fastd_context *ctx, fastd_buffer buffer) {
	switch (ctx->conf->mode) {
	case MODE_TAP:
		return (fastd_eth_addr*)&((struct ethhdr*)buffer.data)->h_source;
	default:
		exit_bug(ctx, "invalid mode");
	}
}

const fastd_eth_addr* fastd_get_dest_address(const fastd_context *ctx, fastd_buffer buffer) {
	switch (ctx->conf->mode) {
	case MODE_TAP:
		return (fastd_eth_addr*)&((struct ethhdr*)buffer.data)->h_dest;
	default:
		exit_bug(ctx, "invalid mode");
	}
}

bool fastd_peer_config_matches_dynamic(const fastd_peer_config *config, const fastd_peer_address *addr) {
	if (!config->hostname)
		return false;

	if (config->address.sa.sa_family != AF_UNSPEC &&
	    config->address.sa.sa_family != addr->sa.sa_family)
		return false;

	if (addr->sa.sa_family == AF_INET6) {
		if (config->address.in.sin_port != addr->in6.sin6_port)
			return false;
	}
	else {
		if (config->address.in.sin_port != addr->in.sin_port)
			return false;
	}

	return true;
}

static inline int fastd_eth_addr_cmp(const fastd_eth_addr *addr1, const fastd_eth_addr *addr2) {
	return memcmp(addr1->data, addr2->data, ETH_ALEN);
}

static inline int fastd_peer_eth_addr_cmp(const fastd_peer_eth_addr *addr1, const fastd_peer_eth_addr *addr2) {
	return fastd_eth_addr_cmp(&addr1->addr, &addr2->addr);
}

static inline fastd_peer_eth_addr* peer_get_by_addr(fastd_context *ctx, const fastd_eth_addr *addr) {
	return bsearch(container_of(addr, fastd_peer_eth_addr, addr), ctx->eth_addr, ctx->n_eth_addr, sizeof(fastd_peer_eth_addr),
		       (int (*)(const void *, const void *))fastd_peer_eth_addr_cmp);
}

void fastd_peer_eth_addr_add(fastd_context *ctx, fastd_peer *peer, const fastd_eth_addr *addr) {
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

		ctx->eth_addr = realloc(ctx->eth_addr, ctx->eth_addr_size*sizeof(fastd_peer_eth_addr));
	}

	int i;
	for (i = ctx->n_eth_addr-1; i > min; i--)
		ctx->eth_addr[i] = ctx->eth_addr[i-1];
	
	ctx->eth_addr[min] = (fastd_peer_eth_addr){ *addr, peer, ctx->now };

	pr_debug(ctx, "learned new MAC address %E on peer %P", addr, peer);
}

void fastd_peer_eth_addr_cleanup(fastd_context *ctx) {
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

fastd_peer *fastd_peer_find_by_eth_addr(fastd_context *ctx, const fastd_eth_addr *addr) {
	fastd_peer_eth_addr *peer_eth_addr = peer_get_by_addr(ctx, addr);

	if (peer_eth_addr)
		return peer_eth_addr->peer;
	else
		return NULL;
}
