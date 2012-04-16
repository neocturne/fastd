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
#include <unistd.h>


static void on_establish(fastd_context *ctx, fastd_peer *peer) {
	if (!ctx->conf->on_establish)
		return;

	char *cwd = get_current_dir_name();

	if(!chdir(ctx->conf->on_establish_dir)) {
		setenv("INTERFACE", ctx->ifname, 1);

		char buf[INET6_ADDRSTRLEN];
		snprintf(buf, sizeof(buf), "%u", ctx->conf->mtu);
		setenv("MTU", buf, 1);

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
		snprintf(buf, sizeof(buf), "%u", ctx->conf->mtu);
		setenv("MTU", buf, 1);

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

static inline void reset_peer(fastd_context *ctx, fastd_peer *peer) {
	if (peer->state == STATE_ESTABLISHED)
		on_disestablish(ctx, peer);

	ctx->conf->protocol->free_peer_state(ctx, peer);
	peer->protocol_state = NULL;

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

static inline void setup_peer(fastd_context *ctx, fastd_peer *peer) {
	if (peer->config->hostname)
		peer->address.sa.sa_family = AF_UNSPEC;
	else
		peer->address = peer->config->address;

	if (peer->config->hostname)
		peer->state = STATE_RESOLVE;
	else
		peer->state = STATE_WAIT;

	peer->seen = (struct timespec){0, 0};

	if (!fastd_peer_is_floating(peer))
		fastd_task_schedule_handshake(ctx, peer, 0);
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

	free(peer);
}


fastd_peer_config* fastd_peer_config_new(fastd_context *ctx, fastd_config *conf) {
	fastd_peer_config *peer = malloc(sizeof(fastd_peer_config));
	peer->enabled = true;

	peer->hostname = NULL;
	memset(&peer->address, 0, sizeof(fastd_peer_address));

	peer->config_source_dir = NULL;

	peer->name = NULL;
	peer->key = NULL;
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

	ctx->conf->protocol->peer_config_purged(ctx, conf);
	fastd_peer_config_free(conf);
}

bool fastd_peer_addr_equal(const fastd_peer_address *addr1, const fastd_peer_address *addr2) {
	if (addr1->sa.sa_family != addr2->sa.sa_family)
		return false;

	switch (addr1->sa.sa_family) {
	case AF_UNSPEC:
		break;

	case AF_INET:
		if (addr1->in.sin_addr.s_addr != addr2->in.sin_addr.s_addr)
			return false;
		break;

	case AF_INET6:
		if (!IN6_ARE_ADDR_EQUAL(&addr1->in6.sin6_addr, &addr2->in6.sin6_addr))
			return false;
	}

	return true;
}

bool fastd_peer_config_equal(const fastd_peer_config *peer1, const fastd_peer_config *peer2) {
	if (peer1->enabled != peer2->enabled)
		return false;

	if (!strequal(peer1->hostname, peer2->hostname))
		return false;

	if (!fastd_peer_addr_equal(&peer1->address, &peer2->address))
		return false;

	if (!strequal(peer1->key, peer2->key))
		return false;

	return true;
}

void fastd_peer_reset(fastd_context *ctx, fastd_peer *peer) {
	pr_debug(ctx, "resetting peer %P", peer);

	reset_peer(ctx, peer);

	if (fastd_peer_is_temporary(peer))
		delete_peer(ctx, peer);
	else
		setup_peer(ctx, peer);
}

void fastd_peer_delete(fastd_context *ctx, fastd_peer *peer) {
	reset_peer(ctx, peer);
	delete_peer(ctx, peer);
}

static fastd_peer* add_peer(fastd_context *ctx) {
	fastd_peer *peer = malloc(sizeof(fastd_peer));

	peer->next = ctx->peers;
	peer->last_req_id = 0;
	peer->protocol_state = NULL;

	ctx->peers = peer;

	return peer;
}

fastd_peer* fastd_peer_add(fastd_context *ctx, fastd_peer_config *peer_conf) {
	fastd_peer *peer = add_peer(ctx);

	peer->config = peer_conf;
	setup_peer(ctx, peer);

	pr_debug(ctx, "adding peer %P", peer);

	return peer;
}

fastd_peer* fastd_peer_add_temp(fastd_context *ctx, const fastd_peer_address *address) {
	fastd_peer *peer = add_peer(ctx);

	peer->config = NULL;
	peer->address = *address;
	peer->state = STATE_TEMP;
	peer->seen = ctx->now;

	pr_debug(ctx, "added peer %P", peer);

	return peer;
}

fastd_peer* fastd_peer_set_established_merge(fastd_context *ctx, fastd_peer *perm_peer, fastd_peer *temp_peer) {
	pr_debug(ctx, "merging peer %P into %P", temp_peer, perm_peer);

	ctx->conf->protocol->free_peer_state(ctx, perm_peer);

	if (perm_peer->state == STATE_ESTABLISHED)
		on_disestablish(ctx, perm_peer);

	perm_peer->address = temp_peer->address;
	perm_peer->state = STATE_ESTABLISHED;
	perm_peer->seen = temp_peer->seen;
	perm_peer->protocol_state = temp_peer->protocol_state;
	temp_peer->protocol_state = NULL;

	int i;
	for (i = 0; i < ctx->n_eth_addr; i++) {
		if (ctx->eth_addr[i].peer == temp_peer) {
			ctx->eth_addr[i].peer = perm_peer;
		}
	}

	fastd_task_replace_peer(ctx, temp_peer, perm_peer);

	fastd_peer_reset(ctx, temp_peer);

	on_establish(ctx, perm_peer);
	pr_info(ctx, "Connection with %P established.", perm_peer);

	return perm_peer;
}

void fastd_peer_set_established(fastd_context *ctx, fastd_peer *peer) {
	switch(peer->state) {
	case STATE_RESOLVE:
	case STATE_WAIT:
		peer->state = STATE_ESTABLISHED;
		on_establish(ctx, peer);
		pr_info(ctx, "Connection with %P established.", peer);
		break;

	case STATE_TEMP:
		exit_bug(ctx, "tried to set a temporary connection to established");

	default:
		return;
	}
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

	pr_debug(ctx, "Learned new MAC address %E on peer %P", addr, peer);
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
