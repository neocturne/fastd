/*
  Copyright (c) 2012, Matthias Schiffer <mschiffer@universe-factory.net>
  Partly based on QuickTun Copyright (c) 2010, Ivo Smits <Ivo@UCIS.nl>.
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
#include "task.h"

#include <arpa/inet.h>


const fastd_eth_addr* fastd_get_source_address(const fastd_context *ctx, fastd_buffer buffer) {
	switch (ctx->conf->protocol) {
	case PROTOCOL_ETHERNET:
		return (fastd_eth_addr*)&((struct ethhdr*)buffer.data)->h_source;
	default:
		exit_bug(ctx, "invalid protocol");
	}
}

const fastd_eth_addr* fastd_get_dest_address(const fastd_context *ctx, fastd_buffer buffer) {
	switch (ctx->conf->protocol) {
	case PROTOCOL_ETHERNET:
		return (fastd_eth_addr*)&((struct ethhdr*)buffer.data)->h_dest;
	default:
		exit_bug(ctx, "invalid protocol");
	}
}

static fastd_peer* add_peer(fastd_context *ctx) {
	fastd_peer *peer = malloc(sizeof(fastd_peer));

	peer->next = ctx->peers;
	peer->last_req_id = 0;

	ctx->peers = peer;

	return peer;
}

fastd_peer* fastd_peer_add(fastd_context *ctx, fastd_peer_config *peer_conf) {
	fastd_peer *peer = add_peer(ctx);

	peer->config = peer_conf;
	peer->address = peer_conf->address;
	peer->port = peer_conf->port;
	peer->state = STATE_WAIT;

	pr_debug(ctx, "added peer %s:%u", inet_ntoa((struct in_addr){ .s_addr = peer->address }), ntohs(peer->port));

	if (peer->address)
		fastd_task_schedule_handshake(ctx, peer, 0);

	return peer;
}

fastd_peer* fastd_peer_add_temp(fastd_context *ctx, in_addr_t address, in_port_t port) {
	fastd_peer *peer = add_peer(ctx);

	if (!ctx->conf->n_floating)
		exit_bug(ctx, "tried to add a temporary peer with no floating remotes defined");

	peer->config = NULL;
	peer->address = address;
	peer->port = port;
	peer->state = STATE_TEMP;

	pr_debug(ctx, "added peer %s:%u (temporary)", inet_ntoa((struct in_addr){ .s_addr = peer->address }), ntohs(peer->port));

	return peer;
}

fastd_peer* fastd_peer_merge(fastd_context *ctx, fastd_peer *perm_peer, fastd_peer *temp_peer) {
	pr_debug(ctx, "merging peers");

	perm_peer->address = temp_peer->address;
	perm_peer->port = temp_peer->port;
	perm_peer->state = fastd_peer_is_established(temp_peer) ? STATE_ESTABLISHED : STATE_WAIT;

	int i;
	for (i = 0; i < ctx->n_eth_addr; i++) {
		if (ctx->eth_addr[i].peer == temp_peer) {
			ctx->eth_addr[i].peer = perm_peer;
		}
	}

	fastd_peer_delete(ctx, temp_peer);

	return perm_peer;
}

void fastd_peer_delete(fastd_context *ctx, fastd_peer *peer) {
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

	fastd_peer **cur_peer;
	for (cur_peer = &ctx->peers; *cur_peer; cur_peer = &(*cur_peer)->next) {
		if ((*cur_peer) == peer) {
			*cur_peer = peer->next;
			break;
		}
	}

	fastd_task_delete_peer(ctx, peer);

	free(peer);
}

static inline int fastd_eth_addr_cmp(const fastd_eth_addr *addr1, const fastd_eth_addr *addr2) {
	return memcmp(addr1->data, addr2->data, ETH_ALEN);
}

static inline int fastd_peer_eth_addr_cmp(const fastd_peer_eth_addr *addr1, const fastd_peer_eth_addr *addr2) {
	return fastd_eth_addr_cmp(&addr1->addr, &addr2->addr);
}

static inline fastd_peer_eth_addr* peer_get_by_addr(fastd_context *ctx, const fastd_eth_addr *addr) {
	return bsearch(((uint8_t*)addr)-offsetof(fastd_peer_eth_addr, addr), ctx->eth_addr, ctx->n_eth_addr, sizeof(fastd_peer_eth_addr),
		       (int (*)(const void *, const void *))fastd_peer_eth_addr_cmp);
}

void fastd_peer_add_eth_addr(fastd_context *ctx, fastd_peer *peer, const fastd_eth_addr *addr) {
	int min = 0, max = ctx->n_eth_addr;

	while (max > min) {
		int cur = (min+max)/2;
		int cmp = fastd_eth_addr_cmp(addr, &ctx->eth_addr[cur].addr);

		if (cmp == 0) {
			ctx->eth_addr[cur].peer = peer;
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
	for (i = ctx->n_eth_addr-1; i > min+1; i--)
		ctx->eth_addr[i] = ctx->eth_addr[i-1];
	
	ctx->eth_addr[min] = (fastd_peer_eth_addr){ *addr, peer };
}

fastd_peer *fastd_peer_find_by_eth_addr(fastd_context *ctx, const fastd_eth_addr *addr) {
	fastd_peer_eth_addr *peer_eth_addr = peer_get_by_addr(ctx, addr);

	if (peer_eth_addr)
		return peer_eth_addr->peer;
	else
		return NULL;
}
