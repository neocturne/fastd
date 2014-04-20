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


#include "peer_hashtable.h"
#include "fastd.h"
#include "hash.h"
#include "peer.h"


#define PEER_ADDR_HT_SIZE 64


void fastd_peer_hashtable_init(void) {
	fastd_random_bytes(&ctx.peer_addr_ht_seed, sizeof(ctx.peer_addr_ht_seed), false);

	ctx.peer_addr_ht = malloc(sizeof(*ctx.peer_addr_ht) * PEER_ADDR_HT_SIZE);

	size_t i;
	for (i = 0; i < PEER_ADDR_HT_SIZE; i++)
		VECTOR_ALLOC(ctx.peer_addr_ht[i], 0);
}

void fastd_peer_hashtable_free(void) {
	size_t i;
	for (i = 0; i < PEER_ADDR_HT_SIZE; i++)
		VECTOR_FREE(ctx.peer_addr_ht[i]);

	free(ctx.peer_addr_ht);
}

static size_t peer_address_bucket(const fastd_peer_address_t *addr) {
	uint32_t hash = ctx.peer_addr_ht_seed;

	switch(addr->sa.sa_family) {
	case AF_INET:
		fastd_hash(&hash, &addr->in, sizeof(addr->in));
		break;

	case AF_INET6:
		fastd_hash(&hash, &addr->in6, sizeof(addr->in6));
		break;

	default:
		exit_bug("peer_address_bucket: unknown address family");
	}

	fastd_hash_final(&hash);

	return hash % PEER_ADDR_HT_SIZE;
}

void fastd_peer_hashtable_insert(fastd_peer_t *peer) {
	size_t b = peer_address_bucket(&peer->address);
	VECTOR_ADD(ctx.peer_addr_ht[b], peer);
}

void fastd_peer_hashtable_remove(fastd_peer_t *peer) {
	if (!peer->address.sa.sa_family)
		return;

	size_t b = peer_address_bucket(&peer->address);

	size_t i;
	for (i = 0; i < VECTOR_LEN(ctx.peer_addr_ht[b]); i++) {
		if (VECTOR_INDEX(ctx.peer_addr_ht[b], i) == peer) {
			VECTOR_DELETE(ctx.peer_addr_ht[b], i);
			break;
		}
	}
}

fastd_peer_t *fastd_peer_hashtable_lookup(const fastd_peer_address_t *addr) {
	size_t b = peer_address_bucket(addr);

	size_t i;
	for (i = 0; i < VECTOR_LEN(ctx.peer_addr_ht[b]); i++) {
		fastd_peer_t *peer = VECTOR_INDEX(ctx.peer_addr_ht[b], i);

		if (fastd_peer_address_equal(&peer->address, addr))
			return peer;
	}

	return NULL;
}
