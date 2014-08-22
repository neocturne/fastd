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

/**
   \file

   A hashtable allowing fast lookup from an IP address to a peer
*/


#include "peer_hashtable.h"
#include "fastd.h"
#include "hash.h"
#include "peer.h"


/** The number of hash buckets used */
#define PEER_ADDR_HT_SIZE 64


/** Initializes the hashtable */
void fastd_peer_hashtable_init(void) {
	fastd_random_bytes(&ctx.peer_addr_ht_seed, sizeof(ctx.peer_addr_ht_seed), false);

	ctx.peer_addr_ht = fastd_new0_array(PEER_ADDR_HT_SIZE, __typeof__(*ctx.peer_addr_ht));
}

/** Frees the resources used by the hashtable */
void fastd_peer_hashtable_free(void) {
	size_t i;
	for (i = 0; i < PEER_ADDR_HT_SIZE; i++)
		VECTOR_FREE(ctx.peer_addr_ht[i]);

	free(ctx.peer_addr_ht);
}

/** Gets the hash bucket used for an address */
static size_t peer_address_bucket(const fastd_peer_address_t *addr) {
	uint32_t hash = ctx.peer_addr_ht_seed;

	switch(addr->sa.sa_family) {
	case AF_INET:
		fastd_hash(&hash, &addr->in.sin_addr.s_addr, sizeof(addr->in.sin_addr.s_addr));
		fastd_hash(&hash, &addr->in.sin_port, sizeof(addr->in.sin_port));
		break;

	case AF_INET6:
		fastd_hash(&hash, &addr->in6.sin6_addr, sizeof(addr->in6.sin6_addr));
		fastd_hash(&hash, &addr->in6.sin6_port, sizeof(addr->in6.sin6_port));
		if (IN6_IS_ADDR_LINKLOCAL(&addr->in6.sin6_addr))
			fastd_hash(&hash, &addr->in6.sin6_scope_id, sizeof(addr->in6.sin6_scope_id));
		break;

	default:
		exit_bug("peer_address_bucket: unknown address family");
	}

	fastd_hash_final(&hash);

	return hash % PEER_ADDR_HT_SIZE;
}

/**
   Inserts a peer into the hash table

   The peer address must not change while the peer is part of the table.
*/
void fastd_peer_hashtable_insert(fastd_peer_t *peer) {
	if (!peer->address.sa.sa_family)
		return;

	size_t b = peer_address_bucket(&peer->address);
	VECTOR_ADD(ctx.peer_addr_ht[b], peer);
}

/**
   Removes a peer from the hash table

   A peer must be removed from the table before it is deleted or its address is changed.
*/
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

/** Looks up a peer in the hashtable */
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
