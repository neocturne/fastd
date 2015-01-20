/*
  Copyright (c) 2012-2015, Matthias Schiffer <mschiffer@universe-factory.net>
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


/** Initializes the hashtable */
static void init_hashtable(void) {
	fastd_random_bytes(&ctx.peer_addr_ht_seed, sizeof(ctx.peer_addr_ht_seed), false);
	ctx.peer_addr_ht = fastd_new0_array(ctx.peer_addr_ht_size, __typeof__(*ctx.peer_addr_ht));
}

/** Initializes the hashtable with the default size */
void fastd_peer_hashtable_init(void) {
	ctx.peer_addr_ht_size = 8;
	init_hashtable();
}

/** Frees the resources used by the hashtable */
void fastd_peer_hashtable_free(void) {
	size_t i;
	for (i = 0; i < ctx.peer_addr_ht_size; i++)
		VECTOR_FREE(ctx.peer_addr_ht[i]);

	free(ctx.peer_addr_ht);
}

/** Doubles the size of the peer hashtable and rebuild it afterwards */
static void resize_hashtable(void) {
	fastd_peer_hashtable_free();
	ctx.peer_addr_ht_used = 0;

	ctx.peer_addr_ht_size *= 2;
	pr_debug("resizing peer address hashtable to %u buckets", (unsigned)ctx.peer_addr_ht_size);

	init_hashtable();

	size_t i;
	for (i = 0; i < VECTOR_LEN(ctx.peers); i++)
		fastd_peer_hashtable_insert(VECTOR_INDEX(ctx.peers, i));
}

/** Gets the hash bucket used for an address */
static size_t peer_address_bucket(const fastd_peer_address_t *addr) {
	uint32_t hash = ctx.peer_addr_ht_seed;
	fastd_peer_address_hash(&hash, addr);
	fastd_hash_final(&hash);

	return hash % ctx.peer_addr_ht_size;
}

/**
   Inserts a peer into the hash table

   The peer address must not change while the peer is part of the table.
*/
void fastd_peer_hashtable_insert(fastd_peer_t *peer) {
	if (!peer->address.sa.sa_family)
		return;

	ctx.peer_addr_ht_used++;

	if (ctx.peer_addr_ht_used > 2*ctx.peer_addr_ht_size) {
		resize_hashtable();
		return;
	}

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

	ctx.peer_addr_ht_used--;
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
