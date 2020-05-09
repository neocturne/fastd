// SPDX-License-Identifier: BSD-2-Clause
/*
  Copyright (c) 2012-2016, Matthias Schiffer <mschiffer@universe-factory.net>
  All rights reserved.
*/

/**
   \file

   A hashtable allowing fast lookup from an IP address to a peer
*/


#pragma once


#include "hash.h"
#include "peer.h"


/** Hashes a peer address */
static inline void fastd_peer_address_hash(uint32_t *hash, const fastd_peer_address_t *addr) {
	switch (addr->sa.sa_family) {
	case AF_INET:
		fastd_hash(hash, &addr->in.sin_addr.s_addr, sizeof(addr->in.sin_addr.s_addr));
		fastd_hash(hash, &addr->in.sin_port, sizeof(addr->in.sin_port));
		break;

	case AF_INET6:
		fastd_hash(hash, &addr->in6.sin6_addr, sizeof(addr->in6.sin6_addr));
		fastd_hash(hash, &addr->in6.sin6_port, sizeof(addr->in6.sin6_port));
		if (IN6_IS_ADDR_LINKLOCAL(&addr->in6.sin6_addr))
			fastd_hash(hash, &addr->in6.sin6_scope_id, sizeof(addr->in6.sin6_scope_id));
		break;

	default:
		exit_bug("peer_address_bucket: unknown address family");
	}
}


void fastd_peer_hashtable_init(void);
void fastd_peer_hashtable_free(void);

void fastd_peer_hashtable_insert(fastd_peer_t *peer);
void fastd_peer_hashtable_remove(fastd_peer_t *peer);
fastd_peer_t *fastd_peer_hashtable_lookup(const fastd_peer_address_t *addr);
