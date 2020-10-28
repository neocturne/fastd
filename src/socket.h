/*
  Copyright (c) 2020, Heiko Wundram <heiko.wundram@gehrkens.it>.
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

   \em Socket configuration.
 */


#pragma once


#include "task.h"

#include <netinet/in.h>


/** An union storing an IPv4 or IPv6 address */
union fastd_peer_address {
	struct sockaddr sa;			/**< A sockaddr field (for access to sa_family) */
	struct sockaddr_in in;			/**< An IPv4 address */
	struct sockaddr_in6 in6;		/**< An IPv6 address */
};

/** A socket descriptor */
struct fastd_socket {
	fastd_poll_fd_t fd;			/**< The file descriptor for the socket */
	const fastd_bind_address_t *addr;	/**< The address this socket is supposed to be bound to (or NULL) */
	fastd_peer_address_t bound_addr;	/**< The actual address that was bound to (may differ from addr when addr has a random port) */
	fastd_peer_t *peer;			/**< If the socket belongs to a single peer (as it was create dynamically when sending a handshake), contains that peer */
	fastd_task_t task;			/**< Socket task for managing discovery packets (multicast bind) */
	fastd_timeout_t discovery_timeout;	/**< Timeout of next discovery packet */
};


/** Checks if a fastd_peer_address_t is the IPv4 any address */
static inline bool fastd_peer_address_host_v4_any(const fastd_peer_address_t *addr) {
	return addr->sa.sa_family == AF_INET && addr->in.sin_addr.s_addr == INADDR_ANY;
}

/** Checks if a fastd_peer_address_t is an IPv4 unicast address */
static inline bool fastd_peer_address_host_v4_unicast(const fastd_peer_address_t *addr) {
	return addr->sa.sa_family == AF_INET && !IN_MULTICAST(ntohl(addr->in.sin_addr.s_addr));
}

/** Checks if a fastd_peer_address_t is an IPv4 multicast address */
static inline bool fastd_peer_address_host_v4_multicast(const fastd_peer_address_t *addr) {
	return addr->sa.sa_family == AF_INET && IN_MULTICAST(ntohl(addr->in.sin_addr.s_addr));
}

/** Checks if fastd_peer_address_t instances are equal */
static inline bool fastd_peer_address_host_v4_equal(const fastd_peer_address_t *addr1, const fastd_peer_address_t *addr2) {
	return addr1->sa.sa_family == AF_INET && addr2->sa.sa_family == AF_INET && addr1->in.sin_addr.s_addr == addr2->in.sin_addr.s_addr;
}

/** Checks if a fastd_peer_address_t is an IPv6 link-local address */
static inline bool fastd_peer_address_host_v6_ll(const fastd_peer_address_t *addr) {
	return addr->sa.sa_family == AF_INET6 && IN6_IS_ADDR_LINKLOCAL(&addr->in6.sin6_addr);
}

/** Checks if a fastd_peer_address_t is the IPv6 any address */
static inline bool fastd_peer_address_host_v6_any(const fastd_peer_address_t *addr) {
	return addr->sa.sa_family == AF_INET6 && IN6_IS_ADDR_UNSPECIFIED(&addr->in6.sin6_addr);
}

/** Checks if a fastd_peer_address_t is an IPv6 unicast address */
static inline bool fastd_peer_address_host_v6_unicast(const fastd_peer_address_t *addr) {
	return addr->sa.sa_family == AF_INET6 && !IN6_IS_ADDR_MULTICAST(&addr->in6.sin6_addr);
}

/** Checks if a fastd_peer_address_t is an IPv6 multicast address */
static inline bool fastd_peer_address_host_v6_multicast(const fastd_peer_address_t *addr) {
	return addr->sa.sa_family == AF_INET6 && IN6_IS_ADDR_MULTICAST(&addr->in6.sin6_addr);
}

/** Checks if fastd_peer_address_t instances are equal */
static inline bool fastd_peer_address_host_v6_equal(const fastd_peer_address_t *addr1, const fastd_peer_address_t *addr2) {
	return addr1->sa.sa_family == AF_INET6 && addr2->sa.sa_family == AF_INET6 && IN6_ARE_ADDR_EQUAL(&addr1->in6.sin6_addr, &addr2->in6.sin6_addr);
}

/** Checks if a fastd_peer_address_t is the any address (IPv4 or v6) */
static inline bool fastd_peer_address_host_any(const fastd_peer_address_t *addr) {
	return fastd_peer_address_host_v4_any(addr) || fastd_peer_address_host_v6_multicast(addr);
}

/** Checks if a fastd_peer_address_t is a unicast address (IPv4 or v6) */
static inline bool fastd_peer_address_host_unicast(const fastd_peer_address_t *addr) {
	return fastd_peer_address_host_v4_unicast(addr) || fastd_peer_address_host_v6_unicast(addr);
}

/** Checks if a fastd_peer_address_t is a multicast address (IPv4 or v6) */
static inline bool fastd_peer_address_host_multicast(const fastd_peer_address_t *addr) {
	return fastd_peer_address_host_v4_multicast(addr) || fastd_peer_address_host_v6_multicast(addr);
}

/** Checks if fastd_peer_address_t instances are equal (IPv4 or v6) */
static inline bool fastd_peer_address_host_equal(const fastd_peer_address_t *addr1, const fastd_peer_address_t *addr2) {
	return fastd_peer_address_host_v4_equal(addr1, addr2) || fastd_peer_address_host_v6_equal(addr1, addr2);
}


void fastd_socket_handle_task(fastd_task_t *task);
