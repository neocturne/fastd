// SPDX-License-Identifier: BSD-2-Clause
/*
  Copyright (c) 2020, Heiko Wundram <heiko.wundram@gehrkens.it>
  All rights reserved.
*/

/**
   \file

   Socket structures.
*/

#pragma once

#include "task.h"

#include <netinet/in.h>


/** An union storing an IPv4 or IPv6 address */
union fastd_peer_address {
	struct sockaddr sa;      /**< A sockaddr field (for access to sa_family) */
	struct sockaddr_in in;   /**< An IPv4 address */
	struct sockaddr_in6 in6; /**< An IPv6 address */
};

/** A socket descriptor */
struct fastd_socket {
	fastd_poll_fd_t fd;               /**< The file descriptor for the socket */
	const fastd_bind_address_t *addr; /**< The address this socket is supposed to be bound to (or NULL) */
	fastd_peer_address_t bound_addr;  /**< The actual address that was bound to (may differ from addr when addr has
	                                     a random port) and also the source address to require for incoming packets */
	fastd_peer_t *peer;               /**< If the socket belongs to a single peer (as it was create dynamically when sending a
	                                     handshake), contains that peer */
	fastd_task_t task;                /**< Task handle for the socket task which is added and dispatched on multicast
	                                     sockets which have a discovery interval */
};

/** Checks if a fastd_peer_address_t is the IPv4 any address */
static inline bool fastd_peer_address_is_v4_any(const fastd_peer_address_t *addr) {
	return addr->sa.sa_family == AF_INET && addr->in.sin_addr.s_addr == INADDR_ANY;
}

/** Checks if a fastd_peer_address_t is an IPv4 multicast address */
static inline bool fastd_peer_address_is_v4_multicast(const fastd_peer_address_t *addr) {
	return addr->sa.sa_family == AF_INET && IN_MULTICAST(ntohl(addr->in.sin_addr.s_addr));
}

/** Checks if host parts of two IPv4 fastd_peer_address_t are equal */
static inline bool fastd_peer_address_is_v4_host_equal(const fastd_peer_address_t *addr1, const fastd_peer_address_t *addr2) {
	return addr1->sa.sa_family == AF_INET && addr2->sa.sa_family == AF_INET && addr1->in.sin_addr.s_addr == addr2->in.sin_addr.s_addr;
}

/** Checks if a fastd_peer_address_t is the IPv6 any address */
static inline bool fastd_peer_address_is_v6_any(const fastd_peer_address_t *addr) {
	return addr->sa.sa_family == AF_INET6 && IN6_IS_ADDR_UNSPECIFIED(&addr->in6.sin6_addr);
}

/** Checks if a fastd_peer_address_t is an IPv6 link-local address */
static inline bool fastd_peer_address_is_v6_ll(const fastd_peer_address_t *addr) {
	return addr->sa.sa_family == AF_INET6 && IN6_IS_ADDR_LINKLOCAL(&addr->in6.sin6_addr);
}

/** Checks if a fastd_peer_address_t is an IPv6 multicast address */
static inline bool fastd_peer_address_is_v6_multicast(const fastd_peer_address_t *addr) {
	return addr->sa.sa_family == AF_INET6 && IN6_IS_ADDR_MULTICAST(&addr->in6.sin6_addr);
}

/** Checks if host parts of two IPv6 fastd_peer_address_t are equal */
static inline bool fastd_peer_address_is_v6_host_equal(const fastd_peer_address_t *addr1, const fastd_peer_address_t *addr2) {
	return addr1->sa.sa_family == AF_INET6 && addr2->sa.sa_family == AF_INET6 && IN6_ARE_ADDR_EQUAL(&addr1->in6.sin6_addr, &addr2->in6.sin6_addr);
}

/** Checks if the fastd_peer_address_t represents the IPv4 or IPv6 any address */
static inline bool fastd_peer_address_is_any(const fastd_peer_address_t *addr) {
	return fastd_peer_address_is_v4_any(addr) || fastd_peer_address_is_v6_any(addr);
}

/** Checks if the fastd_peer_address_t represents an IPv4 or IPv6 multicast address */
static inline bool fastd_peer_address_is_multicast(const fastd_peer_address_t *addr) {
	return fastd_peer_address_is_v4_multicast(addr) || fastd_peer_address_is_v6_multicast(addr);
}

/** Checks if host parts of two fastd_peer_address_t are equal */
static inline bool fastd_peer_address_is_host_equal(const fastd_peer_address_t *addr1, const fastd_peer_address_t *addr2) {
	return fastd_peer_address_is_v4_host_equal(addr1, addr2) || fastd_peer_address_is_v6_host_equal(addr1, addr2);
}


void fastd_socket_handle_task(fastd_task_t *task);
