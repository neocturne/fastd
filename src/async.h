// SPDX-License-Identifier: BSD-2-Clause
/*
  Copyright (c) Matthias Schiffer <mschiffer@universe-factory.net>
  All rights reserved.
*/

/**
   \file

   Asynchronous notifications
*/


#pragma once

#include "peer.h"
#include "types.h"


/** A type of asynchronous notification */
typedef enum fastd_async_type {
	ASYNC_TYPE_NOP, /**< Does nothing (is used to ensure poll returns quickly after a signal has occurred) */
	ASYNC_TYPE_RESOLVE_RETURN, /**< A DNS resolver response */
	ASYNC_TYPE_VERIFY_RETURN,  /**< A on-verify return */
} fastd_async_type_t;


/** A DNS resolver response */
typedef struct fastd_async_resolve_return {
	uint64_t peer_id; /**< The ID of the peer the resolved remote belongs to */
	size_t remote;    /**< The index of the resolved remote */

	size_t n_addr;               /**< The number of addresses returned */
	fastd_peer_address_t addr[]; /**< The resolved addresses */
} fastd_async_resolve_return_t;

/** A on-verify response */
typedef struct fastd_async_verify_return {
	bool ok; /**< true if the verification was successful */

	uint64_t peer_id; /**< The ID of the verified peer */

	fastd_socket_t *sock; /**< The socket the handshake causing the verification was received on */

	fastd_peer_address_t local_addr;  /**< The local address the handshake was received on */
	fastd_peer_address_t remote_addr; /**< The address the handshake was received from */

	uint8_t protocol_data[] __attribute__((aligned(8))); /**< Protocol-specific data */
} fastd_async_verify_return_t;


void fastd_async_init(void);
void fastd_async_handle(void);
void fastd_async_enqueue(fastd_async_type_t type, const void *data, size_t len);
