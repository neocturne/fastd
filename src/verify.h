// SPDX-License-Identifier: BSD-2-Clause
/*
  Copyright (c) Matthias Schiffer <mschiffer@universe-factory.net>
  All rights reserved.
*/

/**
   \file

   Handling of on-verify commands to add peers not configured statically ("dynamic peers")
*/


#pragma once

#include "types.h"

#ifdef WITH_DYNAMIC_PEERS

fastd_tristate_t fastd_verify_peer(
	fastd_peer_t *peer, fastd_socket_t *sock, const fastd_peer_address_t *local_addr,
	const fastd_peer_address_t *remote_addr, const void *data, size_t data_len);

#endif /* WITH_DYNAMIC_PEERS */
