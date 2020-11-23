// SPDX-License-Identifier: BSD-2-Clause
/*
  Copyright (c) 2012-2020, Matthias Schiffer <mschiffer@universe-factory.net>
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
	fastd_peer_t * const peer, fastd_socket_t * const sock, const fastd_peer_address_t * constlocal_addr,
	const fastd_peer_address_t * const remote_addr, const void *data, const size_t data_len);

#endif /* WITH_DYNAMIC_PEERS */
