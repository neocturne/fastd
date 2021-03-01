// SPDX-License-Identifier: BSD-2-Clause
/*
  Copyright (c) 2021, Matthias Schiffer <mschiffer@universe-factory.net>
  All rights reserved.
*/

/**
   \file

   Generic offloading support
*/

#pragma once

#include "../types.h"

/** Generic session offload provider */
struct fastd_offload {
	/** Initializes an offload session for the given peer */
	fastd_offload_state_t *(*init_session)(const fastd_peer_t *peer);
	/** Returns the name and MTU for an offload interface */
	void (*get_iface)(const fastd_offload_state_t *session, const char **ifname, uint16_t *mtu);
	/**
	 * Update a session after a new handshake (e.g. because of peer address change)
	 *
	 * May return false when update is not possible (e.g. bind address has changed),
	 * so a full teardown and new session initialization will be performed.
	 */
	bool (*update_session)(const fastd_peer_t *peer, fastd_offload_state_t *session);
	/** Closes an offload session */
	void (*free_session)(fastd_offload_state_t *session);
};
