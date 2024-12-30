// SPDX-License-Identifier: BSD-2-Clause
/*
  Copyright (c) Matthias Schiffer <mschiffer@universe-factory.net>
  All rights reserved.
*/

/**
   \file

   ec25519-fhmqvc protocol: handshake handling
*/


#pragma once

#include "ec25519_fhmqvc.h"


/**
   An ephemeral keypair used for the handshake protocol

   When a keypair's \e preferred_till has timed out, a new keypair
   will be generated.
*/
typedef struct handshake_key {
	/**
	   With each keypair, the serial number gets incremented.
	   By saving the serial number for established sessions,
	   it can be ensured that no two sessions with the same peer are established
	   with the same keypair
	*/
	uint64_t serial;

	fastd_timeout_t preferred_till; /**< Specifies how long this keypair will be used for new handshakes */
	fastd_timeout_t valid_till;     /**< Specifies how long handshakes using this keypair will be answered */

	keypair_t key; /**< The actual keypair */
} handshake_key_t;

/**
   The protocol-specific global state

   There are up to two keys valid at the same time.
*/
struct fastd_protocol_state {
	handshake_key_t prev_handshake_key; /**< The previously generated handshake keypair */
	handshake_key_t handshake_key;      /**< The newest handshake keypair */
};


/** Checks if a handshake keypair is currently valid */
static inline bool is_handshake_key_valid(const handshake_key_t *handshake_key) {
	return !fastd_timed_out(handshake_key->valid_till);
}

/** Checks if a handshake keypair is currently peferred */
static inline bool is_handshake_key_preferred(const handshake_key_t *handshake_key) {
	return !fastd_timed_out(handshake_key->preferred_till);
}
