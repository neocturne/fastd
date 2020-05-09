// SPDX-License-Identifier: BSD-2-Clause
/*
  Copyright (c) 2012-2016, Matthias Schiffer <mschiffer@universe-factory.net>
  All rights reserved.
*/

/**
   \file

   PCLMULQDQ-based GHASH implementation for newer x86 systems
*/


#pragma once

#include "../../../../crypto.h"


fastd_mac_state_t *fastd_ghash_pclmulqdq_init(const uint8_t *key);
bool fastd_ghash_pclmulqdq_digest(
	const fastd_mac_state_t *state, fastd_block128_t *out, const fastd_block128_t *in, size_t length);
void fastd_ghash_pclmulqdq_free(fastd_mac_state_t *state);
