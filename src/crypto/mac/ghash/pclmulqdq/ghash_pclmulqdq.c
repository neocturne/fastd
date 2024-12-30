// SPDX-License-Identifier: BSD-2-Clause
/*
  Copyright (c) Matthias Schiffer <mschiffer@universe-factory.net>
  All rights reserved.
*/

/**
   \file

   PCLMULQDQ-based GHASH implementation for newer x86 systems
*/


#include "ghash_pclmulqdq.h"
#include "../../../../cpuid.h"


/** Checks if the runtime platform can support the PCLMULQDQ implementation */
static bool ghash_available(void) {
	static const uint64_t REQ = CPUID_FXSR | CPUID_SSSE3 | CPUID_PCLMULQDQ;

	return ((fastd_cpuid() & REQ) == REQ);
}

/** The pclmulqdq ghash implementation */
const fastd_mac_t fastd_mac_ghash_pclmulqdq = {
	.available = ghash_available,

	.init = fastd_ghash_pclmulqdq_init,
	.digest = fastd_ghash_pclmulqdq_digest,
	.free = fastd_ghash_pclmulqdq_free,
};
