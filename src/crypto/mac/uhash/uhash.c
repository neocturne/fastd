// SPDX-License-Identifier: BSD-2-Clause
/*
  Copyright (c) Matthias Schiffer <mschiffer@universe-factory.net>
  All rights reserved.
*/

/**
   \file

   General information about the UHASH algorithm

   \sa http://en.wikipedia.org/wiki/UMAC
   \sa https://tools.ietf.org/html/rfc4418
*/

#include "../../../crypto.h"


/** MAC info about the UHASH algorithm */
const fastd_mac_info_t fastd_mac_info_uhash = {
	.key_length = 1024 + 3 * 16 + 4 * 24 + 4 * 64 + 4 * 4, /* we use 4 iterations */
};
