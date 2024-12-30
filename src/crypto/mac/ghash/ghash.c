// SPDX-License-Identifier: BSD-2-Clause
/*
  Copyright (c) Matthias Schiffer <mschiffer@universe-factory.net>
  All rights reserved.
*/

/**
   \file

   General information about the GHASH algorithm

   \sa http://en.wikipedia.org/wiki/Galois/Counter_Mode
*/

#include "../../../crypto.h"


/** MAC info about the GHASH algorithm */
const fastd_mac_info_t fastd_mac_info_ghash = {
	.key_length = 16,
};
