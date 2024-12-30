// SPDX-License-Identifier: BSD-2-Clause
/*
  Copyright (c) Matthias Schiffer <mschiffer@universe-factory.net>
  All rights reserved.
*/

/**
   \file

   The Salsa20/12 stream cipher, a reduced-round version of Salsa20
*/


#include "../../../crypto.h"


/** Cipher info about Salsa20/12 */
const fastd_cipher_info_t fastd_cipher_info_salsa2012 = {
	.key_length = 32,
	.iv_length = 8,
};
