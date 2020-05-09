// SPDX-License-Identifier: BSD-2-Clause
/*
  Copyright (c) 2012-2016, Matthias Schiffer <mschiffer@universe-factory.net>
  All rights reserved.
*/

/**
   \file

   The Salsa20 stream cipher
*/


#include "../../../crypto.h"


/** Cipher info about Salsa20 */
const fastd_cipher_info_t fastd_cipher_info_salsa20 = {
	.key_length = 32,
	.iv_length = 8,
};
