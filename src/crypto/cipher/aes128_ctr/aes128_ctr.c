// SPDX-License-Identifier: BSD-2-Clause
/*
  Copyright (c) 2012-2016, Matthias Schiffer <mschiffer@universe-factory.net>
  All rights reserved.
*/

/**
   \file

   The aes128-ctr stream cipher
*/


#include "../../../crypto.h"


/** cipher info about aes128-ctr */
const fastd_cipher_info_t fastd_cipher_info_aes128_ctr = {
	.key_length = 16,
	.iv_length = 16,
};
