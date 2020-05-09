// SPDX-License-Identifier: BSD-2-Clause
/*
  Copyright (c) 2012-2016, Matthias Schiffer <mschiffer@universe-factory.net>
  All rights reserved.
*/

/**
   \file

   The null cipher not performing any encryption
*/


#include "../../../crypto.h"


/** cipher info about the null cipher */
const fastd_cipher_info_t fastd_cipher_info_null = {
	.key_length = 0,
	.iv_length = 0,
};
