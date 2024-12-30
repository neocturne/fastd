// SPDX-License-Identifier: BSD-2-Clause
/*
  Copyright (c) Matthias Schiffer <mschiffer@universe-factory.net>
  All rights reserved.
*/

/**
   \file

   The actual main function
*/


#include "fastd.h"


int main(int argc, char *argv[]) {
	fastd_main(argc, argv);

	/* Should not be reached */
	return -1;
}
