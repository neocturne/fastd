// SPDX-License-Identifier: BSD-2-Clause
/*
  Copyright (c) Matthias Schiffer <mschiffer@universe-factory.net>
  All rights reserved.
*/

/**
   \file

   Utilities for random data
*/


#include "fastd.h"

#include <sys/stat.h>


/**
   Opens urandom
*/
void fastd_random_init(void) {
	ctx.urandom = fopen("/dev/urandom", "rb");
	if (!ctx.urandom)
		exit_errno("unable to open /dev/urandom");
}

/**
   Closes urandom
*/
void fastd_random_cleanup(void) {
	fclose(ctx.urandom);
}


/**
   Provides a given amount of cryptographic random data
*/
void fastd_random_bytes(void *buffer, size_t len, bool secure) {
	FILE *f;

	if (secure) {
		f = fopen("/dev/random", "rb");
		if (!f)
			exit_errno("unable to open /dev/random");
	} else {
		f = ctx.urandom;
	}

	if (fread(buffer, len, 1, f) != 1)
		exit_errno("unable to read from random device");

	if (secure)
		fclose(f);
}
