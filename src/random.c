// SPDX-License-Identifier: BSD-2-Clause
/*
  Copyright (c) 2012-2016, Matthias Schiffer <mschiffer@universe-factory.net>
  All rights reserved.
*/

/**
   \file

   Utilities for random data
*/


#include "fastd.h"

#include <sys/stat.h>


/**
   Provides a given amount of cryptographic random data
*/
void fastd_random_bytes(void *buffer, size_t len, bool secure) {
	int fd;
	size_t read_bytes = 0;

	if (secure)
		fd = open("/dev/random", O_RDONLY);
	else
		fd = open("/dev/urandom", O_RDONLY);

	if (fd < 0)
		exit_errno("unable to open random device");

	while (read_bytes < len) {
		ssize_t ret = read(fd, ((char *)buffer) + read_bytes, len - read_bytes);

		if (ret < 0)
			exit_errno("unable to read from random device");

		read_bytes += ret;
	}

	close(fd);
}
