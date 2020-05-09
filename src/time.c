// SPDX-License-Identifier: BSD-2-Clause
/*
  Copyright (c) 2012-2016, Matthias Schiffer <mschiffer@universe-factory.net>
  All rights reserved.
*/

/**
   \file

   Abstractions for monotonic timestamps
*/


#include "fastd.h"

#include <time.h>


#ifdef __APPLE__

#include <mach/mach_time.h>

/** Returns a monotonic timestamp in milliseconds */
int64_t fastd_get_time(void) {
	static mach_timebase_info_data_t timebase_info = {};

	if (!timebase_info.denom)
		mach_timebase_info(&timebase_info);

	int64_t nsecs = (((long double)mach_absolute_time()) * timebase_info.numer) / timebase_info.denom;
	return nsecs / 1000000;
}

#else

/** Returns a monotonic timestamp in milliseconds */
int64_t fastd_get_time(void) {
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);

	return (1000 * (int64_t)ts.tv_sec) + ts.tv_nsec / 1000000;
}

#endif
