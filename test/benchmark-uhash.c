// SPDX-License-Identifier: BSD-2-Clause
/*
  Copyright (c) 2012-2020, Matthias Schiffer <mschiffer@universe-factory.net>
  All rights reserved.
*/


#include "uhash-common.h"
#include "alloc.h"
#include "log.h"

#include <inttypes.h>
#include <stdio.h>


static int64_t get_time(void) {
	struct timespec ts;
	clock_gettime(CLOCK_THREAD_CPUTIME_ID, &ts);

	return (1000*(int64_t)ts.tv_sec) + ts.tv_nsec/1000000;
}

static void run_benchmark(fastd_mac_state_t *mac_state, size_t iters, size_t size) {
	printf("Running %zd iterations with input size %zd... ", iters, size);

	size_t allocsize = alignto(size, 16);
	fastd_block128_t *inblocks = fastd_alloc_aligned(allocsize, 16);
	memset(inblocks, 0, allocsize);

	fastd_block128_t tag;

	int64_t start = get_time();
	for (size_t i = 0; i < iters; i++) {
		bool ok = fastd_mac_uhash_builtin.digest(mac_state, &tag, inblocks, size);
		if (!ok)
			exit_bug("uhash failed");
	}

	int64_t end = get_time();

	printf("done in %"PRId64" ms\n", end - start);
}


int main(void) {
	if (&fastd_mac_uhash_builtin == NULL) {
		return 77;
	}

	fastd_mac_state_t *mac_state = fastd_mac_uhash_builtin.init(key);

	run_benchmark(mac_state, 100000000, 20);
	run_benchmark(mac_state, 100000000, 100);
	run_benchmark(mac_state, 50000000, 300);
	run_benchmark(mac_state, 20000000, 1000);
	run_benchmark(mac_state, 10000000, 1500);
	run_benchmark(mac_state, 5000000, 2000);
	run_benchmark(mac_state, 5000000, 5000);
	run_benchmark(mac_state, 2000000, 10000);

	fastd_mac_uhash_builtin.free(mac_state);

	return 0;
}
