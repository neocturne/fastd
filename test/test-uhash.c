// SPDX-License-Identifier: BSD-2-Clause
/*
  Copyright (c) 2012-2020, Matthias Schiffer <mschiffer@universe-factory.net>
  All rights reserved.
*/


#include "alloc.h"
#include "uhash-common.h"

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>

#include <cmocka.h>

static int setup(void **state) {
	fastd_mac_state_t *mac_state = fastd_mac_uhash_builtin.init(key, 0);
	*state = mac_state;
	return 0;
}

static int teardown(void **state) {
	fastd_mac_state_t *mac_state = *state;
	fastd_mac_uhash_builtin.free(mac_state);
	return 0;
}


static void test_uhash(void **state, const uint8_t expected[16], const uint8_t *in, size_t len) {
	fastd_mac_state_t *mac_state = *state;
	size_t inblocklen = alignto(len, 16);
	fastd_block128_t tag;

	fastd_block128_t *inblock = fastd_alloc_aligned(inblocklen, 16);

	memset(inblock, 0, inblocklen);
	memcpy(inblock, in, len);

	bool ok = fastd_mac_uhash_builtin.digest(mac_state, &tag, inblock, len);
	assert_true(ok);

	block_xor_a(&tag, &pad);
	assert_memory_equal(expected, tag.b, 16);

	free(inblock);
}


static void test_uhash1(void **state) {
	const uint8_t expected[16] = {
		0x32, 0xfe, 0xdb, 0x10, 0x0c, 0x79, 0xad, 0x58, 0xf0, 0x7f, 0xf7, 0x64, 0x3c, 0xc6, 0x04, 0x65,
	};
	const uint8_t in[] = {};

	test_uhash(state, expected, in, array_size(in));
}

static void test_uhash2(void **state) {
	const uint8_t expected[16] = {
		0x18, 0x5e, 0x4f, 0xe9, 0x05, 0xcb, 0xa7, 0xbd, 0x85, 0xe4, 0xc2, 0xdc, 0x3d, 0x11, 0x7d, 0x8d,
	};
	const uint8_t in[] = { 'a', 'a', 'a' };

	test_uhash(state, expected, in, array_size(in));
}

static void test_uhash3(void **state) {
	const uint8_t expected[16] = {
		0x7a, 0x54, 0xab, 0xe0, 0x4a, 0xf8, 0x2d, 0x60, 0xfb, 0x29, 0x8c, 0x3c, 0xbd, 0x19, 0x5b, 0xcb,
	};
	size_t len = 1 << 10;
	uint8_t *in = malloc(len);
	memset(in, 'a', len);
	test_uhash(state, expected, in, len);
	free(in);
}

static void test_uhash4(void **state) {
	const uint8_t expected[16] = {
		0x7b, 0x13, 0x6b, 0xd9, 0x11, 0xe4, 0xb7, 0x34, 0x28, 0x6e, 0xf2, 0xbe, 0x50, 0x1f, 0x2c, 0x3c,
	};
	size_t len = 1 << 15;
	uint8_t *in = malloc(len);
	memset(in, 'a', len);
	test_uhash(state, expected, in, len);
	free(in);
}

static void test_uhash5(void **state) {
	const uint8_t expected[16] = {
		0xf8, 0xac, 0xfa, 0x3a, 0xc3, 0x1c, 0xfe, 0xea, 0x04, 0x7f, 0x7b, 0x11, 0x5b, 0x03, 0xbe, 0xf5,
	};
	size_t len = 1 << 20;
	uint8_t *in = malloc(len);
	memset(in, 'a', len);
	test_uhash(state, expected, in, len);
	free(in);
}

int main(void) {
	if (&fastd_mac_uhash_builtin == NULL) {
		printf("1..0 # Skipped: uhash not included\n");
		return 0;
	}

	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_uhash1), cmocka_unit_test(test_uhash2), cmocka_unit_test(test_uhash3),
		cmocka_unit_test(test_uhash4), cmocka_unit_test(test_uhash5),
	};
	return cmocka_run_group_tests(tests, setup, teardown);
}
