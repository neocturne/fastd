// SPDX-License-Identifier: BSD-2-Clause
/*
  Copyright (c) 2012-2016, Matthias Schiffer <mschiffer@universe-factory.net>
  All rights reserved.
*/

/**
   \file

   An implementation of the Jenkins hash function

   \sa https://en.wikipedia.org/wiki/Jenkins_hash_function
*/


#pragma once


#include <stddef.h>
#include <stdint.h>


/** Adds data bytes to the 32bit hash value */
static inline void fastd_hash(uint32_t *hash, const void *data, size_t len) {
	size_t i;
	for (i = 0; i < len; ++i) {
		*hash += ((uint8_t *)data)[i];
		*hash += (*hash << 10);
		*hash ^= (*hash >> 6);
	}
}

/** Finalizes a hash value */
static inline void fastd_hash_final(uint32_t *hash) {
	*hash += (*hash << 3);
	*hash ^= (*hash >> 11);
	*hash += (*hash << 15);
}
