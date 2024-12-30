// SPDX-License-Identifier: BSD-2-Clause
/*
  Copyright (c) Matthias Schiffer <mschiffer@universe-factory.net>
  All rights reserved.
*/

/**
   \file

   Flag definitions for GHASH MAC algorithm
*/


#pragma once


/**
   Store size in upper instead of lower 8 bytes of the final block

   Used by the composed-gmac method (because of a bad design decision)
*/
#define GHASH_SHIFT_SIZE (1U << 0)

#define GHASH_MASK 0x1
