// SPDX-License-Identifier: BSD-2-Clause
/*
  Copyright (c) Matthias Schiffer <mschiffer@universe-factory.net>
  All rights reserved.
*/

/**
   \file

   L2TP kernel offloading
*/

#pragma once

#include "../../fastd.h"
#include "../offload.h"


#ifdef WITH_OFFLOAD_L2TP

void fastd_offload_l2tp_init(void);
void fastd_offload_l2tp_cleanup(void);

const fastd_offload_t *fastd_offload_l2tp_get(void);

#else

static inline void fastd_offload_l2tp_init(void) {}
static inline void fastd_offload_l2tp_cleanup(void) {}

static inline const fastd_offload_t *fastd_offload_l2tp_get(void) {
	return NULL;
}

#endif
