// SPDX-License-Identifier: BSD-2-Clause
/*
  Copyright (c) 2012-2020, Matthias Schiffer <mschiffer@universe-factory.net>
  All rights reserved.
*/

/**
   \file

   Config scanner for the fastd configuration file format
*/


#pragma once

#include "config.yy.h"
#include "types.h"

#include <stdio.h>


fastd_lex_t *fastd_lex_init(FILE *file);
void fastd_lex_destroy(fastd_lex_t *lex);

int fastd_lex(FASTD_CONFIG_STYPE *yylval, FASTD_CONFIG_LTYPE *yylloc, fastd_lex_t *lex);
