// SPDX-License-Identifier: BSD-2-Clause
/*
  Copyright (c) 2012-2016, Matthias Schiffer <mschiffer@universe-factory.net>
  All rights reserved.
*/

/**
   \file

   Config scanner for the fastd configuration file format
*/


#pragma once

#include "types.h"
#include <generated/config.yy.h>

#include <stdio.h>


fastd_lex_t *fastd_lex_init(FILE *file);
void fastd_lex_destroy(fastd_lex_t *lex);

int fastd_lex(YYSTYPE *yylval, YYLTYPE *yylloc, fastd_lex_t *lex);
