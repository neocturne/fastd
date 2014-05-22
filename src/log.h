/*
  Copyright (c) 2012-2014, Matthias Schiffer <mschiffer@universe-factory.net>
  All rights reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions are met:

    1. Redistributions of source code must retain the above copyright notice,
       this list of conditions and the following disclaimer.
    2. Redistributions in binary form must reproduce the above copyright notice,
       this list of conditions and the following disclaimer in the documentation
       and/or other materials provided with the distribution.

  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
  DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
  FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
  CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
  OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/


#pragma once

#include "types.h"

#include <stdlib.h>
#include <string.h>


typedef enum fastd_loglevel {
	LL_UNSPEC = 0,
	LL_FATAL,
	LL_ERROR,
	LL_WARN,
	LL_INFO,
	LL_VERBOSE,
	LL_DEBUG,
	LL_DEBUG2,
	LL_DEFAULT = LL_VERBOSE,
} fastd_loglevel_t;


void fastd_logf(const fastd_loglevel_t level, const char *format, ...);

#define pr_fatal(args...) fastd_logf(LL_FATAL, args)
#define pr_error(args...) fastd_logf(LL_ERROR, args)
#define pr_warn(args...) fastd_logf(LL_WARN, args)
#define pr_info(args...) fastd_logf(LL_INFO, args)
#define pr_verbose(args...) fastd_logf(LL_VERBOSE, args)
#define pr_debug(args...) fastd_logf(LL_DEBUG, args)
#define pr_debug2(args...) fastd_logf(LL_DEBUG2, args)

#define pr_error_errno(message) pr_error("%s: %s", message, strerror(errno))
#define pr_warn_errno(message) pr_warn("%s: %s", message, strerror(errno))
#define pr_debug_errno(message) pr_debug("%s: %s", message, strerror(errno))
#define pr_debug2_errno(message) pr_debug2("%s: %s", message, strerror(errno))

#define exit_fatal(args...) do { pr_fatal(args); abort(); } while(0)
#define exit_bug(message) exit_fatal("BUG: %s", message)
#define exit_error(args...) do { pr_error(args); exit(1); } while(0)
#define exit_errno(message) exit_error("%s: %s", message, strerror(errno))
