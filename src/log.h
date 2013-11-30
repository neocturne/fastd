/*
  Copyright (c) 2012-2013, Matthias Schiffer <mschiffer@universe-factory.net>
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


#ifndef _FASTD_LOG_H_
#define _FASTD_LOG_H_

#include "types.h"

#include <stdlib.h>
#include <string.h>


#define FASTD_DEFAULT_LOG_LEVEL LL_VERBOSE


void fastd_logf(const fastd_context_t *ctx, fastd_loglevel_t level, const char *format, ...);

#define pr_fatal(ctx, args...) fastd_logf(ctx, LL_FATAL, args)
#define pr_error(ctx, args...) fastd_logf(ctx, LL_ERROR, args)
#define pr_warn(ctx, args...) fastd_logf(ctx, LL_WARN, args)
#define pr_info(ctx, args...) fastd_logf(ctx, LL_INFO, args)
#define pr_verbose(ctx, args...) fastd_logf(ctx, LL_VERBOSE, args)
#define pr_debug(ctx, args...) fastd_logf(ctx, LL_DEBUG, args)
#define pr_debug2(ctx, args...) fastd_logf(ctx, LL_DEBUG2, args)

#define pr_error_errno(ctx, message) pr_error(ctx, "%s: %s", message, strerror(errno))
#define pr_warn_errno(ctx, message) pr_warn(ctx, "%s: %s", message, strerror(errno))
#define pr_debug_errno(ctx, message) pr_debug(ctx, "%s: %s", message, strerror(errno))
#define pr_debug2_errno(ctx, message) pr_debug2(ctx, "%s: %s", message, strerror(errno))

#define exit_fatal(ctx, args...) do { pr_fatal(ctx, args); abort(); } while(0)
#define exit_bug(ctx, message) exit_fatal(ctx, "BUG: %s", message)
#define exit_error(ctx, args...) do { pr_error(ctx, args); exit(1); } while(0)
#define exit_errno(ctx, message) exit_error(ctx, "%s: %s", message, strerror(errno))

#endif /* _FASTD_LOG_H_ */

