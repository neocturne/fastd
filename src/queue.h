/*
  Copyright (c) 2012, Matthias Schiffer <mschiffer@universe-factory.net>
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


#ifndef _FASTD_QUEUE_H_
#define _FASTD_QUEUE_H_

#include "types.h"

#include <stdbool.h>
#include <stdlib.h>
#include <time.h>


typedef struct fastd_queue_entry fastd_queue_entry_t;

struct fastd_queue_entry {
	fastd_queue_entry_t *next;
	struct timespec timeout;
};

typedef struct fastd_queue {
	fastd_queue_entry_t *head;
} fastd_queue_t;


void fastd_queue_put(fastd_context_t *ctx, fastd_queue_t *queue, fastd_queue_entry_t *entry, int timeout);
fastd_queue_entry_t* fastd_queue_get(fastd_context_t *ctx, fastd_queue_t *queue);
int fastd_queue_timeout(fastd_context_t *ctx, fastd_queue_t *queue);
void fastd_queue_filter(fastd_context_t *ctx, fastd_queue_t *queue, bool (*pred)(fastd_queue_entry_t*, void*), void *extra);
bool fastd_queue_has_entry(fastd_context_t *ctx, fastd_queue_t *queue, bool (*pred)(fastd_queue_entry_t*, void*), void *extra);

#endif /* _FASTD_QUEUE_T_H_ */
