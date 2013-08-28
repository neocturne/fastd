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


#ifndef _FASTD_TASK_H_
#define _FASTD_TASK_H_

#include "fastd.h"
#include "packet.h"

#include <sys/uio.h>


typedef enum fastd_task_type {
	TASK_HANDSHAKE,
	TASK_KEEPALIVE,
} fastd_task_type_t;

typedef struct fastd_task {
	fastd_queue_entry_t entry;

	fastd_task_type_t type;
	fastd_peer_t *peer;
} fastd_task_t;


static inline int fastd_task_timeout(fastd_context_t *ctx) {
	return fastd_queue_timeout(ctx, &ctx->task_queue);
}


fastd_task_t* fastd_task_get(fastd_context_t *ctx);

void fastd_task_schedule_handshake(fastd_context_t *ctx, fastd_peer_t *peer, int timeout);
void fastd_task_schedule_keepalive(fastd_context_t *ctx, fastd_peer_t *peer, int timeout);

void fastd_task_delete_peer(fastd_context_t *ctx, fastd_peer_t *peer);
void fastd_task_delete_peer_handshakes(fastd_context_t *ctx, fastd_peer_t *peer);
void fastd_task_delete_peer_keepalives(fastd_context_t *ctx, fastd_peer_t *peer);

#endif /* _FASTD_TASK_H_ */
