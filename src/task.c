/*
  Copyright (c) 2012-2015, Matthias Schiffer <mschiffer@universe-factory.net>
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

/**
   \file

   Task queue
*/

#include "task.h"
#include "peer.h"


/** Performs periodic maintenance tasks */
static inline void maintenance(void) {
	fastd_socket_handle_binds();
	fastd_peer_eth_addr_cleanup();

	fastd_task_reschedule_relative(&ctx.next_maintenance, MAINTENANCE_INTERVAL);
}

/** Handles one task */
static void handle_task(void) {
	fastd_task_t *task = container_of(ctx.task_queue, fastd_task_t, entry);
	fastd_pqueue_remove(ctx.task_queue);

	switch (task->type) {
	case TASK_TYPE_MAINTENANCE:
		maintenance();
		break;

	case TASK_TYPE_PEER:
		fastd_peer_handle_task(task);
		break;

	default:
		exit_bug("unknown task type");
	}
}

/** Handles all tasks whose timeout has been reached */
void fastd_task_handle(void) {
	while (ctx.task_queue && fastd_timed_out(ctx.task_queue->value))
		handle_task();
}

/** Puts a task back into the queue with a new timeout */
void fastd_task_reschedule(fastd_task_t *task, fastd_timeout_t timeout) {
	task->entry.value = timeout;
	fastd_pqueue_insert(&ctx.task_queue, &task->entry);
}

/** Gets the timeout of the next task in the task queue */
fastd_timeout_t fastd_task_queue_timeout(void) {
	if (!ctx.task_queue)
		return fastd_timeout_inv;

	return ctx.task_queue->value;
}
