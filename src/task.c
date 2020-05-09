// SPDX-License-Identifier: BSD-2-Clause
/*
  Copyright (c) 2012-2016, Matthias Schiffer <mschiffer@universe-factory.net>
  All rights reserved.
*/

/**
   \file

   Task queue
*/

#include "task.h"
#include "peer.h"


/** Performs periodic maintenance tasks */
static inline void maintenance(void) {
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
		return FASTD_TIMEOUT_INV;

	return ctx.task_queue->value;
}
