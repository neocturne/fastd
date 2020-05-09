// SPDX-License-Identifier: BSD-2-Clause
/*
  Copyright (c) 2012-2016, Matthias Schiffer <mschiffer@universe-factory.net>
  All rights reserved.
*/

/**
   \file

   Task queue
*/

#pragma once

#include "pqueue.h"


/** A scheduled task */
struct fastd_task {
	fastd_pqueue_t entry;   /**< Task queue entry */
	fastd_task_type_t type; /**< Type of the task */
};


void fastd_task_handle(void);

void fastd_task_reschedule(fastd_task_t *task, fastd_timeout_t timeout);
fastd_timeout_t fastd_task_queue_timeout(void);


/** Checks if the given task is currently scheduled */
static inline bool fastd_task_scheduled(fastd_task_t *task) {
	return fastd_pqueue_linked(&task->entry);
}

/** Gets the timeout of a task */
static inline fastd_timeout_t fastd_task_timeout(fastd_task_t *task) {
	if (!fastd_task_scheduled(task))
		return FASTD_TIMEOUT_INV;

	return task->entry.value;
}

/** Removes a task from the queue */
static inline void fastd_task_unschedule(fastd_task_t *task) {
	fastd_pqueue_remove(&task->entry);
}

/** Puts a task back into the queue with a new timeout relative to the old one */
static inline void fastd_task_reschedule_relative(fastd_task_t *task, int64_t delay) {
	fastd_task_reschedule(task, task->entry.value + delay);
}

/** Schedules a task with given type and timeout */
static inline void fastd_task_schedule(fastd_task_t *task, fastd_task_type_t type, fastd_timeout_t timeout) {
	task->type = type;
	fastd_task_reschedule(task, timeout);
}
