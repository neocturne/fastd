/*
  Copyright (c) 2012-2016, Matthias Schiffer <mschiffer@universe-factory.net>
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

#pragma once

#include "pqueue.h"


/** A scheduled task */
struct fastd_task {
	fastd_pqueue_t entry;	/**< Task queue entry */
	fastd_task_type_t type;	/**< Type of the task */
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
