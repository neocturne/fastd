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


#include "queue.h"
#include "fastd.h"

#include <stdint.h>


void fastd_queue_put(fastd_context_t *ctx, fastd_queue_t *queue, fastd_queue_entry_t *entry, int timeout) {
	entry->timeout = ctx->now;

	if (timeout) {
		entry->timeout.tv_sec += timeout/1000;
		entry->timeout.tv_nsec += (timeout%1000)*1e6;

		if (entry->timeout.tv_nsec > 1e9) {
			entry->timeout.tv_sec++;
			entry->timeout.tv_nsec -= 1e9;
		}
	}

	fastd_queue_entry_t **current;
	for (current = &queue->head;; current = &(*current)->next) {
		if (!(*current) || timespec_after(&(*current)->timeout, &entry->timeout)) {
			entry->next = *current;
			*current = entry;
			break;
		}
	}
}

fastd_queue_entry_t* fastd_queue_get(fastd_context_t *ctx, fastd_queue_t *queue) {
	if (!queue->head || fastd_queue_timeout(ctx, queue) > 0)
		return NULL;

	fastd_queue_entry_t *entry = queue->head;
	queue->head = entry->next;

	return entry;
}

int fastd_queue_timeout(fastd_context_t *ctx, fastd_queue_t *queue) {
	if (!queue->head)
		return -1;

	int diff_msec = timespec_diff(&queue->head->timeout, &ctx->now);
	if (diff_msec < 0)
		return 0;
	else
		return diff_msec;
}

void fastd_queue_filter(fastd_context_t *ctx, fastd_queue_t *queue, bool (*pred)(fastd_queue_entry_t*, void*), void *extra) {
	fastd_queue_entry_t **entry, *next;
	for (entry = &queue->head; *entry;) {
		next = (*entry)->next;

		if (!pred(*entry, extra))
			*entry = next;
		else
			entry = &(*entry)->next;
	}
}

bool fastd_queue_has_entry(fastd_context_t *ctx, fastd_queue_t *queue, bool (*pred)(fastd_queue_entry_t*, void*), void *extra) {
	fastd_queue_entry_t *entry;
	for (entry = queue->head; entry; entry = entry->next) {
		if (pred(entry, extra))
			return true;
	}

	return false;
}
