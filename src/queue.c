/*
  Copyright (c) 2012, Matthias Schiffer <mschiffer@universe-factory.net>
  Partly based on QuickTun Copyright (c) 2010, Ivo Smits <Ivo@UCIS.nl>.
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

#include <stdint.h>


static inline int after(const struct timespec *tp1, const struct timespec *tp2) {
	return (tp1->tv_sec > tp2->tv_sec ||
		(tp1->tv_sec == tp2->tv_sec && tp1->tv_nsec > tp2->tv_nsec));
}

void fastd_queue_put(fastd_queue *queue, void *data, int timeout) {
	fastd_queue_entry *entry = malloc(sizeof(fastd_queue_entry));
	entry->data = data;
	entry->timeout = (struct timespec){ 0, 0 };

	if (timeout) {
		clock_gettime(CLOCK_MONOTONIC, &entry->timeout);

		entry->timeout.tv_sec += timeout/1000;
		entry->timeout.tv_nsec += (timeout%1000)*1e6;

		if (entry->timeout.tv_nsec > 1e9) {
			entry->timeout.tv_sec++;
			entry->timeout.tv_nsec -= 1e9;
		}
	}

	fastd_queue_entry **current;
	for (current = &queue->head;; current = &(*current)->next) {
		if (!(*current) || after(&(*current)->timeout, &entry->timeout)) {
			entry->next = *current;
			*current = entry;
			break;
		}
	}
}

void* fastd_queue_get(fastd_queue *queue) {
	if (!queue->head || fastd_queue_timeout(queue) > 0)
		return NULL;

	fastd_queue_entry *entry = queue->head;
	queue->head = entry->next;

	void *data = entry->data;
	free(entry);
	return data;
}

int fastd_queue_timeout(fastd_queue *queue) {
	if (!queue->head)
		return -1;

	struct timespec tp;
	clock_gettime(CLOCK_MONOTONIC, &tp);

	int64_t diff_msec = ((int64_t)(queue->head->timeout.tv_sec-tp.tv_sec))*1000 + (queue->head->timeout.tv_nsec-tp.tv_nsec)/1e6;
	if (diff_msec < 0)
		return 0;
	else
		return (int)diff_msec;
}
