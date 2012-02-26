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


#ifndef _FASTD_QUEUE_H_
#define _FASTD_QUEUE_H_

#include <stdlib.h>


typedef struct _fastd_queue_entry fastd_queue_entry;

struct _fastd_queue_entry {
	fastd_queue_entry *next;
	void *data;
};

typedef struct _fastd_queue {
	fastd_queue_entry *head;
	fastd_queue_entry *tail;
} fastd_queue;


static inline void fastd_queue_put(fastd_queue *queue, void *data) {
	fastd_queue_entry *entry = malloc(sizeof(fastd_queue_entry));
	entry->next = NULL;
	entry->data = data;

	if (queue->tail)
		queue->tail->next = entry;
	else
		queue->head = entry;

	queue->tail = entry;
}

static inline void* fastd_queue_get(fastd_queue *queue) {
	if (!queue->head)
		return NULL;

	fastd_queue_entry *entry = queue->head;
	queue->head = entry->next;
	if (!queue->head)
		queue->tail = NULL;

	void *data = entry->data;
	free(entry);
	return data;
}

#endif /* _FASTD_QUEUE_H_ */
