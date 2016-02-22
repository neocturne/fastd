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

   Priority queue implementation

   Priority queues implemented using pairing heaps.
*/


#include "pqueue.h"
#include "log.h"


/** Links an element at the position specified by \e pqueue */
static inline void pqueue_link(fastd_pqueue_t **pqueue, fastd_pqueue_t *elem) {
	if (elem->next)
		exit_bug("pqueue_link: element already linked");

	elem->pprev = pqueue;
	elem->next = *pqueue;
	if (elem->next)
		elem->next->pprev = &elem->next;

	*pqueue = elem;
}

/** Unlinks an element */
static inline void pqueue_unlink(fastd_pqueue_t *elem) {
	*elem->pprev = elem->next;
	if (elem->next)
		elem->next->pprev = elem->pprev;

	elem->next = NULL;
}


/**
   Merges two priority queues

   \e pqueue2 may be empty (NULL)
*/
static fastd_pqueue_t * pqueue_merge(fastd_pqueue_t *pqueue1, fastd_pqueue_t *pqueue2) {
	if (!pqueue1)
		exit_bug("pqueue_merge: pqueue1 unset");
	if (pqueue1->next)
		exit_bug("pqueue_merge: pqueue1 has successor");

	if (!pqueue2)
		return pqueue1;

	if (pqueue2->next)
		exit_bug("pqueue_merge: pqueue2 has successor");

	fastd_pqueue_t *lo, *hi;

	if (pqueue1->value < pqueue2->value) {
		lo = pqueue1;
		hi = pqueue2;
	}
	else {
		lo = pqueue2;
		hi = pqueue1;
	}

	pqueue_link(&lo->children, hi);

	return lo;
}

/** Merges a list of priority queues */
static fastd_pqueue_t * pqueue_merge_pairs(fastd_pqueue_t *pqueue0) {
	if (!pqueue0)
		return NULL;

	if (!pqueue0->pprev)
		exit_bug("pqueue_merge_pairs: unlinked pqueue");

	fastd_pqueue_t *pqueue1 = pqueue0->next;

	if (!pqueue1)
		return pqueue0;

	fastd_pqueue_t *pqueue2 = pqueue1->next;

	pqueue0->next = pqueue1->next = NULL;

	return pqueue_merge(pqueue_merge(pqueue0, pqueue1), pqueue_merge_pairs(pqueue2));
}

/** Inserts a new element into a priority queue */
void fastd_pqueue_insert(fastd_pqueue_t **pqueue, fastd_pqueue_t *elem) {
	if (elem->pprev || elem->next || elem->children)
		exit_bug("fastd_pqueue_insert: tried to insert linked pqueue element");

	*pqueue = pqueue_merge(elem, *pqueue);
	(*pqueue)->pprev = pqueue;
}

/** Removes an element from a priority queue */
void fastd_pqueue_remove(fastd_pqueue_t *elem) {
	if (!fastd_pqueue_linked(elem)) {
		if (elem->children || elem->next)
			exit_bug("fastd_pqueue_remove: corrupted pqueue item");

		return;
	}

	fastd_pqueue_t **pprev = elem->pprev;

	pqueue_unlink(elem);

	fastd_pqueue_t *merged = pqueue_merge_pairs(elem->children);
	if (merged)
		pqueue_link(pprev, merged);

	elem->pprev = NULL;
	elem->children = NULL;
}
