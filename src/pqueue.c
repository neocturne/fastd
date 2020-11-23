// SPDX-License-Identifier: BSD-2-Clause
/*
  Copyright (c) 2012-2016, Matthias Schiffer <mschiffer@universe-factory.net>
  All rights reserved.
*/

/**
   \file

   Priority queue implementation

   Priority queues implemented using pairing heaps.
*/


#include "pqueue.h"
#include "log.h"


/** Links an element at the position specified by \e pqueue */
static inline void pqueue_link(fastd_pqueue_t ** const pqueue, fastd_pqueue_t * const elem) {
	if (elem->next)
		exit_bug("pqueue_link: element already linked");

	elem->pprev = pqueue;
	elem->next = *pqueue;
	if (elem->next)
		elem->next->pprev = &elem->next;

	*pqueue = elem;
}

/** Unlinks an element */
static inline void pqueue_unlink(fastd_pqueue_t * const elem) {
	*elem->pprev = elem->next;
	if (elem->next)
		elem->next->pprev = elem->pprev;

	elem->next = NULL;
}


/**
   Merges two priority queues

   \e pqueue2 may be empty (NULL)
*/
static fastd_pqueue_t *pqueue_merge(fastd_pqueue_t * const pqueue1, fastd_pqueue_t * const pqueue2) {
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
	} else {
		lo = pqueue2;
		hi = pqueue1;
	}

	pqueue_link(&lo->children, hi);

	return lo;
}

/** Merges a list of priority queues */
static fastd_pqueue_t *pqueue_merge_pairs(fastd_pqueue_t * const pqueue0) {
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
void fastd_pqueue_insert(fastd_pqueue_t ** const pqueue, fastd_pqueue_t * const elem) {
	if (elem->pprev || elem->next || elem->children)
		exit_bug("fastd_pqueue_insert: tried to insert linked pqueue element");

	*pqueue = pqueue_merge(elem, *pqueue);
	(*pqueue)->pprev = pqueue;
}

/** Removes an element from a priority queue */
void fastd_pqueue_remove(fastd_pqueue_t * const elem) {
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
