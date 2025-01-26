// SPDX-License-Identifier: BSD-2-Clause
/*
  Copyright (c) Matthias Schiffer <mschiffer@universe-factory.net>
  All rights reserved.
*/

/**
   \file

   Priority queues
*/

#pragma once

#include "types.h"


/** Element of a priority queue */
struct fastd_pqueue {
	fastd_pqueue_t **pprev; /**< \e next element of the previous element (or \e children of the parent) */
	fastd_pqueue_t *next;   /**< Next sibling in the heap */

	fastd_pqueue_t *children; /**< Heap children */

	int64_t value; /**< The priority */
};


/** Checks if an element is currently part of a priority queue */
static inline bool fastd_pqueue_linked(fastd_pqueue_t *elem) {
	return elem->pprev;
}

void fastd_pqueue_insert(fastd_pqueue_t **pqueue, fastd_pqueue_t *elem);
void fastd_pqueue_remove(fastd_pqueue_t *elem);
