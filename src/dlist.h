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

   Doubly-linked lists
*/

#pragma once

#include <stddef.h>
#include <stdbool.h>


typedef struct fastd_dlist_head fastd_dlist_head_t;

/** Doubly-linked list element */
struct fastd_dlist_head {
	fastd_dlist_head_t *prev;		/**< The next element of the list or NULL */
	fastd_dlist_head_t *next;		/**< The previous element of the list or NULL */
};


/** Checks if a fastd_dlist_head_t is currently part of a list */
static inline bool fastd_dlist_linked(fastd_dlist_head_t *elem) {
	return elem->prev;
}

/** Adds the element \e elem after \e list */
static inline void fastd_dlist_insert(fastd_dlist_head_t *list, fastd_dlist_head_t *elem) {
	elem->prev = list;
	elem->next = list->next;

	list->next = elem;

	if (elem->next)
		elem->next->prev = elem;
}

/** Removes \e elem from a list */
static inline void fastd_dlist_remove(fastd_dlist_head_t *elem) {
	if (elem->prev)
		elem->prev->next = elem->next;

	if (elem->next)
		elem->next->prev = elem->prev;

	elem->prev = elem->next = NULL;
}
