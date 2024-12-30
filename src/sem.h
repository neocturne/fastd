// SPDX-License-Identifier: BSD-2-Clause
/*
  Copyright (c) Matthias Schiffer <mschiffer@universe-factory.net>
  All rights reserved.
*/

/**
   \file

   Portable semapores
*/


#pragma once

#include "log.h"


#ifdef __APPLE__

#include <dispatch/dispatch.h>

/** Generic semaphore type */
typedef dispatch_semaphore_t fastd_sem_t;


/** Initializes a semaphore with a given value */
static inline void fastd_sem_init(fastd_sem_t *sem, unsigned value) {
	*sem = dispatch_semaphore_create(value);
	if (!*sem)
		exit_errno("dispatch_semaphore_create");
}

/** Increments the semaphore */
static inline void fastd_sem_post(fastd_sem_t *sem) {
	if (dispatch_semaphore_signal(*sem))
		exit_errno("sem_post");
}

/** Tries to decrement the semaphore */
static inline bool fastd_sem_trywait(fastd_sem_t *sem) {
	return !dispatch_semaphore_wait(*sem, DISPATCH_TIME_NOW);
}

#else

#include <semaphore.h>

/** Generic semaphore type */
typedef sem_t fastd_sem_t;


/** Initializes a semaphore with a given value */
static inline void fastd_sem_init(fastd_sem_t *sem, unsigned value) {
	if (sem_init(sem, 0, value))
		exit_errno("sem_init");
}

/** Increments the semaphore */
static inline void fastd_sem_post(fastd_sem_t *sem) {
	if (sem_post(sem))
		exit_errno("sem_post");
}

/** Tries to decrement the semaphore */
static inline bool fastd_sem_trywait(fastd_sem_t *sem) {
	return !sem_trywait(sem);
}

#endif
