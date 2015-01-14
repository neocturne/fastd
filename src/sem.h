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
