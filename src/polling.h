// SPDX-License-Identifier: BSD-2-Clause
/*
  Copyright (c) 2012-2016, Matthias Schiffer <mschiffer@universe-factory.net>
  All rights reserved.
*/

/**
   \file

   Portable polling API
*/


#pragma once


#include "types.h"


/** A file descriptor to poll on */
struct fastd_poll_fd {
	fastd_poll_type_t type; /**< What the file descriptor is used for */
	int fd;                 /**< The file descriptor itself */
};


/** Initializes the poll interface */
void fastd_poll_init(void);
/** Frees the poll interface */
void fastd_poll_free(void);

/** Returns a fastd_poll_fd_t structure */
#define FASTD_POLL_FD(type, fd) ((fastd_poll_fd_t){ type, fd })

/** Registers a new file descriptor to poll on */
void fastd_poll_fd_register(fastd_poll_fd_t *fd);
/** Unregisters and closes a file descriptor */
bool fastd_poll_fd_close(fastd_poll_fd_t *fd);

/** Waits for the next input event */
void fastd_poll_handle(void);
