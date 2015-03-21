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

   Portable polling API
*/


#pragma once


#include "types.h"


/** A file descriptor to poll on */
struct fastd_poll_fd {
	fastd_poll_type_t type;		/**< What the file descriptor is used for */
	int fd;				/**< The file descriptor itself */
};


/** Initializes the poll interface */
void fastd_poll_init(void);
/** Frees the poll interface */
void fastd_poll_free(void);

/** Returns a fastd_poll_fd_t structure */
#define FASTD_POLL_FD(type, fd) ((fastd_poll_fd_t){type, fd})

/** Registers a new file descriptor to poll on */
void fastd_poll_fd_register(fastd_poll_fd_t *fd);
/** Unregisters and closes a file descriptor */
bool fastd_poll_fd_close(fastd_poll_fd_t *fd);

/** Waits for the next input event */
void fastd_poll_handle(void);
