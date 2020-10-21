/*
  Copyright (c) 2020, Heiko Wundram <heiko.wundram@gehrkens.it>.
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

   \em Socket configuration.
 */


#pragma once


#include "task.h"


/** A socket descriptor */
struct fastd_socket {
	fastd_poll_fd_t fd;			/**< The file descriptor for the socket */
	const fastd_bind_address_t *addr;	/**< The address this socket is supposed to be bound to (or NULL) */
	fastd_peer_address_t *bound_addr;	/**< The actual address that was bound to (may differ from addr when addr has a random port) */
	fastd_peer_t *peer;			/**< If the socket belongs to a single peer (as it was create dynamically when sending a handshake), contains that peer */
	fastd_task_t task;			/**< Socket task for managing discovery packets (multicast bind) */
	fastd_timeout_t discovery_timeout;	/**< Timeout of next discovery packet */
};


void fastd_socket_handle_task(fastd_task_t *task);
