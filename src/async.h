/*
  Copyright (c) 2012-2014, Matthias Schiffer <mschiffer@universe-factory.net>
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
   \file async.h

   Asynchronous notifications
*/


#pragma once

#include "types.h"
#include "peer.h"


/** A type of asynchronous notification */
typedef enum fastd_async_type {
	ASYNC_TYPE_RESOLVE_RETURN,		/**< A DNS resolver response */
	ASYNC_TYPE_VERIFY_RETURN,		/**< A on-verify return */
} fastd_async_type_t;


/** A DNS resolver response */
typedef struct fastd_async_resolve_return {
	uint64_t peer_id;
	size_t remote;

	size_t n_addr;
	fastd_peer_address_t addr[];
} fastd_async_resolve_return_t;

/** A on-verify response */
typedef struct fastd_async_verify_return {
	bool ok;

	uint64_t peer_id;

	const fastd_method_info_t *method;
	fastd_socket_t *sock;

	fastd_peer_address_t local_addr;
	fastd_peer_address_t remote_addr;

	uint8_t protocol_data[] __attribute__((aligned(8)));
} fastd_async_verify_return_t;


void fastd_async_init(void);
void fastd_async_handle(void);
void fastd_async_enqueue(fastd_async_type_t type, const void *data, size_t len);
