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

   Asynchronous notifications
*/


#include "async.h"
#include "fastd.h"

#include <sys/uio.h>


/** The packet header used on the async notification sockets */
typedef struct fastd_async_hdr {
	fastd_async_type_t type;	/**< The type of the notification */
	size_t len;			/**< The length of the notification payload */
} fastd_async_hdr_t;


/** Initializes the async notification sockets */
void fastd_async_init(void) {
	int fds[2];

	/* use socketpair with SOCK_DGRAM instead of pipe2 with O_DIRECT to keep this portable */
	if (socketpair(AF_UNIX, SOCK_DGRAM|SOCK_NONBLOCK, 0, fds))
		exit_errno("socketpair");

#ifdef NO_HAVE_SOCK_NONBLOCK
	fastd_setnonblock(fds[0]);
	fastd_setnonblock(fds[1]);
#endif

	ctx.async_rfd = fds[0];
	ctx.async_wfd = fds[1];
}

/** Handles a DNS resolver response */
static void handle_resolve_return(const fastd_async_resolve_return_t *resolve_return) {
	fastd_peer_t *peer = fastd_peer_find_by_id(resolve_return->peer_id);
	if (!peer || !fastd_peer_is_enabled(peer))
		return;

	if (fastd_peer_is_dynamic(peer))
		exit_bug("resolve return for dynamic peer");

	fastd_remote_t *remote = &VECTOR_INDEX(peer->remotes, resolve_return->remote);
	fastd_peer_handle_resolve(peer, remote, resolve_return->n_addr, resolve_return->addr);
}

#ifdef WITH_DYNAMIC_PEERS

/** Handles a on-verify response */
static void handle_verify_return(const fastd_async_verify_return_t *verify_return) {
	fastd_peer_t *peer = fastd_peer_find_by_id(verify_return->peer_id);
	if (!peer)
		return;

	if (!fastd_peer_is_dynamic(peer))
		exit_bug("verify return for permanent peer");

	fastd_peer_set_verified(peer, verify_return->ok);

	conf.protocol->handle_verify_return(peer, verify_return->sock, &verify_return->local_addr, &verify_return->remote_addr,
					    verify_return->method, verify_return->protocol_data, verify_return->ok);
}

#endif


/** Reads and handles a single notification from the async notification socket */
void fastd_async_handle(void) {
	fastd_async_hdr_t header;
	struct iovec vec[2] = {
		{ .iov_base = &header, .iov_len = sizeof(header) },
	};
	struct msghdr msg = {
		.msg_iov = vec,
		.msg_iovlen = 1,
	};

	if (recvmsg(ctx.async_rfd, &msg, MSG_PEEK) < 0)
		exit_errno("fastd_async_handle: recvmsg");

	uint8_t buf[header.len] __attribute__((aligned(8)));
	vec[1].iov_base = buf;
	vec[1].iov_len = sizeof(buf);
	msg.msg_iovlen = 2;

	if (recvmsg(ctx.async_rfd, &msg, 0) < 0)
		exit_errno("fastd_async_handle: recvmsg");

	switch (header.type) {
	case ASYNC_TYPE_NOP:
		break;

	case ASYNC_TYPE_RESOLVE_RETURN:
		handle_resolve_return((const fastd_async_resolve_return_t *)buf);
		break;

#ifdef WITH_DYNAMIC_PEERS
	case ASYNC_TYPE_VERIFY_RETURN:
		handle_verify_return((const fastd_async_verify_return_t *)buf);
		break;
#endif

	default:
		exit_bug("fastd_async_handle: unknown type");
	}
}

/** Enqueues a new async notification */
void fastd_async_enqueue(fastd_async_type_t type, const void *data, size_t len) {
	fastd_async_hdr_t header;
	/* use memset to zero the holes in the struct to make valgrind happy */
	memset(&header, 0, sizeof(header));
	header.type = type;
	header.len = len;

	struct iovec vec[2] = {
		{ .iov_base = &header, .iov_len = sizeof(header) },
		{ .iov_base = (void *)data, .iov_len = len },
	};
	struct msghdr msg = {
		.msg_iov = vec,
		.msg_iovlen = len ? 2 : 1,
	};

	if (sendmsg(ctx.async_wfd, &msg, 0) < 0)
		pr_warn_errno("fastd_async_enqueue: sendmsg");
}
