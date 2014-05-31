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
   \file

   Portable polling API implementations
*/


#include "poll.h"
#include "async.h"
#include "peer.h"

#include <pthread.h>
#include <signal.h>


#ifdef USE_EPOLL

#include <sys/epoll.h>

#endif


/** Returns the time to the next handshake or -1 */
static inline int handshake_timeout(void) {
	if (!ctx.handshake_queue.next)
		return -1;

	fastd_peer_t *peer = container_of(ctx.handshake_queue.next, fastd_peer_t, handshake_entry);

	int diff_msec = timespec_diff(&peer->next_handshake, &ctx.now);
	if (diff_msec < 0)
		return 0;
	else
		return diff_msec;
}


#ifdef USE_EPOLL

#include <fcntl.h>
#include <sys/epoll.h>


void fastd_poll_init(void) {
	ctx.epoll_fd = epoll_create1(0);
	if (ctx.epoll_fd < 0)
		exit_errno("epoll_create1");

	struct epoll_event event = {
		.events = EPOLLIN,
		.data.ptr = &ctx.async_rfd,
	};
	if (epoll_ctl(ctx.epoll_fd, EPOLL_CTL_ADD, ctx.async_rfd, &event) < 0)
		exit_errno("epoll_ctl");
}

void fastd_poll_free(void) {
	if (close(ctx.epoll_fd))
		pr_warn_errno("closing EPOLL: close");
}

void fastd_poll_set_fd_tuntap(void) {
	struct epoll_event event = {
		.events = EPOLLIN,
		.data.ptr = &ctx.tunfd,
	};
	if (epoll_ctl(ctx.epoll_fd, EPOLL_CTL_ADD, ctx.tunfd, &event) < 0)
		exit_errno("epoll_ctl");
}

void fastd_poll_set_fd_sock(size_t i) {
	struct epoll_event event = {
		.events = EPOLLIN,
		.data.ptr = &ctx.socks[i],
	};
	if (epoll_ctl(ctx.epoll_fd, EPOLL_CTL_ADD, ctx.socks[i].fd, &event) < 0)
		exit_errno("epoll_ctl");
}

void fastd_poll_set_fd_peer(size_t i) {
	fastd_peer_t *peer = VECTOR_INDEX(ctx.peers, i);

	if (!peer->sock || !fastd_peer_is_socket_dynamic(peer))
		return;

	struct epoll_event event = {
		.events = EPOLLIN,
		.data.ptr = peer->sock,
	};
	if (epoll_ctl(ctx.epoll_fd, EPOLL_CTL_ADD, peer->sock->fd, &event) < 0)
		exit_errno("epoll_ctl");
}

void fastd_poll_add_peer(void) {
}

void fastd_poll_delete_peer(size_t i UNUSED) {
}


void fastd_poll_handle(void) {
	int maintenance_timeout = timespec_diff(&ctx.next_maintenance, &ctx.now);

	if (maintenance_timeout < 0)
		maintenance_timeout = 0;

	int timeout = handshake_timeout();
	if (timeout < 0 || timeout > maintenance_timeout)
		timeout = maintenance_timeout;

	sigset_t set, oldset;
	sigemptyset(&set);
	pthread_sigmask(SIG_SETMASK, &set, &oldset);

	struct epoll_event events[16];
	int ret = epoll_wait(ctx.epoll_fd, events, 16, timeout);
	if (ret < 0) {
		if (errno == EINTR)
			return;

		exit_errno("epoll_wait");
	}

	pthread_sigmask(SIG_SETMASK, &oldset, NULL);

	fastd_update_time();

	size_t i;
	for (i = 0; i < (size_t)ret; i++) {
		if (events[i].data.ptr == &ctx.tunfd) {
			if (events[i].events & EPOLLIN)
				fastd_tuntap_handle();
		}
		else if (events[i].data.ptr == &ctx.async_rfd) {
			if (events[i].events & EPOLLIN)
				fastd_async_handle();
		}
		else {
			fastd_socket_t *sock = events[i].data.ptr;

			if (events[i].events & (EPOLLERR|EPOLLHUP)) {
				if (sock->peer)
					fastd_peer_reset_socket(sock->peer);
				else
					fastd_socket_error(sock);
			}
			else if (events[i].events & EPOLLIN) {
				fastd_receive(sock);
			}
		}
	}
}

#else

void fastd_poll_init(void) {
	VECTOR_ALLOC(ctx.pollfds, 2 + ctx.n_socks);

	VECTOR_INDEX(ctx.pollfds, 0) = (struct pollfd) {
		.fd = -1,
		.events = POLLIN,
		.revents = 0,
	};

	VECTOR_INDEX(ctx.pollfds, 1) = (struct pollfd) {
		.fd = ctx.async_rfd,
		.events = POLLIN,
		.revents = 0,
	};

	size_t i;
	for (i = 0; i < ctx.n_socks; i++) {
		VECTOR_INDEX(ctx.pollfds, 2+i) = (struct pollfd) {
			.fd = -1,
			.events = POLLIN,
			.revents = 0,
		};
	}
}

void fastd_poll_free(void) {
	VECTOR_FREE(ctx.pollfds);
}


void fastd_poll_set_fd_tuntap(void) {
	VECTOR_INDEX(ctx.pollfds, 0).fd = ctx.tunfd;
}

void fastd_poll_set_fd_sock(size_t i) {
	VECTOR_INDEX(ctx.pollfds, 2+i).fd = ctx.socks[i].fd;
}

void fastd_poll_set_fd_peer(size_t i) {
	fastd_peer_t *peer = VECTOR_INDEX(ctx.peers, i);

	if (!peer->sock || !fastd_peer_is_socket_dynamic(peer))
		VECTOR_INDEX(ctx.pollfds, 2+ctx.n_socks+i).fd = -1;
	else
		VECTOR_INDEX(ctx.pollfds, 2+ctx.n_socks+i).fd = peer->sock->fd;
}

void fastd_poll_add_peer(void) {
	struct pollfd pollfd = {
		.fd = -1,
		.events = POLLIN,
		.revents = 0,
	};

	VECTOR_ADD(ctx.pollfds, pollfd);
}

void fastd_poll_delete_peer(size_t i) {
	VECTOR_DELETE(ctx.pollfds, 2+ctx.n_socks+i);
}


void fastd_poll_handle(void) {
	int maintenance_timeout = timespec_diff(&ctx.next_maintenance, &ctx.now);

	if (maintenance_timeout < 0)
		maintenance_timeout = 0;

	int timeout = handshake_timeout();
	if (timeout < 0 || timeout > maintenance_timeout)
		timeout = maintenance_timeout;

	if (VECTOR_LEN(ctx.pollfds) != 2 + ctx.n_socks + VECTOR_LEN(ctx.peers))
		exit_bug("fd count mismatch");

	sigset_t set, oldset;
	sigemptyset(&set);
	pthread_sigmask(SIG_SETMASK, &set, &oldset);

	int ret = poll(VECTOR_DATA(ctx.pollfds), VECTOR_LEN(ctx.pollfds), timeout);
	if (ret < 0) {
		if (errno == EINTR)
			return;

		exit_errno("poll");
	}

	pthread_sigmask(SIG_SETMASK, &oldset, NULL);

	fastd_update_time();

	if (VECTOR_INDEX(ctx.pollfds, 0).revents & POLLIN)
		fastd_tuntap_handle();
	if (VECTOR_INDEX(ctx.pollfds, 1).revents & POLLIN)
		fastd_async_handle();

	size_t i;
	for (i = 0; i < ctx.n_socks; i++) {
		if (VECTOR_INDEX(ctx.pollfds, 2+i).revents & (POLLERR|POLLHUP|POLLNVAL)) {
			fastd_socket_error(&ctx.socks[i]);
			VECTOR_INDEX(ctx.pollfds, 2+i).fd = -1;
		}
		else if (VECTOR_INDEX(ctx.pollfds, 2+i).revents & POLLIN) {
			fastd_receive(&ctx.socks[i]);
		}
	}

	for (i = 0; i < VECTOR_LEN(ctx.peers); i++) {
		fastd_peer_t *peer = VECTOR_INDEX(ctx.peers, i);

		if (VECTOR_INDEX(ctx.pollfds, 2+ctx.n_socks+i).revents & (POLLERR|POLLHUP|POLLNVAL)) {
			fastd_peer_reset_socket(peer);
		}
		else if (VECTOR_INDEX(ctx.pollfds, 2+ctx.n_socks+i).revents & POLLIN) {
			fastd_receive(peer->sock);
		}
	}

	if (VECTOR_LEN(ctx.pollfds) != 2 + ctx.n_socks + VECTOR_LEN(ctx.peers))
		exit_bug("fd count mismatch");
}

#endif

