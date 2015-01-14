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

   Portable polling API implementations
*/


#include "poll.h"
#include "async.h"
#include "peer.h"

#include <signal.h>


#ifdef USE_EPOLL

#include <sys/epoll.h>
#include <sys/syscall.h>

#endif

#ifdef USE_SELECT

#include <sys/select.h>

#endif


/** Returns the time to the next handshake or -1 */
static inline int handshake_timeout(void) {
	if (!ctx.handshake_queue.next)
		return -1;

	fastd_peer_t *peer = container_of(ctx.handshake_queue.next, fastd_peer_t, handshake_entry);

	int diff_msec = peer->next_handshake - ctx.now;
	if (diff_msec < 0)
		return 0;
	else
		return diff_msec;
}


#ifdef USE_EPOLL


#ifndef SYS_epoll_pwait
#define SYS_epoll_pwait __NR_epoll_pwait
#endif

/** Simplified epoll_pwait wrapper (as there are systems without or with broken epoll_pwait) */
static inline int epoll_wait_unblocked(int epfd, struct epoll_event *events, int maxevents, int timeout) {
	const uint8_t buf[_NSIG/8] = {};
	return syscall(SYS_epoll_pwait, epfd, events, maxevents, timeout, buf, sizeof(buf));
}


void fastd_poll_init(void) {
	ctx.epoll_fd = epoll_create(1);
	if (ctx.epoll_fd < 0)
		exit_errno("epoll_create1");

	struct epoll_event event_async = {
		.events = EPOLLIN,
		.data.ptr = &ctx.async_rfd,
	};
	if (epoll_ctl(ctx.epoll_fd, EPOLL_CTL_ADD, ctx.async_rfd, &event_async) < 0)
		exit_errno("epoll_ctl");

#ifdef WITH_STATUS_SOCKET
	if (ctx.status_fd >= 0) {
		struct epoll_event event_status = {
			.events = EPOLLIN,
			.data.ptr = &ctx.status_fd,
		};

		if (epoll_ctl(ctx.epoll_fd, EPOLL_CTL_ADD, ctx.status_fd, &event_status) < 0)
			exit_errno("epoll_ctl");
	}
#endif
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

void fastd_poll_delete_peer(UNUSED size_t i) {
}


void fastd_poll_handle(void) {
	int maintenance_timeout = ctx.next_maintenance - ctx.now;

	if (maintenance_timeout < 0)
		maintenance_timeout = 0;

	int timeout = handshake_timeout();
	if (timeout < 0 || timeout > maintenance_timeout)
		timeout = maintenance_timeout;

	struct epoll_event events[16];
	int ret = epoll_wait_unblocked(ctx.epoll_fd, events, 16, timeout);
	if (ret < 0 && errno != EINTR)
		exit_errno("epoll_pwait");

	fastd_update_time();

	if (ret < 0)
		return;

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
#ifdef WITH_STATUS_SOCKET
		else if (events[i].data.ptr == &ctx.status_fd) {
			if (events[i].events & EPOLLIN)
				fastd_status_handle();
		}
#endif
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
	VECTOR_RESIZE(ctx.pollfds, 3 + ctx.n_socks + VECTOR_LEN(ctx.peers));

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

	VECTOR_INDEX(ctx.pollfds, 2) = (struct pollfd) {
#ifdef WITH_STATUS_SOCKET
		.fd = ctx.status_fd,
#else
		.fd = -1,
#endif
		.events = POLLIN,
		.revents = 0,
	};

	size_t i;
	for (i = 0; i < ctx.n_socks + VECTOR_LEN(ctx.peers); i++) {
		VECTOR_INDEX(ctx.pollfds, 3+i) = (struct pollfd) {
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
	VECTOR_INDEX(ctx.pollfds, 3+i).fd = ctx.socks[i].fd;
}

void fastd_poll_set_fd_peer(size_t i) {
	if (!VECTOR_LEN(ctx.pollfds))
		exit_bug("fastd_poll_set_fd_peer: polling not initialized yet");

	fastd_peer_t *peer = VECTOR_INDEX(ctx.peers, i);

	if (!peer->sock || !fastd_peer_is_socket_dynamic(peer))
		VECTOR_INDEX(ctx.pollfds, 3+ctx.n_socks+i).fd = -1;
	else
		VECTOR_INDEX(ctx.pollfds, 3+ctx.n_socks+i).fd = peer->sock->fd;
}

void fastd_poll_add_peer(void) {
	if (!VECTOR_LEN(ctx.pollfds))
		/* Polling is not initialized yet */
		return;

	struct pollfd pollfd = {
		.fd = -1,
		.events = POLLIN,
		.revents = 0,
	};

	VECTOR_ADD(ctx.pollfds, pollfd);
}

void fastd_poll_delete_peer(size_t i) {
	VECTOR_DELETE(ctx.pollfds, 3+ctx.n_socks+i);
}


void fastd_poll_handle(void) {
	size_t i;

	int maintenance_timeout = ctx.next_maintenance - ctx.now;

	if (maintenance_timeout < 0)
		maintenance_timeout = 0;

	int timeout = handshake_timeout();
	if (timeout < 0 || timeout > maintenance_timeout)
		timeout = maintenance_timeout;

	if (VECTOR_LEN(ctx.pollfds) != 3 + ctx.n_socks + VECTOR_LEN(ctx.peers))
		exit_bug("fd count mismatch");

	sigset_t set, oldset;
	sigemptyset(&set);
	pthread_sigmask(SIG_SETMASK, &set, &oldset);

	int ret = 0;

#ifdef USE_SELECT
	/* Inefficient implementation for OSX... */
	fd_set readfds;
	FD_ZERO(&readfds);
	int maxfd = -1;

	for (i = 0; i < VECTOR_LEN(ctx.pollfds); i++) {
		struct pollfd *pollfd = &VECTOR_INDEX(ctx.pollfds, i);
		if (pollfd->fd >= 0) {
			FD_SET(pollfd->fd, &readfds);

			if (pollfd->fd > maxfd)
				maxfd = pollfd->fd;
		}
	}

	fd_set errfds = readfds;

	if (maxfd >= 0) {
		struct timeval tv = {}, *tvp = NULL;
		if (timeout >= 0) {
			tvp = &tv;
			tv.tv_sec = timeout/1000;
			tv.tv_usec = (timeout%1000)*1000;
		}
		ret = select(maxfd+1, &readfds, NULL, &errfds, tvp);
		if (ret < 0 && errno != EINTR)
			exit_errno("select");
	}

	if (ret > 0) {
		for (i = 0; i < VECTOR_LEN(ctx.pollfds); i++) {
			struct pollfd *pollfd = &VECTOR_INDEX(ctx.pollfds, i);
			pollfd->revents = 0;

			if (pollfd->fd < 0)
				continue;

			if (FD_ISSET(pollfd->fd, &readfds))
				pollfd->revents |= POLLIN;
			if (FD_ISSET(pollfd->fd, &errfds))
				pollfd->revents |= POLLERR;
		}
	}

#else
	ret = poll(VECTOR_DATA(ctx.pollfds), VECTOR_LEN(ctx.pollfds), timeout);
	if (ret < 0 && errno != EINTR)
		exit_errno("poll");
#endif

	pthread_sigmask(SIG_SETMASK, &oldset, NULL);
	fastd_update_time();

	if (ret <= 0)
		return;

	if (VECTOR_INDEX(ctx.pollfds, 0).revents & POLLIN)
		fastd_tuntap_handle();
	if (VECTOR_INDEX(ctx.pollfds, 1).revents & POLLIN)
		fastd_async_handle();

#ifdef WITH_STATUS_SOCKET
	if (VECTOR_INDEX(ctx.pollfds, 2).revents & POLLIN)
		fastd_status_handle();
#endif

	for (i = 0; i < ctx.n_socks; i++) {
		if (VECTOR_INDEX(ctx.pollfds, 3+i).revents & (POLLERR|POLLHUP|POLLNVAL)) {
			fastd_socket_error(&ctx.socks[i]);
			VECTOR_INDEX(ctx.pollfds, 3+i).fd = -1;
		}
		else if (VECTOR_INDEX(ctx.pollfds, 3+i).revents & POLLIN) {
			fastd_receive(&ctx.socks[i]);
		}
	}

	for (i = 0; i < VECTOR_LEN(ctx.peers); i++) {
		fastd_peer_t *peer = VECTOR_INDEX(ctx.peers, i);

		if (VECTOR_INDEX(ctx.pollfds, 3+ctx.n_socks+i).revents & (POLLERR|POLLHUP|POLLNVAL)) {
			fastd_peer_reset_socket(peer);
		}
		else if (VECTOR_INDEX(ctx.pollfds, 3+ctx.n_socks+i).revents & POLLIN) {
			fastd_receive(peer->sock);
		}
	}

	if (VECTOR_LEN(ctx.pollfds) != 3 + ctx.n_socks + VECTOR_LEN(ctx.peers))
		exit_bug("fd count mismatch");
}

#endif

