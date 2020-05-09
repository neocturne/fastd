// SPDX-License-Identifier: BSD-2-Clause
/*
  Copyright (c) 2012-2016, Matthias Schiffer <mschiffer@universe-factory.net>
  All rights reserved.
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


/** Returns the time to the next task or -1 */
static inline int task_timeout(void) {
	fastd_timeout_t timeout = fastd_task_queue_timeout();
	if (timeout == FASTD_TIMEOUT_INV)
		return -1;

	int diff_msec = timeout - ctx.now;
	if (diff_msec < 0)
		return 0;
	else
		return diff_msec;
}


/** Handles a file descriptor that was selected on */
static inline void handle_fd(fastd_poll_fd_t *fd, bool input, bool error) {
	switch (fd->type) {
	case POLL_TYPE_ASYNC:
		if (input)
			fastd_async_handle();
		break;

	case POLL_TYPE_STATUS:
		if (input)
			fastd_status_handle();
		break;

	case POLL_TYPE_IFACE: {
		fastd_iface_t *iface = container_of(fd, fastd_iface_t, fd);

		if (input)
			fastd_iface_handle(iface);

		break;
	}

	case POLL_TYPE_SOCKET: {
		fastd_socket_t *sock = container_of(fd, fastd_socket_t, fd);

		if (error) {
			if (sock->peer)
				fastd_peer_reset_socket(sock->peer);
			else
				fastd_socket_error(sock);

			return;
		}

		if (input)
			fastd_receive(sock);

		break;
	}

	default:
		exit_bug("unknown FD type");
	}

	if (error)
		exit_error("unexpected poll error");
}


#ifdef USE_EPOLL


#ifndef SYS_epoll_pwait
#define SYS_epoll_pwait __NR_epoll_pwait
#endif

/** Simplified epoll_pwait wrapper (as there are systems without or with broken epoll_pwait) */
static inline int epoll_wait_unblocked(int epfd, struct epoll_event *events, int maxevents, int timeout) {
	const uint8_t buf[_NSIG / 8] = {};
	return syscall(SYS_epoll_pwait, epfd, events, maxevents, timeout, buf, sizeof(buf));
}


void fastd_poll_init(void) {
	ctx.epoll_fd = epoll_create(1);
	if (ctx.epoll_fd < 0)
		exit_errno("epoll_create1");
}

void fastd_poll_free(void) {
	if (close(ctx.epoll_fd))
		pr_warn_errno("closing EPOLL: close");
}


void fastd_poll_fd_register(fastd_poll_fd_t *fd) {
	if (fd->fd < 0)
		exit_bug("fastd_poll_fd_register: invalid FD");

	struct epoll_event event = {
		.events = EPOLLIN,
		.data.ptr = fd,
	};

	if (epoll_ctl(ctx.epoll_fd, EPOLL_CTL_ADD, fd->fd, &event) < 0)
		exit_errno("epoll_ctl");
}

bool fastd_poll_fd_close(fastd_poll_fd_t *fd) {
	if (epoll_ctl(ctx.epoll_fd, EPOLL_CTL_DEL, fd->fd, NULL) < 0)
		exit_errno("epoll_ctl");

	return (close(fd->fd) == 0);
}


void fastd_poll_handle(void) {
	int timeout = task_timeout();

	struct epoll_event events[16];
	int ret = epoll_wait_unblocked(ctx.epoll_fd, events, 16, timeout);
	if (ret < 0 && errno != EINTR)
		exit_errno("epoll_pwait");

	fastd_update_time();

	if (ret < 0)
		return;

	size_t i;
	for (i = 0; i < (size_t)ret; i++)
		handle_fd(events[i].data.ptr, events[i].events & EPOLLIN, events[i].events & (EPOLLERR | EPOLLHUP));
}

#else

void fastd_poll_init(void) {}

void fastd_poll_free(void) {
	VECTOR_FREE(ctx.fds);
	VECTOR_FREE(ctx.pollfds);
}


void fastd_poll_fd_register(fastd_poll_fd_t *fd) {
	if (fd->fd < 0)
		exit_bug("fastd_poll_fd_register: invalid FD");

	while (VECTOR_LEN(ctx.fds) <= (size_t)fd->fd)
		VECTOR_ADD(ctx.fds, NULL);

	VECTOR_INDEX(ctx.fds, fd->fd) = fd;

	VECTOR_RESIZE(ctx.pollfds, 0);
}

bool fastd_poll_fd_close(fastd_poll_fd_t *fd) {
	if (fd->fd < 0 || (size_t)fd->fd >= VECTOR_LEN(ctx.fds))
		exit_bug("fastd_poll_fd_close: invalid FD");

	VECTOR_INDEX(ctx.fds, fd->fd) = NULL;

	VECTOR_RESIZE(ctx.pollfds, 0);

	return (close(fd->fd) == 0);
}


void fastd_poll_handle(void) {
	size_t i;

	int timeout = task_timeout();

	if (!VECTOR_LEN(ctx.pollfds)) {
		for (i = 0; i < VECTOR_LEN(ctx.fds); i++) {
			fastd_poll_fd_t *fd = VECTOR_INDEX(ctx.fds, i);
			if (!fd)
				continue;

			struct pollfd pollfd = {
				.fd = fd->fd,
				.events = POLLIN,
				.revents = 0,
			};
			VECTOR_ADD(ctx.pollfds, pollfd);
		}
	}

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
			tv.tv_sec = timeout / 1000;
			tv.tv_usec = (timeout % 1000) * 1000;
		}
		ret = select(maxfd + 1, &readfds, NULL, &errfds, tvp);
		if (ret < 0 && errno != EINTR)
			exit_errno("select");
	}

	if (ret > 0) {
		ret = 0;

		for (i = 0; i < VECTOR_LEN(ctx.pollfds); i++) {
			struct pollfd *pollfd = &VECTOR_INDEX(ctx.pollfds, i);
			pollfd->revents = 0;

			if (pollfd->fd < 0)
				continue;

			if (FD_ISSET(pollfd->fd, &readfds))
				pollfd->revents |= POLLIN;
			if (FD_ISSET(pollfd->fd, &errfds))
				pollfd->revents |= POLLERR;

			if (pollfd->revents)
				ret++;
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

	for (i = 0; i < VECTOR_LEN(ctx.pollfds) && ret > 0; i++) {
		struct pollfd *pollfd = &VECTOR_INDEX(ctx.pollfds, i);

		if (pollfd->revents)
			ret--;

		handle_fd(
			VECTOR_INDEX(ctx.fds, pollfd->fd), pollfd->revents & POLLIN,
			pollfd->revents & (POLLERR | POLLHUP | POLLNVAL));
	}
}

#endif
