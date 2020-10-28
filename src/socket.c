/*
  Copyright (c) 2012-2016, Matthias Schiffer <mschiffer@universe-factory.net>
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

   Socket handling
*/

#include "fastd.h"
#include "peer.h"
#include "poll.h"
#include "socket.h"

#include <net/if.h>


/**
   Creates a new socket bound to a specific address

   \return The new socket's file descriptor
*/
static int bind_socket(const fastd_bind_address_t *addr) {
	const int zero = 0;
	const int one = 1;
	int fd = -1;
	int af = AF_UNSPEC;
	fastd_peer_address_t bind_address = addr->addr;

	if (!fastd_peer_address_host_v4_multicast(&bind_address)) {
		fd = socket(PF_INET6, SOCK_DGRAM|SOCK_NONBLOCK, IPPROTO_UDP);
		if (fd >= 0) {
			af = AF_INET6;

			const int val = bind_address.sa.sa_family == AF_INET6 || addr->sourceaddr.sa.sa_family == AF_INET6;
			if (setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &val, sizeof(val))) {
				pr_error_errno("setsockopt: unable to set socket to IPv6 only");
				goto error;
			}
		}
	}

	if (fd < 0 && bind_address.sa.sa_family != AF_INET6 && addr->sourceaddr.sa.sa_family != AF_INET6) {
		fd = socket(PF_INET, SOCK_DGRAM|SOCK_NONBLOCK, IPPROTO_UDP);
		if (fd >= 0)
			af = AF_INET;
	}

	if (fd < 0) {
		pr_error_errno("socket: unable to initialize socket");
		goto error;
	}

	if ((bind_address.sa.sa_family == AF_UNSPEC && (af == AF_INET || addr->sourceaddr.sa.sa_family == AF_INET)) || fastd_peer_address_host_v4_multicast(&bind_address)) {
		bind_address.in.sin_family = AF_INET;
		bind_address.in.sin_addr.s_addr = INADDR_ANY;

		if (af == AF_INET6)
			fastd_peer_address_widen(&bind_address);
	} else if (bind_address.sa.sa_family == AF_UNSPEC || fastd_peer_address_host_v6_multicast(&bind_address)) {
		bind_address.in6.sin6_family = AF_INET6;
		bind_address.in6.sin6_addr = in6addr_any;

		if (addr->addr.sa.sa_family == AF_UNSPEC)
			bind_address.in6.sin6_port = addr->addr.in.sin_port;
	} else if (af == AF_INET6)
		fastd_peer_address_widen(&bind_address);

#ifdef NO_HAVE_SOCK_NONBLOCK
	fastd_setnonblock(fd);
#endif

#ifdef USE_PKTINFO
	if (af == AF_INET && setsockopt(fd, IPPROTO_IP, IP_PKTINFO, &one, sizeof(one))) {
		pr_error_errno("setsockopt: unable to set IP_PKTINFO");
		goto error;
	}
#endif
	if (af == AF_INET6 && setsockopt(fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &one, sizeof(one))) {
		pr_error_errno("setsockopt: unable to set IPV6_RECVPKTINFO");
		goto error;
	}

#ifdef USE_FREEBIND
	if (af == AF_INET && setsockopt(fd, IPPROTO_IP, IP_FREEBIND, &one, sizeof(one)))
		pr_warn_errno("setsockopt: unable to set IP_FREEBIND");
#endif

#ifdef USE_BINDTODEVICE
	if (addr->bindtodev && !fastd_peer_address_host_v6_ll(&addr->addr) &&
		setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, addr->bindtodev, strlen(addr->bindtodev))) {
		pr_error_errno("setsockopt: unable to bind to device");
		goto error;
	}
#endif

#ifdef USE_PMTU
	int pmtu = IP_PMTUDISC_DONT;
	if (af == AF_INET && setsockopt(fd, IPPROTO_IP, IP_MTU_DISCOVER, &pmtu, sizeof(pmtu))) {
		pr_error_errno("setsockopt: unable to disable IPv4 PMTU discovery");
		goto error;
	}
	if (af == AF_INET6 && setsockopt(fd, IPPROTO_IPV6, IPV6_MTU_DISCOVER, &pmtu, sizeof(pmtu))) {
		pr_error_errno("setsockopt: unable to disable IPv6 PMTU discovery");
		goto error;
	}
#endif

#ifdef USE_PACKET_MARK
	if (conf.packet_mark && setsockopt(fd, SOL_SOCKET, SO_MARK, &conf.packet_mark, sizeof(conf.packet_mark))) {
		pr_error_errno("setsockopt: unable to set packet mark");
		goto error;
	}
#endif

	if (bind(fd, &bind_address.sa, bind_address.sa.sa_family == AF_INET6 ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in))) {
		pr_error_errno("bind: unable to bind socket");
		goto error;
	}

	if (fastd_peer_address_host_v4_multicast(&addr->addr)) {
		if (setsockopt(fd, IPPROTO_IP, IP_MULTICAST_LOOP, &zero, sizeof(zero))) {
			pr_error_errno("setsockopt: unable to disable IPv4 multicast loop");
			goto error;
		}

		struct ip_mreqn mreq = { .imr_multiaddr = addr->addr.in.sin_addr, .imr_address = { .s_addr = INADDR_ANY } };
		if (addr->sourceaddr.sa.sa_family != AF_UNSPEC)
			mreq.imr_address = addr->sourceaddr.in.sin_addr;
		if (addr->bindtodev) {
			mreq.imr_ifindex = if_nametoindex(addr->bindtodev);
			if (!mreq.imr_ifindex) {
				pr_error_errno("if_nametoindex: failed to resolve IPv4 multicast device");
				goto error;
			}
		}

		if (setsockopt(fd, IPPROTO_IP, IP_MULTICAST_IF, &mreq, sizeof(mreq))) {
			pr_error_errno("setsockopt: unable to set up IPv4 multicast binding");
			goto error;
		}

		if (setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq))) {
			pr_error_errno("setsockopt: unable to join IPv4 multicast group");
			goto error;
		}
	} else if (fastd_peer_address_host_v6_multicast(&addr->addr)) {
		if (setsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, &zero, sizeof(zero))) {
			pr_error_errno("setsockopt: unable to disable IPv6 multicast loop");
			goto error;
		}

		struct ipv6_mreq mreq = { .ipv6mr_multiaddr = addr->addr.in6.sin6_addr, .ipv6mr_interface = if_nametoindex(addr->bindtodev) };
		if (!mreq.ipv6mr_interface) {
			pr_error_errno("if_nametoindex: failed to resolve IPv6 multicast device");
			goto error;
		}

		if (setsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_IF, &mreq.ipv6mr_interface, sizeof(mreq.ipv6mr_interface))) {
			pr_error_errno("setsockopt: unable to set up IPv6 multicast binding");
			goto error;
		}

		if (setsockopt(fd, IPPROTO_IPV6, IPV6_JOIN_GROUP, &mreq, sizeof(mreq))) {
			pr_error_errno("setsockopt: unable to join IPv6 multicast group");
			goto error;
		}
	}

#ifdef __ANDROID__
	if (!fastd_android_protect_socket(fd)) {
		pr_error("error protecting socket");
		goto error;
	}
#endif

	return fd;

error:
	if (fd >= 0 && close(fd))
		pr_error_errno("close");

	if (addr->bindtodev)
		pr_error(fastd_peer_address_host_v6_ll(&bind_address) ? "unable to bind to %L" : "unable to bind to %B on `%s'", &bind_address, addr->bindtodev);
	else
		pr_error("unable to bind to %B", &bind_address);

	return -1;
}

/** Gets the address a socket is bound to and sets it in the socket structure */
static void set_bound_address(fastd_socket_t *sock) {
	fastd_peer_address_t addr = {};
	socklen_t len = sizeof(addr);

	if (getsockname(sock->fd.fd, &addr.sa, &len) < 0)
		exit_errno("getsockname");

	if (sock->addr->sourceaddr.sa.sa_family != AF_UNSPEC) {
		sock->bound_addr = sock->addr->sourceaddr;

		if (addr.sa.sa_family == AF_INET6) {
			fastd_peer_address_widen(&sock->bound_addr);
			sock->bound_addr.in6.sin6_port = addr.in6.sin6_port;
		} else
			sock->bound_addr.in.sin_port = addr.in.sin_port;
	} else
		sock->bound_addr = addr;
}

/** Set up discovery timeout based on socket binding state */
static void reset_discovery_timeout(fastd_socket_t *sock) {
	if (sock->addr->discovery_interval != FASTD_TIMEOUT_INV)
		sock->discovery_timeout = ctx.now + sock->addr->discovery_interval;
	else
		sock->discovery_timeout = FASTD_TIMEOUT_INV;
}

/** (Re)schedule socket task based on the timeout bound to socket */
static void schedule_socket_task(fastd_socket_t *sock) {
	if (sock->discovery_timeout == FASTD_TIMEOUT_INV) {
		pr_debug2("removing scheduled task for socket %B", &sock->bound_addr);
		fastd_task_unschedule(&sock->task);
	} else if (fastd_task_timeout(&sock->task) > sock->discovery_timeout) {
		pr_debug2("replacing scheduled task for socket %B", &sock->bound_addr);
		fastd_task_unschedule(&sock->task);
		fastd_task_schedule(&sock->task, TASK_TYPE_SOCKET, sock->discovery_timeout);
	} else
		pr_debug2("keeping scheduled task for socket %B", &sock->bound_addr);
}

/** Tries to initialize sockets for all configured bind addresses */
void fastd_socket_bind_all(void) {
	size_t i;

	for (i = 0; i < ctx.n_socks; i++) {
		fastd_socket_t *sock = &ctx.socks[i];

		if (!sock->addr)
			continue;

		sock->fd = FASTD_POLL_FD(POLL_TYPE_SOCKET, bind_socket(sock->addr));
		if (sock->fd.fd < 0)
			exit(1); /* message has already been printed */

		set_bound_address(sock);
		reset_discovery_timeout(sock);

		if (sock->addr->bindtodev && !fastd_peer_address_host_v6_ll(&sock->bound_addr))
			pr_info("bound to %B on `%s'", &sock->bound_addr, sock->addr->bindtodev);
		else
			pr_info("bound to %B", &sock->bound_addr);

		fastd_poll_fd_register(&sock->fd);
		schedule_socket_task(sock);
	}
}

/** Opens a single socket bound to a random port for the given address family */
fastd_socket_t * fastd_socket_open(fastd_peer_t *peer, int af) {
	const fastd_bind_address_t any_address = { .addr.sa.sa_family = af, .discovery_interval = FASTD_TIMEOUT_INV };
	const fastd_bind_address_t *bind_address;

	if (af == AF_INET && conf.bind_addr_default_v4) {
		bind_address = conf.bind_addr_default_v4;
	}
	else if (af == AF_INET6 && conf.bind_addr_default_v6) {
		bind_address = conf.bind_addr_default_v6;
	}
	else if (!conf.bind_addr_default_v4 && !conf.bind_addr_default_v6) {
		bind_address = &any_address;
	}
	else {
		pr_debug("not opening an %s socket for peer %P (no bind address with matching address family)", (af == AF_INET6) ? "IPv6" : "IPv4", peer);
		return NULL;
	}

	int fd = bind_socket(bind_address);
	if (fd < 0)
		return NULL;

	fastd_socket_t *sock = fastd_new(fastd_socket_t);

	sock->fd = FASTD_POLL_FD(POLL_TYPE_SOCKET, fd);
	sock->addr = NULL;
	sock->peer = peer;

	set_bound_address(sock);
	reset_discovery_timeout(sock);

	fastd_poll_fd_register(&sock->fd);
	schedule_socket_task(sock);

	return sock;
}

/** Closes a socket */
void fastd_socket_close(fastd_socket_t *sock) {
	if (sock->fd.fd >= 0) {
		if (!fastd_poll_fd_close(&sock->fd))
			pr_error_errno("closing socket: close");

		sock->fd.fd = -1;
	}

	sock->discovery_timeout = FASTD_TIMEOUT_INV;
	schedule_socket_task(sock);
}

/** Handles an error that occured on a socket */
void fastd_socket_error(fastd_socket_t *sock) {
	if (sock->addr->bindtodev && !fastd_peer_address_host_v6_ll(&sock->bound_addr))
		exit_error("error on socket bound to %B on `%s'", &sock->bound_addr, sock->addr->bindtodev);
	else
		exit_error("error on socket bound to %B", &sock->bound_addr);
}

/** Handle socket task for a socket, dispatching discovery */
void fastd_socket_handle_task(fastd_task_t *task) {
	fastd_socket_t *sock = container_of(task, fastd_socket_t, task);

	if (fastd_timed_out(sock->discovery_timeout)) {
		pr_debug("dispatching discovery task to multicast address %B", &sock->addr->addr);
		if (sock->addr->sourceaddr.sa.sa_family != AF_UNSPEC)
			conf.protocol->handshake_init(sock, &sock->bound_addr, &sock->addr->addr, NULL);
		else
			conf.protocol->handshake_init(sock, NULL, &sock->addr->addr, NULL);

		reset_discovery_timeout(sock);
	}

	schedule_socket_task(sock);
}
