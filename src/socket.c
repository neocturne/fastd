// SPDX-License-Identifier: BSD-2-Clause
/*
  Copyright (c) 2012-2016, Matthias Schiffer <mschiffer@universe-factory.net>
  All rights reserved.
*/

/**
   \file

   Socket handling
*/

#include "fastd.h"
#include "polling.h"

#include <net/if.h>


/**
   Creates a new socket bound to a specific address

   \return The new socket's file descriptor
*/
static int bind_socket(const fastd_bind_address_t *addr) {
	int fd = -1;
	int af = AF_UNSPEC;

	if (addr->addr.sa.sa_family != AF_INET) {
		fd = socket(PF_INET6, SOCK_DGRAM | SOCK_NONBLOCK, IPPROTO_UDP);
		if (fd >= 0) {
			af = AF_INET6;

			int val = (addr->addr.sa.sa_family == AF_INET6);
			if (setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &val, sizeof(val))) {
				pr_warn_errno("setsockopt");
				goto error;
			}
		}
	}
	if (fd < 0 && addr->addr.sa.sa_family != AF_INET6) {
		fd = socket(PF_INET, SOCK_DGRAM | SOCK_NONBLOCK, IPPROTO_UDP);
		if (fd < 0)
			exit_errno("unable to create socket");
		else
			af = AF_INET;
	}

	if (fd < 0)
		goto error;

#ifdef NO_HAVE_SOCK_NONBLOCK
	fastd_setnonblock(fd);
#endif

	int one = 1;

#ifdef USE_PKTINFO
	if (setsockopt(fd, IPPROTO_IP, IP_PKTINFO, &one, sizeof(one))) {
		pr_error_errno("setsockopt: unable to set IP_PKTINFO");
		goto error;
	}
#endif

#ifdef USE_FREEBIND
	if (setsockopt(fd, IPPROTO_IP, IP_FREEBIND, &one, sizeof(one)))
		pr_warn_errno("setsockopt: unable to set IP_FREEBIND");
#endif

	if (af == AF_INET6) {
		if (setsockopt(fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &one, sizeof(one))) {
			pr_error_errno("setsockopt: unable to set IPV6_RECVPKTINFO");
			goto error;
		}
	}

#ifdef USE_BINDTODEVICE
	if (addr->bindtodev && !fastd_peer_address_is_v6_ll(&addr->addr)) {
		if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, addr->bindtodev, strlen(addr->bindtodev))) {
			pr_warn_errno("setsockopt: unable to bind to device");
			goto error;
		}
	}
#endif

#ifdef USE_PMTU
	int pmtu = IP_PMTUDISC_DONT;
	if (setsockopt(fd, IPPROTO_IP, IP_MTU_DISCOVER, &pmtu, sizeof(pmtu))) {
		pr_error_errno("setsockopt: unable to disable PMTU discovery");
		goto error;
	}
#endif

#ifdef USE_PACKET_MARK
	if (conf.packet_mark) {
		if (setsockopt(fd, SOL_SOCKET, SO_MARK, &conf.packet_mark, sizeof(conf.packet_mark))) {
			pr_error_errno("setsockopt: unable to set packet mark");
			goto error;
		}
	}
#endif

	fastd_peer_address_t bind_address = addr->addr;

	if (fastd_peer_address_is_v6_ll(&addr->addr) && addr->bindtodev) {
		char *end;
		bind_address.in6.sin6_scope_id = strtoul(addr->bindtodev, &end, 10);

		if (*end)
			bind_address.in6.sin6_scope_id = if_nametoindex(addr->bindtodev);

		if (!bind_address.in6.sin6_scope_id) {
			pr_warn_errno("if_nametoindex");
			goto error;
		}
	}

	if (bind_address.sa.sa_family == AF_UNSPEC) {
		memset(&bind_address, 0, sizeof(bind_address));
		bind_address.sa.sa_family = af;

		if (af == AF_INET6)
			bind_address.in6.sin6_port = addr->addr.in.sin_port;
		else
			bind_address.in.sin_port = addr->addr.in.sin_port;
	}

	if (bind(fd, &bind_address.sa,
		 bind_address.sa.sa_family == AF_INET6 ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in))) {
		pr_warn_errno("bind");
		goto error;
	}

#ifdef __ANDROID__
	if (!fastd_android_protect_socket(fd)) {
		pr_error("error protecting socket");
		goto error;
	}
#endif

	return fd;

error:
	if (fd >= 0) {
		if (close(fd))
			pr_error_errno("close");
	}

	if (addr->bindtodev)
		pr_error(
			fastd_peer_address_is_v6_ll(&addr->addr) ? "unable to bind to %L"
								 : "unable to bind to %B on `%s'",
			&addr->addr, addr->bindtodev);
	else
		pr_error("unable to bind to %B", &addr->addr);

	return -1;
}

/** Gets the address a socket is bound to and sets it in the socket structure */
static void set_bound_address(fastd_socket_t *sock) {
	fastd_peer_address_t addr = {};
	socklen_t len = sizeof(addr);

	if (getsockname(sock->fd.fd, &addr.sa, &len) < 0)
		exit_errno("getsockname");

	sock->bound_addr = fastd_new(fastd_peer_address_t);
	*sock->bound_addr = addr;
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

		fastd_peer_address_t bound_addr = *sock->bound_addr;
		if (!sock->addr->addr.sa.sa_family)
			bound_addr.sa.sa_family = AF_UNSPEC;

		if (sock->addr->bindtodev && !fastd_peer_address_is_v6_ll(&bound_addr))
			pr_info("bound to %B on `%s'", &bound_addr, sock->addr->bindtodev);
		else
			pr_info("bound to %B", &bound_addr);

		fastd_poll_fd_register(&sock->fd);
	}
}

/** Opens a single socket bound to a random port for the given address family */
fastd_socket_t *fastd_socket_open(fastd_peer_t *peer, int af) {
	const fastd_bind_address_t any_address = { .addr.sa.sa_family = af };

	const fastd_bind_address_t *bind_address;

	if (af == AF_INET && conf.bind_addr_default_v4) {
		bind_address = conf.bind_addr_default_v4;
	} else if (af == AF_INET6 && conf.bind_addr_default_v6) {
		bind_address = conf.bind_addr_default_v6;
	} else if (!conf.bind_addr_default_v4 && !conf.bind_addr_default_v6) {
		bind_address = &any_address;
	} else {
		pr_debug(
			"not opening an %s socket for peer %P (no bind address with matching address family)",
			(af == AF_INET6) ? "IPv6" : "IPv4", peer);
		return NULL;
	}

	int fd = bind_socket(bind_address);
	if (fd < 0)
		return NULL;

	fastd_socket_t *sock = fastd_new0(fastd_socket_t);

	sock->fd = FASTD_POLL_FD(POLL_TYPE_SOCKET, fd);
	sock->peer = peer;

	set_bound_address(sock);

	fastd_poll_fd_register(&sock->fd);

	return sock;
}

/** Closes a socket */
void fastd_socket_close(fastd_socket_t *sock) {
	if (sock->fd.fd >= 0) {
		if (!fastd_poll_fd_close(&sock->fd))
			pr_error_errno("closing socket: close");

		sock->fd.fd = -1;
	}

	if (sock->bound_addr) {
		free(sock->bound_addr);
		sock->bound_addr = NULL;
	}
}

/** Handles an error that occured on a socket */
void fastd_socket_error(const fastd_socket_t *sock) {
	/* This function is only called for sockets that have been registered
	 * for polling. This implies that bound_addr is set. */
	pr_debug2("error on socket bound to %B", sock->bound_addr);

	int error;
	socklen_t errlen = sizeof(error);
	getsockopt(sock->fd.fd, SOL_SOCKET, SO_ERROR, &error, &errlen);
}
