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

   Socket handling
*/

#include "fastd.h"
#include "poll.h"


/**
   Creates a new socket bound to a specific address

   \return The new socket's file descriptor
*/
static int bind_socket(const fastd_bind_address_t *addr, bool warn) {
	int fd = -1;
	int af = AF_UNSPEC;

	if (addr->addr.sa.sa_family != AF_INET) {
		fd = socket(PF_INET6, SOCK_DGRAM|SOCK_NONBLOCK, IPPROTO_UDP);
		if (fd >= 0) {
			af = AF_INET6;

			int val = (addr->addr.sa.sa_family == AF_INET6);
			if (setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &val, sizeof(val))) {
				if (warn)
					pr_warn_errno("setsockopt");
				goto error;
			}
		}
	}
	if (fd < 0 && addr->addr.sa.sa_family != AF_INET6) {
		fd = socket(PF_INET, SOCK_DGRAM|SOCK_NONBLOCK, IPPROTO_UDP);
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
			if (warn)
				pr_warn_errno("setsockopt: unable to bind to device");
			goto error;
		}
	}
#endif

#ifdef USE_PMTU
	if (conf.pmtu.set) {
		int pmtu = conf.pmtu.state ? IP_PMTUDISC_DO : IP_PMTUDISC_DONT;
		if (setsockopt(fd, IPPROTO_IP, IP_MTU_DISCOVER, &pmtu, sizeof(pmtu))) {
			pr_error_errno("setsockopt: unable to set PMTU discovery");
			goto error;
		}
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
			if (warn)
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

	if (bind(fd, &bind_address.sa, bind_address.sa.sa_family == AF_INET6 ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in))) {
		if (warn)
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

	if (warn) {
		if (addr->bindtodev)
			pr_warn(fastd_peer_address_is_v6_ll(&addr->addr) ? "unable to bind to %L" : "unable to bind to %B on `%s'", &addr->addr, addr->bindtodev);
		else
			pr_warn("unable to bind to %B", &addr->addr);
	}

	return -1;
}

/** Gets the address a socket is bound to and sets it in the socket structure */
static bool set_bound_address(fastd_socket_t *sock) {
	fastd_peer_address_t addr = {};
	socklen_t len = sizeof(addr);

	if (getsockname(sock->fd, &addr.sa, &len) < 0) {
		pr_error_errno("getsockname");
		return false;
	}

	if (len > sizeof(addr)) {
		pr_error("getsockname: got strange long address");
		return false;
	}

	sock->bound_addr = fastd_new0(fastd_peer_address_t);
	*sock->bound_addr = addr;

	return true;
}

/** Tries to initialize sockets for all configured bind addresses */
bool fastd_socket_handle_binds(void) {
	size_t i;

	for (i = 0; i < ctx.n_socks; i++) {
		if (ctx.socks[i].fd >= 0)
			continue;

		if (!ctx.socks[i].addr)
			continue;

		ctx.socks[i].fd = bind_socket(ctx.socks[i].addr, ctx.socks[i].fd < -1);

		if (ctx.socks[i].fd >= 0) {
			if (!set_bound_address(&ctx.socks[i])) {
				fastd_socket_close(&ctx.socks[i]);
				continue;
			}

			fastd_poll_set_fd_sock(i);

			fastd_peer_address_t bound_addr = *ctx.socks[i].bound_addr;
			if (!ctx.socks[i].addr->addr.sa.sa_family)
				bound_addr.sa.sa_family = AF_UNSPEC;

			if (ctx.socks[i].addr->bindtodev && !fastd_peer_address_is_v6_ll(&bound_addr))
				pr_info("successfully bound to %B on `%s'", &bound_addr, ctx.socks[i].addr->bindtodev);
			else
				pr_info("successfully bound to %B", &bound_addr);
		}
	}

	if ((ctx.sock_default_v4 && ctx.sock_default_v4->fd < 0) || (ctx.sock_default_v6 && ctx.sock_default_v6->fd < 0))
		return false;

	return true;
}

/** Opens a single socket bound to a random port for the given address family */
fastd_socket_t * fastd_socket_open(fastd_peer_t *peer, int af) {
	const fastd_bind_address_t any_address = { .addr.sa.sa_family = af };

	const fastd_bind_address_t *bind_address;

	if (af == AF_INET && conf.bind_addr_default_v4)
		bind_address = conf.bind_addr_default_v4;
	else if (af == AF_INET6 && conf.bind_addr_default_v6)
		bind_address = conf.bind_addr_default_v6;
	else
		bind_address = &any_address;

	int fd = bind_socket(bind_address, true);
	if (fd < 0)
		return NULL;

	fastd_socket_t *sock = fastd_new(fastd_socket_t);

	sock->fd = fd;
	sock->addr = NULL;
	sock->bound_addr = NULL;
	sock->peer = peer;

	if (!set_bound_address(sock)) {
		fastd_socket_close(sock);
		free(sock);
		return NULL;
	}

	return sock;
}

/** Closes a socket */
void fastd_socket_close(fastd_socket_t *sock) {
	if (sock->fd >= 0) {
		if(close(sock->fd))
			pr_error_errno("closing socket: close");

		sock->fd = -2;
	}

	if (sock->bound_addr) {
		free(sock->bound_addr);
		sock->bound_addr = NULL;
	}
}

/** Handles an error that occured on a socket */
void fastd_socket_error(fastd_socket_t *sock) {
	if (sock->addr->bindtodev)
		pr_warn("socket bind %I on `%s' lost", &sock->addr->addr, sock->addr->bindtodev);
	else
		pr_warn("socket bind %I lost", &sock->addr->addr);

	fastd_socket_close(sock);
}
