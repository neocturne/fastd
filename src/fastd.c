/*
  Copyright (c) 2012-2013, Matthias Schiffer <mschiffer@universe-factory.net>
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


#define _GNU_SOURCE

#include "fastd.h"
#include "crypto.h"
#include "handshake.h"
#include "peer.h"
#include "task.h"

#include <fcntl.h>
#include <grp.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <sys/socket.h>


static volatile bool sighup = false;
static volatile bool terminate = false;
static volatile bool dump = false;


static void on_sighup(int signo) {
	sighup = true;
}

static void on_terminate(int signo) {
	terminate = true;
}

static void on_sigusr1(int signo) {
	dump = true;
}

static void init_signals(fastd_context_t *ctx) {
	struct sigaction action;

	action.sa_flags = 0;
	sigemptyset(&action.sa_mask);

	action.sa_handler = on_sighup;
	if(sigaction(SIGHUP, &action, NULL))
		exit_errno(ctx, "sigaction");

	action.sa_handler = on_terminate;
	if(sigaction(SIGTERM, &action, NULL))
		exit_errno(ctx, "sigaction");
	if(sigaction(SIGQUIT, &action, NULL))
		exit_errno(ctx, "sigaction");
	if(sigaction(SIGINT, &action, NULL))
		exit_errno(ctx, "sigaction");

	action.sa_handler = on_sigusr1;
	if(sigaction(SIGUSR1, &action, NULL))
		exit_errno(ctx, "sigaction");

	action.sa_handler = SIG_IGN;
	if(sigaction(SIGPIPE, &action, NULL))
		exit_errno(ctx, "sigaction");
}

static void init_pipes(fastd_context_t *ctx) {
	int pipefd[2];

	if (pipe(pipefd))
		exit_errno(ctx, "pipe");

	fastd_setfd(ctx, pipefd[0], FD_CLOEXEC, 0);
	fastd_setfd(ctx, pipefd[1], FD_CLOEXEC, 0);

	ctx->resolverfd = pipefd[0];
	ctx->resolvewfd = pipefd[1];
}

static void init_log(fastd_context_t *ctx) {
	uid_t uid = geteuid();
	gid_t gid = getegid();

	if (ctx->conf->user || ctx->conf->group) {
		if (setegid(ctx->conf->gid) < 0)
			pr_debug_errno(ctx, "setegid");
		if (seteuid(ctx->conf->uid) < 0)
			pr_debug_errno(ctx, "seteuid");
	}

	if (ctx->conf->log_syslog_level >= 0)
		openlog(ctx->conf->log_syslog_ident, LOG_PID, LOG_DAEMON);

	fastd_log_file_t *config;
	for (config = ctx->conf->log_files; config; config = config->next) {
		fastd_log_fd_t *file = malloc(sizeof(fastd_log_fd_t));

		file->config = config;
		file->fd = open(config->filename, O_WRONLY|O_APPEND|O_CREAT, 0600);

		file->next = ctx->log_files;
		ctx->log_files = file;
	}

	if (seteuid(uid) < 0)
		pr_debug_errno(ctx, "seteuid");
	if (setegid(gid) < 0)
		pr_debug_errno(ctx, "setegid");
}

static void close_log(fastd_context_t *ctx) {
	while (ctx->log_files) {
		fastd_log_fd_t *next = ctx->log_files->next;

		close(ctx->log_files->fd);
		free(ctx->log_files);

		ctx->log_files = next;
	}

	closelog();
}

static void crypto_init(fastd_context_t *ctx) {
#ifdef USE_CRYPTO_AES128CTR
	ctx->crypto_aes128ctr = ctx->conf->crypto_aes128ctr->init(ctx);
	if (!ctx->crypto_aes128ctr)
		exit_error(ctx, "Unable to initialize AES128-CTR implementation");
#endif

#ifdef USE_CRYPTO_GHASH
	ctx->crypto_ghash = ctx->conf->crypto_ghash->init(ctx);
	if (!ctx->crypto_ghash)
		exit_error(ctx, "Unable to initialize GHASH implementation");
#endif
}

static void crypto_free(fastd_context_t *ctx) {
#ifdef USE_CRYPTO_AES128CTR
	ctx->conf->crypto_aes128ctr->free(ctx, ctx->crypto_aes128ctr);
	ctx->crypto_aes128ctr = NULL;
#endif

#ifdef USE_CRYPTO_GHASH
	ctx->conf->crypto_ghash->free(ctx, ctx->crypto_ghash);
	ctx->crypto_ghash = NULL;
#endif
}


static void init_sockets(fastd_context_t *ctx) {
	ctx->socks = malloc(ctx->conf->n_bind_addrs * sizeof(fastd_socket_t));

	unsigned i;
	fastd_bind_address_t *addr = ctx->conf->bind_addrs;
	for (i = 0; i < ctx->conf->n_bind_addrs; i++) {
		ctx->socks[i] = (fastd_socket_t){-2, addr, NULL};

		if (addr == ctx->conf->bind_addr_default_v4)
			ctx->sock_default_v4 = &ctx->socks[i];

		if (addr == ctx->conf->bind_addr_default_v6)
			ctx->sock_default_v6 = &ctx->socks[i];

		addr = addr->next;
	}

	ctx->n_socks = ctx->conf->n_bind_addrs;
}

static int bind_socket(fastd_context_t *ctx, const fastd_bind_address_t *addr, bool warn) {
	int fd = -1;
	int af = AF_UNSPEC;

	if (addr->addr.sa.sa_family != AF_INET) {
		fd = socket(PF_INET6, SOCK_DGRAM, IPPROTO_UDP);
		if (fd >= 0) {
			af = AF_INET6;

			int val = (addr->addr.sa.sa_family == AF_INET6);
			if (setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &val, sizeof(val))) {
				if (warn)
					pr_warn_errno(ctx, "setsockopt");
				goto error;
			}
		}
	}
	if (fd < 0 && addr->addr.sa.sa_family != AF_INET6) {
		fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
		if (fd < 0)
			exit_errno(ctx, "unable to create socket");
		else
			af = AF_INET;
	}

	if (fd < 0)
		goto error;

	fastd_setfd(ctx, fd, FD_CLOEXEC, 0);
	fastd_setfl(ctx, fd, O_NONBLOCK, 0);

	int one = 1;
	if (setsockopt(fd, IPPROTO_IP, IP_PKTINFO, &one, sizeof(one))) {
		pr_error_errno(ctx, "setsockopt: unable to set IP_PKTINFO");
		goto error;
	}

	if (af == AF_INET6) {
		if (setsockopt(fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &one, sizeof(one))) {
			pr_error_errno(ctx, "setsockopt: unable to set IPV6_RECVPKTINFO");
			goto error;
		}
	}

	if (addr->bindtodev) {
		if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, addr->bindtodev, strlen(addr->bindtodev))) {
			if (warn)
				pr_warn_errno(ctx, "setsockopt: unable to bind to device");
			goto error;
		}
	}

	fastd_peer_address_t bind_address = addr->addr;

	if (bind_address.sa.sa_family == AF_UNSPEC) {
		memset(&bind_address, 0, sizeof(bind_address));
		bind_address.sa.sa_family = af;

		if (af == AF_INET6)
			bind_address.in6.sin6_port = addr->addr.in.sin_port;
		else
			bind_address.in.sin_port = addr->addr.in.sin_port;
	}

	if (bind(fd, (struct sockaddr*)&bind_address, af == AF_INET6 ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in))) {
		if (warn)
			pr_warn_errno(ctx, "bind");
		goto error;
	}

	return fd;

 error:
	if (fd >= 0) {
		if (close(fd))
			pr_error_errno(ctx, "close");
	}

	if (warn) {
		if (addr->bindtodev)
			pr_warn(ctx, "unable to bind to %B on `%s'", &addr->addr, addr->bindtodev);
		else
			pr_warn(ctx, "unable to bind to %B", &addr->addr);
	}

	return -1;
}

static bool set_bound_address(fastd_context_t *ctx, fastd_socket_t *sock) {
	fastd_peer_address_t addr = {};
	socklen_t len = sizeof(addr);

	if (getsockname(sock->fd, &addr.sa, &len) < 0) {
		pr_error_errno(ctx, "getsockname");
		return false;
	}

	if (len > sizeof(addr)) {
		pr_error(ctx, "getsockname: got strange long address");
		return false;
	}

	sock->bound_addr = calloc(1, sizeof(addr));
	*sock->bound_addr = addr;

	return true;
}

static bool bind_sockets(fastd_context_t *ctx) {
	unsigned i;

	for (i = 0; i < ctx->n_socks; i++) {
		if (ctx->socks[i].fd >= 0)
			continue;

		ctx->socks[i].fd = bind_socket(ctx, ctx->socks[i].addr, ctx->socks[i].fd < -1);

		if (ctx->socks[i].fd >= 0) {
			if (!set_bound_address(ctx, &ctx->socks[i])) {
				fastd_socket_close(ctx, &ctx->socks[i]);
				continue;
			}

			fastd_peer_address_t bound_addr = *ctx->socks[i].bound_addr;
			if (!ctx->socks[i].addr->addr.sa.sa_family)
				bound_addr.sa.sa_family = AF_UNSPEC;

			if (ctx->socks[i].addr->bindtodev)
				pr_info(ctx, "successfully bound to %B on `%s'", &bound_addr, ctx->socks[i].addr->bindtodev);
			else
				pr_info(ctx, "successfully bound to %B", &bound_addr);
		}
	}

	if ((ctx->sock_default_v4 && ctx->sock_default_v4->fd < 0) || (ctx->sock_default_v6 && ctx->sock_default_v6->fd < 0))
		return false;

	return true;
}

fastd_socket_t* fastd_socket_open(fastd_context_t *ctx, fastd_peer_t *peer, int af) {
	const fastd_bind_address_t any_address = { .addr.sa.sa_family = af };

	int fd = bind_socket(ctx, &any_address, true);
	if (fd < 0)
		return NULL;

	fastd_socket_t *sock = malloc(sizeof(fastd_socket_t));

	sock->fd = fd;
	sock->addr = NULL;
	sock->bound_addr = NULL;
	sock->peer = peer;

	if (!set_bound_address(ctx, sock)) {
		fastd_socket_close(ctx, sock);
		free(sock);
		return NULL;
	}

	return sock;
}

void fastd_setfd(const fastd_context_t *ctx, int fd, int set, int unset) {
	int flags = fcntl(fd, F_GETFD);
	if (flags < 0)
		exit_errno(ctx, "Getting file descriptor flags failed: fcntl");

	if (fcntl(fd, F_SETFD, (flags|set) & (~unset)) < 0)
		exit_errno(ctx, "Setting file descriptor flags failed: fcntl");
}

void fastd_setfl(const fastd_context_t *ctx, int fd, int set, int unset) {
	int flags = fcntl(fd, F_GETFL);
	if (flags < 0)
		exit_errno(ctx, "Getting file status flags failed: fcntl");

	if (fcntl(fd, F_SETFL, (flags|set) & (~unset)) < 0)
		exit_errno(ctx, "Setting file status flags failed: fcntl");
}

static void init_tuntap(fastd_context_t *ctx) {
	struct ifreq ifr;

	pr_debug(ctx, "initializing tun/tap device...");

	if ((ctx->tunfd = open("/dev/net/tun", O_RDWR|O_CLOEXEC|O_NONBLOCK)) < 0)
		exit_errno(ctx, "could not open tun/tap device file");

	memset(&ifr, 0, sizeof(ifr));

	if (ctx->conf->ifname)
		strncpy(ifr.ifr_name, ctx->conf->ifname, IFNAMSIZ-1);

	switch (ctx->conf->mode) {
	case MODE_TAP:
		ifr.ifr_flags = IFF_TAP;
		break;

	case MODE_TUN:
		ifr.ifr_flags = IFF_TUN;
		break;

	default:
		exit_bug(ctx, "invalid mode");
	}

	ifr.ifr_flags |= IFF_NO_PI;
	if (ioctl(ctx->tunfd, TUNSETIFF, &ifr) < 0)
		exit_errno(ctx, "TUNSETIFF ioctl failed");

	ctx->ifname = strndup(ifr.ifr_name, IFNAMSIZ-1);

	int ctl_sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (ctl_sock < 0)
		exit_errno(ctx, "socket");

	if (ioctl(ctl_sock, SIOCGIFMTU, &ifr) < 0)
		exit_errno(ctx, "SIOCGIFMTU ioctl failed");

	if (ifr.ifr_mtu != ctx->conf->mtu) {
		ifr.ifr_mtu = ctx->conf->mtu;
		if (ioctl(ctl_sock, SIOCSIFMTU, &ifr) < 0)
			exit_errno(ctx, "SIOCSIFMTU ioctl failed");
	}

	if (close(ctl_sock))
		pr_error_errno(ctx, "close");

	pr_debug(ctx, "tun/tap device initialized.");
}

static void close_tuntap(fastd_context_t *ctx) {
	if(close(ctx->tunfd))
		pr_warn_errno(ctx, "closing tun/tap: close");

	free(ctx->ifname);
}

static void close_sockets(fastd_context_t *ctx) {
	unsigned i;
	for (i = 0; i < ctx->n_socks; i++)
		fastd_socket_close(ctx, &ctx->socks[i]);

	free(ctx->socks);
}

static size_t methods_max_packet_size(fastd_context_t *ctx) {
	size_t ret = ctx->conf->methods[0]->max_packet_size(ctx);

	int i;
	for (i = 0; i < MAX_METHODS; i++) {
		if (!ctx->conf->methods[i])
			break;

		size_t s = ctx->conf->methods[i]->max_packet_size(ctx);
		if (s > ret)
			ret = s;
	}

	return ret;
}

static size_t methods_min_encrypt_head_space(fastd_context_t *ctx) {
	size_t ret = 0;

	int i;
	for (i = 0; i < MAX_METHODS; i++) {
		if (!ctx->conf->methods[i])
			break;

		size_t s = ctx->conf->methods[i]->min_encrypt_head_space(ctx);
		if (s > ret)
			ret = s;
	}

	return alignto(ret, 16);
}

static size_t methods_min_decrypt_head_space(fastd_context_t *ctx) {
	size_t ret = 0;

	int i;
	for (i = 0; i < MAX_METHODS; i++) {
		if (!ctx->conf->methods[i])
			break;

		size_t s = ctx->conf->methods[i]->min_decrypt_head_space(ctx);
		if (s > ret)
			ret = s;
	}

	/* ugly hack to get alignment right for aes128-gcm, which needs data aligned to 16 and has a 24 byte header */
	return alignto(ret, 16) + 8;
}

static size_t methods_min_encrypt_tail_space(fastd_context_t *ctx) {
	size_t ret = 0;

	int i;
	for (i = 0; i < MAX_METHODS; i++) {
		if (!ctx->conf->methods[i])
			break;

		size_t s = ctx->conf->methods[i]->min_encrypt_tail_space(ctx);
		if (s > ret)
			ret = s;
	}

	return ret;
}

static size_t methods_min_decrypt_tail_space(fastd_context_t *ctx) {
	size_t ret = 0;

	int i;
	for (i = 0; i < MAX_METHODS; i++) {
		if (!ctx->conf->methods[i])
			break;

		size_t s = ctx->conf->methods[i]->min_decrypt_tail_space(ctx);
		if (s > ret)
			ret = s;
	}

	return ret;
}

static void fastd_send_type(fastd_context_t *ctx, const fastd_socket_t *sock, const fastd_peer_address_t *local_addr, const fastd_peer_address_t *remote_addr, uint8_t packet_type, fastd_buffer_t buffer) {
	if (!sock)
		exit_bug(ctx, "send: sock == NULL");

	struct msghdr msg = {};
	char cbuf[1024] = {};

	switch (remote_addr->sa.sa_family) {
	case AF_INET:
		msg.msg_name = (void*)&remote_addr->in;
		msg.msg_namelen = sizeof(struct sockaddr_in);
		break;

	case AF_INET6:
		msg.msg_name = (void*)&remote_addr->in6;
		msg.msg_namelen = sizeof(struct sockaddr_in6);
		break;

	default:
		exit_bug(ctx, "unsupported address family");
	}

	struct iovec iov[2] = {
		{ .iov_base = &packet_type, .iov_len = 1 },
		{ .iov_base = buffer.data, .iov_len = buffer.len }
	};

	msg.msg_iov = iov;
	msg.msg_iovlen = buffer.len ? 2 : 1;

	if (local_addr && (local_addr->sa.sa_family == AF_INET || local_addr->sa.sa_family == AF_INET6)) {
		msg.msg_control = cbuf;
		msg.msg_controllen = sizeof(cbuf);

		struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);

		if (local_addr->sa.sa_family == AF_INET) {
			cmsg->cmsg_level = IPPROTO_IP;
			cmsg->cmsg_type = IP_PKTINFO;

			msg.msg_controllen = cmsg->cmsg_len = CMSG_LEN(sizeof(struct in_pktinfo));

			struct in_pktinfo *pktinfo = (struct in_pktinfo*)CMSG_DATA(cmsg);
			pktinfo->ipi_addr = local_addr->in.sin_addr;
		}
		else {
			cmsg->cmsg_level = IPPROTO_IPV6;
			cmsg->cmsg_type = IPV6_PKTINFO;

			msg.msg_controllen = cmsg->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));

			struct in6_pktinfo *pktinfo = (struct in6_pktinfo*)CMSG_DATA(cmsg);

			pktinfo->ipi6_addr = local_addr->in6.sin6_addr;

			if (IN6_IS_ADDR_LINKLOCAL(&local_addr->in6.sin6_addr))
				pktinfo->ipi6_ifindex = local_addr->in6.sin6_scope_id;
		}
	}

	int ret;
	do {
		ret = sendmsg(sock->fd, &msg, 0);
	} while (ret < 0 && errno == EINTR);

	if (ret < 0)
		pr_warn_errno(ctx, "sendmsg");

	fastd_buffer_free(buffer);
}

void fastd_send(fastd_context_t *ctx, const fastd_socket_t *sock, const fastd_peer_address_t *local_addr, const fastd_peer_address_t *remote_addr, fastd_buffer_t buffer) {
	fastd_send_type(ctx, sock, local_addr, remote_addr, PACKET_DATA, buffer);
}

void fastd_send_handshake(fastd_context_t *ctx, const fastd_socket_t *sock, const fastd_peer_address_t *local_addr, const fastd_peer_address_t *remote_addr, fastd_buffer_t buffer) {
	fastd_send_type(ctx, sock, local_addr, remote_addr, PACKET_HANDSHAKE, buffer);
}

static inline void handle_forward(fastd_context_t *ctx, fastd_peer_t *peer, fastd_buffer_t *buffer) {
	const fastd_eth_addr_t *dest_addr = fastd_get_dest_address(ctx, *buffer);

	if (fastd_eth_addr_is_unicast(dest_addr)) {
		fastd_peer_t *dest_peer = fastd_peer_find_by_eth_addr(ctx, dest_addr);

		if (!dest_peer || dest_peer == peer || !fastd_peer_is_established(dest_peer))
			return;

		ctx->conf->protocol->send(ctx, dest_peer, *buffer);
		*buffer = FASTD_BUFFER_NULL;
	}
	else {
		fastd_peer_t *dest_peer;
		for (dest_peer = ctx->peers; dest_peer; dest_peer = dest_peer->next) {
			if (dest_peer == peer || !fastd_peer_is_established(dest_peer))
				continue;

			ctx->conf->protocol->send(ctx, dest_peer, fastd_buffer_dup(ctx, *buffer, methods_min_encrypt_head_space(ctx), methods_min_encrypt_tail_space(ctx)));
		}
	}
}

void fastd_handle_receive(fastd_context_t *ctx, fastd_peer_t *peer, fastd_buffer_t buffer) {
	if (ctx->conf->mode == MODE_TAP) {
		if (buffer.len < ETH_HLEN) {
			pr_debug(ctx, "received truncated packet");
			fastd_buffer_free(buffer);
			return;
		}

		const fastd_eth_addr_t *src_addr = fastd_get_source_address(ctx, buffer);

		if (fastd_eth_addr_is_unicast(src_addr))
			fastd_peer_eth_addr_add(ctx, peer, src_addr);
	}

	if (write(ctx->tunfd, buffer.data, buffer.len) < 0)
		pr_warn_errno(ctx, "write");

	if (ctx->conf->mode == MODE_TAP && ctx->conf->forward)
		handle_forward(ctx, peer, &buffer);

	fastd_buffer_free(buffer);
}

static inline void on_up(fastd_context_t *ctx) {
	if (!ctx->conf->on_up)
		return;

	fastd_shell_exec(ctx, ctx->conf->on_up, ctx->conf->on_up_dir, NULL, NULL, NULL, NULL);
}

static inline void on_down(fastd_context_t *ctx) {
	if (!ctx->conf->on_down)
		return;

	fastd_shell_exec(ctx, ctx->conf->on_down, ctx->conf->on_down_dir, NULL, NULL, NULL, NULL);
}

static fastd_peer_group_t* init_peer_group(const fastd_peer_group_config_t *config, fastd_peer_group_t *parent) {
	fastd_peer_group_t *ret = calloc(1, sizeof(fastd_peer_group_t));

	ret->conf = config;
	ret->parent = parent;

	fastd_peer_group_t **children = &ret->children;
	fastd_peer_group_config_t *child_config;

	for (child_config = config->children; child_config; child_config = child_config->next) {
		*children = init_peer_group(child_config, ret);
		children = &(*children)->next;
	}

	return ret;
}

static void init_peer_groups(fastd_context_t *ctx) {
	ctx->peer_group = init_peer_group(ctx->conf->peer_group, NULL);
}

static void free_peer_group(fastd_peer_group_t *group) {
	while (group->children) {
		fastd_peer_group_t *child = group->children;
		group->children = group->children->next;

		free_peer_group(child);
	}

	free(group);
}

static void delete_peer_groups(fastd_context_t *ctx) {
	free_peer_group(ctx->peer_group);
}

static void init_peers(fastd_context_t *ctx) {
	fastd_peer_config_t *peer_conf;
	for (peer_conf = ctx->conf->peers; peer_conf; peer_conf = peer_conf->next)
		ctx->conf->protocol->peer_configure(ctx, peer_conf);

	for (peer_conf = ctx->conf->peers; peer_conf; peer_conf = peer_conf->next) {
		bool enable = ctx->conf->protocol->peer_check(ctx, peer_conf);

		if (enable && !peer_conf->enabled)
			fastd_peer_add(ctx, peer_conf);

		peer_conf->enabled = enable;
	}

	fastd_peer_t *peer, *next;
	for (peer = ctx->peers; peer; peer = next) {
		next = peer->next;

		if (peer->config) {
			if (!peer->config->enabled) {
				pr_info(ctx, "previously enabled peer %P disabled, deleting.", peer);
				fastd_peer_delete(ctx, peer);
			}
		}
		else {
			if (!ctx->conf->protocol->peer_check_temporary(ctx, peer))
				fastd_peer_delete(ctx, peer);
		}
	}
}

static void delete_peers(fastd_context_t *ctx) {
	fastd_peer_t *peer, *next;
	for (peer = ctx->peers; peer; peer = next) {
		next = peer->next;

		fastd_peer_delete(ctx, peer);
	}
}

static void dump_peers(fastd_context_t *ctx) {
	pr_info(ctx, "dumping peers...");

	fastd_peer_t *peer;
	for (peer = ctx->peers; peer; peer = peer->next) {
		if (!fastd_peer_is_established(peer)) {
			pr_info(ctx, "peer %P not connected, address: %I", peer, &peer->address);
			continue;
		}

		if (ctx->conf->mode == MODE_TAP) {
			unsigned int eth_addresses = 0;
			size_t i;
			for (i = 0; i < ctx->n_eth_addr; i++) {
				if (ctx->eth_addr[i].peer == peer)
					eth_addresses++;
			}

			pr_info(ctx, "peer %P connected, address: %I, associated MAC addresses: %u", peer, &peer->address, eth_addresses);
		}
		else {
			pr_info(ctx, "peer %P connected, address: %I", peer, &peer->address);
		}
	}

	pr_info(ctx, "peer dump finished.");
}

static inline void update_time(fastd_context_t *ctx) {
	clock_gettime(CLOCK_MONOTONIC, &ctx->now);
}

static inline void schedule_new_handshake(fastd_context_t *ctx, fastd_peer_t *peer) {
	fastd_task_schedule_handshake(ctx, peer, fastd_rand(ctx, 17500, 22500));
}

static void send_handshake(fastd_context_t *ctx, fastd_peer_t *peer) {
	if (!fastd_peer_may_connect(ctx, peer)) {
		schedule_new_handshake(ctx, peer);
		return;
	}

	if (!fastd_peer_is_established(peer))
		fastd_peer_reset_socket(ctx, peer);

	if (peer->sock) {
		if (timespec_diff(&ctx->now, &peer->last_handshake) < ctx->conf->min_handshake_interval*1000
		    && fastd_peer_address_equal(&peer->address, &peer->last_handshake_address)) {
			pr_debug(ctx, "not sending a handshake to %P as we sent one a short time ago", peer);
		}
		else {
			pr_debug(ctx, "sending handshake to %P...", peer);
			peer->last_handshake = ctx->now;
			peer->last_handshake_address = peer->address;
			ctx->conf->protocol->handshake_init(ctx, peer->sock, &peer->local_address, &peer->address, peer);
		}
	}

	schedule_new_handshake(ctx, peer);
}

static void handle_tasks(fastd_context_t *ctx) {
	fastd_task_t *task;
	while ((task = fastd_task_get(ctx)) != NULL) {
		switch (task->type) {
		case TASK_HANDSHAKE:
			if (fastd_peer_is_dynamic(task->peer) && !(fastd_peer_is_floating(task->peer) && fastd_peer_is_established(task->peer))) {
				if (fastd_peer_may_connect(ctx, task->peer))
					fastd_resolve_peer(ctx, task->peer);
				else
					schedule_new_handshake(ctx, task->peer);
			}
			else {
				send_handshake(ctx, task->peer);
			}
			break;

		case TASK_KEEPALIVE:
			pr_debug(ctx, "sending keepalive to %P", task->peer);
			ctx->conf->protocol->send(ctx, task->peer, fastd_buffer_alloc(ctx, 0, methods_min_encrypt_head_space(ctx), methods_min_encrypt_tail_space(ctx)));
			break;

		default:
			exit_bug(ctx, "invalid task type");
		}

		free(task);
	}
}

static void handle_tun(fastd_context_t *ctx) {
	size_t max_len = fastd_max_packet_size(ctx);
	fastd_buffer_t buffer = fastd_buffer_alloc(ctx, max_len, methods_min_encrypt_head_space(ctx), methods_min_encrypt_tail_space(ctx));

	ssize_t len = read(ctx->tunfd, buffer.data, max_len);
	if (len < 0) {
		if (errno == EINTR) {
			fastd_buffer_free(buffer);
			return;
		}

		exit_errno(ctx, "read");
	}

	buffer.len = len;

	fastd_peer_t *peer = NULL;

	if (ctx->conf->mode == MODE_TAP) {
		if (buffer.len < ETH_HLEN) {
			pr_debug(ctx, "truncated packet on tap interface");
			fastd_buffer_free(buffer);
			return;
		}

		const fastd_eth_addr_t *dest_addr = fastd_get_dest_address(ctx, buffer);
		if (fastd_eth_addr_is_unicast(dest_addr)) {
			peer = fastd_peer_find_by_eth_addr(ctx, dest_addr);

			if (peer == NULL) {
				fastd_buffer_free(buffer);
				return;
			}

			if (fastd_peer_is_established(peer)) {
				ctx->conf->protocol->send(ctx, peer, buffer);
			}
			else {
				fastd_buffer_free(buffer);
			}
		}
	}
	if (peer == NULL) {
		for (peer = ctx->peers; peer; peer = peer->next) {
			if (fastd_peer_is_established(peer)) {
				fastd_buffer_t send_buffer = fastd_buffer_alloc(ctx, len, methods_min_encrypt_head_space(ctx), methods_min_encrypt_tail_space(ctx));
				memcpy(send_buffer.data, buffer.data, len);
				ctx->conf->protocol->send(ctx, peer, send_buffer);
			}
		}

		fastd_buffer_free(buffer);
	}
}

static inline void handle_socket_control(fastd_context_t *ctx, struct msghdr *message, const fastd_socket_t *sock, fastd_peer_address_t *local_addr) {
	memset(local_addr, 0, sizeof(fastd_peer_address_t));

	const char *end = message->msg_control + message->msg_controllen;

	struct cmsghdr *cmsg;
	for (cmsg = CMSG_FIRSTHDR(message); cmsg; cmsg = CMSG_NXTHDR(message, cmsg)) {
		if ((char*)cmsg + sizeof(*cmsg) > end)
			return;

		if (cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_PKTINFO) {
			struct in_pktinfo *pktinfo = (struct in_pktinfo*)CMSG_DATA(cmsg);
			if ((char*)pktinfo + sizeof(*pktinfo) > end)
				return;

			local_addr->in.sin_family = AF_INET;
			local_addr->in.sin_addr = pktinfo->ipi_addr;
			local_addr->in.sin_port = fastd_peer_address_get_port(sock->bound_addr);

			return;
		}

		if (cmsg->cmsg_level == IPPROTO_IPV6 && cmsg->cmsg_type == IPV6_PKTINFO) {
			struct in6_pktinfo *pktinfo = (struct in6_pktinfo*)CMSG_DATA(cmsg);
			if ((char*)pktinfo + sizeof(*pktinfo) > end)
				return;

			local_addr->in6.sin6_family = AF_INET6;
			local_addr->in6.sin6_addr = pktinfo->ipi6_addr;
			local_addr->in6.sin6_port = fastd_peer_address_get_port(sock->bound_addr);

			if (IN6_IS_ADDR_LINKLOCAL(&local_addr->in6.sin6_addr))
				local_addr->in6.sin6_scope_id = pktinfo->ipi6_ifindex;

			return;
		}
	}
}

static inline void handle_socket_receive_known(fastd_context_t *ctx, fastd_socket_t *sock, const fastd_peer_address_t *local_addr, const fastd_peer_address_t *remote_addr, fastd_peer_t *peer, fastd_buffer_t buffer) {
	if (!fastd_peer_may_connect(ctx, peer)) {
		fastd_buffer_free(buffer);
		return;
	}

	const uint8_t *packet_type = buffer.data;
	fastd_buffer_push_head(ctx, &buffer, 1);

	switch (*packet_type) {
	case PACKET_DATA:
		if (!fastd_peer_is_established(peer) || !fastd_peer_address_equal(&peer->local_address, local_addr)) {
			fastd_buffer_free(buffer);
			ctx->conf->protocol->handshake_init(ctx, sock, local_addr, remote_addr, NULL);
			return;
		}

		ctx->conf->protocol->handle_recv(ctx, peer, buffer);
		break;

	case PACKET_HANDSHAKE:
		fastd_handshake_handle(ctx, sock, local_addr, remote_addr, peer, buffer);
	}
}

static inline bool is_unknown_peer_valid(fastd_context_t *ctx, const fastd_peer_address_t *remote_addr) {
	return ctx->conf->n_floating || ctx->conf->n_dynamic || ctx->conf->on_verify ||
		(remote_addr->sa.sa_family == AF_INET && ctx->conf->n_dynamic_v4) ||
		(remote_addr->sa.sa_family == AF_INET6 && ctx->conf->n_dynamic_v6);
}

static inline void handle_socket_receive_unknown(fastd_context_t *ctx, fastd_socket_t *sock, const fastd_peer_address_t *local_addr, const fastd_peer_address_t *remote_addr, fastd_buffer_t buffer) {
	const uint8_t *packet_type = buffer.data;
	fastd_buffer_push_head(ctx, &buffer, 1);

	switch (*packet_type) {
	case PACKET_DATA:
		fastd_buffer_free(buffer);
		ctx->conf->protocol->handshake_init(ctx, sock, local_addr, remote_addr, NULL);
		break;

	case PACKET_HANDSHAKE:
		fastd_handshake_handle(ctx, sock, local_addr, remote_addr, NULL, buffer);
	}
}

static inline void handle_socket_receive(fastd_context_t *ctx, fastd_socket_t *sock, const fastd_peer_address_t *local_addr, const fastd_peer_address_t *remote_addr, fastd_buffer_t buffer) {
	fastd_peer_t *peer = NULL;

	if (sock->peer) {
		if (fastd_peer_address_equal(&sock->peer->address, remote_addr)) {
			peer = sock->peer;
		}
	}
	else {
		for (peer = ctx->peers; peer; peer = peer->next) {
			if (fastd_peer_address_equal(&peer->address, remote_addr))
				break;
		}
	}

	if (peer) {
		handle_socket_receive_known(ctx, sock, local_addr, remote_addr, peer, buffer);
	}
	else if(is_unknown_peer_valid(ctx, remote_addr)) {
		handle_socket_receive_unknown(ctx, sock, local_addr, remote_addr, buffer);
	}
	else  {
		pr_debug(ctx, "received packet from unknown peer %I", remote_addr);
		fastd_buffer_free(buffer);
	}
}

static void handle_socket(fastd_context_t *ctx, fastd_socket_t *sock) {
	size_t max_len = PACKET_TYPE_LEN + methods_max_packet_size(ctx);
	fastd_buffer_t buffer = fastd_buffer_alloc(ctx, max_len, methods_min_decrypt_head_space(ctx), methods_min_decrypt_tail_space(ctx));
	fastd_peer_address_t local_addr;
	fastd_peer_address_t recvaddr;
	struct iovec buffer_vec = { .iov_base = buffer.data, .iov_len = buffer.len };
	char cbuf[1024];

	struct msghdr message = {
		.msg_name = &recvaddr,
		.msg_namelen = sizeof(recvaddr),
		.msg_iov = &buffer_vec,
		.msg_iovlen = 1,
		.msg_control = cbuf,
		.msg_controllen = sizeof(cbuf),
	};

	ssize_t len = recvmsg(sock->fd, &message, 0);
	if (len <= 0) {
		if (len < 0 && errno != EINTR)
			pr_warn_errno(ctx, "recvmsg");

		fastd_buffer_free(buffer);
		return;
	}

	buffer.len = len;

	handle_socket_control(ctx, &message, sock, &local_addr);

	if (!local_addr.sa.sa_family) {
		pr_error(ctx, "received packet without packet info");
		fastd_buffer_free(buffer);
		return;
	}

	fastd_peer_address_simplify(&recvaddr);

	handle_socket_receive(ctx, sock, &local_addr, &recvaddr, buffer);
}

static void handle_resolv_returns(fastd_context_t *ctx) {
	fastd_resolve_return_t resolve_return;

	while (read(ctx->resolverfd, &resolve_return, sizeof(resolve_return)) < 0) {
		if (errno != EINTR)
			exit_errno(ctx, "handle_resolv_return: read");
	}

	char hostname[resolve_return.hostname_len+1];
	while (read(ctx->resolverfd, hostname, resolve_return.hostname_len) < 0) {
		if (errno != EINTR)
			exit_errno(ctx, "handle_resolv_return: read");
	}

	hostname[resolve_return.hostname_len] = 0;

	fastd_peer_t *peer;
	for (peer = ctx->peers; peer; peer = peer->next) {
		if (!peer->config)
			continue;

		if (!strequal(peer->config->hostname, hostname))
			continue;

		if (!fastd_peer_config_matches_dynamic(peer->config, &resolve_return.constraints))
			continue;

		peer->last_resolve_return = ctx->now;

		if (fastd_peer_claim_address(ctx, peer, NULL, NULL, &resolve_return.addr)) {
			send_handshake(ctx, peer);
		}
		else {
			pr_warn(ctx, "hostname `%s' resolved to address %I which is used by a fixed peer", hostname, &resolve_return.addr);
			fastd_task_schedule_handshake(ctx, peer, fastd_rand(ctx, 17500, 22500));
		}
		break;
	}
}

static inline void handle_socket_error(fastd_context_t *ctx, fastd_socket_t *sock) {
	if (sock->addr->bindtodev)
		pr_warn(ctx, "socket bind %I on `%s' lost", &sock->addr->addr, sock->addr->bindtodev);
	else
		pr_warn(ctx, "socket bind %I lost", &sock->addr->addr);

	fastd_socket_close(ctx, sock);
}

static void handle_input(fastd_context_t *ctx) {
	const size_t n_fds = 2 + ctx->n_socks + ctx->n_peers;
	struct pollfd fds[n_fds];
	fds[0].fd = ctx->tunfd;
	fds[0].events = POLLIN;
	fds[1].fd = ctx->resolverfd;
	fds[1].events = POLLIN;

	unsigned i;
	for (i = 2; i < ctx->n_socks+2; i++) {
		fds[i].fd = ctx->socks[i-2].fd;
		fds[i].events = POLLIN;
	}

	fastd_peer_t *peer;
	for (peer = ctx->peers; peer; peer = peer->next) {
		if (peer->sock && fastd_peer_is_socket_dynamic(peer))
			fds[i].fd = peer->sock->fd;
		else
			fds[i].fd = -1;

		fds[i].events = POLLIN;

		i++;
	}

	if (i != n_fds)
		exit_bug(ctx, "fd count mismatch");

	int timeout = fastd_task_timeout(ctx);

	if (timeout < 0 || timeout > 60000)
		timeout = 60000; /* call maintenance at least once a minute */

	int ret = poll(fds, n_fds, timeout);
	if (ret < 0) {
		if (errno == EINTR)
			return;

		exit_errno(ctx, "poll");
	}

	update_time(ctx);

	if (fds[0].revents & POLLIN)
		handle_tun(ctx);
	if (fds[1].revents & POLLIN)
		handle_resolv_returns(ctx);

	for (i = 2; i < ctx->n_socks+2; i++) {
		if (fds[i].revents & (POLLERR|POLLHUP|POLLNVAL))
			handle_socket_error(ctx, &ctx->socks[i-2]);
		else if (fds[i].revents & POLLIN)
			handle_socket(ctx, &ctx->socks[i-2]);
	}

	for (peer = ctx->peers; peer; peer = peer->next) {
		if (fds[i].revents & (POLLERR|POLLHUP|POLLNVAL))
			fastd_peer_reset_socket(ctx, peer);
		else if (fds[i].revents & POLLIN)
			handle_socket(ctx, peer->sock);

		i++;
	}

	if (i != n_fds)
		exit_bug(ctx, "fd count mismatch");
}

static void cleanup_peers(fastd_context_t *ctx) {
	fastd_peer_t *peer, *next;

	for (peer = ctx->peers; peer; peer = next) {
		next = peer->next;

		if (fastd_peer_is_temporary(peer) || fastd_peer_is_established(peer)) {
			if (timespec_diff(&ctx->now, &peer->seen) > ctx->conf->peer_stale_time*1000) {
				if (fastd_peer_is_temporary(peer)) {
					fastd_peer_delete(ctx, peer);
				}
				else {
					fastd_peer_reset(ctx, peer);
				}
			}
		}
	}
}

static void maintenance(fastd_context_t *ctx) {
	while (ctx->peers_temp) {
		fastd_peer_t *peer = ctx->peers_temp;
		ctx->peers_temp = ctx->peers_temp->next;

		fastd_peer_enable_temporary(ctx, peer);
	}

	cleanup_peers(ctx);
	fastd_peer_eth_addr_cleanup(ctx);

	bind_sockets(ctx);
}


static void close_fds(fastd_context_t *ctx) {
	struct rlimit rl;
	int fd, maxfd;

	if (getrlimit(RLIMIT_NOFILE, &rl) > 0)
		maxfd = (int)rl.rlim_max;
	else
		maxfd = sysconf(_SC_OPEN_MAX);

	for (fd = 3; fd < maxfd; fd++) {
		if (close(fd) < 0) {
			if (errno == EINTR) {
				fd--;
				continue;
			}

			if (errno != EBADF)
				pr_error_errno(ctx, "close");
		}
	}
}

static void write_pid(fastd_context_t *ctx, pid_t pid) {
	if (!ctx->conf->pid_file)
		return;

	uid_t uid = geteuid();
	gid_t gid = getegid();

	if (ctx->conf->user || ctx->conf->group) {
		if (setegid(ctx->conf->gid) < 0)
			pr_debug_errno(ctx, "setegid");
		if (seteuid(ctx->conf->uid) < 0)
			pr_debug_errno(ctx, "seteuid");
	}

	int fd = open(ctx->conf->pid_file, O_WRONLY|O_CREAT|O_TRUNC, 0666);
	if (fd < 0) {
		pr_error_errno(ctx, "can't write PID file: open");
		goto end;
	}

	if (dprintf(fd, "%i", pid) < 0)
		pr_error_errno(ctx, "can't write PID file: dprintf");

	if (close(fd) < 0)
		pr_warn_errno(ctx, "close");

 end:
	if (seteuid(uid) < 0)
		pr_debug_errno(ctx, "seteuid");
	if (setegid(gid) < 0)
		pr_debug_errno(ctx, "setegid");
}

static void set_user(fastd_context_t *ctx) {
	if (ctx->conf->user || ctx->conf->group) {
		if (setgid(ctx->conf->gid) < 0)
			exit_errno(ctx, "setgid");

		if (setuid(ctx->conf->uid) < 0)
			exit_errno(ctx, "setuid");

		pr_info(ctx, "Changed to UID %i, GID %i.", ctx->conf->uid, ctx->conf->gid);
	}
}

static void set_groups(fastd_context_t *ctx) {
	if (ctx->conf->groups) {
		if (setgroups(ctx->conf->n_groups, ctx->conf->groups) < 0) {
			if (errno != EPERM)
				pr_debug_errno(ctx, "setgroups");
		}
	}
	else if (ctx->conf->user || ctx->conf->group) {
		if (setgroups(1, &ctx->conf->gid) < 0) {
			if (errno != EPERM)
				pr_debug_errno(ctx, "setgroups");
		}
	}
}

static void drop_caps(fastd_context_t *ctx) {
	set_user(ctx);
	fastd_cap_drop(ctx);
}

int main(int argc, char *argv[]) {
	fastd_context_t ctx;
	memset(&ctx, 0, sizeof(ctx));

	close_fds(&ctx);

	fastd_random_bytes(&ctx, &ctx.randseed, sizeof(ctx.randseed), false);

	init_signals(&ctx);
	init_pipes(&ctx);

	fastd_config_t conf;
	fastd_configure(&ctx, &conf, argc, argv);
	ctx.conf = &conf;

	init_log(&ctx);

	if (conf.generate_key) {
		conf.protocol->generate_key(&ctx);
		exit(0);
	}

	conf.protocol_config = conf.protocol->init(&ctx);

	if (conf.show_key) {
		conf.protocol->show_key(&ctx);
		exit(0);
	}

	update_time(&ctx);

	pr_info(&ctx, "fastd " FASTD_VERSION " starting");

	fastd_cap_init(&ctx);

	/* change groups early as the can be relevant for file access (for PID file & log files) */
	set_groups(&ctx);

	crypto_init(&ctx);

	init_sockets(&ctx);

	if (!bind_sockets(&ctx))
		exit_error(&ctx, "unable to bind default socket");

	init_tuntap(&ctx);

	init_peer_groups(&ctx);
	fastd_config_load_peer_dirs(&ctx, &conf);
	init_peers(&ctx);

	if (conf.daemon) {
		pid_t pid = fork();
		if (pid < 0) {
			exit_errno(&ctx, "fork");
		}
		else if (pid > 0) {
			write_pid(&ctx, pid);
			exit(0);
		}

		if (setsid() < 0)
			pr_error_errno(&ctx, "setsid");
	}
	else {
		write_pid(&ctx, getpid());
	}

	if (conf.drop_caps == DROP_CAPS_EARLY)
		drop_caps(&ctx);

	on_up(&ctx);

	if (conf.drop_caps == DROP_CAPS_ON)
		drop_caps(&ctx);
	else if (conf.drop_caps == DROP_CAPS_OFF)
		set_user(&ctx);

	while (!terminate) {
		handle_tasks(&ctx);

		handle_input(&ctx);

		maintenance(&ctx);

		sigset_t set, oldset;
		sigemptyset(&set);
		pthread_sigmask(SIG_SETMASK, &set, &oldset);

		if (sighup) {
			sighup = false;

			pr_info(&ctx, "reconfigure triggered");

			close_log(&ctx);
			init_log(&ctx);

			fastd_config_load_peer_dirs(&ctx, &conf);
			init_peers(&ctx);
		}

		if (dump) {
			dump = false;
			dump_peers(&ctx);
		}

		pthread_sigmask(SIG_SETMASK, &oldset, NULL);
	}

	on_down(&ctx);

	delete_peers(&ctx);
	delete_peer_groups(&ctx);

	close_tuntap(&ctx);
	close_sockets(&ctx);

	free(ctx.protocol_state);
	free(ctx.eth_addr);

	crypto_free(&ctx);

	close_log(&ctx);
	fastd_config_release(&ctx, &conf);

	return 0;
}
