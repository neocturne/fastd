/*
  Copyright (c) 2012, Matthias Schiffer <mschiffer@universe-factory.net>
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



static void on_sighup(int signo) {
	sighup = true;
}

static void on_terminate(int signo) {
	terminate = true;
}

static void init_signals(fastd_context *ctx) {
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

	action.sa_handler = SIG_IGN;
	if(sigaction(SIGPIPE, &action, NULL))
		exit_errno(ctx, "sigaction");
}

static void init_pipes(fastd_context *ctx) {
	int pipefd[2];

	if (pipe(pipefd))
		exit_errno(ctx, "pipe");

	ctx->resolverfd = pipefd[0];
	ctx->resolvewfd = pipefd[1];
}

static void init_log(fastd_context *ctx) {
	if (ctx->conf->log_syslog_level >= 0)
		openlog(ctx->conf->log_syslog_ident, LOG_PID, LOG_DAEMON);

	fastd_log_file *config;
	for (config = ctx->conf->log_files; config; config = config->next) {
		fastd_log_fd *file = malloc(sizeof(fastd_log_fd));

		file->config = config;
		file->fd = open(config->filename, O_WRONLY|O_APPEND|O_CREAT, 0600);

		file->next = ctx->log_files;
		ctx->log_files = file;
	}
}

static void close_log(fastd_context *ctx) {
	while (ctx->log_files) {
		fastd_log_fd *next = ctx->log_files->next;

		close(ctx->log_files->fd);
		free(ctx->log_files);

		ctx->log_files = next;
	}

	closelog();
}

static void crypto_init(fastd_context *ctx) {
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

static void crypto_free(fastd_context *ctx) {
#ifdef USE_CRYPTO_AES128CTR
	ctx->conf->crypto_aes128ctr->free(ctx, ctx->crypto_aes128ctr);
	ctx->crypto_aes128ctr = NULL;
#endif

#ifdef USE_CRYPTO_GHASH
	ctx->conf->crypto_ghash->free(ctx, ctx->crypto_ghash);
	ctx->crypto_ghash = NULL;
#endif
}


static void init_sockets(fastd_context *ctx) {
	ctx->socks = malloc(ctx->conf->n_bind_addrs * sizeof(fastd_socket));

	unsigned i;
	fastd_bind_address *addr = ctx->conf->bind_addrs;
	for (i = 0; i < ctx->conf->n_bind_addrs; i++) {
		ctx->socks[i] = (fastd_socket){-2, addr, NULL};

		if (addr == ctx->conf->bind_addr_default_v4)
			ctx->sock_default_v4 = &ctx->socks[i];

		if (addr == ctx->conf->bind_addr_default_v6)
			ctx->sock_default_v6 = &ctx->socks[i];

		addr = addr->next;
	}

	ctx->n_socks = ctx->conf->n_bind_addrs;
}

static int bind_socket(fastd_context *ctx, const fastd_bind_address *addr, bool warn) {
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

	if (addr->bindtodev) {
		if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, addr->bindtodev, strlen(addr->bindtodev))) {
			if (warn)
				pr_warn_errno(ctx, "setsockopt: unable to bind to device");
			goto error;
		}
	}

	fastd_peer_address bind_address = addr->addr;

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
			pr_warn(ctx, "unable to bind to %I on `%s'", &addr->addr, addr->bindtodev);
                else
			pr_warn(ctx, "unable to bind to %I", &addr->addr);
	}

	return -1;
}

static void bind_sockets(fastd_context *ctx) {
	unsigned i;

	for (i = 0; i < ctx->n_socks; i++) {
		if (ctx->socks[i].fd >= 0)
			continue;

		ctx->socks[i].fd = bind_socket(ctx, ctx->socks[i].addr, ctx->socks[i].fd < -1);

		if (ctx->socks[i].fd >= 0) {
			if (ctx->socks[i].addr->bindtodev)
				pr_info(ctx, "successfully bound to %I on `%s'", &ctx->socks[i].addr->addr, ctx->socks[i].addr->bindtodev);
			else
				pr_info(ctx, "successfully bound to %I", &ctx->socks[i].addr->addr);
		}
	}
}

fastd_socket* fastd_socket_open(fastd_context *ctx, fastd_peer *peer, int af) {
	const fastd_bind_address any_address = { .addr.sa.sa_family = af };

	int fd = bind_socket(ctx, &any_address, true);
	if (fd < 0)
		return NULL;

	fastd_socket *sock = malloc(sizeof(fastd_socket));

	sock->fd = fd;
	sock->addr = NULL;
	sock->peer = peer;

	return sock;
}

static void init_tuntap(fastd_context *ctx) {
	struct ifreq ifr;

	pr_debug(ctx, "initializing tun/tap device...");

	if ((ctx->tunfd = open("/dev/net/tun", O_RDWR)) < 0)
		exit_errno(ctx, "could not open tun/tap device file");

	memset(&ifr, 0, sizeof(ifr));

	if (ctx->conf->ifname)
		strncpy(ifr.ifr_name, ctx->conf->ifname, IFNAMSIZ);

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

	ctx->ifname = strndup(ifr.ifr_name, IFNAMSIZ);

	int ctl_sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (ctl_sock < 0)
		exit_errno(ctx, "socket");

	ifr.ifr_mtu = ctx->conf->mtu;
	if (ioctl(ctl_sock, SIOCSIFMTU, &ifr) < 0)
		exit_errno(ctx, "SIOCSIFMTU ioctl failed");

	if (close(ctl_sock))
		pr_error_errno(ctx, "close");

	pr_debug(ctx, "tun/tap device initialized.");
}

static void close_tuntap(fastd_context *ctx) {
	if(close(ctx->tunfd))
		pr_warn_errno(ctx, "closing tun/tap: close");

	free(ctx->ifname);
}

static void close_sockets(fastd_context *ctx) {
	unsigned i;
	for (i = 0; i < ctx->n_socks; i++)
		fastd_socket_close(ctx, &ctx->socks[i]);

	free(ctx->socks);
}

static size_t methods_max_packet_size(fastd_context *ctx) {
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

static size_t methods_min_encrypt_head_space(fastd_context *ctx) {
	size_t ret = ctx->conf->methods[0]->min_encrypt_head_space(ctx);

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

static size_t methods_min_decrypt_head_space(fastd_context *ctx) {
	size_t ret = ctx->conf->methods[0]->min_decrypt_head_space(ctx);

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

static size_t methods_min_encrypt_tail_space(fastd_context *ctx) {
	size_t ret = ctx->conf->methods[0]->min_encrypt_tail_space(ctx);

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

static size_t methods_min_decrypt_tail_space(fastd_context *ctx) {
	size_t ret = ctx->conf->methods[0]->min_decrypt_tail_space(ctx);

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

static void fastd_send_type(fastd_context *ctx, const fastd_socket *sock, const fastd_peer_address *address, uint8_t packet_type, fastd_buffer buffer) {
	if (!sock)
		exit_bug(ctx, "send: sock == NULL");

	struct msghdr msg;
	memset(&msg, 0, sizeof(msg));

	switch (address->sa.sa_family) {
	case AF_INET:
		msg.msg_name = (void*)&address->in;
		msg.msg_namelen = sizeof(struct sockaddr_in);
		break;

	case AF_INET6:
		msg.msg_name = (void*)&address->in6;
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

	int ret;
	do {
		ret = sendmsg(sock->fd, &msg, 0);
	} while (ret < 0 && errno == EINTR);

	if (ret < 0)
		pr_warn_errno(ctx, "sendmsg");

	fastd_buffer_free(buffer);
}

void fastd_send(fastd_context *ctx, const fastd_socket *sock, const fastd_peer_address *address, fastd_buffer buffer) {
	fastd_send_type(ctx, sock, address, PACKET_DATA, buffer);
}

void fastd_send_handshake(fastd_context *ctx, const fastd_socket *sock, const fastd_peer_address *address, fastd_buffer buffer) {
	fastd_send_type(ctx, sock, address, PACKET_HANDSHAKE, buffer);
}

void fastd_handle_receive(fastd_context *ctx, fastd_peer *peer, fastd_buffer buffer) {
	if (ctx->conf->mode == MODE_TAP) {
		const fastd_eth_addr *src_addr = fastd_get_source_address(ctx, buffer);

		if (fastd_eth_addr_is_unicast(src_addr))
			fastd_peer_eth_addr_add(ctx, peer, src_addr);
	}

	if (write(ctx->tunfd, buffer.data, buffer.len) < 0)
		pr_warn_errno(ctx, "write");

	if (ctx->conf->mode == MODE_TAP && ctx->conf->forward) {
		const fastd_eth_addr *dest_addr = fastd_get_dest_address(ctx, buffer);

		if (fastd_eth_addr_is_unicast(dest_addr)) {
			fastd_peer *dest_peer = fastd_peer_find_by_eth_addr(ctx, dest_addr);

			if (dest_peer && dest_peer != peer && fastd_peer_is_established(dest_peer)) {
				ctx->conf->protocol->send(ctx, dest_peer, buffer);
			}
			else {
				fastd_buffer_free(buffer);
			}
		}
		else {
			fastd_peer *dest_peer;
			for (dest_peer = ctx->peers; dest_peer; dest_peer = dest_peer->next) {
				if (dest_peer != peer && fastd_peer_is_established(dest_peer)) {
					fastd_buffer send_buffer = fastd_buffer_alloc(buffer.len, methods_min_encrypt_head_space(ctx), methods_min_encrypt_tail_space(ctx));
					memcpy(send_buffer.data, buffer.data, buffer.len);
					ctx->conf->protocol->send(ctx, dest_peer, send_buffer);
				}
			}

			fastd_buffer_free(buffer);
		}
	}
	else {
		fastd_buffer_free(buffer);
	}
}

static void on_up(fastd_context *ctx) {
	if (!ctx->conf->on_up)
		return;

	char *cwd = get_current_dir_name();

	if (!chdir(ctx->conf->on_up_dir)) {
		setenv("INTERFACE", ctx->ifname, 1);

		int ret = system(ctx->conf->on_up);

		if (WIFSIGNALED(ret))
			pr_error(ctx, "on-up command exited with signal %i", WTERMSIG(ret));
		else if(ret)
			pr_warn(ctx, "on-up command exited with status %i", WEXITSTATUS(ret));

		if (chdir(cwd))
			pr_error(ctx, "can't chdir to `%s': %s", cwd, strerror(errno));
	}
	else {
		pr_error(ctx, "can't chdir to `%s': %s", ctx->conf->on_up_dir, strerror(errno));
	}

	free(cwd);
}

static void on_down(fastd_context *ctx) {
	if (!ctx->conf->on_down)
		return;

	char *cwd = get_current_dir_name();

	if(!chdir(ctx->conf->on_down_dir)) {
		setenv("INTERFACE", ctx->ifname, 1);

		int ret = system(ctx->conf->on_down);

		if (WIFSIGNALED(ret))
			pr_error(ctx, "on-down command exited with signal %i", WTERMSIG(ret));
		else if(ret)
			pr_warn(ctx, "on-down command exited with status %i", WEXITSTATUS(ret));

		if (chdir(cwd))
			pr_error(ctx, "can't chdir to `%s': %s", cwd, strerror(errno));
	}
	else {
		pr_error(ctx, "can't chdir to `%s': %s", ctx->conf->on_down_dir, strerror(errno));
	}

	free(cwd);
}

static fastd_peer_group* init_peer_group(const fastd_peer_group_config *config, fastd_peer_group *parent) {
	fastd_peer_group *ret = calloc(1, sizeof(fastd_peer_group));

	ret->conf = config;
	ret->parent = parent;

	fastd_peer_group **children = &ret->children;
	fastd_peer_group_config *child_config;

	for (child_config = config->children; child_config; child_config = child_config->next) {
		*children = init_peer_group(child_config, ret);
		children = &(*children)->next;
	}

	return ret;
}

static void init_peer_groups(fastd_context *ctx) {
	ctx->peer_group = init_peer_group(ctx->conf->peer_group, NULL);
}

static void free_peer_group(fastd_peer_group *group) {
	while (group->children) {
		fastd_peer_group *child = group->children;
		group->children = group->children->next;

		free_peer_group(child);
	}

	free(group);
}

static void delete_peer_groups(fastd_context *ctx) {
	free_peer_group(ctx->peer_group);
}

static void init_peers(fastd_context *ctx) {
	fastd_peer_config *peer_conf;
	for (peer_conf = ctx->conf->peers; peer_conf; peer_conf = peer_conf->next) {
		ctx->conf->protocol->peer_configure(ctx, peer_conf);

		if (peer_conf->enabled) {
			fastd_peer_add(ctx, peer_conf);
			ctx->n_peers++;
		}
	}
}

static void delete_peers(fastd_context *ctx) {
	fastd_peer *peer, *next;
	for (peer = ctx->peers; peer; peer = next) {
		next = peer->next;

		fastd_peer_delete(ctx, peer);
	}
}

static inline void update_time(fastd_context *ctx) {
	clock_gettime(CLOCK_MONOTONIC, &ctx->now);
}

static void send_handshake(fastd_context *ctx, fastd_peer *peer) {
	if (fastd_peer_may_connect(ctx, peer)) {
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
				ctx->conf->protocol->handshake_init(ctx, peer->sock, &peer->address, peer->config);
			}
		}
	}

	fastd_task_schedule_handshake(ctx, peer, fastd_rand(ctx, 17500, 22500));
}

static void handle_tasks(fastd_context *ctx) {
	fastd_task *task;
	while ((task = fastd_task_get(ctx)) != NULL) {
		switch (task->type) {
		case TASK_HANDSHAKE:
			if (fastd_peer_is_dynamic(task->peer) && !(fastd_peer_is_floating(task->peer) && fastd_peer_is_established(task->peer)))
				fastd_resolve_peer(ctx, task->peer);
			else
				send_handshake(ctx, task->peer);
			break;

		case TASK_KEEPALIVE:
			pr_debug(ctx, "sending keepalive to %P", task->peer);
			ctx->conf->protocol->send(ctx, task->peer, fastd_buffer_alloc(0, methods_min_encrypt_head_space(ctx), methods_min_encrypt_tail_space(ctx)));
			break;

		default:
			exit_bug(ctx, "invalid task type");
		}

		free(task);
	}
}

static void handle_tun(fastd_context *ctx) {
	size_t max_len = fastd_max_packet_size(ctx);
	fastd_buffer buffer = fastd_buffer_alloc(max_len, methods_min_encrypt_head_space(ctx), methods_min_encrypt_tail_space(ctx));

	ssize_t len = read(ctx->tunfd, buffer.data, max_len);
	if (len < 0) {
		if (errno == EINTR) {
			fastd_buffer_free(buffer);
			return;
		}

		exit_errno(ctx, "read");
	}

	buffer.len = len;

	fastd_peer *peer = NULL;

	if (ctx->conf->mode == MODE_TAP) {
		const fastd_eth_addr *dest_addr = fastd_get_dest_address(ctx, buffer);
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
				fastd_buffer send_buffer = fastd_buffer_alloc(len, methods_min_encrypt_head_space(ctx), methods_min_encrypt_tail_space(ctx));
				memcpy(send_buffer.data, buffer.data, len);
				ctx->conf->protocol->send(ctx, peer, send_buffer);
			}
		}

		fastd_buffer_free(buffer);
	}
}

static void handle_socket(fastd_context *ctx, fastd_socket *sock) {
	size_t max_len = PACKET_TYPE_LEN + methods_max_packet_size(ctx);
	fastd_buffer buffer = fastd_buffer_alloc(max_len, methods_min_decrypt_head_space(ctx), methods_min_decrypt_tail_space(ctx));
	uint8_t *packet_type;

	fastd_peer_address recvaddr;
	socklen_t recvaddrlen = sizeof(recvaddr);
			
	ssize_t len = recvfrom(sock->fd, buffer.data, buffer.len, 0, (struct sockaddr*)&recvaddr, &recvaddrlen);
	if (len < 0) {
		if (errno != EINTR)
			pr_warn(ctx, "recvfrom: %s", strerror(errno));

		fastd_buffer_free(buffer);
		return;
	}

	packet_type = buffer.data;
	buffer.len = len;

	fastd_buffer_push_head(&buffer, 1);

	fastd_peer *peer = NULL;

	if (sock->peer) {
		if (fastd_peer_address_equal(&sock->peer->address, &recvaddr)) {
			peer = sock->peer;
		}
	}
	else {
		for (peer = ctx->peers; peer; peer = peer->next) {
			if (fastd_peer_address_equal(&peer->address, &recvaddr))
				break;
		}
	}

	if (peer) {
		if (!fastd_peer_may_connect(ctx, peer)) {
			fastd_buffer_free(buffer);
			return;
		}

		switch (*packet_type) {
		case PACKET_DATA:
			ctx->conf->protocol->handle_recv(ctx, peer, buffer);
			break;

		case PACKET_HANDSHAKE:
			fastd_handshake_handle(ctx, sock, &recvaddr, peer->config, buffer);
			break;

		default:
			fastd_buffer_free(buffer);
		}
	}
	else if(ctx->conf->n_floating || ctx->conf->n_dynamic ||
		(recvaddr.sa.sa_family == AF_INET && ctx->conf->n_dynamic_v4) ||
		(recvaddr.sa.sa_family == AF_INET6 && ctx->conf->n_dynamic_v6)) {
		switch (*packet_type) {
		case PACKET_DATA:
			fastd_buffer_free(buffer);
			ctx->conf->protocol->handshake_init(ctx, sock, &recvaddr, NULL);
			break;

		case PACKET_HANDSHAKE:
			fastd_handshake_handle(ctx, sock, &recvaddr, NULL, buffer);
			break;

		default:
			fastd_buffer_free(buffer);
		}
	}
	else  {
		pr_debug(ctx, "received packet from unknown peer %I", &recvaddr);
		fastd_buffer_free(buffer);
	}
}

static void handle_resolv_returns(fastd_context *ctx) {
	fastd_resolve_return resolve_return;

	if (read(ctx->resolverfd, &resolve_return, sizeof(resolve_return)) < 0) {
		if (errno != EINTR)
			pr_warn(ctx, "read: %s", strerror(errno));

		return;
	}

	fastd_peer *peer;
	for (peer = ctx->peers; peer; peer = peer->next) {
		if (!peer->config)
			continue;

		if (!strequal(peer->config->hostname, resolve_return.hostname))
			continue;

		if (!fastd_peer_config_matches_dynamic(peer->config, &resolve_return.constraints))
			continue;

		peer->last_resolve_return = ctx->now;

		if (fastd_peer_claim_address(ctx, peer, NULL, &resolve_return.addr)) {
			send_handshake(ctx, peer);
		}
		else {
			pr_warn(ctx, "hostname `%s' resolved to address %I which is used by a fixed peer", resolve_return.hostname, &resolve_return.addr);
			fastd_task_schedule_handshake(ctx, peer, fastd_rand(ctx, 17500, 22500));
		}
		break;
	}

	free(resolve_return.hostname);
}

static inline void handle_socket_error(fastd_context *ctx, fastd_socket *sock) {
	if (sock->addr->bindtodev)
		pr_warn(ctx, "socket bind %I on `%s' lost", &sock->addr->addr, sock->addr->bindtodev);
	else
		pr_warn(ctx, "socket bind %I lost", &sock->addr->addr);

	fastd_socket_close(ctx, sock);
}

static void handle_input(fastd_context *ctx) {
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

	fastd_peer *peer;
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

static void cleanup_peers(fastd_context *ctx) {
	fastd_peer *peer, *next;

	for (peer = ctx->peers; peer; peer = next) {
		next = peer->next;

		if (fastd_peer_is_established(peer)) {
			if (timespec_diff(&ctx->now, &peer->seen) > ctx->conf->peer_stale_time*1000)
				fastd_peer_reset(ctx, peer);
		}
	}
}

static void maintenance(fastd_context *ctx) {
	cleanup_peers(ctx);
	fastd_peer_eth_addr_cleanup(ctx);

	bind_sockets(ctx);
}


static void close_fds(fastd_context *ctx) {
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

static void write_pid(fastd_context *ctx, pid_t pid) {
	if (!ctx->conf->pid_file)
		return;

	int fd = open(ctx->conf->pid_file, O_WRONLY|O_CREAT, 0666);
	if (fd < 0) {
		pr_error_errno(ctx, "can't write PID file: open");
		return;
	}

	if (dprintf(fd, "%i", pid) < 0)
		pr_error_errno(ctx, "can't write PID file: dprintf");

	if (close(fd) < 0)
		pr_warn_errno(ctx, "close");
}

int main(int argc, char *argv[]) {
	fastd_context ctx;
	memset(&ctx, 0, sizeof(ctx));

	close_fds(&ctx);

	fastd_random_bytes(&ctx, &ctx.randseed, sizeof(ctx.randseed), false);

	init_signals(&ctx);
	init_pipes(&ctx);

	fastd_config conf;
	fastd_configure(&ctx, &conf, argc, argv);
	ctx.conf = &conf;

	init_log(&ctx);

	crypto_init(&ctx);

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

	init_sockets(&ctx);
	bind_sockets(&ctx);

	init_tuntap(&ctx);

	init_peer_groups(&ctx);
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

	on_up(&ctx);

	while (!terminate) {
		handle_tasks(&ctx);

		handle_input(&ctx);

		maintenance(&ctx);

		sigset_t set, oldset;
		sigemptyset(&set);
		pthread_sigmask(SIG_SETMASK, &set, &oldset);

		if (sighup) {
			sighup = false;

			close_log(&ctx);
			init_log(&ctx);

			fastd_reconfigure(&ctx, &conf);
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
