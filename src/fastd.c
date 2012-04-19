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
#include <sys/socket.h>
#include <unistd.h>


static volatile bool sighup = false;
static volatile bool terminate = false;


static void on_sighup(int signo) {
	sighup = true;
}

static void on_terminate(int signo) {
	terminate = true;
}

static void on_sigusr1(int signo, siginfo_t *siginfo, void *context) {
	if (siginfo->si_code != SI_QUEUE || !siginfo->si_value.sival_ptr)
		return;

	fastd_resolve_return *ret = siginfo->si_value.sival_ptr;

	ret->next = ret->ctx->resolve_returns;
	ret->ctx->resolve_returns = ret;
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

	action.sa_flags = SA_SIGINFO;
	action.sa_sigaction = on_sigusr1;
	if(sigaction(SIGUSR1, &action, NULL))
		exit_errno(ctx, "sigaction");
}

static void init_tuntap(fastd_context *ctx) {
	struct ifreq ifr;

	pr_debug(ctx, "Initializing tun/tap device...");

	if ((ctx->tunfd = open("/dev/net/tun", O_RDWR)) < 0)
		exit_errno(ctx, "Could not open tun/tap device file");

	memset(&ifr, 0, sizeof(ifr));

	if (ctx->conf->ifname)
		strncpy(ifr.ifr_name, ctx->conf->ifname, IF_NAMESIZE-1);

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
	if (ioctl(ctx->tunfd, TUNSETIFF, (void *)&ifr) < 0)
		exit_errno(ctx, "TUNSETIFF ioctl failed");

	ctx->ifname = strdup(ifr.ifr_name);

	pr_debug(ctx, "tun/tap device initialized.");
}

static void close_tuntap(fastd_context *ctx) {
	if(close(ctx->tunfd))
		pr_warn_errno(ctx, "closing tun/tap: close");

	free(ctx->ifname);
}

static void init_sockets(fastd_context *ctx) {
	struct sockaddr_in addr_in = ctx->conf->bind_addr_in;
	struct sockaddr_in6 addr_in6 = ctx->conf->bind_addr_in6;

	if (addr_in.sin_family == AF_UNSPEC && addr_in6.sin6_family == AF_UNSPEC) {
		if (ctx->conf->peer_dirs || ctx->conf->n_floating || ctx->conf->n_v4 || ctx->conf->n_dynamic || ctx->conf->n_dynamic_v4)
			addr_in.sin_family = AF_INET;

		if (ctx->conf->peer_dirs || ctx->conf->n_floating || ctx->conf->n_v6 || ctx->conf->n_dynamic || ctx->conf->n_dynamic_v6)
			addr_in6.sin6_family = AF_INET6;
	}

	if (addr_in.sin_family == AF_UNSPEC && ctx->conf->n_v4)
		pr_warn(ctx, "there are IPv4 peers defined, but bind is explicitly set to IPv6");

	if (addr_in6.sin6_family == AF_UNSPEC && ctx->conf->n_v6)
		pr_warn(ctx, "there are IPv6 peers defined, but bind is explicitly set to IPv4");

	if (addr_in.sin_family == AF_INET) {
		pr_debug(ctx, "Initializing IPv4 socket...");

		if ((ctx->sockfd = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
			exit_errno(ctx, "socket");

		if (bind(ctx->sockfd, (struct sockaddr*)&addr_in, sizeof(struct sockaddr_in)))
			exit_errno(ctx, "bind");

		pr_debug(ctx, "IPv4 socket initialized.");
	}
	else {
		ctx->sockfd = -1;
	}

	if (addr_in6.sin6_family == AF_INET6) {
		pr_debug(ctx, "Initializing IPv6 socket...");

		if ((ctx->sock6fd = socket(PF_INET6, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
			if (ctx->sockfd >= 0)
				pr_warn_errno(ctx, "socket");
			else
				exit_errno(ctx, "socket");
		}
		else {
			int val = 1;
			if (setsockopt(ctx->sock6fd, IPPROTO_IPV6, IPV6_V6ONLY, &val, sizeof(val)))
				exit_errno(ctx, "setsockopt");

			if (bind(ctx->sock6fd, (struct sockaddr*)&addr_in6, sizeof(struct sockaddr_in6)))
				exit_errno(ctx, "bind");

			pr_debug(ctx, "IPv6 socket initialized.");
		}
	}
	else {
		ctx->sock6fd = -1;
	}
}

static void close_sockets(fastd_context *ctx) {
	if (ctx->sockfd >= 0) {
		if(close(ctx->sockfd))
			pr_warn_errno(ctx, "closing IPv4 socket: close");
	}

	if (ctx->sock6fd >= 0) {
		if(close(ctx->sock6fd))
			pr_warn_errno(ctx, "closing IPv6 socket: close");
	}
}

static void fastd_send_type(fastd_context *ctx, const fastd_peer_address *address, uint8_t packet_type, fastd_buffer buffer) {
	int sockfd;
	struct msghdr msg;
	memset(&msg, 0, sizeof(msg));

	switch (address->sa.sa_family) {
	case AF_INET:
		msg.msg_name = (void*)&address->in;
		msg.msg_namelen = sizeof(struct sockaddr_in);
		sockfd = ctx->sockfd;
		break;

	case AF_INET6:
		msg.msg_name = (void*)&address->in6;
		msg.msg_namelen = sizeof(struct sockaddr_in6);
		sockfd = ctx->sock6fd;
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
		ret = sendmsg(sockfd, &msg, 0);
	} while (ret < 0 && errno == EINTR);

	if (ret < 0)
		pr_warn_errno(ctx, "sendmsg");

	fastd_buffer_free(buffer);
}

void fastd_send(fastd_context *ctx, const fastd_peer_address *address, fastd_buffer buffer) {
	fastd_send_type(ctx, address, PACKET_DATA, buffer);
}

void fastd_send_handshake(fastd_context *ctx, const fastd_peer_address *address, fastd_buffer buffer) {
	fastd_send_type(ctx, address, PACKET_HANDSHAKE, buffer);
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
					fastd_buffer send_buffer = fastd_buffer_alloc(buffer.len, ctx->conf->method->min_encrypt_head_space(ctx), 0);
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

		char buf[6];
		snprintf(buf, 6, "%u", ctx->conf->mtu);
		setenv("MTU", buf, 1);

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

		char buf[6];
		snprintf(buf, 6, "%u", ctx->conf->mtu);
		setenv("MTU", buf, 1);

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

static void init_peers(fastd_context *ctx) {
	fastd_peer_config *peer_conf;
	for (peer_conf = ctx->conf->peers; peer_conf; peer_conf = peer_conf->next) {
		ctx->conf->protocol->peer_configure(ctx, peer_conf);

		if (peer_conf->enabled)
			fastd_peer_add(ctx, peer_conf);
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

static inline void send_handshake(fastd_context *ctx, fastd_peer *peer) {
	if (peer->address.sa.sa_family != AF_UNSPEC) {
		pr_debug(ctx, "sending handshake to %P...", peer);
		ctx->conf->protocol->handshake_init(ctx, &peer->address, peer->config);
	}

	fastd_task_schedule_handshake(ctx, peer, fastd_rand(ctx, 17500, 22500));
}

static void handle_tasks(fastd_context *ctx) {
	fastd_task *task;
	while ((task = fastd_task_get(ctx)) != NULL) {
		switch (task->type) {
		case TASK_HANDSHAKE:
			if (fastd_peer_is_dynamic(task->peer))
				fastd_resolve_peer(ctx, task->peer->config);
			else
				send_handshake(ctx, task->peer);
			break;

		case TASK_KEEPALIVE:
			pr_debug(ctx, "sending keepalive to %P", task->peer);
			ctx->conf->protocol->send(ctx, task->peer, fastd_buffer_alloc(0, ctx->conf->method->min_encrypt_head_space(ctx), 0));
			break;

		default:
			exit_bug(ctx, "invalid task type");
		}

		free(task);
	}
}

static void handle_tun(fastd_context *ctx) {
	size_t max_len = fastd_max_packet_size(ctx);
	fastd_buffer buffer = fastd_buffer_alloc(max_len, ctx->conf->method->min_encrypt_head_space(ctx), 0);

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
				fastd_buffer send_buffer = fastd_buffer_alloc(len, ctx->conf->method->min_encrypt_head_space(ctx), 0);
				memcpy(send_buffer.data, buffer.data, len);
				ctx->conf->protocol->send(ctx, peer, send_buffer);
			}
		}

		fastd_buffer_free(buffer);
	}
}

static void handle_socket(fastd_context *ctx, int sockfd) {
	size_t max_len = ctx->conf->method->max_packet_size(ctx);
	fastd_buffer buffer = fastd_buffer_alloc(max_len, ctx->conf->method->min_decrypt_head_space(ctx), 0);
	uint8_t packet_type;

	struct iovec iov[2] = {
		{ .iov_base = &packet_type, .iov_len = 1 },
		{ .iov_base = buffer.data, .iov_len = max_len }
	};
	fastd_peer_address recvaddr;
			
	struct msghdr msg;
	memset(&msg, 0, sizeof(msg));

	msg.msg_name = &recvaddr;
	msg.msg_namelen = sizeof(recvaddr);
	msg.msg_iov = iov;
	msg.msg_iovlen = 2;

	ssize_t len = recvmsg(sockfd, &msg, 0);
	if (len < 0) {
		if (errno != EINTR)
			pr_warn(ctx, "recvfrom: %s", strerror(errno));

		fastd_buffer_free(buffer);
		return;
	}

	buffer.len = len - 1;

	fastd_peer *peer;
	for (peer = ctx->peers; peer; peer = peer->next) {
		if (fastd_peer_address_equal(&peer->address, &recvaddr))
			break;
	}

	if (peer) {
		switch (packet_type) {
		case PACKET_DATA:
			ctx->conf->protocol->handle_recv(ctx, peer, buffer);
			break;

		case PACKET_HANDSHAKE:
			fastd_handshake_handle(ctx, &recvaddr, peer->config, buffer);
			break;

		default:
			fastd_buffer_free(buffer);
		}
	}
	else if(ctx->conf->n_floating || ctx->conf->n_dynamic ||
		(recvaddr.sa.sa_family == AF_INET && ctx->conf->n_dynamic_v4) ||
		(recvaddr.sa.sa_family == AF_INET6 && ctx->conf->n_dynamic_v6)) {
		switch (packet_type) {
		case PACKET_DATA:
			ctx->conf->protocol->handshake_init(ctx, &recvaddr, NULL);
			break;

		case PACKET_HANDSHAKE:
			fastd_handshake_handle(ctx, &recvaddr, NULL, buffer);
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

static void handle_input(fastd_context *ctx) {
	struct pollfd fds[3];
	fds[0].fd = ctx->tunfd;
	fds[0].events = POLLIN;
	fds[1].fd = ctx->sockfd;
	fds[1].events = POLLIN;
	fds[2].fd = ctx->sock6fd;
	fds[2].events = POLLIN;

	int timeout = fastd_task_timeout(ctx);

	if (timeout < 0 || timeout > 60000)
		timeout = 60000; /* call maintenance at least once a minute */

	int ret = poll(fds, 3, timeout);
	if (ret < 0) {
		if (errno == EINTR)
			return;

		exit_errno(ctx, "poll");
	}

	update_time(ctx);

	if (fds[0].revents & POLLIN)
		handle_tun(ctx);
	if (fds[1].revents & POLLIN)
		handle_socket(ctx, ctx->sockfd);
	if (fds[2].revents & POLLIN)
		handle_socket(ctx, ctx->sock6fd);
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


static void handle_resolv_returns(fastd_context *ctx) {
	while (ctx->resolve_returns) {
		fastd_peer *peer;
		for (peer = ctx->peers; peer; peer = peer->next) {
			if (!peer->config)
				continue;

			if (!strequal(peer->config->hostname, ctx->resolve_returns->hostname))
				continue;

			if (!fastd_peer_config_matches_dynamic(peer->config, &ctx->resolve_returns->constraints))
				continue;

			if (fastd_peer_claim_address(ctx, peer, &ctx->resolve_returns->addr)) {
				if (!fastd_peer_is_established(peer))
					send_handshake(ctx, peer);
			}
			else {
				pr_warn(ctx, "hostname `%s' resolved to address %I which is used by a fixed peer", ctx->resolve_returns->hostname, ctx->resolve_returns->addr);
			}
			break;
		}

		fastd_resolve_return *next = ctx->resolve_returns->next;
		free(ctx->resolve_returns->hostname);
		free(ctx->resolve_returns);
		ctx->resolve_returns = next;
	}
}

static void maintenance(fastd_context *ctx) {
	cleanup_peers(ctx);

	fastd_peer_eth_addr_cleanup(ctx);
}


int main(int argc, char *argv[]) {
	fastd_context ctx;
	memset(&ctx, 0, sizeof(ctx));

	fastd_random_bytes(&ctx, &ctx.randseed, sizeof(ctx.randseed), false);

	init_signals(&ctx);

	fastd_config conf;
	fastd_configure(&ctx, &conf, argc, argv);
	ctx.conf = &conf;

	conf.protocol_config = conf.protocol->init(&ctx);

	update_time(&ctx);

	init_tuntap(&ctx);
	init_sockets(&ctx);

	init_peers(&ctx);

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
			fastd_reconfigure(&ctx, &conf);
		}

		handle_resolv_returns(&ctx);

		pthread_sigmask(SIG_SETMASK, &oldset, NULL);
	}

	on_down(&ctx);

	delete_peers(&ctx);

	close_sockets(&ctx);
	close_tuntap(&ctx);

	free(ctx.protocol_state);

	fastd_config_release(&ctx, &conf);

	return 0;
}
