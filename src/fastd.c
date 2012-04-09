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
#include <signal.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>


static bool sighup = false;
static bool terminate = false;


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
		warn_errno(ctx, "closing tun/tap: close");

	free(ctx->ifname);
}

static void init_sockets(fastd_context *ctx) {
	struct sockaddr_in addr_in = ctx->conf->bind_addr_in;
	struct sockaddr_in6 addr_in6 = ctx->conf->bind_addr_in6;

	if (addr_in.sin_family == AF_UNSPEC && addr_in6.sin6_family == AF_UNSPEC) {
		if (ctx->conf->n_floating || ctx->conf->peer_dirs || ctx->conf->n_v4)
			addr_in.sin_family = AF_INET;

		if (ctx->conf->n_floating || ctx->conf->peer_dirs || ctx->conf->n_v6)
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
				warn_errno(ctx, "socket");
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
			warn_errno(ctx, "closing IPv4 socket: close");
	}

	if (ctx->sock6fd >= 0) {
		if(close(ctx->sock6fd))
			warn_errno(ctx, "closing IPv6 socket: close");
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

static void update_time(fastd_context *ctx) {
	clock_gettime(CLOCK_MONOTONIC, &ctx->now);
}

static void handle_tasks(fastd_context *ctx) {
	fastd_task *task;
	while ((task = fastd_task_get(ctx)) != NULL) {
		switch (task->type) {
		case TASK_SEND:
			if (task->peer) {
				int sockfd;
				struct msghdr msg;
				memset(&msg, 0, sizeof(msg));

				switch (task->peer->address.sa.sa_family) {
				case AF_INET:
					msg.msg_name = &task->peer->address.in;
					msg.msg_namelen = sizeof(struct sockaddr_in);
					sockfd = ctx->sockfd;
					break;

				case AF_INET6:
					msg.msg_name = &task->peer->address.in6;
					msg.msg_namelen = sizeof(struct sockaddr_in6);
					sockfd = ctx->sock6fd;
					break;

				default:
					exit_bug(ctx, "unsupported address family");
				}

				uint8_t packet_type = task->send.packet_type;

				struct iovec iov[2] = {
					{ .iov_base = &packet_type, .iov_len = 1 },
					{ .iov_base = task->send.buffer.data, .iov_len = task->send.buffer.len }
				};

				msg.msg_iov = iov;
				msg.msg_iovlen = task->send.buffer.len ? 2 : 1;

				sendmsg(sockfd, &msg, 0);
			}

			fastd_buffer_free(task->send.buffer);
			break;

		case TASK_HANDLE_RECV:
			if (ctx->conf->mode == MODE_TAP) {
				const fastd_eth_addr *src_addr = fastd_get_source_address(ctx, task->handle_recv.buffer);

				if (fastd_eth_addr_is_unicast(src_addr))
					fastd_peer_eth_addr_add(ctx, task->peer, src_addr);
			}

			if (write(ctx->tunfd, task->handle_recv.buffer.data, task->handle_recv.buffer.len) < 0)
				warn_errno(ctx, "write");

			if (ctx->conf->mode == MODE_TAP && ctx->conf->peer_to_peer) {
				const fastd_eth_addr *dest_addr = fastd_get_dest_address(ctx, task->handle_recv.buffer);

				if (fastd_eth_addr_is_unicast(dest_addr)) {
					fastd_peer *dest_peer = fastd_peer_find_by_eth_addr(ctx, dest_addr);

					if (dest_peer && dest_peer != task->peer && dest_peer->state == STATE_ESTABLISHED) {
						ctx->conf->protocol->send(ctx, dest_peer, task->handle_recv.buffer);
					}
					else {
						fastd_buffer_free(task->handle_recv.buffer);
					}
				}
				else {
					fastd_peer *dest_peer;
					for (dest_peer = ctx->peers; dest_peer; dest_peer = dest_peer->next) {
						if (dest_peer != task->peer && dest_peer->state == STATE_ESTABLISHED) {
							fastd_buffer send_buffer = fastd_buffer_alloc(task->handle_recv.buffer.len, ctx->conf->protocol->min_encrypt_head_space(ctx), 0);
							memcpy(send_buffer.data, task->handle_recv.buffer.data, task->handle_recv.buffer.len);
							ctx->conf->protocol->send(ctx, dest_peer, send_buffer);
						}
					}

					fastd_buffer_free(task->handle_recv.buffer);
				}
			}
			else {
				fastd_buffer_free(task->handle_recv.buffer);
			}
			break;

		case TASK_HANDSHAKE:
			pr_debug(ctx, "sending handshake to %P...", task->peer);
			ctx->conf->protocol->handshake_init(ctx, task->peer);

			if (fastd_peer_is_established(task->peer))
				fastd_task_schedule_handshake(ctx, task->peer, fastd_rand(ctx, 10000, 20000));
			else
				fastd_task_schedule_handshake(ctx, task->peer, 20000);
			break;

		case TASK_KEEPALIVE:
			pr_debug(ctx, "sending keepalive to %P", task->peer);
			ctx->conf->protocol->send(ctx, task->peer, fastd_buffer_alloc(0, ctx->conf->protocol->min_encrypt_head_space(ctx), 0));
			break;

		default:
			exit_bug(ctx, "invalid task type");
		}

		free(task);
	}
}

static void handle_tun(fastd_context *ctx) {
	size_t max_len = fastd_max_packet_size(ctx);
	fastd_buffer buffer = fastd_buffer_alloc(max_len, ctx->conf->protocol->min_encrypt_head_space(ctx), 0);

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

			if (peer->state == STATE_ESTABLISHED) {
				ctx->conf->protocol->send(ctx, peer, buffer);
			}
			else {
				fastd_buffer_free(buffer);
			}
		}
	}
	if (peer == NULL) {
		for (peer = ctx->peers; peer; peer = peer->next) {
			if (peer->state == STATE_ESTABLISHED) {
				fastd_buffer send_buffer = fastd_buffer_alloc(len, ctx->conf->protocol->min_encrypt_head_space(ctx), 0);
				memcpy(send_buffer.data, buffer.data, len);
				ctx->conf->protocol->send(ctx, peer, send_buffer);
			}
		}

		fastd_buffer_free(buffer);
	}
}

static void handle_socket(fastd_context *ctx, int sockfd) {
	size_t max_len = ctx->conf->protocol->max_packet_size(ctx);
	fastd_buffer buffer = fastd_buffer_alloc(max_len, ctx->conf->protocol->min_decrypt_head_space(ctx), 0);
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
		if (peer->address.sa.sa_family != recvaddr.sa.sa_family)
			continue;

		if (recvaddr.sa.sa_family == AF_INET) {
			if (peer->address.in.sin_addr.s_addr != recvaddr.in.sin_addr.s_addr)
				continue;
			if (peer->address.in.sin_port != recvaddr.in.sin_port)
				continue;

			break;
		}
		else if (recvaddr.sa.sa_family == AF_INET6) {
			if (!IN6_ARE_ADDR_EQUAL(&peer->address.in6.sin6_addr, &recvaddr.in6.sin6_addr))
				continue;
			if (peer->address.in6.sin6_port != recvaddr.in6.sin6_port)
				continue;

			break;
		}
		else {
			exit_bug(ctx, "unsupported address family");
		}
	}

	if (peer) {
		switch (packet_type) {
		case PACKET_DATA:
			ctx->conf->protocol->handle_recv(ctx, peer, buffer);
			break;

		case PACKET_HANDSHAKE:
			fastd_handshake_handle(ctx, peer, buffer);
			break;

		default:
			fastd_buffer_free(buffer);
		}
	}
	else if(ctx->conf->n_floating) {
		switch (packet_type) {
		case PACKET_DATA:
			peer = fastd_peer_add_temp(ctx, (fastd_peer_address*)&recvaddr);
			ctx->conf->protocol->handle_recv(ctx, peer, buffer);
			break;

		case PACKET_HANDSHAKE:
			peer = fastd_peer_add_temp(ctx, (fastd_peer_address*)&recvaddr);
			fastd_handshake_handle(ctx, peer, buffer);
			break;

		default:
			fastd_buffer_free(buffer);
		}
	}
	else  {
		pr_debug(ctx, "received packet from unknown peer");
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

		if (fastd_peer_is_temporary(peer)) {
			if (timespec_diff(&ctx->now, &peer->seen) > ctx->conf->peer_stale_time_temp*1000)
				fastd_peer_reset(ctx, peer);
		}
		else if (fastd_peer_is_established(peer)) {
			if (timespec_diff(&ctx->now, &peer->seen) > ctx->conf->peer_stale_time*1000)
				fastd_peer_reset(ctx, peer);
		}
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

		if (sighup) {
			sighup = false;
			fastd_reconfigure(&ctx, &conf);
		}
	}

	on_down(&ctx);

	delete_peers(&ctx);

	close_sockets(&ctx);
	close_tuntap(&ctx);

	fastd_config_release(&ctx, &conf);

	return 0;
}
