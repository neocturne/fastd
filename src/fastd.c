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


#include "fastd.h"
#include "config.h"
#include "crypto.h"
#include "handshake.h"
#include "peer.h"
#include <fastd_version.h>

#include <fcntl.h>
#include <grp.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <string.h>
#include <syslog.h>
#include <sys/resource.h>
#include <sys/wait.h>

#ifdef HAVE_LIBSODIUM
#include <sodium/core.h>
#endif

#ifdef USE_OPENSSL
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#endif


static volatile bool sighup = false;
static volatile bool terminate = false;
static volatile bool dump = false;


static void on_sighup(int signo UNUSED) {
	sighup = true;
}

static void on_terminate(int signo UNUSED) {
	terminate = true;
}

static void on_sigusr1(int signo UNUSED) {
	dump = true;
}

static void on_sigchld(int signo UNUSED) {
}

static void init_signals(fastd_context_t *ctx) {
	struct sigaction action;

	action.sa_flags = 0;
	sigemptyset(&action.sa_mask);

	/* unblock all signals */
	sigprocmask(SIG_SETMASK, &action.sa_mask, NULL);

	action.sa_handler = on_sighup;
	if (sigaction(SIGHUP, &action, NULL))
		exit_errno(ctx, "sigaction");

	action.sa_handler = on_terminate;
	if (sigaction(SIGTERM, &action, NULL))
		exit_errno(ctx, "sigaction");
	if (sigaction(SIGQUIT, &action, NULL))
		exit_errno(ctx, "sigaction");
	if (sigaction(SIGINT, &action, NULL))
		exit_errno(ctx, "sigaction");

	action.sa_handler = on_sigusr1;
	if (sigaction(SIGUSR1, &action, NULL))
		exit_errno(ctx, "sigaction");

	action.sa_handler = on_sigchld;
	if (sigaction(SIGCHLD, &action, NULL))
		exit_errno(ctx, "sigaction");

	action.sa_handler = SIG_IGN;
	if (sigaction(SIGPIPE, &action, NULL))
		exit_errno(ctx, "sigaction");
	if (sigaction(SIGTTIN, &action, NULL))
		exit_errno(ctx, "sigaction");
	if (sigaction(SIGTTOU, &action, NULL))
		exit_errno(ctx, "sigaction");

}

static void open_pipe(fastd_context_t *ctx, int *readfd, int *writefd) {
	int pipefd[2];

	if (pipe(pipefd))
		exit_errno(ctx, "pipe");

	fastd_setfd(ctx, pipefd[0], FD_CLOEXEC, 0);
	fastd_setfd(ctx, pipefd[1], FD_CLOEXEC, 0);

	*readfd = pipefd[0];
	*writefd = pipefd[1];
}

static inline void init_pipes(fastd_context_t *ctx) {
	open_pipe(ctx, &ctx->resolverfd, &ctx->resolvewfd);
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

	if (ctx->conf->log_syslog_level > LL_UNSPEC)
		openlog(ctx->conf->log_syslog_ident, LOG_PID, LOG_DAEMON);

	fastd_log_file_t *config;
	for (config = ctx->conf->log_files; config; config = config->next) {
		fastd_log_fd_t *file = malloc(sizeof(fastd_log_fd_t));

		file->config = config;
		file->fd = open(config->filename, O_WRONLY|O_APPEND|O_CREAT, 0600);

		file->next = ctx->log_files;
		ctx->log_files = file;
	}

	ctx->log_initialized = true;

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


static void init_sockets(fastd_context_t *ctx) {
	ctx->socks = malloc(ctx->conf->n_bind_addrs * sizeof(fastd_socket_t));

	unsigned i;
	fastd_bind_address_t *addr = ctx->conf->bind_addrs;
	for (i = 0; i < ctx->conf->n_bind_addrs; i++) {
		ctx->socks[i] = (fastd_socket_t){ .fd = -2, .addr = addr };

		if (addr == ctx->conf->bind_addr_default_v4)
			ctx->sock_default_v4 = &ctx->socks[i];

		if (addr == ctx->conf->bind_addr_default_v6)
			ctx->sock_default_v6 = &ctx->socks[i];

		addr = addr->next;
	}

	ctx->n_socks = ctx->conf->n_bind_addrs;
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

static void close_sockets(fastd_context_t *ctx) {
	unsigned i;
	for (i = 0; i < ctx->n_socks; i++)
		fastd_socket_close(ctx, &ctx->socks[i]);

	free(ctx->socks);
}

static inline void handle_forward(fastd_context_t *ctx, fastd_peer_t *source_peer, fastd_buffer_t buffer) {
	fastd_eth_addr_t dest_addr = fastd_get_dest_address(ctx, buffer);

	if (fastd_eth_addr_is_unicast(dest_addr)) {
		fastd_peer_t *dest_peer = fastd_peer_find_by_eth_addr(ctx, dest_addr);

		if (!dest_peer || dest_peer == source_peer || !fastd_peer_is_established(dest_peer)) {
			fastd_buffer_free(buffer);
			return;
		}

		ctx->conf->protocol->send(ctx, dest_peer, buffer);
	}
	else {
		fastd_send_all(ctx, source_peer, buffer);
	}
}

void fastd_handle_receive(fastd_context_t *ctx, fastd_peer_t *peer, fastd_buffer_t buffer) {
	if (ctx->conf->mode == MODE_TAP) {
		if (buffer.len < ETH_HLEN) {
			pr_debug(ctx, "received truncated packet");
			fastd_buffer_free(buffer);
			return;
		}

		fastd_eth_addr_t src_addr = fastd_get_source_address(ctx, buffer);

		if (fastd_eth_addr_is_unicast(src_addr))
			fastd_peer_eth_addr_add(ctx, peer, src_addr);
	}

	ctx->rx.packets++;
	ctx->rx.bytes += buffer.len;

	fastd_tuntap_write(ctx, buffer);

	if (ctx->conf->mode == MODE_TAP && ctx->conf->forward) {
		handle_forward(ctx, peer, buffer);
		return;
	}

	fastd_buffer_free(buffer);
}

static inline void on_pre_up(fastd_context_t *ctx) {
	if (!ctx->conf->on_pre_up)
		return;

	fastd_shell_exec(ctx, ctx->conf->on_pre_up, ctx->conf->on_pre_up_dir, NULL, NULL, NULL, NULL);
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

static inline void on_post_down(fastd_context_t *ctx) {
	if (!ctx->conf->on_post_down)
		return;

	fastd_shell_exec(ctx, ctx->conf->on_post_down, ctx->conf->on_post_down_dir, NULL, NULL, NULL, NULL);
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

static void dump_state(fastd_context_t *ctx) {
	pr_info(ctx, "TX stats: %U packet(s), %U byte(s); dropped: %U packet(s), %U byte(s); error: %U packet(s), %U byte(s)",
		ctx->tx.packets, ctx->tx.bytes, ctx->tx_dropped.packets, ctx->tx_dropped.bytes, ctx->tx_error.packets, ctx->tx_error.bytes);
	pr_info(ctx, "RX stats: %U packet(s), %U byte(s)", ctx->rx.packets, ctx->rx.bytes);

	pr_info(ctx, "dumping peers:");

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

	pr_info(ctx, "dump finished.");
}

static inline void update_time(fastd_context_t *ctx) {
	clock_gettime(CLOCK_MONOTONIC, &ctx->now);
}

static inline void no_valid_address_debug(fastd_context_t *ctx, const fastd_peer_t *peer) {
	pr_debug(ctx, "not sending a handshake to %P (no valid address resolved)", peer);
}

static void send_handshake(fastd_context_t *ctx, fastd_peer_t *peer) {
	if (!fastd_peer_is_established(peer)) {
		if (!peer->next_remote->n_addresses) {
			no_valid_address_debug(ctx, peer);
			return;
		}

		fastd_peer_claim_address(ctx, peer, NULL, NULL, &peer->next_remote->addresses[peer->next_remote->current_address]);
		fastd_peer_reset_socket(ctx, peer);
	}

	if (!peer->sock)
		return;

	if (peer->address.sa.sa_family == AF_UNSPEC) {
		no_valid_address_debug(ctx, peer);
		return;
	}

	if (!fastd_timed_out(ctx, &peer->last_handshake_timeout)
	    && fastd_peer_address_equal(&peer->address, &peer->last_handshake_address)) {
		pr_debug(ctx, "not sending a handshake to %P as we sent one a short time ago", peer);
		return;
	}

	pr_debug(ctx, "sending handshake to %P[%I]...", peer, &peer->address);
	peer->last_handshake_timeout = fastd_in_seconds(ctx, ctx->conf->min_handshake_interval);
	peer->last_handshake_address = peer->address;
	ctx->conf->protocol->handshake_init(ctx, peer->sock, &peer->local_address, &peer->address, peer);
}

static void handle_handshake_queue(fastd_context_t *ctx) {
	if (!ctx->handshake_queue.next)
		return;

	fastd_peer_t *peer = container_of(ctx->handshake_queue.next, fastd_peer_t, handshake_entry);
	if (!fastd_timed_out(ctx, &peer->next_handshake))
		return;

	fastd_peer_schedule_handshake_default(ctx, peer);

	if (!fastd_peer_may_connect(ctx, peer)) {
		if (peer->next_remote != NULL) {
			pr_debug(ctx, "temporarily disabling handshakes with %P", peer);
			peer->next_remote = NULL;
		}

		return;
	}

	if (peer->next_remote || fastd_peer_is_established(peer)) {
		send_handshake(ctx, peer);

		if (fastd_peer_is_established(peer))
			return;

		if (++peer->next_remote->current_address < peer->next_remote->n_addresses)
			return;

		peer->next_remote = peer->next_remote->next;
	}

	if (!peer->next_remote)
		peer->next_remote = peer->remotes;

	peer->next_remote->current_address = 0;

	if (fastd_remote_is_dynamic(peer->next_remote))
		fastd_resolve_peer(ctx, peer, peer->next_remote);
}

static inline bool handle_tun_tap(fastd_context_t *ctx, fastd_buffer_t buffer) {
	if (ctx->conf->mode != MODE_TAP)
		return false;

	if (buffer.len < ETH_HLEN) {
		pr_debug(ctx, "truncated packet on tap interface");
		fastd_buffer_free(buffer);
		return true;
	}

	fastd_eth_addr_t dest_addr = fastd_get_dest_address(ctx, buffer);
	if (!fastd_eth_addr_is_unicast(dest_addr))
		return false;

	fastd_peer_t *peer = fastd_peer_find_by_eth_addr(ctx, dest_addr);

	if (!peer || !fastd_peer_is_established(peer)) {
		fastd_buffer_free(buffer);
		return true;
	}

	ctx->conf->protocol->send(ctx, peer, buffer);
	return true;
}

static void handle_tun(fastd_context_t *ctx) {
	fastd_buffer_t buffer = fastd_tuntap_read(ctx);
	if (!buffer.len)
		return;

	if (handle_tun_tap(ctx, buffer))
		return;

	/* TUN mode or multicast packet */
	fastd_send_all(ctx, NULL, buffer);
}

static void handle_resolve_returns(fastd_context_t *ctx) {
	fastd_resolve_return_t resolve_return;
	while (read(ctx->resolverfd, &resolve_return, sizeof(resolve_return)) < 0) {
		if (errno != EINTR)
			exit_errno(ctx, "handle_resolve_return: read");
	}

	fastd_peer_address_t addresses[resolve_return.n_addr];
	while (read(ctx->resolverfd, &addresses, sizeof(addresses)) < 0) {
		if (errno != EINTR)
			exit_errno(ctx, "handle_resolve_return: read");
	}

	fastd_peer_t *peer;
	for (peer = ctx->peers; peer; peer = peer->next) {
		if (!peer->config)
			continue;

		fastd_remote_t *remote;
		for (remote = peer->remotes; remote; remote = remote->next) {
			if (remote == resolve_return.remote)
				break;
		}

		if (!remote)
			continue;

		fastd_peer_handle_resolve(ctx, peer, remote, resolve_return.n_addr, addresses);

		break;
	}

	fastd_remote_unref(resolve_return.remote);
}

static inline int handshake_timeout(fastd_context_t *ctx) {
	if (!ctx->handshake_queue.next)
		return -1;

       fastd_peer_t *peer = container_of(ctx->handshake_queue.next, fastd_peer_t, handshake_entry);

       int diff_msec = timespec_diff(&peer->next_handshake, &ctx->now);
       if (diff_msec < 0)
	       return 0;
       else
	       return diff_msec;
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

	int keepalive_timeout = timespec_diff(&ctx->next_keepalives, &ctx->now);

	if (keepalive_timeout < 0)
		keepalive_timeout = 0;

	int timeout = handshake_timeout(ctx);
	if (timeout < 0 || timeout > keepalive_timeout)
		timeout = keepalive_timeout;

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
		handle_resolve_returns(ctx);

	for (i = 2; i < ctx->n_socks+2; i++) {
		if (fds[i].revents & (POLLERR|POLLHUP|POLLNVAL))
			fastd_socket_error(ctx, &ctx->socks[i-2]);
		else if (fds[i].revents & POLLIN)
			fastd_receive(ctx, &ctx->socks[i-2]);
	}

	for (peer = ctx->peers; peer; peer = peer->next) {
		if (fds[i].revents & (POLLERR|POLLHUP|POLLNVAL))
			fastd_peer_reset_socket(ctx, peer);
		else if (fds[i].revents & POLLIN)
			fastd_receive(ctx, peer->sock);

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
			if (timespec_diff(&ctx->now, &peer->seen) > (int)ctx->conf->peer_stale_time*1000) {
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

	fastd_socket_handle_binds(ctx);

	if (fastd_timed_out(ctx, &ctx->next_keepalives)) {
		fastd_peer_t *peer;
		for (peer = ctx->peers; peer; peer = peer->next) {
			if (!fastd_peer_is_established(peer))
				continue;

			if (timespec_diff(&ctx->now, &peer->last_send) < (int)ctx->conf->keepalive_timeout*1000)
				continue;

			pr_debug2(ctx, "sending keepalive to %P", peer);
			ctx->conf->protocol->send(ctx, peer, fastd_buffer_alloc(ctx, 0, ctx->conf->min_encrypt_head_space, ctx->conf->min_encrypt_tail_space));
		}

		ctx->next_keepalives.tv_sec += ctx->conf->keepalive_interval;
	}
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
	if (chdir("/"))
		pr_error(ctx, "can't chdir to `/': %s", strerror(errno));

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

/* will double fork and forward potential exit codes from the child to the parent */
static int daemonize(fastd_context_t *ctx) {
	static const uint8_t ERROR_STATUS = 1;

	uint8_t status = 1;
	int parent_rpipe, parent_wpipe;
	open_pipe(ctx, &parent_rpipe, &parent_wpipe);

	pid_t fork1 = fork();

	if (fork1 < 0) {
		exit_errno(ctx, "fork");
	}
	else if (fork1 == 0) {
		/* child 1 */
		if (close(parent_rpipe) < 0)
			pr_error_errno(ctx, "close");

		if (setsid() < 0)
			pr_error_errno(ctx, "setsid");

		int child_rpipe, child_wpipe;
		open_pipe(ctx, &child_rpipe, &child_wpipe);

		pid_t fork2 = fork();

		if (fork2 < 0) {
			write(parent_wpipe, &ERROR_STATUS, 1);
			exit_errno(ctx, "fork");
		}
		else if (fork2 == 0) {
			/* child 2 */

			if (close(child_rpipe) < 0 || close(parent_wpipe) < 0) {
				write(child_wpipe, &ERROR_STATUS, 1);
				pr_error_errno(ctx, "close");
			}

			return child_wpipe;
		}
		else {
			/* still child 1 */
			int child_status;
			pid_t ret;
			do {
				if (read(child_rpipe, &status, 1) > 0) {
					write(parent_wpipe, &status, 1);
					exit(0);
				}

				ret = waitpid(fork2, &child_status, WNOHANG);
			} while (!ret);

			if (ret < 0) {
				write(child_wpipe, &ERROR_STATUS, 1);
				pr_error_errno(ctx, "waitpid");
			}

			if (WIFEXITED(child_status)) {
				status = WEXITSTATUS(child_status);
				write(parent_wpipe, &status, 1);
				exit(status);
			}
			else {
				write(parent_wpipe, &ERROR_STATUS, 1);
				if (WIFSIGNALED(child_status))
					exit_error(ctx, "child exited with signal %i", WTERMSIG(child_status));
				exit(1);
			}
		}
	}
	else {
		/* parent */
		struct sigaction action;
		action.sa_flags = 0;
		sigemptyset(&action.sa_mask);
		action.sa_handler = SIG_IGN;

		if (sigaction(SIGCHLD, &action, NULL))
			exit_errno(ctx, "sigaction");

		if (read(parent_rpipe, &status, 1) < 0)
			exit_errno(ctx, "read");

		exit(status);
	}

	return -1;
}

int main(int argc, char *argv[]) {
	fastd_context_t ctx = {};
	int status_fd = -1;

	close_fds(&ctx);

	fastd_random_bytes(&ctx, &ctx.randseed, sizeof(ctx.randseed), false);

	fastd_config_t conf;
	fastd_configure(&ctx, &conf, argc, argv);
	ctx.conf = &conf;

	if (conf.generate_key) {
		conf.protocol->generate_key(&ctx);
		exit(0);
	}

	conf.protocol_config = conf.protocol->init(&ctx);

	if (conf.show_key) {
		conf.protocol->show_key(&ctx);
		exit(0);
	}

	init_signals(&ctx);

	if (conf.daemon)
		status_fd = daemonize(&ctx);

	init_log(&ctx);

#ifdef HAVE_LIBSODIUM
	sodium_init();
#endif

#ifdef USE_OPENSSL
	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();
	OPENSSL_config(NULL);
#endif

	fastd_config_check(&ctx, &conf);

	update_time(&ctx);

	ctx.next_keepalives = ctx.now;
	ctx.next_keepalives.tv_sec += conf.keepalive_interval;

	ctx.unknown_handshakes[0].timeout = ctx.now;

	pr_info(&ctx, "fastd " FASTD_VERSION " starting");

	fastd_cap_init(&ctx);

	/* change groups early as the can be relevant for file access (for PID file & log files) */
	set_groups(&ctx);

	init_pipes(&ctx);
	init_sockets(&ctx);

	if (!fastd_socket_handle_binds(&ctx))
		exit_error(&ctx, "unable to bind default socket");

	on_pre_up(&ctx);

	fastd_tuntap_open(&ctx);

	init_peer_groups(&ctx);

	write_pid(&ctx, getpid());

	if (status_fd >= 0) {
		static const uint8_t STATUS = 0;
		if (write(status_fd, &STATUS, 1) < 0)
			exit_errno(&ctx, "status: write");
		if (close(status_fd))
			exit_errno(&ctx, "status: close");
	}

	if (conf.drop_caps == DROP_CAPS_EARLY)
		drop_caps(&ctx);

	on_up(&ctx);

	if (conf.drop_caps == DROP_CAPS_ON)
		drop_caps(&ctx);
	else if (conf.drop_caps == DROP_CAPS_OFF)
		set_user(&ctx);

	fastd_config_load_peer_dirs(&ctx, &conf);
	init_peers(&ctx);

	while (!terminate) {
		handle_handshake_queue(&ctx);

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
			dump_state(&ctx);
		}

		pthread_sigmask(SIG_SETMASK, &oldset, NULL);
	}

	on_down(&ctx);

	delete_peers(&ctx);
	delete_peer_groups(&ctx);

	fastd_tuntap_close(&ctx);
	close_sockets(&ctx);

	on_post_down(&ctx);

	free(ctx.protocol_state);
	free(ctx.eth_addr);
	free(ctx.ifname);

#ifdef USE_OPENSSL
	CONF_modules_free();
	EVP_cleanup();
	ERR_free_strings();
#endif

	close_log(&ctx);
	fastd_config_release(&ctx, &conf);

	return 0;
}
