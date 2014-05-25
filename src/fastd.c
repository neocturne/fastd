/*
  Copyright (c) 2012-2014, Matthias Schiffer <mschiffer@universe-factory.net>
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
#include "async.h"
#include "config.h"
#include "peer.h"
#include "peer_hashtable.h"
#include "poll.h"
#include <fastd_version.h>

#include <grp.h>
#include <pthread.h>
#include <signal.h>
#include <syslog.h>
#include <sys/resource.h>
#include <sys/wait.h>

#ifdef HAVE_LIBSODIUM
#include <sodium/core.h>
#endif

#ifdef ENABLE_OPENSSL
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#endif

#ifdef ENABLE_SYSTEMD
#include <sys/un.h>
#endif


fastd_context_t ctx;


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
	size_t i;
	for (i = 0; i < VECTOR_LEN(ctx.async_pids);) {
		pid_t pid = VECTOR_INDEX(ctx.async_pids, i);
		if (waitpid(pid, NULL, WNOHANG) > 0) {
			pr_debug("child process %u finished", (unsigned)pid);
		}
		else {
			if (errno == ECHILD) {
				i++;
				continue;
			}
			else {
				pr_error_errno("waitpid");
			}
		}

		VECTOR_DELETE(ctx.async_pids, i);
	}
}

static void init_signals(void) {
	struct sigaction action;

	action.sa_flags = 0;
	sigemptyset(&action.sa_mask);

	/* unblock all signals */
	sigprocmask(SIG_SETMASK, &action.sa_mask, NULL);

	action.sa_handler = on_sighup;
	if (sigaction(SIGHUP, &action, NULL))
		exit_errno("sigaction");

	action.sa_handler = on_terminate;
	if (sigaction(SIGTERM, &action, NULL))
		exit_errno("sigaction");
	if (sigaction(SIGQUIT, &action, NULL))
		exit_errno("sigaction");
	if (sigaction(SIGINT, &action, NULL))
		exit_errno("sigaction");

	action.sa_handler = on_sigusr1;
	if (sigaction(SIGUSR1, &action, NULL))
		exit_errno("sigaction");

	action.sa_handler = on_sigchld;
	if (sigaction(SIGCHLD, &action, NULL))
		exit_errno("sigaction");

	action.sa_handler = SIG_IGN;
	if (sigaction(SIGPIPE, &action, NULL))
		exit_errno("sigaction");
	if (sigaction(SIGTTIN, &action, NULL))
		exit_errno("sigaction");
	if (sigaction(SIGTTOU, &action, NULL))
		exit_errno("sigaction");

}

static inline void init_log(void) {
	if (conf.log_syslog_level > LL_UNSPEC)
		openlog(conf.log_syslog_ident, LOG_PID, LOG_DAEMON);

	ctx.log_initialized = true;
}

static inline void close_log(void) {
	closelog();
}


static void init_sockets(void) {
	ctx.socks = malloc(conf.n_bind_addrs * sizeof(fastd_socket_t));

	size_t i;
	fastd_bind_address_t *addr = conf.bind_addrs;
	for (i = 0; i < conf.n_bind_addrs; i++) {
		ctx.socks[i] = (fastd_socket_t){ .fd = -2, .addr = addr };

		if (addr == conf.bind_addr_default_v4)
			ctx.sock_default_v4 = &ctx.socks[i];

		if (addr == conf.bind_addr_default_v6)
			ctx.sock_default_v6 = &ctx.socks[i];

		addr = addr->next;
	}

	ctx.n_socks = conf.n_bind_addrs;
}

static void close_sockets(void) {
	size_t i;
	for (i = 0; i < ctx.n_socks; i++)
		fastd_socket_close(&ctx.socks[i]);

	free(ctx.socks);
}

static inline void on_pre_up(void) {
	fastd_shell_command_exec(&conf.on_pre_up, NULL);
}

static inline void on_up(void) {
	fastd_shell_command_exec(&conf.on_up, NULL);
}

static inline void on_down(void) {
	fastd_shell_command_exec(&conf.on_down, NULL);
}

static inline void on_post_down(void) {
	fastd_shell_command_exec(&conf.on_post_down, NULL);
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

static void init_peer_groups(void) {
	ctx.peer_group = init_peer_group(conf.peer_group, NULL);
}

static void free_peer_group(fastd_peer_group_t *group) {
	while (group->children) {
		fastd_peer_group_t *child = group->children;
		group->children = group->children->next;

		free_peer_group(child);
	}

	free(group);
}

static void delete_peer_groups(void) {
	free_peer_group(ctx.peer_group);
}

static void init_peers(void) {
	fastd_peer_config_t *peer_conf;
	for (peer_conf = conf.peers; peer_conf; peer_conf = peer_conf->next)
		conf.protocol->peer_configure(peer_conf);

	for (peer_conf = conf.peers; peer_conf; peer_conf = peer_conf->next) {
		bool enable = conf.protocol->peer_check(peer_conf);

		if (enable && !peer_conf->enabled)
			fastd_peer_add(peer_conf);

		peer_conf->enabled = enable;
	}

	size_t i;
	for (i = 0; i < VECTOR_LEN(ctx.peers);) {
		fastd_peer_t *peer = VECTOR_INDEX(ctx.peers, i);

		if (peer->config) {
			if (!peer->config->enabled) {
				pr_info("previously enabled peer %P disabled, deleting.", peer);
				fastd_peer_delete(peer);
				continue;
			}
		}
		else {
			if (!conf.protocol->peer_check_temporary(peer)) {
				fastd_peer_delete(peer);
				continue;
			}
		}

		i++;
	}
}

static void delete_peers(void) {
	while (VECTOR_LEN(ctx.peers))
		fastd_peer_delete(VECTOR_INDEX(ctx.peers, VECTOR_LEN(ctx.peers)-1));
}

static void dump_state(void) {
	pr_info("TX stats: %U packet(s), %U byte(s); dropped: %U packet(s), %U byte(s); error: %U packet(s), %U byte(s)",
		ctx.tx.packets, ctx.tx.bytes, ctx.tx_dropped.packets, ctx.tx_dropped.bytes, ctx.tx_error.packets, ctx.tx_error.bytes);
	pr_info("RX stats: %U packet(s), %U byte(s)", ctx.rx.packets, ctx.rx.bytes);

	pr_info("dumping peers:");

	size_t i;
	for (i = 0; i < VECTOR_LEN(ctx.peers);) {
		fastd_peer_t *peer = VECTOR_INDEX(ctx.peers, i);

		if (!fastd_peer_is_established(peer)) {
			pr_info("peer %P not connected, address: %I", peer, &peer->address);
			continue;
		}

		if (conf.mode == MODE_TAP) {
			size_t i, eth_addresses = 0;
			for (i = 0; i < VECTOR_LEN(ctx.eth_addrs); i++) {
				if (VECTOR_INDEX(ctx.eth_addrs, i).peer == peer)
					eth_addresses++;
			}

			pr_info("peer %P connected, address: %I, associated MAC addresses: %u", peer, &peer->address, eth_addresses);
		}
		else {
			pr_info("peer %P connected, address: %I", peer, &peer->address);
		}
	}

	pr_info("dump finished.");
}

static inline void maintenance(void) {
	if (!fastd_timed_out(&ctx.next_maintenance))
		return;

	fastd_socket_handle_binds();
	fastd_peer_maintenance();

	ctx.next_maintenance.tv_sec += MAINTENANCE_INTERVAL;
}


/** Closes all open FDs except stdin, stdout and stderr */
void fastd_close_all_fds(void) {
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
				pr_error_errno("close");
		}
	}
}

static void write_pid(pid_t pid) {
	if (!conf.pid_file)
		return;

	uid_t uid = geteuid();
	gid_t gid = getegid();

	if (conf.user || conf.group) {
		if (setegid(conf.gid) < 0)
			pr_debug_errno("setegid");
		if (seteuid(conf.uid) < 0)
			pr_debug_errno("seteuid");
	}

	int fd = open(conf.pid_file, O_WRONLY|O_CREAT|O_TRUNC, 0666);
	if (fd < 0) {
		pr_error_errno("can't write PID file: open");
		goto end;
	}

	if (dprintf(fd, "%i", pid) < 0)
		pr_error_errno("can't write PID file: dprintf");

	if (close(fd) < 0)
		pr_warn_errno("close");

 end:
	if (seteuid(uid) < 0)
		pr_debug_errno("seteuid");
	if (setegid(gid) < 0)
		pr_debug_errno("setegid");
}

static void set_user(void) {
	if (conf.user || conf.group) {
		if (setgid(conf.gid) < 0)
			exit_errno("setgid");

		if (setuid(conf.uid) < 0)
			exit_errno("setuid");

		pr_info("Changed to UID %i, GID %i.", conf.uid, conf.gid);
	}
}

static void set_groups(void) {
	if (conf.groups) {
		if (setgroups(conf.n_groups, conf.groups) < 0) {
			if (errno != EPERM)
				pr_debug_errno("setgroups");
		}
	}
	else if (conf.user || conf.group) {
		if (setgroups(1, &conf.gid) < 0) {
			if (errno != EPERM)
				pr_debug_errno("setgroups");
		}
	}
}

static void drop_caps(void) {
	set_user();
	fastd_cap_drop();
}

/* will double fork and wait for a status notification from the child */
static int daemonize(void) {
	uint8_t status = 1;
	int pipefd[2];

	if (pipe(pipefd))
		exit_errno("pipe");

	pid_t fork1 = fork();

	if (fork1 < 0) {
		exit_errno("fork");
	}
	else if (fork1 > 0) {
		/* parent */
		if (close(pipefd[1]) < 0)
			exit_errno("close");

		if (waitpid(fork1, NULL, 0) < 0)
			exit_errno("waitpid");

		if (read(pipefd[0], &status, 1) < 0)
			exit_errno("read");

		exit(status);
	}
	else {
		/* child 1 */
		if (close(pipefd[0]) < 0)
			pr_error_errno("close");

		if (setsid() < 0)
			pr_error_errno("setsid");

		pid_t fork2 = fork();

		if (fork2 < 0) {
			exit_errno("fork");
		}
		else if (fork2 > 0) {
			/* still child 1 */
			_exit(0);
		}
		else {
			/* child 2 */
			return pipefd[1];
		}
	}
}

#ifdef ENABLE_SYSTEMD
static void notify_systemd(const char *notify_socket) {
	int fd;
	struct sockaddr_un sa = {};

	if ((notify_socket[0] != '@' && notify_socket[0] != '/') || notify_socket[1] == 0)
		return;

	fd = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (fd < 0)
		return;

	sa.sun_family = AF_UNIX;

	strncpy(sa.sun_path, notify_socket, sizeof(sa.sun_path));
	if (sa.sun_path[0] == '@')
		sa.sun_path[0] = 0;

	if (connect(fd, (struct sockaddr*)&sa, offsetof(struct sockaddr_un, sun_path) + strnlen(notify_socket, sizeof(sa.sun_path))) < 0) {
		pr_debug_errno("unable to connect to notify socket: connect");
		close(fd);
		return;
	}

	dprintf(fd, "READY=1\nMAINPID=%lu", (unsigned long) getpid());
	pr_debug("sent startup notification to systemd");

	close(fd);
}
#endif

int main(int argc, char *argv[]) {
	memset(&ctx, 0, sizeof(ctx));
	int status_fd = -1;

#ifdef ENABLE_SYSTEMD
	char *notify_socket = getenv("NOTIFY_SOCKET");

	if (notify_socket) {
		notify_socket = strdup(notify_socket);

		/* unset the socket to allow calling on_pre_up safely */
		unsetenv("NOTIFY_SOCKET");
	}
#endif

	fastd_close_all_fds();

	fastd_random_bytes(&ctx.randseed, sizeof(ctx.randseed), false);

	fastd_configure(argc, argv);

	if (conf.verify_config) {
		fastd_config_verify();
		exit(0);
	}

	if (conf.generate_key) {
		conf.protocol->generate_key();
		exit(0);
	}

	conf.protocol_config = conf.protocol->init();

	if (conf.show_key) {
		conf.protocol->show_key();
		exit(0);
	}

	init_signals();

	if (conf.daemon)
		status_fd = daemonize();

	if (chdir("/"))
		pr_error("can't chdir to `/': %s", strerror(errno));

	init_log();

#ifdef HAVE_LIBSODIUM
	sodium_init();
#endif

#ifdef ENABLE_OPENSSL
	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();
	OPENSSL_config(NULL);
#endif

	fastd_config_check();

	fastd_update_time();

	ctx.next_maintenance = fastd_in_seconds(MAINTENANCE_INTERVAL);

	ctx.unknown_handshakes[0].timeout = ctx.now;

	pr_info("fastd " FASTD_VERSION " starting");

	fastd_cap_init();

	/* change groups early as the can be relevant for file access (for the PID file) */
	set_groups();

	init_sockets();
	fastd_async_init();
	fastd_poll_init();

	if (!fastd_socket_handle_binds())
		exit_error("unable to bind default socket");

	on_pre_up();

	fastd_tuntap_open();

	init_peer_groups();

	write_pid(getpid());

#ifdef ENABLE_SYSTEMD
	if (notify_socket) {
		notify_systemd(notify_socket);
		free(notify_socket);
	}
#endif

	if (status_fd >= 0) {
		static const uint8_t STATUS = 0;
		if (write(status_fd, &STATUS, 1) < 0)
			exit_errno("status: write");
		if (close(status_fd))
			exit_errno("status: close");
	}

	if (conf.drop_caps == DROP_CAPS_EARLY)
		drop_caps();

	on_up();

	if (conf.drop_caps == DROP_CAPS_ON)
		drop_caps();
	else if (conf.drop_caps == DROP_CAPS_OFF)
		set_user();

	fastd_config_load_peer_dirs();

	VECTOR_ALLOC(ctx.eth_addrs, 0);
	VECTOR_ALLOC(ctx.peers, 0);
	VECTOR_ALLOC(ctx.async_pids, 0);

	fastd_peer_hashtable_init();

	init_peers();

	while (!terminate) {
		fastd_peer_handle_handshake_queue();

		fastd_poll_handle();

		maintenance();

		sigset_t set, oldset;
		sigemptyset(&set);
		pthread_sigmask(SIG_SETMASK, &set, &oldset);

		if (sighup) {
			sighup = false;

			pr_info("reconfigure triggered");

			fastd_config_load_peer_dirs();
			init_peers();
		}

		if (dump) {
			dump = false;
			dump_state();
		}

		pthread_sigmask(SIG_SETMASK, &oldset, NULL);
	}

	on_down();

	delete_peers();
	delete_peer_groups();

	fastd_tuntap_close();
	close_sockets();
	fastd_poll_free();

	on_post_down();

	fastd_peer_hashtable_free();

	VECTOR_FREE(ctx.async_pids);
	VECTOR_FREE(ctx.peers);
	VECTOR_FREE(ctx.eth_addrs);

	free(ctx.protocol_state);
	free(ctx.ifname);

#ifdef ENABLE_OPENSSL
	CONF_modules_free();
	EVP_cleanup();
	ERR_free_strings();
#endif

	close_log();
	fastd_config_release();

	return 0;
}
