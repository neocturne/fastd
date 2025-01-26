// SPDX-License-Identifier: BSD-2-Clause
/*
  Copyright (c) Matthias Schiffer <mschiffer@universe-factory.net>
  All rights reserved.

  Android port contributor:
  Copyright (c) 2014-2015, Haofeng "Rick" Lei <ricklei@gmail.com>
  All rights reserved.
*/

/**
   \file

   Initialization, main loop and cleanup
*/


#include "fastd.h"
#include "async.h"
#include "config.h"
#include "crypto.h"
#include "offload/l2tp/l2tp.h"
#include "peer.h"
#include "peer_group.h"
#include "peer_hashtable.h"
#include "polling.h"
#include "version.h"

#include <grp.h>
#include <signal.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <syslog.h>

#ifdef HAVE_LIBSODIUM
#include <sodium/core.h>
#endif

#ifdef WITH_SYSTEMD
#include <sys/un.h>
#endif


/** The global context */
fastd_context_t ctx = {};


static volatile bool sig_reload = false; /**< Is set to true when a SIGHUP is received */
static volatile bool sig_reset = false;  /**< Is set to true when a SIGUSR2 is received */
static volatile bool sig_child = false;  /**< Is set to true when a SIGCHLD is received */
static volatile int sig_terminate = 0;   /**< Holds the signal number when a SIGTERM, SIGQUIT or SIGINT is received */


/** Signal handler; just saves the signals to be handled later */
static void on_signal(int signo) {
	switch (signo) {
	case SIGHUP:
		sig_reload = true;
		break;

	case SIGUSR2:
		sig_reset = true;
		break;

	case SIGCHLD:
		sig_child = true;
		break;

	case SIGTERM:
	case SIGQUIT:
	case SIGINT:
		sig_terminate = signo;
		break;

	default:
		return;
	}

#ifndef USE_EPOLL
	/* Avoids a race condition between pthread_sigmask() and poll() (FreeBSD doesn't have ppoll() ...) */
	fastd_async_enqueue(ASYNC_TYPE_NOP, NULL, 0);
#endif
}

/** Installs signal handlers */
static void init_signals(void) {
	/* block all non-fatal signals */
	sigset_t set;
	sigfillset(&set);
	sigdelset(&set, SIGILL);
	sigdelset(&set, SIGABRT);
	sigdelset(&set, SIGFPE);
	sigdelset(&set, SIGSEGV);
	pthread_sigmask(SIG_SETMASK, &set, NULL);

	struct sigaction action = {};
	sigemptyset(&action.sa_mask);

	action.sa_handler = on_signal;
	if (sigaction(SIGHUP, &action, NULL))
		exit_errno("sigaction");
	if (sigaction(SIGUSR2, &action, NULL))
		exit_errno("sigaction");
	if (sigaction(SIGCHLD, &action, NULL))
		exit_errno("sigaction");
	if (sigaction(SIGTERM, &action, NULL))
		exit_errno("sigaction");
	if (sigaction(SIGQUIT, &action, NULL))
		exit_errno("sigaction");
	if (sigaction(SIGINT, &action, NULL))
		exit_errno("sigaction");

	action.sa_handler = SIG_IGN;
	if (sigaction(SIGPIPE, &action, NULL))
		exit_errno("sigaction");
	if (sigaction(SIGTTIN, &action, NULL))
		exit_errno("sigaction");
	if (sigaction(SIGTTOU, &action, NULL))
		exit_errno("sigaction");
	if (sigaction(SIGUSR1, &action, NULL))
		exit_errno("sigaction");
}

/** Initializes log destinations */
static inline void init_log(void) {
	if (conf.log_syslog_level > LL_UNSPEC)
		openlog(conf.log_syslog_ident, LOG_PID, LOG_DAEMON);

	ctx.log_initialized = true;
}

/** Cleans up log destinations */
static inline void close_log(void) {
	closelog();
}

/** Initializes the configured sockets */
static void init_sockets(void) {
	ctx.ioctl_sock = socket(PF_INET, SOCK_DGRAM, 0);
	if (ctx.ioctl_sock < 0)
		exit_errno("unable to create ioctl socket");

	ctx.socks = fastd_new_array(conf.n_bind_addrs, fastd_socket_t);

	size_t i;
	fastd_bind_address_t *addr = conf.bind_addrs;
	for (i = 0; i < conf.n_bind_addrs; i++) {
		if (addr->flags & FASTD_BIND_DYNAMIC) {
			ctx.socks[i] = (fastd_socket_t){ .fd = FASTD_POLL_FD(POLL_TYPE_SOCKET, -1), .addr = NULL };
		} else {
			ctx.socks[i] = (fastd_socket_t){ .fd = FASTD_POLL_FD(POLL_TYPE_SOCKET, -1), .addr = addr };

			if (addr == conf.bind_addr_default_v4)
				ctx.sock_default_v4 = &ctx.socks[i];

			if (addr == conf.bind_addr_default_v6)
				ctx.sock_default_v6 = &ctx.socks[i];
		}

		addr = addr->next;
	}

	ctx.n_socks = conf.n_bind_addrs;
}

/** Closes fastd's sockets */
static void close_sockets(void) {
	size_t i;
	for (i = 0; i < ctx.n_socks; i++)
		fastd_socket_close(&ctx.socks[i]);

	free(ctx.socks);

	if (close(ctx.ioctl_sock))
		pr_error_errno("close");
}

/** Calls the on-pre-up command */
static inline void on_pre_up(void) {
	fastd_shell_command_exec_sync(&conf.on_pre_up, NULL, NULL);
}

/** Calls the on-up command */
static inline void on_up(fastd_iface_t *iface) {
	fastd_shell_env_t *env = fastd_shell_env_alloc();
	fastd_shell_env_set_iface(env, iface->name, iface->mtu);
	fastd_shell_command_exec_sync(&conf.peer_group->on_up, env, NULL);
	fastd_shell_env_free(env);
}

/** Calls the on-down command */
static inline void on_down(fastd_iface_t *iface) {
	fastd_shell_env_t *env = fastd_shell_env_alloc();
	fastd_shell_env_set_iface(env, iface->name, iface->mtu);
	fastd_shell_command_exec_sync(&conf.peer_group->on_down, env, NULL);
	fastd_shell_env_free(env);
}

/** Calls the on-post-down command */
static inline void on_post_down(void) {
	fastd_shell_command_exec(&conf.on_post_down, NULL);
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
			if (errno != EBADF)
				pr_error_errno("close");
		}
	}
}


/** Writes the PID file */
static inline void write_pid(void) {
	if (!conf.pid_file)
		return;

#ifdef __ANDROID__
	if (conf.android_integration) {
		pr_warn("fastd doesn't support pid file in GUI integration mode on Android");
		return;
	}
#endif

#ifdef USE_USER
	uid_t uid = geteuid();
	gid_t gid = getegid();

	if (conf.user || conf.group) {
		if (setegid(conf.gid) < 0)
			pr_debug_errno("setegid");
		if (seteuid(conf.uid) < 0)
			pr_debug_errno("seteuid");
	}
#endif

	FILE *f = fopen(conf.pid_file, "w");
	if (f) {
		if (fprintf(f, "%u", (unsigned)getpid()) < 0)
			pr_error_errno("can't write PID file: fprintf");

		if (fclose(f) < 0)
			pr_warn_errno("fclose");

	} else {
		pr_error_errno("can't write PID file: fopen");
	}

#ifdef USE_USER
	if (seteuid(uid) < 0)
		pr_debug_errno("seteuid");
	if (setegid(gid) < 0)
		pr_debug_errno("setegid");
#endif
}

/** Switches to the configured user */
static void set_user(void) {
#ifdef USE_USER
	if (conf.user || conf.group) {

#ifdef HAVE_SETRESGID
		if (setresgid(conf.gid, conf.gid, conf.gid) < 0)
			exit_errno("setresgid");
#else
		if (setregid(conf.gid, conf.gid) < 0)
			exit_errno("setregid");
#endif

#ifdef HAVE_SETRESUID
		if (setresuid(conf.uid, conf.uid, conf.uid) < 0)
			exit_errno("setresuid");
#else
		if (setreuid(conf.uid, conf.uid) < 0)
			exit_errno("setreuid");
#endif

		pr_info("changed to UID %u, GID %u", (unsigned)conf.uid, (unsigned)conf.gid);
	}
#endif
}

/** Sets the configured user's supplementary groups */
static void set_groups(void) {
#ifdef USE_USER
	if (conf.groups) {
		if (setgroups(conf.n_groups, conf.groups) < 0) {
			if (errno != EPERM)
				pr_debug_errno("setgroups");
		}
	} else if (conf.user || conf.group) {
		if (setgroups(1, &conf.gid) < 0) {
			if (errno != EPERM)
				pr_debug_errno("setgroups");
		}
	}
#endif
}

/** Switches the user and drops all capabilities */
static void drop_caps(void) {
	set_user();
	fastd_cap_reacquire_drop();
}

/** Will double fork and wait for a status notification from the child before exiting in the original parent */
static int daemonize(void) {
	uint8_t status = 1;
	int pipefd[2];

	if (pipe(pipefd))
		exit_errno("pipe");

	pid_t fork1 = fork();

	if (fork1 < 0) {
		exit_errno("fork");
	} else if (fork1 > 0) {
		/* parent */
		if (close(pipefd[1]) < 0)
			exit_errno("close");

		if (waitpid(fork1, NULL, 0) < 0)
			exit_errno("waitpid");

		if (read(pipefd[0], &status, 1) < 0)
			exit_errno("read");

		exit(status);
	} else {
		/* child 1 */
		if (close(pipefd[0]) < 0)
			pr_error_errno("close");

		if (setsid() < 0)
			pr_error_errno("setsid");

		pid_t fork2 = fork();

		if (fork2 < 0) {
			exit_errno("fork");
		} else if (fork2 > 0) {
			/* still child 1 */
			_exit(0);
		} else {
			/* child 2 */
			return pipefd[1];
		}
	}
}

/** Sends a readiness notification on a notify socket */
static inline void notify_systemd(void) {
#ifdef WITH_SYSTEMD
	int fd;
	struct sockaddr_un sa = {};
	const char *notify_socket = getenv("NOTIFY_SOCKET");

	if (!notify_socket)
		return;

	if ((notify_socket[0] != '@' && notify_socket[0] != '/') || notify_socket[1] == 0)
		return;

	fd = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (fd < 0)
		return;

	sa.sun_family = AF_UNIX;

	strncpy(sa.sun_path, notify_socket, sizeof(sa.sun_path));
	if (sa.sun_path[0] == '@')
		sa.sun_path[0] = 0;

	if (connect(fd, (struct sockaddr *)&sa,
		    offsetof(struct sockaddr_un, sun_path) + strnlen(notify_socket, sizeof(sa.sun_path))) < 0) {
		pr_debug_errno("unable to connect to notify socket: connect");
		close(fd);
		return;
	}

	dprintf(fd, "READY=1\nMAINPID=%lu", (unsigned long)getpid());
	pr_debug("sent startup notification to systemd");

	close(fd);
#endif
}

/** Early initialization before reading the config */
static inline void init_early(void) {
	fastd_close_all_fds();

	fastd_random_init();

	unsigned int seed;
	fastd_random_bytes(&seed, sizeof(seed), false);
	srandom(seed);

	fastd_cipher_init();
	fastd_mac_init();
}

/**
   Performs further initialization after the config has been loaded

   This also handles special run modes like \em generate-key and \em verify-config.
*/
static inline void init_config(int *status_fd) {
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
		*status_fd = daemonize();

	if (chdir("/"))
		pr_error("can't chdir to `/': %s", strerror(errno));

	/*
	  Initialize log here, as:
	   - we have already daemonized, so syslog will show the correct PID
	   - special run modes that should always log to stderr have been handled
	 */
	init_log();

	/* Init crypto libs here as fastd_config_check() initializes the methods and might need them */
#ifdef HAVE_LIBSODIUM
	if (sodium_init() < 0)
		exit_error("unable to initialize libsodium");
#endif

	fastd_config_check();
}

/** Initializes fastd */
static inline void init(int argc, char *argv[]) {
	int status_fd = -1;

	init_early();
	fastd_configure(argc, argv);
	init_config(&status_fd);

	fastd_update_time();
	fastd_task_schedule(&ctx.next_maintenance, TASK_TYPE_MAINTENANCE, ctx.now + MAINTENANCE_INTERVAL);

	fastd_receive_unknown_init();

#ifdef WITH_DYNAMIC_PEERS
	fastd_sem_init(&ctx.verify_limit, VERIFY_LIMIT);
#endif

	if (fastd_use_offload_l2tp())
		fastd_offload_l2tp_init();

	if (pthread_attr_init(&ctx.detached_thread))
		exit_errno("pthread_attr_init");
	if (pthread_attr_setdetachstate(&ctx.detached_thread, PTHREAD_CREATE_DETACHED))
		exit_errno("pthread_attr_setdetachstate");

	pr_info("fastd " FASTD_VERSION " starting");

	fastd_update_time();
	ctx.started = ctx.now;

	fastd_cap_acquire();

	fastd_poll_init();

	init_sockets();

	fastd_status_init();
	fastd_async_init();

	fastd_socket_bind_all();

	on_pre_up();

	if (conf.mode == MODE_TAP || fastd_use_android_integration()) {
		ctx.iface = fastd_iface_open(NULL);
		if (!ctx.iface)
			exit(1); /* An error message has already been printed by fastd_iface_open() */
	}

	/* change groups before trying to write the PID file as they can be relevant for file access */
	set_groups();
	write_pid();

	fastd_peer_hashtable_init();

	notify_systemd();

	if (status_fd >= 0) {
		static const uint8_t STATUS = 0;
		if (write(status_fd, &STATUS, 1) < 0)
			exit_errno("status: write");
		if (close(status_fd))
			exit_errno("status: close");
	}

	if (conf.drop_caps == DROP_CAPS_EARLY || conf.drop_caps == DROP_CAPS_FORCE)
		drop_caps();

	if (ctx.iface)
		on_up(ctx.iface);

	fastd_configure_peers();
	fastd_init_buffers();

	if (conf.drop_caps == DROP_CAPS_ON)
		drop_caps();
	else if (conf.drop_caps == DROP_CAPS_OFF)
		set_user();

	fastd_config_load_peer_dirs(true);
}


/** Reaps zombies of asynchronous shell commands. */
static inline void reap_zombies(void) {
	size_t i;
	for (i = 0; i < VECTOR_LEN(ctx.async_pids);) {
		pid_t pid = VECTOR_INDEX(ctx.async_pids, i);

		pid_t ret = waitpid(pid, NULL, WNOHANG);

		if (ret > 0) {
			pr_debug("child process %u finished", (unsigned)pid);
		} else {
			if (ret == 0 || errno == EINTR) {
				i++;
				continue;
			} else {
				pr_error_errno("waitpid");
			}
		}

		VECTOR_DELETE(ctx.async_pids, i);
	}
}

/** The \em real signal handlers */
static inline void handle_signals(void) {
	if (sig_reload) {
		sig_reload = false;

		pr_info("reconfigure triggered");

		fastd_config_load_peer_dirs(false);
	}

	if (sig_reset) {
		sig_reset = false;

		pr_info("triggered reset of all connections");

		fastd_peer_reset_all();
	}

	if (sig_child) {
		sig_child = false;
		reap_zombies();
	}
}


/** A single iteration of fastd's main loop */
static inline void run(void) {
	fastd_task_handle();
	fastd_poll_handle();

	handle_signals();
}

/** Removes all peers */
static void delete_peers(void) {
	while (VECTOR_LEN(ctx.peers))
		fastd_peer_delete(VECTOR_INDEX(ctx.peers, VECTOR_LEN(ctx.peers) - 1));
}

/**
   Performs cleanup of resources used by fastd

   Besides running the on-down scripts and closing the TUN/TAP interface, this
   also frees all memory allocated by fastd to make debugging memory leaks with
   valgrind as easy as possible.
*/
static inline void cleanup(void) {
	pr_info("terminating fastd");

	delete_peers();

	fastd_cleanup_buffers();

	if (ctx.iface) {
		on_down(ctx.iface);
		fastd_iface_close(ctx.iface);
	}

	fastd_status_close();
	close_sockets();
	fastd_poll_free();

	on_post_down();

	fastd_peer_hashtable_free();

	if (fastd_use_offload_l2tp())
		fastd_offload_l2tp_cleanup();

	pthread_attr_destroy(&ctx.detached_thread);

	VECTOR_FREE(ctx.async_pids);
	VECTOR_FREE(ctx.peers);
	VECTOR_FREE(ctx.eth_addrs);

	free(ctx.protocol_state);

	fastd_receive_unknown_free();

	close_log();
	fastd_config_release();

	fastd_random_cleanup();
}

/** Terminates fastd by re-raising the received signal */
static inline void terminate(void) {
	struct sigaction action = {};
	sigemptyset(&action.sa_mask);

	action.sa_handler = SIG_DFL;
	sigaction(sig_terminate, &action, NULL);

	pthread_sigmask(SIG_SETMASK, &action.sa_mask, NULL);

	raise(sig_terminate);
}

/** Main function */
void fastd_main(int argc, char *argv[]) {
	init(argc, argv);

	while (!sig_terminate)
		run();

	cleanup();
	terminate();
}
