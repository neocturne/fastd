/*
  Copyright (c) 2012-2014, Matthias Schiffer <mschiffer@universe-factory.net>
  All rights reserved.

  Android port contributor:
  Copyright (c) 2014-2015, Haofeng "Rick" Lei <ricklei@gmail.com>
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

   \em fastd main header file defining most data structures
*/


#pragma once

#include "dlist.h"
#include "buffer.h"
#include "log.h"
#include "sem.h"
#include "shell.h"
#include "util.h"
#include "vector.h"

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <poll.h>
#include <semaphore.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>


/** An ethernet address */
struct __attribute__((__packed__)) fastd_eth_addr {
	uint8_t data[ETH_ALEN];		/**< The bytes of the address */
};


/**
   A structure describing callbacks that define a handshake protocol

   Currently, only one such protocol, \em ec25519-fhmqvc, is defined.
*/
struct fastd_protocol {
	/** The name of the procotol */
	const char *name;

	/** Performs one-time initialization tasks for the protocol */
	fastd_protocol_config_t * (*init)(void);

	/** Sends a handshake to the given peer */
	void (*handshake_init)(fastd_socket_t *sock, const fastd_peer_address_t *local_addr, const fastd_peer_address_t *remote_addr, fastd_peer_t *peer);

	/** Handles a handshake for the given peer */
	void (*handshake_handle)(fastd_socket_t *sock, const fastd_peer_address_t *local_addr, const fastd_peer_address_t *remote_addr, fastd_peer_t *peer, const fastd_handshake_t *handshake, const fastd_method_info_t *method);

#ifdef WITH_DYNAMIC_PEERS
	/** Handles an asynchronous on-verify command return */
	void (*handle_verify_return)(fastd_peer_t *peer, fastd_socket_t *sock, const fastd_peer_address_t *local_addr, const fastd_peer_address_t *remote_addr, const fastd_method_info_t *method, const void *protocol_data, bool ok);
#endif


	/** Handles a received payload packet (performs decryption and validity check, etc.) */
	void (*handle_recv)(fastd_peer_t *peer, fastd_buffer_t buffer);

	/** Sends a payload data packet to the given peer */
	void (*send)(fastd_peer_t *peer, fastd_buffer_t buffer);


	/** Initializes the protocol state for a peer */
	void (*init_peer_state)(fastd_peer_t *peer);

	/** Resets the protocol state for a peer (resets active sessions etc.) */
	void (*reset_peer_state)(fastd_peer_t *peer);

	/** Frees the protocol state for a peer */
	void (*free_peer_state)(fastd_peer_t *peer);


	/** Initializes protocol-specific parts of a peer configuration */
	fastd_protocol_key_t * (*read_key)(const char *key);

	/** Checks a peer after reading its configuration */
	bool (*check_peer)(const fastd_peer_t *peer);

	/** Searches a peer identified by a specific key */
	fastd_peer_t * (*find_peer)(const fastd_protocol_key_t *key);


	/** Retrieves information about the currently used encyption/authentication method of a connection with a peer */
	const fastd_method_info_t * (*get_current_method)(const fastd_peer_t *peer);


	/** Generates a new keypair and outputs it */
	void (*generate_key)(void);

	/** Outputs the public key for the configured secret */
	void (*show_key)(void);


	/** Adds peer-specific environment variables to env */
	void (*set_shell_env)(fastd_shell_env_t *env, const fastd_peer_t *peer);

	/** Creates a human-readable representation of the peer */
	bool (*describe_peer)(const fastd_peer_t *peer, char *buf, size_t len);
};

/** An union storing an IPv4 or IPv6 address */
union fastd_peer_address {
	struct sockaddr sa;			/**< A sockaddr field (for access to sa_family) */
	struct sockaddr_in in;			/**< An IPv4 address */
	struct sockaddr_in6 in6;		/**< An IPv6 address */
};

/** A linked list of addresses to bind to */
struct fastd_bind_address {
	fastd_bind_address_t *next;		/**< The next address in the list */
	fastd_peer_address_t addr;		/**< The address to bind to */
	char *bindtodev;			/**< May contain an interface name to limit the bind to */
};

/** A socket descriptor */
struct fastd_socket {
	int fd;					/**< The file descriptor for the socket */
	const fastd_bind_address_t *addr;	/**< The address this socket is supposed to be bound to (or NULL) */
	fastd_peer_address_t *bound_addr;	/**< The actual address that was bound to (may differ from addr when addr has a random port) */
	fastd_peer_t *peer;			/**< If the socket belongs to a single peer (as it was create dynamically when sending a handshake), contains that peer */
};


/** Type of a traffic stat counter */
typedef enum fastd_stat_type {
	STAT_RX = 0,				/**< Reception statistics (total) */
	STAT_RX_REORDERED,			/**< Reception statistics (reordered) */
	STAT_TX,				/**< Transmission statistics (OK) */
	STAT_TX_DROPPED,			/**< Transmission statistics (dropped because of full queues) */
	STAT_TX_ERROR,				/**< Transmission statistics (other errors) */
	STAT_MAX,				/**< (Number of defined stat types) */
} fastd_stat_type_t;

/** Some kind of network transfer statistics */
struct fastd_stats {
#ifdef WITH_STATUS_SOCKET
	uint64_t packets[STAT_MAX];		/**< The number of packets transferred */
	uint64_t bytes[STAT_MAX];		/**< The number of bytes transferred */
#endif
};


/** A data structure keeping track of an unknown addresses that a handshakes was received from recently */
struct fastd_handshake_timeout {
	fastd_peer_address_t address;		/**< An address a handshake was received from */
	fastd_timeout_t timeout;		/**< Timeout until handshakes from this address are ignored */
};


/** The static configuration of \em fastd */
struct fastd_config {
	fastd_loglevel_t log_stderr_level;	/**< The minimum loglevel of messages to print to stderr (or -1 to not print any messages on stderr) */
	fastd_loglevel_t log_syslog_level;	/**< The minimum loglevel of messages to print to syslog (or -1 to not print any messages on syslog) */
	char *log_syslog_ident;			/**< The identification string for messages sent to syslog (default: "fastd") */

	char *ifname;				/**< The configured interface name */

	size_t n_bind_addrs;			/**< Number of elements in bind_addrs */
	fastd_bind_address_t *bind_addrs;	/**< Configured bind addresses */

	fastd_bind_address_t *bind_addr_default_v4; /**< Pointer to the bind address to be used for IPv4 connections by default */
	fastd_bind_address_t *bind_addr_default_v6; /**< Pointer to the bind address to be used for IPv6 connections by default */

	uint16_t mtu;				/**< The configured MTU */
	fastd_mode_t mode;			/**< The configured mode of operation */

	uint32_t packet_mark;			/**< The configured packet mark (or 0) */
	bool forward;				/**< Specifies if packet forwarding is enable */
	fastd_tristate_t pmtu;			/**< Can be set to explicitly enable or disable PMTU detection */
	bool secure_handshakes;			/**< Can be set to false to support connections with fastd versions before v11 */

	fastd_drop_caps_t drop_caps;		/**< Specifies if and when to drop capabilities */

	char *user;				/**< Specifies which user to switch to after initialization */
	char *group;				/**< Can specify an alternative group to switch to */

	uid_t uid;				/**< The UID of the configured user */
	gid_t gid;				/**< The GID of the configured group */
	size_t n_groups;			/**< The number of supplementary groups of the user */
	gid_t *groups;				/**< The supplementary groups of the configured user */

	const fastd_protocol_t *protocol;	/**< The handshake protocol */
	fastd_string_stack_t *method_list;	/**< The list of configured method names */
	fastd_method_info_t *methods;		/**< The list of configured methods */

	size_t max_overhead;			/**< The maximum overhead of all configured methods */
	size_t min_encrypt_head_space;		/**< The minimum space a configured methods needs a the beginning of a buffer to encrypt */
	size_t min_decrypt_head_space;		/**< The minimum space a configured methods needs a the beginning of a buffer to decrypt */
	size_t min_encrypt_tail_space;		/**< The minimum space a configured methods needs a the end of a buffer to encrypt */
	size_t min_decrypt_tail_space;		/**< The minimum space a configured methods needs a the end of a buffer to decrypt */

	char *secret;				/**< The configured secret key */

	fastd_peer_group_t *peer_group;		/**< The root peer group configuration */

	fastd_protocol_config_t *protocol_config; /**< The protocol-specific configuration */

	fastd_shell_command_t on_pre_up;	/**< The command to execute before the initialization of the tunnel interface */
	fastd_shell_command_t on_up;		/**< The command to execute after the initialization of the tunnel interface */
	fastd_shell_command_t on_down;		/**< The command to execute before the destruction of the tunnel interface */
	fastd_shell_command_t on_post_down;	/**< The command to execute after the destruction of the tunnel interface */
	fastd_shell_command_t on_connect;	/**< The command to execute before a handshake is sent to establish a new connection */
	fastd_shell_command_t on_establish;	/**< The command to execute when a new connection has been established */
	fastd_shell_command_t on_disestablish;	/**< The command to execute when a connection has been disestablished */
#ifdef WITH_DYNAMIC_PEERS
	fastd_shell_command_t on_verify;	/**< The command to execute to check if a connection from an unknown peer should be allowed */
#endif

#ifdef WITH_STATUS_SOCKET
	char *status_socket;			/**< The path of the status socket */
#endif

#ifdef __ANDROID__
	bool android_integration;		/**< Enable Android GUI integration features */
#endif

	bool daemon;				/**< Set to make fastd fork to the background after initialization */
	char *pid_file;				/**< A filename to write fastd's PID to */

	bool hide_ip_addresses;			/**< Tells fastd to hide peers' IP address in the log output */
	bool hide_mac_addresses;		/**< Tells fastd to hide peers' MAC address in the log output */

	bool machine_readable;			/**< Supresses explanatory messages in the generate_key and show_key commands */
	bool generate_key;			/**< Makes fastd generate a new keypair and exit */
	bool show_key;				/**< Makes fastd output the public key for the configured secret and exit */
	bool verify_config;			/**< Does basic verification of the configuration and exits */
};

/** The dynamic state of \em fastd */
struct fastd_context {
	bool log_initialized;			/**< true if the logging facilities have been properly initialized */

	char *ifname;				/**< The actual interface name */

	int64_t started;			/**< The timestamp when fastd was started */

	int64_t now;				/**< The current monotonous timestamp in microseconds after an arbitrary point in time */

	uint64_t next_peer_id;			/**< An monotonously increasing ID peers are identified with in some components */
	VECTOR(fastd_peer_t *) peers;		/**< The currectly active peers */

#ifdef WITH_DYNAMIC_PEERS
	fastd_sem_t verify_limit;		/**< Keeps track of the number of verifier threads */
#endif

#ifdef USE_EPOLL
	int epoll_fd;				/**< The file descriptor for the epoll facility */
#else
	VECTOR(struct pollfd) pollfds;		/**< The vector of pollfds for all file descriptors */
#endif

#ifdef WITH_STATUS_SOCKET
	int status_fd;				/**< The file descriptor of the status socket */
#endif

	bool has_floating;			/**< Specifies if any of the configured peers have floating remotes */

	uint32_t peer_addr_ht_seed;		/**< The hash seed used for peer_addr_ht */
	size_t peer_addr_ht_size;		/**< The number of hash buckets in the peer address hashtable */
	size_t peer_addr_ht_used;		/**< The current number of entries in the peer address hashtable */
	VECTOR(fastd_peer_t *) *peer_addr_ht;	/**< An array of hash buckets for the peer hash table */

	fastd_dlist_head_t handshake_queue;	/**< A doubly linked list of the peers currently queued for handshakes (ordered by the time of the next handshake) */
	fastd_timeout_t next_maintenance;	/**< The time of the next maintenance call */

	VECTOR(pid_t) async_pids;		/**< PIDs of asynchronously executed commands which still have to be reaped */
	int async_rfd;				/**< The read side of the pipe used to send data from other thread to the main thread */
	int async_wfd;				/**< The write side of the pipe used to send data from other thread to the main thread */

	pthread_attr_t detached_thread;		/**< pthread_attr_t for creating detached threads */

	int tunfd;				/**< The file descriptor of the tunnel interface */

#ifdef __ANDROID__
	int android_ctrl_sock_fd;		/**< The unix domain socket for communicating with Android GUI */
#endif

	size_t n_socks;				/**< The number of sockets in socks */
	fastd_socket_t *socks;			/**< Array of all sockets */

	fastd_socket_t *sock_default_v4;	/**< Points to the socket that is used for new outgoing IPv4 connections */
	fastd_socket_t *sock_default_v6;	/**< Points to the socket that is used for new outgoing IPv6 connections */

	fastd_stats_t stats;			/**< Traffic statistics */

	VECTOR(fastd_peer_eth_addr_t) eth_addrs; /**< Sorted vector of all known ethernet addresses with associated peers and timeouts */

	size_t unknown_handshake_pos;		/**< Current start position in the ring buffer unknown_handshakes */
	fastd_handshake_timeout_t unknown_handshakes[8]; /**< Ring buffer of unknown addresses handshakes have been received from */

	fastd_protocol_state_t *protocol_state;	/**< Protocol-specific state */
};

/** A stack of strings */
struct fastd_string_stack {
	fastd_string_stack_t *next;		/**< The next element of the stack */
	char str[];				/**< Zero-terminated character data */
};


extern fastd_context_t ctx;
extern fastd_config_t conf;


void fastd_send(const fastd_socket_t *sock, const fastd_peer_address_t *local_addr, const fastd_peer_address_t *remote_addr, fastd_peer_t *peer, fastd_buffer_t buffer, size_t stat_size);
void fastd_send_handshake(const fastd_socket_t *sock, const fastd_peer_address_t *local_addr, const fastd_peer_address_t *remote_addr, fastd_peer_t *peer, fastd_buffer_t buffer);
void fastd_send_data(fastd_buffer_t buffer, fastd_peer_t *source);

void fastd_receive(fastd_socket_t *sock);
void fastd_handle_receive(fastd_peer_t *peer, fastd_buffer_t buffer, bool reordered);

void fastd_close_all_fds(void);

bool fastd_socket_handle_binds(void);
fastd_socket_t * fastd_socket_open(fastd_peer_t *peer, int af);
void fastd_socket_close(fastd_socket_t *sock);
void fastd_socket_error(fastd_socket_t *sock);

#ifdef __ANDROID__
int fastd_android_receive_tunfd(void);
void fastd_android_send_pid(void);
bool fastd_android_protect_socket(int fd);
#endif

void fastd_resolve_peer(fastd_peer_t *peer, fastd_remote_t *remote);

void fastd_tuntap_open(void);
void fastd_tuntap_handle(void);
void fastd_tuntap_write(fastd_buffer_t buffer);
void fastd_tuntap_close(void);

void fastd_cap_init(void);
void fastd_cap_drop(void);

void fastd_random_bytes(void *buffer, size_t len, bool secure);

#ifdef WITH_STATUS_SOCKET

void fastd_status_init(void);
void fastd_status_close(void);
void fastd_status_handle(void);

#else

static inline void fastd_status_init(void) {
}

static inline void fastd_status_close(void) {
}

#endif


/** Returns a random number between \a min (inclusively) and \a max (exclusively) */
static inline int fastd_rand(int min, int max) {
	unsigned int r = (unsigned int)random();
	return (r%(max-min) + min);
}

/** Sets the O_NONBLOCK flag on a file descriptor */
static inline void fastd_setnonblock(int fd) {
	int flags = fcntl(fd, F_GETFL);
	if (flags < 0)
		exit_errno("Getting file status flags failed: fcntl");

	if (fcntl(fd, F_SETFL, flags|O_NONBLOCK) < 0)
		exit_errno("Setting file status flags failed: fcntl");
}


/** Returns the maximum payload size \em fastd is configured to transport */
static inline size_t fastd_max_payload(void) {
	switch (conf.mode) {
	case MODE_TAP:
		return conf.mtu+ETH_HLEN;
	case MODE_TUN:
		return conf.mtu;
	default:
		exit_bug("invalid mode");
	}
}


/** Returns the source address of an ethernet packet */
static inline fastd_eth_addr_t fastd_buffer_source_address(const fastd_buffer_t buffer) {
	fastd_eth_addr_t ret;
	memcpy(&ret, buffer.data+offsetof(struct ethhdr, h_source), ETH_ALEN);
	return ret;
}

/** Returns the destination address of an ethernet packet */
static inline fastd_eth_addr_t fastd_buffer_dest_address(const fastd_buffer_t buffer) {
	fastd_eth_addr_t ret;
	memcpy(&ret, buffer.data+offsetof(struct ethhdr, h_dest), ETH_ALEN);
	return ret;
}


/** Checks if a fastd_peer_address_t is an IPv6 link-local address */
static inline bool fastd_peer_address_is_v6_ll(const fastd_peer_address_t *addr) {
	return (addr->sa.sa_family == AF_INET6 && IN6_IS_ADDR_LINKLOCAL(&addr->in6.sin6_addr));
}

/** Duplicates a string, creating a one-element string stack */
static inline fastd_string_stack_t * fastd_string_stack_dup(const char *str) {
	fastd_string_stack_t *ret = fastd_alloc(alignto(sizeof(fastd_string_stack_t) + strlen(str) + 1, 8));
	ret->next = NULL;
	strcpy(ret->str, str);

	return ret;
}

/** Duplicates a string of a given maximum length, creating a one-element string stack */
static inline fastd_string_stack_t * fastd_string_stack_dupn(const char *str, size_t len) {
	size_t str_len = strnlen(str, len);
	fastd_string_stack_t *ret = fastd_alloc(alignto(sizeof(fastd_string_stack_t) + str_len + 1, 8));
	ret->next = NULL;
	strncpy(ret->str, str, str_len);
	ret->str[str_len] = 0;

	return ret;
}

/** Pushes the copy of a string onto the top of a string stack */
static inline fastd_string_stack_t * fastd_string_stack_push(fastd_string_stack_t *stack, const char *str) {
	fastd_string_stack_t *ret = fastd_alloc(alignto(sizeof(fastd_string_stack_t) + strlen(str) + 1, 8));
	ret->next = stack;
	strcpy(ret->str, str);

	return ret;
}

/** Gets the head of string stack (or NULL if the stack is NULL) */
static inline const char * fastd_string_stack_get(const fastd_string_stack_t *stack) {
	return stack ? stack->str : NULL;
}

/**  */
static inline bool fastd_string_stack_contains(const fastd_string_stack_t *stack, const char *str) {
	while (stack) {
		if (strcmp(stack->str, str) == 0)
			return true;

		stack = stack->next;
	}

	return false;
}

/** Frees a whole string stack */
static inline void fastd_string_stack_free(fastd_string_stack_t *str) {
	while (str) {
		fastd_string_stack_t *next = str->next;
		free(str);
		str = next;
	}
}

/**
   Checks if a timeout has occured

   @param timeout the time the timeout should occur

   @return true if the given timeout is before or equal to the current time

   \note The current time is updated only once per main loop iteration, after waiting for input.
*/
static inline bool fastd_timed_out(fastd_timeout_t timeout) {
	return timeout <= ctx.now;
}

/** Updates the current time */
static inline void fastd_update_time(void) {
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);

	ctx.now = (1000*(int64_t)ts.tv_sec) + ts.tv_nsec/1000000;
}

/** Checks if a on-verify command is set */
static inline bool fastd_allow_verify(void) {
#ifdef WITH_DYNAMIC_PEERS
	return fastd_shell_command_isset(&conf.on_verify);
#else
	return false;
#endif
}
