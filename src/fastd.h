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

/**
   \file fastd.h

   \em fastd main header file defining most data structures
 */


#pragma once

#include "types.h"
#include "dlist.h"
#include "buffer.h"
#include "log.h"
#include "shell.h"
#include "vector.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <sys/uio.h>


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
	fastd_protocol_config_t* (*init)(void);

	/** Does some basic checks for the validity of a peer configuration */
	void (*peer_verify)(fastd_peer_config_t *peer_conf);

	/** Initializes protocol-specific parts of a peer configuration */
	void (*peer_configure)(fastd_peer_config_t *peer_conf);

	/** Checks if a peer configuration is valid and a connection may be established */
	bool (*peer_check)(fastd_peer_config_t *peer_conf);

	/** Checks if a temporary peer is valid and a connection may be established */
	bool (*peer_check_temporary)(fastd_peer_t *peer);


	/** Sends a handshake to the given peer */
	void (*handshake_init)(fastd_socket_t *sock, const fastd_peer_address_t *local_addr, const fastd_peer_address_t *remote_addr, fastd_peer_t *peer);

	/** Handles a handshake for the given peer */
	void (*handshake_handle)(fastd_socket_t *sock, const fastd_peer_address_t *local_addr, const fastd_peer_address_t *remote_addr, fastd_peer_t *peer, const fastd_handshake_t *handshake, const fastd_method_info_t *method);

#ifdef WITH_VERIFY
	/** Handles an asynchrounous on-verify command return */
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
	struct sockaddr sa;		/**< A generic sockaddr union field of the address (for access to sa_family) */
	struct sockaddr_in in;		/**< An IPv4 address */
	struct sockaddr_in6 in6;	/**< An IPv6 address */
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

/** Some kind of network transfer stratistics */
struct fastd_stats {
	uint64_t packets;			/**< The number of packets transferred */
	uint64_t bytes;				/**< The number of bytes transferred */
};

/** A data structure keeping track of an unknown addresses that a handshakes was received from recently */
struct fastd_handshake_timeout {
	fastd_peer_address_t address;		/**< An address a handshake was received from */
	struct timespec timeout;		/**< Timeout until handshakes from this address are ignored */
};


/** The static configuration of \em fastd */
struct fastd_config {
	fastd_loglevel_t log_stderr_level;	/**< The minimum loglevel of messages to print to stderr (or -1 to not print any messages on stderr) */
	fastd_loglevel_t log_syslog_level;	/**< The minimum loglevel of messages to print to syslog (or -1 to not print any messages on syslog) */
	char *log_syslog_ident;			/**< The identification string for messages sent to syslog (default: "fastd") */

	char *ifname;

	size_t n_bind_addrs;
	fastd_bind_address_t *bind_addrs;

	fastd_bind_address_t *bind_addr_default_v4;
	fastd_bind_address_t *bind_addr_default_v6;

	uint16_t mtu;
	fastd_mode_t mode;

	uint32_t packet_mark;
	bool forward;
	fastd_tristate_t pmtu;
	bool secure_handshakes;

	fastd_drop_caps_t drop_caps;

	char *user;
	char *group;

	uid_t uid;
	gid_t gid;
	size_t n_groups;
	gid_t *groups;

	const fastd_protocol_t *protocol;
	fastd_string_stack_t *method_list;
	fastd_method_info_t *methods;

	size_t max_overhead;
	size_t min_encrypt_head_space;
	size_t min_decrypt_head_space;
	size_t min_encrypt_tail_space;
	size_t min_decrypt_tail_space;

	char *secret;

	const fastd_cipher_t **ciphers;
	const fastd_mac_t **macs;

	fastd_peer_group_config_t *peer_group;
	fastd_peer_config_t *peers;

	bool has_floating;

	fastd_protocol_config_t *protocol_config;

	fastd_shell_command_t on_pre_up;
	fastd_shell_command_t on_up;
	fastd_shell_command_t on_down;
	fastd_shell_command_t on_post_down;
	fastd_shell_command_t on_connect;
	fastd_shell_command_t on_establish;
	fastd_shell_command_t on_disestablish;
#ifdef WITH_VERIFY
	fastd_shell_command_t on_verify;
#endif

	bool daemon;
	char *pid_file;

	bool hide_ip_addresses;
	bool hide_mac_addresses;

	bool machine_readable;
	bool generate_key;
	bool show_key;
	bool verify_config;
};

/** The dynamic state of \em fastd */
struct fastd_context {
	bool log_initialized;

	char *ifname;

	struct timespec now;

	fastd_peer_group_t *peer_group;

	uint64_t next_peer_id;
	VECTOR(fastd_peer_t*) peers;

#ifdef USE_EPOLL
	int epoll_fd;
#else
	VECTOR(struct pollfd) pollfds;
#endif

	uint32_t peer_addr_ht_seed;
	VECTOR(fastd_peer_t*) *peer_addr_ht;

	fastd_dlist_head_t handshake_queue;
	struct timespec next_maintenance;

	VECTOR(pid_t) async_pids;
	int async_rfd;
	int async_wfd;

	int tunfd;

	size_t n_socks;
	fastd_socket_t *socks;

	fastd_socket_t *sock_default_v4;
	fastd_socket_t *sock_default_v6;

	fastd_stats_t rx;

	fastd_stats_t tx;
	fastd_stats_t tx_dropped;
	fastd_stats_t tx_error;

	VECTOR(fastd_peer_eth_addr_t) eth_addrs;

	unsigned int randseed;

	size_t unknown_handshake_pos;
	fastd_handshake_timeout_t unknown_handshakes[8];

	fastd_protocol_state_t *protocol_state;
};

/** A stack of strings */
struct fastd_string_stack {
	fastd_string_stack_t *next;
	char str[];
};


extern fastd_context_t ctx;	/**< The global context */
extern fastd_config_t conf;	/**< The global configuration */


void fastd_send(const fastd_socket_t *sock, const fastd_peer_address_t *local_addr, const fastd_peer_address_t *remote_addr, fastd_peer_t *peer, fastd_buffer_t buffer, size_t stat_size);
void fastd_send_all(fastd_peer_t *source_peer, fastd_buffer_t buffer);
void fastd_send_handshake(const fastd_socket_t *sock, const fastd_peer_address_t *local_addr, const fastd_peer_address_t *remote_addr, fastd_peer_t *peer, fastd_buffer_t buffer);
void fastd_receive(fastd_socket_t *sock);

void fastd_handle_receive(fastd_peer_t *peer, fastd_buffer_t buffer);

void fastd_close_all_fds(void);

bool fastd_socket_handle_binds(void);
fastd_socket_t* fastd_socket_open(fastd_peer_t *peer, int af);
void fastd_socket_close(fastd_socket_t *sock);
void fastd_socket_error(fastd_socket_t *sock);

void fastd_resolve_peer(fastd_peer_t *peer, fastd_remote_t *remote);

void fastd_tuntap_open(void);
fastd_buffer_t fastd_tuntap_read(void);
void fastd_tuntap_write(fastd_buffer_t buffer);
void fastd_tuntap_close(void);

void fastd_cap_init(void);
void fastd_cap_drop(void);

void fastd_random_bytes(void *buffer, size_t len, bool secure);

/** Returns a random number between \a min (inclusively) and \a max (exclusively) */
static inline int fastd_rand(int min, int max) {
	unsigned int r = (unsigned int)rand_r(&ctx.randseed);
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


/**
   Returns a pointer to a data structure, given the address of a member contained in the structure

   @param ptr		the address of the member
   @param type		the type of the container
   @param member	the name of the member

   \hideinitializer
 */
#define container_of(ptr, type, member) ({				\
			const __typeof__(((type *)0)->member) *_mptr = (ptr); \
			(type*)((char*)_mptr - offsetof(type, member)); \
		})

/**
   Returns the number of elements of an array

   \hideinitializer
 */
#define array_size(array) (sizeof(array)/sizeof((array)[0]))

/**
   Determines how many blocks of a given size \a a are needed to contain some length \a l
 */
static inline size_t block_count(size_t l, size_t a) {
	return (l+a-1)/a;
}

/**
   Rounds up a length \a l to the next multiple of a block size \a a
 */
static inline size_t alignto(size_t l, size_t a) {
	return block_count(l, a)*a;
}

/** Returns the maximum payload size \em fastd is configured to transport */
static inline size_t fastd_max_inner_packet(void) {
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
static inline fastd_eth_addr_t fastd_get_source_address(const fastd_buffer_t buffer) {
	fastd_eth_addr_t ret;

	switch (conf.mode) {
	case MODE_TAP:
		memcpy(&ret, buffer.data+offsetof(struct ethhdr, h_source), ETH_ALEN);
		return ret;
	default:
		exit_bug("invalid mode");
	}
}

/** Returns the destination address of an ethernet packet */
static inline fastd_eth_addr_t fastd_get_dest_address(const fastd_buffer_t buffer) {
	fastd_eth_addr_t ret;
	switch (conf.mode) {
	case MODE_TAP:
		memcpy(&ret, buffer.data+offsetof(struct ethhdr, h_dest), ETH_ALEN);
		return ret;
	default:
		exit_bug("invalid mode");
	}
}

/** Returns the packet size (payload + overhead) \em fastd is configured to transport */
static inline size_t fastd_max_outer_packet(void) {
	return 1 + fastd_max_inner_packet() + conf.max_overhead;
}

/** Checks if a fastd_peer_address_t is an IPv6 link-local address */
static inline bool fastd_peer_address_is_v6_ll(const fastd_peer_address_t *addr) {
	return (addr->sa.sa_family == AF_INET6 && IN6_IS_ADDR_LINKLOCAL(&addr->in6.sin6_addr));
}

/** Duplicates a string, creating a one-element string stack */
static inline fastd_string_stack_t* fastd_string_stack_dup(const char *str) {
	fastd_string_stack_t *ret = malloc(alignto(sizeof(fastd_string_stack_t) + strlen(str) + 1, 8));
	ret->next = NULL;
	strcpy(ret->str, str);

	return ret;
}

/** Duplicates a string of a given maximum length, creating a one-element string stack */
static inline fastd_string_stack_t* fastd_string_stack_dupn(const char *str, size_t len) {
	size_t str_len = strnlen(str, len);
	fastd_string_stack_t *ret = malloc(alignto(sizeof(fastd_string_stack_t) + str_len + 1, 8));
	ret->next = NULL;
	strncpy(ret->str, str, str_len);
	ret->str[str_len] = 0;

	return ret;
}

/** Pushes the copy of a string onto the top of a string stack */
static inline fastd_string_stack_t* fastd_string_stack_push(fastd_string_stack_t *stack, const char *str) {
	fastd_string_stack_t *ret = malloc(alignto(sizeof(fastd_string_stack_t) + strlen(str) + 1, 8));
	ret->next = stack;
	strcpy(ret->str, str);

	return ret;
}

/** Frees a whole string stack */
static inline void fastd_string_stack_free(fastd_string_stack_t *str) {
	while (str) {
		fastd_string_stack_t *next = str->next;
		free(str);
		str = next;
	}
}

/** Compares two timespecs and returns \em true if \p tp1 is after \p tp2 */
static inline bool timespec_after(const struct timespec *tp1, const struct timespec *tp2) {
	return (tp1->tv_sec > tp2->tv_sec ||
		(tp1->tv_sec == tp2->tv_sec && tp1->tv_nsec > tp2->tv_nsec));
}

/** Returns (\a tp1 - \a tp2) in milliseconds  */
static inline int timespec_diff(const struct timespec *tp1, const struct timespec *tp2) {
	return ((tp1->tv_sec - tp2->tv_sec))*1000 + (tp1->tv_nsec - tp2->tv_nsec)/1e6;
}

/**
   Returns true if the given timespec is before or equal to the current time

   \note The current time is updated only once per main loop iteration, after waiting for input.
*/
static inline bool fastd_timed_out(const struct timespec *timeout) {
	return !timespec_after(timeout, &ctx.now);
}

/** Returns a timespec that lies a given number of seconds in the future */
static inline struct timespec fastd_in_seconds(const int seconds) {
	struct timespec ret = ctx.now;
	ret.tv_sec += seconds;
	return ret;
}

/** Updates the current time */
static inline void fastd_update_time(void) {
	clock_gettime(CLOCK_MONOTONIC, &ctx.now);
}

/** Checks if a on-verify command is set */
static inline bool fastd_allow_verify(void) {
#ifdef WITH_VERIFY
	return fastd_shell_command_isset(&conf.on_verify);
#else
	return false;
#endif
}

/**
   Checks if two strings are equal

   The strings may be NULL.
*/
static inline bool strequal(const char *str1, const char *str2) {
	if (str1 && str2)
		return (!strcmp(str1, str2));
	else
		return (str1 == str2);
}

/** Returns the maximum of two size_t values */
static inline size_t max_size_t(size_t a, size_t b) {
	return (a > b) ? a : b;
}

/** Returns the minimum of two size_t values */
static inline size_t min_size_t(size_t a, size_t b) {
	return (a < b) ? a : b;
}
