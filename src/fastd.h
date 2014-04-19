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


#pragma once

#include "types.h"
#include "dlist.h"
#include "buffer.h"
#include "log.h"
#include "shell.h"

#include <errno.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <sys/uio.h>


struct __attribute__((__packed__)) fastd_eth_addr {
	uint8_t data[ETH_ALEN];
};

struct fastd_protocol {
	const char *name;

	fastd_protocol_config_t* (*init)(fastd_context_t *ctx);
	void (*peer_verify)(fastd_context_t *ctx, fastd_peer_config_t *peer_conf);
	void (*peer_configure)(fastd_context_t *ctx, fastd_peer_config_t *peer_conf);
	bool (*peer_check)(fastd_context_t *ctx, fastd_peer_config_t *peer_conf);
	bool (*peer_check_temporary)(fastd_context_t *ctx, fastd_peer_t *peer);

	void (*handshake_init)(fastd_context_t *ctx, const fastd_socket_t *sock, const fastd_peer_address_t *local_addr, const fastd_peer_address_t *remote_addr, fastd_peer_t *peer);
	void (*handshake_handle)(fastd_context_t *ctx, fastd_socket_t *sock, const fastd_peer_address_t *local_addr, const fastd_peer_address_t *remote_addr, fastd_peer_t *peer, const fastd_handshake_t *handshake, const fastd_method_info_t *method);

	void (*handle_recv)(fastd_context_t *ctx, fastd_peer_t *peer, fastd_buffer_t buffer);
	void (*send)(fastd_context_t *ctx, fastd_peer_t *peer, fastd_buffer_t buffer);

	void (*init_peer_state)(fastd_context_t *ctx, fastd_peer_t *peer);
	void (*reset_peer_state)(fastd_context_t *ctx, fastd_peer_t *peer);
	void (*free_peer_state)(fastd_context_t *ctx, fastd_peer_t *peer);

	void (*generate_key)(fastd_context_t *ctx);
	void (*show_key)(fastd_context_t *ctx);
	void (*set_shell_env)(fastd_context_t *ctx, const fastd_peer_t *peer);
	bool (*describe_peer)(const fastd_context_t *ctx, const fastd_peer_t *peer, char *buf, size_t len);
};

union fastd_peer_address {
	struct sockaddr sa;
	struct sockaddr_in in;
	struct sockaddr_in6 in6;
};

struct fastd_log_file {
	fastd_log_file_t *next;

	fastd_loglevel_t level;
	char *filename;
};

struct fastd_log_fd {
	fastd_log_fd_t *next;

	fastd_log_file_t *config;
	int fd;
};

struct fastd_bind_address {
	fastd_bind_address_t *next;
	fastd_peer_address_t addr;
	char *bindtodev;
};

struct fastd_socket {
	int fd;
	const fastd_bind_address_t *addr;
	fastd_peer_address_t *bound_addr;
	fastd_peer_t *peer;
};

struct fastd_peer_group_config {
	fastd_peer_group_config_t *next;
	fastd_peer_group_config_t *parent;
	fastd_peer_group_config_t *children;

	char *name;
	fastd_string_stack_t *peer_dirs;

	/* constraints */
	int max_connections;
};

struct fastd_peer_group {
	fastd_peer_group_t *next;
	fastd_peer_group_t *parent;
	fastd_peer_group_t *children;

	const fastd_peer_group_config_t *conf;

	unsigned n_connections;
};

struct fastd_stats {
	uint64_t packets;
	uint64_t bytes;
};

struct fastd_handshake_timeout {
	fastd_peer_address_t address;
	struct timespec timeout;
};

struct fastd_config {
	fastd_loglevel_t log_stderr_level;
	fastd_loglevel_t log_syslog_level;
	char *log_syslog_ident;
	fastd_log_file_t *log_files;

	unsigned maintenance_interval;
	unsigned keepalive_timeout;
	unsigned peer_stale_time;
	unsigned eth_addr_stale_time;

	unsigned reorder_time;

	unsigned min_handshake_interval;
	unsigned min_resolve_interval;

	char *ifname;

	unsigned n_bind_addrs;
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
	unsigned key_valid;
	unsigned key_valid_old;
	unsigned key_refresh;
	unsigned key_refresh_splay;

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
	fastd_shell_command_t on_verify;

	bool daemon;
	char *pid_file;

	bool hide_ip_addresses;
	bool hide_mac_addresses;

	bool machine_readable;
	bool generate_key;
	bool show_key;
	bool verify_config;
};

struct fastd_context {
	const fastd_config_t *conf;

	bool log_initialized;
	fastd_log_fd_t *log_files;

	char *ifname;

	struct timespec now;

	unsigned n_peers;
	fastd_peer_group_t *peer_group;
	fastd_peer_t *peers;
	fastd_peer_t *peers_temp;

	fastd_dlist_head_t handshake_queue;
	struct timespec next_maintenance;

	int async_rfd;
	int async_wfd;

	int tunfd;

	unsigned n_socks;
	fastd_socket_t *socks;

	fastd_socket_t *sock_default_v4;
	fastd_socket_t *sock_default_v6;

	fastd_stats_t rx;

	fastd_stats_t tx;
	fastd_stats_t tx_dropped;
	fastd_stats_t tx_error;

	size_t eth_addr_size;
	size_t n_eth_addr;
	fastd_peer_eth_addr_t *eth_addr;

	unsigned int randseed;

	size_t unknown_handshake_pos;
	fastd_handshake_timeout_t unknown_handshakes[8];

	fastd_protocol_state_t *protocol_state;
};

struct fastd_string_stack {
	fastd_string_stack_t *next;
	char str[];
};


void fastd_send(fastd_context_t *ctx, const fastd_socket_t *sock, const fastd_peer_address_t *local_addr, const fastd_peer_address_t *remote_addr, fastd_peer_t *peer, fastd_buffer_t buffer, size_t stat_size);
void fastd_send_all(fastd_context_t *ctx, fastd_peer_t *source_peer, fastd_buffer_t buffer);
void fastd_send_handshake(fastd_context_t *ctx, const fastd_socket_t *sock, const fastd_peer_address_t *local_addr, const fastd_peer_address_t *remote_addr, fastd_peer_t *peer, fastd_buffer_t buffer);
void fastd_receive(fastd_context_t *ctx, fastd_socket_t *sock);

void fastd_handle_receive(fastd_context_t *ctx, fastd_peer_t *peer, fastd_buffer_t buffer);

bool fastd_socket_handle_binds(fastd_context_t *ctx);
fastd_socket_t* fastd_socket_open(fastd_context_t *ctx, fastd_peer_t *peer, int af);
void fastd_socket_close(fastd_context_t *ctx, fastd_socket_t *sock);
void fastd_socket_error(fastd_context_t *ctx, fastd_socket_t *sock);

void fastd_open_pipe(fastd_context_t *ctx, int *readfd, int *writefd);
void fastd_setfd(const fastd_context_t *ctx, int fd, int set, int unset);
void fastd_setfl(const fastd_context_t *ctx, int fd, int set, int unset);

void fastd_resolve_peer(fastd_context_t *ctx, fastd_peer_t *peer, fastd_remote_t *remote);

void fastd_tuntap_open(fastd_context_t *ctx);
fastd_buffer_t fastd_tuntap_read(fastd_context_t *ctx);
void fastd_tuntap_write(fastd_context_t *ctx, fastd_buffer_t buffer);
void fastd_tuntap_close(fastd_context_t *ctx);

void fastd_cap_init(fastd_context_t *ctx);
void fastd_cap_drop(fastd_context_t *ctx);

void fastd_random_bytes(fastd_context_t *ctx, void *buffer, size_t len, bool secure);

static inline int fastd_rand(fastd_context_t *ctx, int min, int max) {
	unsigned int r = (unsigned int)rand_r(&ctx->randseed);
	return (r%(max-min) + min);
}


#define container_of(ptr, type, member) ({				\
			const __typeof__(((type *)0)->member) *_mptr = (ptr); \
			(type*)((char*)_mptr - offsetof(type, member)); \
		})

#define array_size(array) (sizeof(array)/sizeof((array)[0]))

static inline size_t block_count(size_t l, size_t a) {
	return (l+a-1)/a;
}

static inline size_t alignto(size_t l, size_t a) {
	return block_count(l, a)*a;
}


static inline size_t fastd_max_inner_packet(const fastd_context_t *ctx) {
	switch (ctx->conf->mode) {
	case MODE_TAP:
		return ctx->conf->mtu+ETH_HLEN;
	case MODE_TUN:
		return ctx->conf->mtu;
	default:
		exit_bug(ctx, "invalid mode");
	}
}

static inline size_t fastd_max_outer_packet(const fastd_context_t *ctx) {
	return PACKET_TYPE_LEN + fastd_max_inner_packet(ctx) + ctx->conf->max_overhead;
}

static inline bool fastd_peer_address_is_v6_ll(const fastd_peer_address_t *addr) {
	return (addr->sa.sa_family == AF_INET6 && IN6_IS_ADDR_LINKLOCAL(&addr->in6.sin6_addr));
}

static inline fastd_string_stack_t* fastd_string_stack_dup(const char *str) {
	fastd_string_stack_t *ret = malloc(alignto(sizeof(fastd_string_stack_t) + strlen(str) + 1, 8));
	ret->next = NULL;
	strcpy(ret->str, str);

	return ret;
}

static inline fastd_string_stack_t* fastd_string_stack_dupn(const char *str, size_t len) {
	size_t str_len = strnlen(str, len);
	fastd_string_stack_t *ret = malloc(alignto(sizeof(fastd_string_stack_t) + str_len + 1, 8));
	ret->next = NULL;
	strncpy(ret->str, str, str_len);
	ret->str[str_len] = 0;

	return ret;
}

static inline fastd_string_stack_t* fastd_string_stack_push(fastd_string_stack_t *stack, const char *str) {
	fastd_string_stack_t *ret = malloc(alignto(sizeof(fastd_string_stack_t) + strlen(str) + 1, 8));
	ret->next = stack;
	strcpy(ret->str, str);

	return ret;
}

static inline void fastd_string_stack_free(fastd_string_stack_t *str) {
	while(str) {
		fastd_string_stack_t *next = str->next;
		free(str);
		str = next;
	}
}

static inline bool timespec_after(const struct timespec *tp1, const struct timespec *tp2) {
	return (tp1->tv_sec > tp2->tv_sec ||
		(tp1->tv_sec == tp2->tv_sec && tp1->tv_nsec > tp2->tv_nsec));
}

/* returns (tp1 - tp2) in milliseconds  */
static inline int timespec_diff(const struct timespec *tp1, const struct timespec *tp2) {
	return ((tp1->tv_sec - tp2->tv_sec))*1000 + (tp1->tv_nsec - tp2->tv_nsec)/1e6;
}

static inline bool fastd_timed_out(const fastd_context_t *ctx, const struct timespec *timeout) {
	return !timespec_after(timeout, &ctx->now);
}

static inline struct timespec fastd_in_seconds(const fastd_context_t *ctx, int seconds) {
	struct timespec ret = ctx->now;
	ret.tv_sec += seconds;
	return ret;
}

static inline bool strequal(const char *str1, const char *str2) {
	if (str1 && str2)
		return (!strcmp(str1, str2));
	else
		return (str1 == str2);
}

static inline size_t max_size_t(size_t a, size_t b) {
	return (a > b) ? a : b;
}

static inline size_t min_size_t(size_t a, size_t b) {
	return (a < b) ? a : b;
}
