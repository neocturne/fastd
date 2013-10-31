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


#ifndef _FASTD_FASTD_H_
#define _FASTD_FASTD_H_

#include "compat.h"
#include "types.h"
#include "dlist.h"

#include <errno.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <sys/uio.h>


struct fastd_buffer {
	void *base;
	size_t base_len;

	void *data;
	size_t len;
};

struct __attribute__((__packed__)) fastd_eth_addr {
	uint8_t data[ETH_ALEN];
};

struct fastd_protocol {
	const char *name;

	fastd_protocol_config_t* (*init)(fastd_context_t *ctx);
	void (*peer_configure)(fastd_context_t *ctx, fastd_peer_config_t *peer_conf);
	bool (*peer_check)(fastd_context_t *ctx, fastd_peer_config_t *peer_conf);
	bool (*peer_check_temporary)(fastd_context_t *ctx, fastd_peer_t *peer);

	void (*handshake_init)(fastd_context_t *ctx, const fastd_socket_t *sock, const fastd_peer_address_t *local_addr, const fastd_peer_address_t *remote_addr, fastd_peer_t *peer);
	void (*handshake_handle)(fastd_context_t *ctx, fastd_socket_t *sock, const fastd_peer_address_t *local_addr, const fastd_peer_address_t *remote_addr, fastd_peer_t *peer, const fastd_handshake_t *handshake, const char *method);

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

struct fastd_method {
	const char *name;

	size_t (*max_packet_size)(fastd_context_t *ctx);
	size_t (*min_encrypt_head_space)(fastd_context_t *ctx);
	size_t (*min_decrypt_head_space)(fastd_context_t *ctx);
	size_t (*min_encrypt_tail_space)(fastd_context_t *ctx);
	size_t (*min_decrypt_tail_space)(fastd_context_t *ctx);

	size_t (*key_length)(fastd_context_t *ctx);
	fastd_method_session_state_t* (*session_init)(fastd_context_t *ctx, uint8_t *secret, bool initiator);
	fastd_method_session_state_t* (*session_init_compat)(fastd_context_t *ctx, uint8_t *secret, size_t length, bool initiator);
	bool (*session_is_valid)(fastd_context_t *ctx, fastd_method_session_state_t *session);
	bool (*session_is_initiator)(fastd_context_t *ctx, fastd_method_session_state_t *session);
	bool (*session_want_refresh)(fastd_context_t *ctx, fastd_method_session_state_t *session);
	void (*session_superseded)(fastd_context_t *ctx, fastd_method_session_state_t *session);
	void (*session_free)(fastd_context_t *ctx, fastd_method_session_state_t *session);

	bool (*encrypt)(fastd_context_t *ctx, fastd_peer_t *peer, fastd_method_session_state_t *session, fastd_buffer_t *out, fastd_buffer_t in);
	bool (*decrypt)(fastd_context_t *ctx, fastd_peer_t *peer, fastd_method_session_state_t *session, fastd_buffer_t *out, fastd_buffer_t in);
};

union fastd_peer_address {
	struct sockaddr sa;
	struct sockaddr_in in;
	struct sockaddr_in6 in6;
};

struct fastd_resolve_return {
	fastd_remote_t *remote;
	fastd_peer_address_t addr;
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

struct fastd_config {
	struct timespec long_ago;

	fastd_loglevel_t log_stderr_level;
	fastd_loglevel_t log_syslog_level;
	char *log_syslog_ident;
	fastd_log_file_t *log_files;

	unsigned keepalive_timeout;
	unsigned keepalive_interval;
	unsigned peer_stale_time;
	unsigned eth_addr_stale_time;

	unsigned reorder_count;
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

	bool forward;
	fastd_tristate_t pmtu;
	bool secure_handshakes_set;
	bool secure_handshakes;

	fastd_drop_caps_t drop_caps;

	char *user;
	char *group;

	uid_t uid;
	gid_t gid;
	size_t n_groups;
	gid_t *groups;

	const fastd_protocol_t *protocol;
	fastd_string_stack_t *methods;

	size_t max_packet_size;
	size_t min_encrypt_head_space;
	size_t min_decrypt_head_space;
	size_t min_encrypt_tail_space;
	size_t min_decrypt_tail_space;

	char *secret;
	unsigned key_valid;
	unsigned key_valid_old;
	unsigned key_refresh;
	unsigned key_refresh_splay;

#ifdef USE_CRYPTO_AES128CTR
	const fastd_crypto_aes128ctr_t *crypto_aes128ctr;
#endif
#ifdef USE_CRYPTO_GHASH
	const fastd_crypto_ghash_t *crypto_ghash;
#endif

	fastd_peer_group_config_t *peer_group;
	fastd_peer_config_t *peers;

	bool has_floating;

	fastd_protocol_config_t *protocol_config;

	char *on_pre_up;
	char *on_pre_up_dir;

	char *on_up;
	char *on_up_dir;

	char *on_down;
	char *on_down_dir;

	char *on_post_down;
	char *on_post_down_dir;

	char *on_establish;
	char *on_establish_dir;

	char *on_disestablish;
	char *on_disestablish_dir;

	char *on_verify;
	char *on_verify_dir;

	bool daemon;
	char *pid_file;

	bool hide_ip_addresses;
	bool hide_mac_addresses;

	bool machine_readable;
	bool generate_key;
	bool show_key;
};

struct fastd_context {
	const fastd_config_t *conf;

	fastd_log_fd_t *log_files;

	char *ifname;

	struct timespec now;

	unsigned n_peers;
	fastd_peer_group_t *peer_group;
	fastd_peer_t *peers;
	fastd_peer_t *peers_temp;

	fastd_dlist_head_t handshake_queue;
	struct timespec next_keepalives;

	int resolverfd;
	int resolvewfd;

	int tunfd;

	unsigned n_socks;
	fastd_socket_t *socks;

	fastd_socket_t *sock_default_v4;
	fastd_socket_t *sock_default_v6;

	fastd_stats_t rx;

	fastd_stats_t tx;
	fastd_stats_t tx_dropped;
	fastd_stats_t tx_error;

#ifdef USE_CRYPTO_AES128CTR
	fastd_crypto_aes128ctr_context_t *crypto_aes128ctr;
#endif
#ifdef USE_CRYPTO_GHASH
	fastd_crypto_ghash_context_t *crypto_ghash;
#endif

	size_t eth_addr_size;
	size_t n_eth_addr;
	fastd_peer_eth_addr_t *eth_addr;

	unsigned int randseed;

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

void fastd_setfd(const fastd_context_t *ctx, int fd, int set, int unset);
void fastd_setfl(const fastd_context_t *ctx, int fd, int set, int unset);

void fastd_resolve_peer(fastd_context_t *ctx, fastd_peer_t *peer, fastd_remote_t *remote);

int fastd_vsnprintf(const fastd_context_t *ctx, char *buffer, size_t size, const char *format, va_list ap);
void fastd_logf(const fastd_context_t *ctx, fastd_loglevel_t level, const char *format, ...);

void fastd_add_peer_dir(fastd_context_t *ctx, fastd_config_t *conf, const char *dir);
bool fastd_read_config(fastd_context_t *ctx, fastd_config_t *conf, const char *filename, bool peer_config, int depth);

const fastd_method_t* fastd_method_get_by_name(const char *name);

bool fastd_config_protocol(fastd_context_t *ctx, fastd_config_t *conf, const char *name);
bool fastd_config_method(fastd_context_t *ctx, fastd_config_t *conf, const char *name);
bool fastd_config_crypto(fastd_context_t *ctx, fastd_config_t *conf, const char *alg, const char *impl);
bool fastd_config_add_log_file(fastd_context_t *ctx, fastd_config_t *conf, const char *name, fastd_loglevel_t level);
bool fastd_config_bind_address(fastd_context_t *ctx, fastd_config_t *conf, const fastd_peer_address_t *address, const char *bindtodev, bool default_v4, bool default_v6);
void fastd_config_peer_group_push(fastd_context_t *ctx, fastd_config_t *conf, const char *name);
void fastd_config_peer_group_pop(fastd_context_t *ctx, fastd_config_t *conf);
void fastd_config_release(fastd_context_t *ctx, fastd_config_t *conf);
void fastd_configure(fastd_context_t *ctx, fastd_config_t *conf, int argc, char *const argv[]);
void fastd_config_load_peer_dirs(fastd_context_t *ctx, fastd_config_t *conf);
void fastd_config_handle_options(fastd_context_t *ctx, fastd_config_t *conf, int argc, char *const argv[]);

void fastd_tuntap_open(fastd_context_t *ctx);
fastd_buffer_t fastd_tuntap_read(fastd_context_t *ctx);
void fastd_tuntap_write(fastd_context_t *ctx, fastd_buffer_t buffer);
void fastd_tuntap_close(fastd_context_t *ctx);

void fastd_cap_init(fastd_context_t *ctx);
void fastd_cap_drop(fastd_context_t *ctx);

bool fastd_shell_exec(fastd_context_t *ctx, const char *command, const char *dir, const fastd_peer_t *peer, const fastd_peer_address_t *local_addr, const fastd_peer_address_t *peer_addr, int *ret);

void fastd_random_bytes(fastd_context_t *ctx, void *buffer, size_t len, bool secure);

static inline int fastd_rand(fastd_context_t *ctx, int min, int max) {
	unsigned int r = (unsigned int)rand_r(&ctx->randseed);
	return (r%(max-min) + min);
}


#define FASTD_DEFAULT_LOG_LEVEL	LL_VERBOSE


#define pr_fatal(ctx, args...) fastd_logf(ctx, LL_FATAL, args)
#define pr_error(ctx, args...) fastd_logf(ctx, LL_ERROR, args)
#define pr_warn(ctx, args...) fastd_logf(ctx, LL_WARN, args)
#define pr_info(ctx, args...) fastd_logf(ctx, LL_INFO, args)
#define pr_verbose(ctx, args...) fastd_logf(ctx, LL_VERBOSE, args)
#define pr_debug(ctx, args...) fastd_logf(ctx, LL_DEBUG, args)
#define pr_debug2(ctx, args...) fastd_logf(ctx, LL_DEBUG2, args)

#define pr_error_errno(ctx, message) pr_error(ctx, "%s: %s", message, strerror(errno))
#define pr_warn_errno(ctx, message) pr_warn(ctx, "%s: %s", message, strerror(errno))
#define pr_debug_errno(ctx, message) pr_debug(ctx, "%s: %s", message, strerror(errno))
#define pr_debug2_errno(ctx, message) pr_debug2(ctx, "%s: %s", message, strerror(errno))

#define exit_fatal(ctx, args...) do { pr_fatal(ctx, args); abort(); } while(0)
#define exit_bug(ctx, message) exit_fatal(ctx, "BUG: %s", message)
#define exit_error(ctx, args...) do { pr_error(ctx, args); exit(1); } while(0)
#define exit_errno(ctx, message) exit_error(ctx, "%s: %s", message, strerror(errno))


#define container_of(ptr, type, member) ({                      \
			const typeof( ((type *)0)->member ) *__mptr = (ptr); \
			(type *)( (char *)__mptr - offsetof(type,member) );})


static inline size_t block_count(size_t l, size_t a) {
	return (l+a-1)/a;
}

static inline size_t alignto(size_t l, size_t a) {
	return block_count(l, a)*a;
}

static inline fastd_buffer_t fastd_buffer_alloc(const fastd_context_t *ctx, size_t len, size_t head_space, size_t tail_space) {
	size_t base_len = head_space+len+tail_space;
	void *ptr;
	if (posix_memalign(&ptr, 16, base_len))
		exit_errno(ctx, "posix_memalign");

	return (fastd_buffer_t){ .base = ptr, .base_len = base_len, .data = ptr+head_space, .len = len };
}

static inline fastd_buffer_t fastd_buffer_dup(const fastd_context_t *ctx, fastd_buffer_t buffer, size_t head_space, size_t tail_space) {
	fastd_buffer_t new_buffer = fastd_buffer_alloc(ctx, buffer.len, head_space, tail_space);
	memcpy(new_buffer.data, buffer.data, buffer.len);
	return new_buffer;
}

static inline void fastd_buffer_free(fastd_buffer_t buffer) {
	free(buffer.base);
}

static inline void fastd_buffer_pull_head(const fastd_context_t *ctx, fastd_buffer_t *buffer, size_t len) {
	buffer->data -= len;
	buffer->len += len;

	if (buffer->data < buffer->base)
		exit_bug(ctx, "tried to pull buffer across head");
}

static inline void fastd_buffer_push_head(const fastd_context_t *ctx, fastd_buffer_t *buffer, size_t len) {
	if (buffer->len < len)
		exit_bug(ctx, "tried to push buffer across tail");

	buffer->data += len;
	buffer->len -= len;
}

static inline size_t fastd_max_packet_size(const fastd_context_t *ctx) {
	switch (ctx->conf->mode) {
	case MODE_TAP:
		return ctx->conf->mtu+ETH_HLEN;
	case MODE_TUN:
		return ctx->conf->mtu;
	default:
		exit_bug(ctx, "invalid mode");
	}
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

static inline void secure_memzero(void *s, size_t n) {
	memset(s, 0, n);
	asm volatile("" : : "m"(s));
}

#endif /* _FASTD_FASTD_H_ */
