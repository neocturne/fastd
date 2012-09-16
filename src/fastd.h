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


#ifndef _FASTD_FASTD_H_
#define _FASTD_FASTD_H_

#include "types.h"
#include "queue.h"

#include <errno.h>
#include <linux/if_ether.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <sys/uio.h>
#include <sys/socket.h>
#include <time.h>


#define FASTD_VERSION "0.5-rc3"


/* This must be adjusted when new methods are added */
#define MAX_METHODS 3


struct _fastd_buffer {
	void *base;
	size_t base_len;

	void *data;
	size_t len;
};

struct _fastd_eth_addr {
	uint8_t data[ETH_ALEN];
};

struct _fastd_protocol {
	const char *name;

	fastd_protocol_config* (*init)(fastd_context *ctx);
	void (*peer_configure)(fastd_context *ctx, fastd_peer_config *peer_conf);

	void (*handshake_init)(fastd_context *ctx, const fastd_peer_address *address, const fastd_peer_config *peer_conf);
	void (*handshake_handle)(fastd_context *ctx, const fastd_peer_address *address, const fastd_peer_config *peer_conf, const fastd_handshake *handshake, const fastd_method *method);

	void (*handle_recv)(fastd_context *ctx, fastd_peer *peer, fastd_buffer buffer);
	void (*send)(fastd_context *ctx, fastd_peer *peer, fastd_buffer buffer);

	void (*init_peer_state)(fastd_context *ctx, fastd_peer *peer);
	void (*reset_peer_state)(fastd_context *ctx, fastd_peer *peer);
	void (*free_peer_state)(fastd_context *ctx, fastd_peer *peer);

	void (*generate_key)(fastd_context *ctx);
	void (*show_key)(fastd_context *ctx);
};

struct _fastd_method {
	const char *name;

	size_t (*max_packet_size)(fastd_context *ctx);
	size_t (*min_encrypt_head_space)(fastd_context *ctx);
	size_t (*min_decrypt_head_space)(fastd_context *ctx);
	size_t (*min_encrypt_tail_space)(fastd_context *ctx);
	size_t (*min_decrypt_tail_space)(fastd_context *ctx);

	fastd_method_session_state* (*session_init)(fastd_context *ctx, uint8_t *secret, size_t length, bool initiator);
	bool (*session_is_valid)(fastd_context *ctx, fastd_method_session_state *session);
	bool (*session_is_initiator)(fastd_context *ctx, fastd_method_session_state *session);
	bool (*session_want_refresh)(fastd_context *ctx, fastd_method_session_state *session);
	void (*session_free)(fastd_context *ctx, fastd_method_session_state *session);

	bool (*encrypt)(fastd_context *ctx, fastd_peer *peer, fastd_method_session_state *session, fastd_buffer *out, fastd_buffer in);
	bool (*decrypt)(fastd_context *ctx, fastd_peer *peer, fastd_method_session_state *session, fastd_buffer *out, fastd_buffer in);
};

union _fastd_peer_address {
	struct sockaddr sa;
	struct sockaddr_in in;
	struct sockaddr_in6 in6;
};

struct _fastd_resolve_return {
	char *hostname;
	fastd_peer_address constraints;

	fastd_peer_address addr;
};

struct _fastd_log_file {
	fastd_log_file *next;

	int level;
	char *filename;
};

struct _fastd_log_fd {
	fastd_log_fd *next;

	fastd_log_file *config;
	int fd;
};

struct _fastd_config {
	int log_stderr_level;
	int log_syslog_level;
	char *log_syslog_ident;
	fastd_log_file *log_files;

	unsigned keepalive_interval;
	unsigned peer_stale_time;
	unsigned eth_addr_stale_time;

	unsigned reorder_count;
	unsigned reorder_time;

	unsigned min_handshake_interval;
	unsigned min_resolve_interval;

	char *ifname;

	struct sockaddr_in bind_addr_in;
	struct sockaddr_in6 bind_addr_in6;

	uint16_t mtu;
	fastd_mode mode;

	bool forward;

	const fastd_protocol *protocol;
	const fastd_method *methods[MAX_METHODS];
	const fastd_method *method_default;
	char *secret;
	unsigned key_valid;
	unsigned key_refresh;
	fastd_alg_impl alg_impl_aes128ctr;
	fastd_alg_impl alg_impl_ghash;

	fastd_string_stack *peer_dirs;
	fastd_peer_config *peers;

	unsigned n_floating;
	unsigned n_v4;
	unsigned n_v6;
	unsigned n_dynamic;
	unsigned n_dynamic_v4;
	unsigned n_dynamic_v6;

	fastd_protocol_config *protocol_config;

	char *on_up;
	char *on_up_dir;

	char *on_down;
	char *on_down_dir;

	char *on_establish;
	char *on_establish_dir;

	char *on_disestablish;
	char *on_disestablish_dir;

	bool daemon;
	char *pid_file;

	bool machine_readable;
	bool generate_key;
	bool show_key;
};

struct _fastd_context {
	const fastd_config *conf;

	fastd_log_fd *log_files;

	char *ifname;

	struct timespec now;

	fastd_peer *peers;
	fastd_queue task_queue;

	int resolverfd;
	int resolvewfd;

	int tunfd;
	int sockfd;
	int sock6fd;

	int algfd_ghash;
	int algfd_aesctr;

	size_t eth_addr_size;
	size_t n_eth_addr;
	fastd_peer_eth_addr *eth_addr;

	unsigned int randseed;

	fastd_protocol_state *protocol_state;
};

struct _fastd_string_stack {
	fastd_string_stack *next;
	char str[];
};


void fastd_send(fastd_context *ctx, const fastd_peer_address *address, fastd_buffer buffer);
void fastd_send_handshake(fastd_context *ctx, const fastd_peer_address *address, fastd_buffer buffer);
void fastd_handle_receive(fastd_context *ctx, fastd_peer *peer, fastd_buffer buffer);

void fastd_resolve_peer(fastd_context *ctx, fastd_peer *peer);

int fastd_vsnprintf(const fastd_context *ctx, char *buffer, size_t size, const char *format, va_list ap);
void fastd_logf(const fastd_context *ctx, int level, const char *format, ...);

void fastd_read_peer_dir(fastd_context *ctx, fastd_config *conf, const char *dir);
bool fastd_read_config(fastd_context *ctx, fastd_config *conf, const char *filename, bool peer_config, int depth);

bool fastd_config_protocol(fastd_context *ctx, fastd_config *conf, const char *name);
bool fastd_config_method(fastd_context *ctx, fastd_config *conf, const char *name);
bool fastd_config_algorithm(fastd_context *ctx, fastd_config *conf, const char *alg, const char *impl);
bool fastd_config_add_log_file(fastd_context *ctx, fastd_config *conf, const char *name, int level);
void fastd_configure(fastd_context *ctx, fastd_config *conf, int argc, char *const argv[]);
void fastd_reconfigure(fastd_context *ctx, fastd_config *conf);
void fastd_config_release(fastd_context *ctx, fastd_config *conf);

void fastd_random_bytes(fastd_context *ctx, void *buffer, size_t len, bool secure);

static inline int fastd_rand(fastd_context *ctx, int min, int max) {
	unsigned int r = (unsigned int)rand_r(&ctx->randseed);
	return (r%(max-min) + min);
}


#define FASTD_DEFAULT_LOG_LEVEL	LOG_INFO


#define pr_fatal(ctx, args...) fastd_logf(ctx, LOG_CRIT, args)
#define pr_error(ctx, args...) fastd_logf(ctx, LOG_ERR, args)
#define pr_warn(ctx, args...) fastd_logf(ctx, LOG_WARNING, args)
#define pr_info(ctx, args...) fastd_logf(ctx, LOG_NOTICE, args)
#define pr_verbose(ctx, args...) fastd_logf(ctx, LOG_INFO, args)
#define pr_debug(ctx, args...) fastd_logf(ctx, LOG_DEBUG, args)

#define pr_warn_errno(ctx, message) pr_warn(ctx, "%s: %s", message, strerror(errno))
#define pr_error_errno(ctx, message) pr_warn(ctx, "%s: %s", message, strerror(errno))
#define exit_fatal(ctx, args...) do { pr_fatal(ctx, args); abort(); } while(0)
#define exit_bug(ctx, message) exit_fatal(ctx, "BUG: %s", message)
#define exit_error(ctx, args...) do { pr_error(ctx, args); exit(1); } while(0)
#define exit_errno(ctx, message) exit_error(ctx, "%s: %s", message, strerror(errno))


#define container_of(ptr, type, member) ({                      \
        const typeof( ((type *)0)->member ) *__mptr = (ptr);    \
        (type *)( (char *)__mptr - offsetof(type,member) );})


static inline size_t alignto(size_t l, size_t a) {
	return ((l+a-1)/a)*a;
}

static inline fastd_buffer fastd_buffer_alloc(size_t len, size_t head_space, size_t tail_space) {
	size_t base_len = head_space+len+tail_space;
	void *ptr;
	if (posix_memalign(&ptr, 16, base_len))
		return (fastd_buffer){ .base = NULL, .base_len = 0, .data = NULL, .len = 0 };

	return (fastd_buffer){ .base = ptr, .base_len = base_len, .data = ptr+head_space, .len = len };
}

static inline void fastd_buffer_free(fastd_buffer buffer) {
	free(buffer.base);
}

static inline void fastd_buffer_pull_head(fastd_buffer *buffer, size_t len) {
	buffer->data -= len;
	buffer->len += len;

	if (buffer->data < buffer->base)
		abort();
}

static inline void fastd_buffer_push_head(fastd_buffer *buffer, size_t len) {
	if (buffer->len < len)
		abort();

	buffer->data += len;
	buffer->len -= len;
}

static inline size_t fastd_max_packet_size(const fastd_context *ctx) {
	switch (ctx->conf->mode) {
	case MODE_TAP:
		return ctx->conf->mtu+ETH_HLEN;
	case MODE_TUN:
		return ctx->conf->mtu;
	default:
		exit_bug(ctx, "invalid mode");
	}
}

static inline fastd_string_stack* fastd_string_stack_dup(const char *str) {
	fastd_string_stack *ret = malloc(sizeof(fastd_string_stack) + strlen(str) + 1);
	ret->next = NULL;
	strcpy(ret->str, str);

	return ret;
}

static inline fastd_string_stack* fastd_string_stack_dupn(const char *str, size_t len) {
	size_t str_len = strnlen(str, len);
	fastd_string_stack *ret = malloc(sizeof(fastd_string_stack) + str_len + 1);
	ret->next = NULL;
	strncpy(ret->str, str, str_len);
	ret->str[str_len] = 0;

	return ret;
}

static inline fastd_string_stack* fastd_string_stack_push(fastd_string_stack *stack, const char *str) {
	fastd_string_stack *ret = malloc(sizeof(fastd_string_stack) + strlen(str) + 1);
	ret->next = stack;
	strcpy(ret->str, str);

	return ret;
}

static inline void fastd_string_stack_free(fastd_string_stack *str) {
	while(str) {
		fastd_string_stack *next = str->next;
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

#endif /* _FASTD_FASTD_H_ */
