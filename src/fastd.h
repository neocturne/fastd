/*
  Copyright (c) 2012, Matthias Schiffer <mschiffer@universe-factory.net>
  Partly based on QuickTun Copyright (c) 2010, Ivo Smits <Ivo@UCIS.nl>.
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

#include "queue.h"

#include <errno.h>
#include <linux/if_ether.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/uio.h>


typedef enum _fastd_loglevel {
	LOG_FATAL = 0,
	LOG_ERROR,
	LOG_WARN,
	LOG_INFO,
	LOG_DEBUG,
} fastd_loglevel;

typedef struct _fastd_buffer {
	void *base;
	size_t len;

	void (*free)(void *free_p);
	void *free_p;
} fastd_buffer;

typedef enum _fastd_protocol {
	PROTOCOL_ETHERNET,
	PROTOCOL_IP,
} fastd_protocol;

typedef struct _fastd_peer_config {
	struct _fastd_peer_config *next;

	in_addr_t address;
	in_port_t port;
} fastd_peer_config;

typedef enum _fastd_peer_state {
	STATE_WAIT,
	STATE_HANDSHAKE_SENT,
	STATE_ESTABLISHED,
} fastd_peer_state;

typedef struct _fastd_peer {
	struct _fastd_peer *next;

	const fastd_peer_config *config;

	in_addr_t address;
	in_port_t port;

	fastd_peer_state state;
	uint8_t last_req_id;

	void **addresses;
} fastd_peer;

typedef struct _fastd_context fastd_context;

typedef struct _fastd_method {
	const char *name;

	size_t (*method_max_packet_size)(fastd_context *ctx);

	void (*method_init)(fastd_context *ctx, const fastd_peer *peer);

	void (*method_handle_recv)(fastd_context *ctx, const fastd_peer *peer, fastd_buffer buffer);
	void (*method_send)(fastd_context *ctx, const fastd_peer *peer, fastd_buffer buffer);
} fastd_method;

typedef struct _fastd_config {
	fastd_loglevel loglevel;

	char *ifname;

	in_addr_t bind_address;
	in_port_t bind_port;

	uint16_t mtu;
	fastd_protocol protocol;

	fastd_method *method;

	fastd_peer_config *peers;
} fastd_config;

struct _fastd_context {
	const fastd_config *conf;

	fastd_peer *peers;
	fastd_queue task_queue;

	int tunfd;
	int sockfd;
};


#define pr_log(context, level, args...) if ((context)->conf == NULL || (level) <= (context)->conf->loglevel) do { fprintf(stderr, args); fputs("\n", stderr); } while(0)

#define pr_fatal(context, args...) pr_log(context, LOG_FATAL, args)
#define pr_error(context, args...) pr_log(context, LOG_ERROR, args)
#define pr_warn(context, args...) pr_log(context, LOG_WARN, args)
#define pr_info(context, args...) pr_log(context, LOG_INFO, args)
#define pr_debug(context, args...) pr_log(context, LOG_DEBUG, args)

#define exit_fatal(context, args...) do { pr_fatal(context, args); exit(1); } while(0)
#define exit_bug(context, message) exit_fatal(context, "BUG: %s", message)
#define exit_errno(context, message) exit_fatal(context, "%s: %s", message, strerror(errno))


static inline fastd_buffer fastd_buffer_alloc(size_t len, size_t head_space) {
	uint8_t *ptr = malloc(head_space+len);
	return (fastd_buffer){ .base = ptr, .len = len, .free = free, .free_p = ptr+head_space };
}

static inline void fastd_buffer_free(fastd_buffer buffer) {
	if (buffer.free) {
		buffer.free(buffer.free_p);
	}
}


static inline size_t fastd_max_packet_size(const fastd_context *ctx) {
	switch (ctx->conf->protocol) {
	case PROTOCOL_ETHERNET:
		return ctx->conf->mtu+ETH_HLEN;
	case PROTOCOL_IP:
		return ctx->conf->mtu;
	default:
		exit_bug(ctx, "invalid protocol");
	}
}

#endif /* _FASTD_FASTD_H_ */
