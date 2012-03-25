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


#define _GNU_SOURCE

#include "fastd.h"
#include "peer.h"

#include <arpa/inet.h>

#include <libuecc/ecc.h>
#include <crypto_secretbox_xsalsa20poly1305.h>


typedef struct _protocol_context {
	ecc_secret_key_256 secret_key;
} protocol_context;

typedef struct _protocol_peer_config {
	ecc_public_key_256 public_key;
} protocol_peer_config;

typedef struct _protocol_peer_state {
} protocol_peer_state;


static bool protocol_check_config(fastd_context *ctx, const fastd_config *conf) {
	return true;
}

static void protocol_init(fastd_context *ctx) {
}

static size_t protocol_max_packet_size(fastd_context *ctx) {
	return (fastd_max_packet_size(ctx) - crypto_secretbox_xsalsa20poly1305_NONCEBYTES);
}

static char* protocol_peer_str(const fastd_context *ctx, const fastd_peer *peer) {
	char addr_buf[INET6_ADDRSTRLEN] = "";
	char *ret;

	const char *temp = fastd_peer_is_temporary(peer) ? " (temporary)" : "";

	switch (peer->address.sa.sa_family) {
	case AF_UNSPEC:
		if (asprintf(&ret, "<floating>%s", temp) > 0)
			return ret;
		break;

	case AF_INET:
		if (inet_ntop(AF_INET, &peer->address.in.sin_addr, addr_buf, sizeof(addr_buf))) {
			if (asprintf(&ret, "%s:%u%s", addr_buf, ntohs(peer->address.in.sin_port), temp) > 0)
				return ret;
		}
		break;

	case AF_INET6:
		if (inet_ntop(AF_INET6, &peer->address.in6.sin6_addr, addr_buf, sizeof(addr_buf))) {
			if (asprintf(&ret, "[%s]:%u%s", addr_buf, ntohs(peer->address.in6.sin6_port), temp) > 0)
				return ret;
		}
		break;

	default:
		exit_bug(ctx, "unsupported address family");
	}

	return NULL;
}

static void protocol_init_peer(fastd_context *ctx, fastd_peer *peer) {
	pr_info(ctx, "Initializing session with %P...", peer);
}

static void protocol_handle_recv(fastd_context *ctx, fastd_peer *peer, fastd_buffer buffer) {
	fastd_buffer_free(buffer);
}

static void protocol_send(fastd_context *ctx, fastd_peer *peer, fastd_buffer buffer) {
	fastd_buffer_free(buffer);
}

static void protocol_free_peer_private(fastd_context *ctx, fastd_peer *peer) {
}


const fastd_protocol fastd_protocol_ec25519_fhmqvc_xsalsa20_poly1305 = {
	.name = "ec25519-fhmqvc-xsalsa20-poly1305",

	.check_config = protocol_check_config,

	.init = protocol_init,

	.max_packet_size = protocol_max_packet_size,

	.peer_str = protocol_peer_str,

	.init_peer = protocol_init_peer,
	.handle_recv = protocol_handle_recv,
	.send = protocol_send,

	.free_peer_private = protocol_free_peer_private,
};
