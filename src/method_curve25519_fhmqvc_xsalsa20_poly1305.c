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

#include <crypto_secretbox_xsalsa20poly1305.h>


static bool method_check_config(fastd_context *ctx, const fastd_config *conf) {
	return true;
}

static size_t method_max_packet_size(fastd_context *ctx) {
	return (fastd_max_packet_size(ctx) - crypto_secretbox_xsalsa20poly1305_NONCEBYTES);
}

static char* method_peer_str(const fastd_context *ctx, const fastd_peer *peer) {
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

static void method_init(fastd_context *ctx, fastd_peer *peer) {
}

static void method_handle_recv(fastd_context *ctx, fastd_peer *peer, fastd_buffer buffer) {
	fastd_buffer_free(buffer);
}

static void method_send(fastd_context *ctx, fastd_peer *peer, fastd_buffer buffer) {
	fastd_buffer_free(buffer);
}

const fastd_method fastd_method_curve25519_fhmqvc_xsalsa20_poly1305 = {
	.name = "curve25519-fhmqvc-xsalsa20-poly1305",

	.check_config = method_check_config,

	.max_packet_size = method_max_packet_size,

	.peer_str = method_peer_str,

	.init = method_init,
	.handle_recv = method_handle_recv,
	.send = method_send,
};
