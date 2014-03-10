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


#include "fastd.h"
#include "handshake.h"
#include "peer.h"


static inline void handle_socket_control(struct msghdr *message, const fastd_socket_t *sock, fastd_peer_address_t *local_addr) {
	memset(local_addr, 0, sizeof(fastd_peer_address_t));

	const uint8_t *end = (const uint8_t*)message->msg_control + message->msg_controllen;

	struct cmsghdr *cmsg;
	for (cmsg = CMSG_FIRSTHDR(message); cmsg; cmsg = CMSG_NXTHDR(message, cmsg)) {
		if ((const uint8_t*)cmsg + sizeof(*cmsg) > end)
			return;

#ifdef USE_PKTINFO
		if (cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_PKTINFO) {
			struct in_pktinfo pktinfo;

			if ((const uint8_t*)CMSG_DATA(cmsg) + sizeof(pktinfo) > end)
				return;

			memcpy(&pktinfo, CMSG_DATA(cmsg), sizeof(pktinfo));

			local_addr->in.sin_family = AF_INET;
			local_addr->in.sin_addr = pktinfo.ipi_addr;
			local_addr->in.sin_port = fastd_peer_address_get_port(sock->bound_addr);

			return;
		}
#endif

		if (cmsg->cmsg_level == IPPROTO_IPV6 && cmsg->cmsg_type == IPV6_PKTINFO) {
			struct in6_pktinfo pktinfo;

			if ((uint8_t*)CMSG_DATA(cmsg) + sizeof(pktinfo) > end)
				return;

			memcpy(&pktinfo, CMSG_DATA(cmsg), sizeof(pktinfo));

			local_addr->in6.sin6_family = AF_INET6;
			local_addr->in6.sin6_addr = pktinfo.ipi6_addr;
			local_addr->in6.sin6_port = fastd_peer_address_get_port(sock->bound_addr);

			if (IN6_IS_ADDR_LINKLOCAL(&local_addr->in6.sin6_addr))
				local_addr->in6.sin6_scope_id = pktinfo.ipi6_ifindex;

			return;
		}
	}
}

static bool backoff_unknown(fastd_context_t *ctx, const fastd_peer_address_t *addr) {
	size_t i;
	for (i = 0; i < array_size(ctx->unknown_handshakes); i++) {
		const fastd_handshake_timeout_t *t = &ctx->unknown_handshakes[(ctx->unknown_handshake_pos + i) % array_size(ctx->unknown_handshakes)];

		if (fastd_timed_out(ctx, &t->timeout))
			break;

		if (fastd_peer_address_equal(addr, &t->address)) {
			pr_debug2(ctx, "sent a handshake to unknown address %I a short time ago, not sending again", addr);
			return true;
		}
	}

	if (ctx->unknown_handshake_pos == 0)
		ctx->unknown_handshake_pos = array_size(ctx->unknown_handshakes)-1;
	else
		ctx->unknown_handshake_pos--;

	fastd_handshake_timeout_t *t = &ctx->unknown_handshakes[ctx->unknown_handshake_pos];

	t->address = *addr;
	t->timeout = fastd_in_seconds(ctx, ctx->conf->min_handshake_interval);

	return false;
}

static inline void handle_socket_receive_known(fastd_context_t *ctx, fastd_socket_t *sock, const fastd_peer_address_t *local_addr, const fastd_peer_address_t *remote_addr, fastd_peer_t *peer, fastd_buffer_t buffer) {
	if (!fastd_peer_may_connect(ctx, peer)) {
		fastd_buffer_free(buffer);
		return;
	}

	const uint8_t *packet_type = buffer.data;
	fastd_buffer_push_head(ctx, &buffer, 1);

	switch (*packet_type) {
	case PACKET_DATA:
		if (!fastd_peer_is_established(peer) || !fastd_peer_address_equal(&peer->local_address, local_addr)) {
			fastd_buffer_free(buffer);

			if (!backoff_unknown(ctx, remote_addr))
				ctx->conf->protocol->handshake_init(ctx, sock, local_addr, remote_addr, NULL);
			return;
		}

		ctx->conf->protocol->handle_recv(ctx, peer, buffer);
		break;

	case PACKET_HANDSHAKE:
		fastd_handshake_handle(ctx, sock, local_addr, remote_addr, peer, buffer);
	}
}

static inline bool allow_unknown_peers(fastd_context_t *ctx) {
	return ctx->conf->has_floating || ctx->conf->on_verify;
}

static inline void handle_socket_receive_unknown(fastd_context_t *ctx, fastd_socket_t *sock, const fastd_peer_address_t *local_addr, const fastd_peer_address_t *remote_addr, fastd_buffer_t buffer) {
	const uint8_t *packet_type = buffer.data;
	fastd_buffer_push_head(ctx, &buffer, 1);

	switch (*packet_type) {
	case PACKET_DATA:
		fastd_buffer_free(buffer);

		if (!backoff_unknown(ctx, remote_addr))
			ctx->conf->protocol->handshake_init(ctx, sock, local_addr, remote_addr, NULL);
		break;

	case PACKET_HANDSHAKE:
		fastd_handshake_handle(ctx, sock, local_addr, remote_addr, NULL, buffer);
	}
}

static inline void handle_socket_receive(fastd_context_t *ctx, fastd_socket_t *sock, const fastd_peer_address_t *local_addr, const fastd_peer_address_t *remote_addr, fastd_buffer_t buffer) {
	fastd_peer_t *peer = NULL;

	if (sock->peer) {
		if (!fastd_peer_address_equal(&sock->peer->address, remote_addr)) {
			fastd_buffer_free(buffer);
			return;
		}

		peer = sock->peer;
	}
	else {
		for (peer = ctx->peers; peer; peer = peer->next) {
			if (fastd_peer_address_equal(&peer->address, remote_addr))
				break;
		}
	}

	if (peer) {
		handle_socket_receive_known(ctx, sock, local_addr, remote_addr, peer, buffer);
	}
	else if (allow_unknown_peers(ctx)) {
		handle_socket_receive_unknown(ctx, sock, local_addr, remote_addr, buffer);
	}
	else  {
		pr_debug(ctx, "received packet from unknown peer %I", remote_addr);
		fastd_buffer_free(buffer);
	}
}

void fastd_receive(fastd_context_t *ctx, fastd_socket_t *sock) {
	size_t max_len = fastd_max_outer_packet(ctx);
	fastd_buffer_t buffer = fastd_buffer_alloc(ctx, max_len, ctx->conf->min_decrypt_head_space, ctx->conf->min_decrypt_tail_space);
	fastd_peer_address_t local_addr;
	fastd_peer_address_t recvaddr;
	struct iovec buffer_vec = { .iov_base = buffer.data, .iov_len = buffer.len };
	uint8_t cbuf[1024] __attribute__((aligned(8)));

	struct msghdr message = {
		.msg_name = &recvaddr,
		.msg_namelen = sizeof(recvaddr),
		.msg_iov = &buffer_vec,
		.msg_iovlen = 1,
		.msg_control = cbuf,
		.msg_controllen = sizeof(cbuf),
	};

	ssize_t len = recvmsg(sock->fd, &message, 0);
	if (len <= 0) {
		if (len < 0 && errno != EINTR)
			pr_warn_errno(ctx, "recvmsg");

		fastd_buffer_free(buffer);
		return;
	}

	buffer.len = len;

	handle_socket_control(&message, sock, &local_addr);

#ifdef USE_PKTINFO
	if (!local_addr.sa.sa_family) {
		pr_error(ctx, "received packet without packet info");
		fastd_buffer_free(buffer);
		return;
	}
#endif

	fastd_peer_address_simplify(&recvaddr);

	handle_socket_receive(ctx, sock, &local_addr, &recvaddr, buffer);
}
