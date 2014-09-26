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
   \file

   Functions for receiving and handling packets
*/


#include "fastd.h"
#include "handshake.h"
#include "peer.h"
#include "peer_hashtable.h"

#include <sys/uio.h>


/** Handles the ancillary control messages of received packets */
static inline void handle_socket_control(struct msghdr *message, const fastd_socket_t *sock, fastd_peer_address_t *local_addr) {
	memset(local_addr, 0, sizeof(fastd_peer_address_t));

	const uint8_t *end = (const uint8_t *)message->msg_control + message->msg_controllen;

	struct cmsghdr *cmsg;
	for (cmsg = CMSG_FIRSTHDR(message); cmsg; cmsg = CMSG_NXTHDR(message, cmsg)) {
		if ((const uint8_t *)cmsg + sizeof(*cmsg) > end)
			return;

#ifdef USE_PKTINFO
		if (cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_PKTINFO) {
			struct in_pktinfo pktinfo;

			if ((const uint8_t *)CMSG_DATA(cmsg) + sizeof(pktinfo) > end)
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

			if ((uint8_t *)CMSG_DATA(cmsg) + sizeof(pktinfo) > end)
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

/**
   Checks if a handshake should be sent after an unexpected payload packet has been received

   backoff_unknown() tries to avoid flooding hosts with handshakes.
*/
static bool backoff_unknown(const fastd_peer_address_t *addr) {
	size_t i;
	for (i = 0; i < array_size(ctx.unknown_handshakes); i++) {
		const fastd_handshake_timeout_t *t = &ctx.unknown_handshakes[(ctx.unknown_handshake_pos + i) % array_size(ctx.unknown_handshakes)];

		if (fastd_timed_out(t->timeout))
			break;

		if (fastd_peer_address_equal(addr, &t->address)) {
			pr_debug2("sent a handshake to unknown address %I a short time ago, not sending again", addr);
			return true;
		}
	}

	if (ctx.unknown_handshake_pos == 0)
		ctx.unknown_handshake_pos = array_size(ctx.unknown_handshakes)-1;
	else
		ctx.unknown_handshake_pos--;

	fastd_handshake_timeout_t *t = &ctx.unknown_handshakes[ctx.unknown_handshake_pos];

	t->address = *addr;
	t->timeout = ctx.now + MIN_HANDSHAKE_INTERVAL;

	return false;
}

/** Handles a packet received from a known peer address */
static inline void handle_socket_receive_known(fastd_socket_t *sock, const fastd_peer_address_t *local_addr, const fastd_peer_address_t *remote_addr, fastd_peer_t *peer, fastd_buffer_t buffer) {
	if (!fastd_peer_may_connect(peer)) {
		fastd_buffer_free(buffer);
		return;
	}

	const uint8_t *packet_type = buffer.data;
	fastd_buffer_push_head(&buffer, 1);

	switch (*packet_type) {
	case PACKET_DATA:
		if (!fastd_peer_is_established(peer) || !fastd_peer_address_equal(&peer->local_address, local_addr)) {
			fastd_buffer_free(buffer);

			if (!backoff_unknown(remote_addr)) {
				pr_debug("unexpectedly received payload data from %P[%I]", peer, remote_addr);
				conf.protocol->handshake_init(sock, local_addr, remote_addr, NULL);
			}
			return;
		}

		conf.protocol->handle_recv(peer, buffer);
		break;

	case PACKET_HANDSHAKE:
		fastd_handshake_handle(sock, local_addr, remote_addr, peer, buffer);
	}
}

/** Determines if packets from known addresses are accepted */
static inline bool allow_unknown_peers(void) {
	return ctx.has_floating || fastd_allow_verify();
}

/** Handles a packet received from an unknown address */
static inline void handle_socket_receive_unknown(fastd_socket_t *sock, const fastd_peer_address_t *local_addr, const fastd_peer_address_t *remote_addr, fastd_buffer_t buffer) {
	const uint8_t *packet_type = buffer.data;
	fastd_buffer_push_head(&buffer, 1);

	switch (*packet_type) {
	case PACKET_DATA:
		fastd_buffer_free(buffer);

		if (!backoff_unknown(remote_addr)) {
			pr_debug("unexpectedly received payload data from unknown address %I", remote_addr);
			conf.protocol->handshake_init(sock, local_addr, remote_addr, NULL);
		}
		break;

	case PACKET_HANDSHAKE:
		fastd_handshake_handle(sock, local_addr, remote_addr, NULL, buffer);
	}
}

/** Handles a packet read from a socket */
static inline void handle_socket_receive(fastd_socket_t *sock, const fastd_peer_address_t *local_addr, const fastd_peer_address_t *remote_addr, fastd_buffer_t buffer) {
	fastd_peer_t *peer = NULL;

	if (sock->peer) {
		if (!fastd_peer_address_equal(&sock->peer->address, remote_addr)) {
			fastd_buffer_free(buffer);
			return;
		}

		peer = sock->peer;
	}
	else {
		peer = fastd_peer_hashtable_lookup(remote_addr);
	}

	if (peer) {
		handle_socket_receive_known(sock, local_addr, remote_addr, peer, buffer);
	}
	else if (allow_unknown_peers()) {
		handle_socket_receive_unknown(sock, local_addr, remote_addr, buffer);
	}
	else  {
		pr_debug("received packet from unknown peer %I", remote_addr);
		fastd_buffer_free(buffer);
	}
}

/** Reads a packet from a socket */
void fastd_receive(fastd_socket_t *sock) {
	size_t max_len = 1 + fastd_max_payload() + conf.max_overhead;
	fastd_buffer_t buffer = fastd_buffer_alloc(max_len, conf.min_decrypt_head_space, conf.min_decrypt_tail_space);
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
		if (len < 0)
			pr_warn_errno("recvmsg");

		fastd_buffer_free(buffer);
		return;
	}

	buffer.len = len;

	handle_socket_control(&message, sock, &local_addr);

#ifdef USE_PKTINFO
	if (!local_addr.sa.sa_family) {
		pr_error("received packet without packet info");
		fastd_buffer_free(buffer);
		return;
	}
#endif

	fastd_peer_address_simplify(&recvaddr);

	handle_socket_receive(sock, &local_addr, &recvaddr, buffer);
}

/** Handles a received and decrypted payload packet */
void fastd_handle_receive(fastd_peer_t *peer, fastd_buffer_t buffer, bool reordered) {
	if (conf.mode == MODE_TAP) {
		if (buffer.len < ETH_HLEN) {
			pr_debug("received truncated packet");
			fastd_buffer_free(buffer);
			return;
		}

		fastd_eth_addr_t src_addr = fastd_buffer_source_address(buffer);

		if (fastd_eth_addr_is_unicast(src_addr))
			fastd_peer_eth_addr_add(peer, src_addr);
	}

	fastd_stats_add(peer, STAT_RX, buffer.len);

	if (reordered)
		fastd_stats_add(peer, STAT_RX_REORDERED, buffer.len);

	fastd_tuntap_write(buffer);

	if (conf.mode == MODE_TAP && conf.forward) {
		fastd_send_data(buffer, peer);
		return;
	}

	fastd_buffer_free(buffer);
}
