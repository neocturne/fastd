/*
  Copyright (c) 2012-2015, Matthias Schiffer <mschiffer@universe-factory.net>
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

   Functions for sending packets
*/


#include "fastd.h"
#include "peer.h"

#include <sys/uio.h>


/** Adds packet info to ancillary control messages */
static inline void add_pktinfo(struct msghdr *msg, const fastd_peer_address_t *local_addr) {
#ifdef __ANDROID__
	/* PKTINFO will mess with Android VpnService.protect(socket) */
	if (conf.android_integration)
		return;
#endif
	if (!local_addr)
		return;

	struct cmsghdr *cmsg = (struct cmsghdr *)((char *)msg->msg_control + msg->msg_controllen);

#ifdef USE_PKTINFO
	if (local_addr->sa.sa_family == AF_INET) {
		cmsg->cmsg_level = IPPROTO_IP;
		cmsg->cmsg_type = IP_PKTINFO;
		cmsg->cmsg_len = CMSG_LEN(sizeof(struct in_pktinfo));

		msg->msg_controllen += cmsg->cmsg_len;

		struct in_pktinfo pktinfo = {};
		pktinfo.ipi_spec_dst = local_addr->in.sin_addr;
		memcpy(CMSG_DATA(cmsg), &pktinfo, sizeof(pktinfo));
		return;
	}
#endif

	if (local_addr->sa.sa_family == AF_INET6) {
		cmsg->cmsg_level = IPPROTO_IPV6;
		cmsg->cmsg_type = IPV6_PKTINFO;
		cmsg->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));

		msg->msg_controllen += cmsg->cmsg_len;

		struct in6_pktinfo pktinfo = {};
		pktinfo.ipi6_addr = local_addr->in6.sin6_addr;

		if (IN6_IS_ADDR_LINKLOCAL(&local_addr->in6.sin6_addr))
			pktinfo.ipi6_ifindex = local_addr->in6.sin6_scope_id;

		memcpy(CMSG_DATA(cmsg), &pktinfo, sizeof(pktinfo));
	}
}

/** Sends a packet of a given type */
static void send_type(const fastd_socket_t *sock, const fastd_peer_address_t *local_addr, const fastd_peer_address_t *remote_addr, fastd_peer_t *peer, uint8_t packet_type, fastd_buffer_t buffer, size_t stat_size) {
	if (!sock)
		exit_bug("send: sock == NULL");

	struct msghdr msg = {};
	uint8_t cbuf[1024] __attribute__((aligned(8))) = {};
	fastd_peer_address_t remote_addr6;

	switch (remote_addr->sa.sa_family) {
	case AF_INET:
		msg.msg_name = (void *)&remote_addr->in;
		msg.msg_namelen = sizeof(struct sockaddr_in);
		break;

	case AF_INET6:
		msg.msg_name = (void *)&remote_addr->in6;
		msg.msg_namelen = sizeof(struct sockaddr_in6);
		break;

	default:
		exit_bug("unsupported address family");
	}

	if (sock->bound_addr->sa.sa_family == AF_INET6) {
		remote_addr6 = *remote_addr;
		fastd_peer_address_widen(&remote_addr6);

		msg.msg_name = (void *)&remote_addr6.in6;
		msg.msg_namelen = sizeof(struct sockaddr_in6);
	}

	struct iovec iov[2] = {
		{ .iov_base = &packet_type, .iov_len = 1 },
		{ .iov_base = buffer.data, .iov_len = buffer.len }
	};

	msg.msg_iov = iov;
	msg.msg_iovlen = buffer.len ? 2 : 1;
	msg.msg_control = cbuf;
	msg.msg_controllen = 0;

	add_pktinfo(&msg, local_addr);

	if (!msg.msg_controllen)
		msg.msg_control = NULL;

	int ret = sendmsg(sock->fd, &msg, 0);

	if (ret < 0 && errno == EINVAL && msg.msg_controllen) {
		pr_debug2("sendmsg failed, trying again without pktinfo");

		if (peer && !fastd_peer_handshake_scheduled(peer))
			fastd_peer_schedule_handshake_default(peer);

		msg.msg_control = NULL;
		msg.msg_controllen = 0;

		ret = sendmsg(sock->fd, &msg, 0);
	}

	if (ret < 0) {
		switch (errno) {
		case EAGAIN:
#if EAGAIN != EWOULDBLOCK
		case EWOULDBLOCK:
#endif
			pr_debug2_errno("sendmsg");
			fastd_stats_add(peer, STAT_TX_DROPPED, stat_size);
			break;

		case ENETDOWN:
		case ENETUNREACH:
		case EHOSTUNREACH:
			pr_debug_errno("sendmsg");
			fastd_stats_add(peer, STAT_TX_ERROR, stat_size);
			break;

		default:
			pr_warn_errno("sendmsg");
			fastd_stats_add(peer, STAT_TX_ERROR, stat_size);
		}
	}
	else {
		fastd_stats_add(peer, STAT_TX, stat_size);
	}

	fastd_buffer_free(buffer);
}

/** Sends a payload packet */
void fastd_send(const fastd_socket_t *sock, const fastd_peer_address_t *local_addr, const fastd_peer_address_t *remote_addr, fastd_peer_t *peer, fastd_buffer_t buffer, size_t stat_size) {
	send_type(sock, local_addr, remote_addr, peer, PACKET_DATA, buffer, stat_size);
}

/** Sends a handshake packet */
void fastd_send_handshake(const fastd_socket_t *sock, const fastd_peer_address_t *local_addr, const fastd_peer_address_t *remote_addr, fastd_peer_t *peer, fastd_buffer_t buffer) {
	send_type(sock, local_addr, remote_addr, peer, PACKET_HANDSHAKE, buffer, 0);
}

/** Encrypts and sends a payload packet to all peers */
static inline void send_all(fastd_buffer_t buffer, fastd_peer_t *source) {
	size_t i;
	for (i = 0; i < VECTOR_LEN(ctx.peers); i++) {
		fastd_peer_t *dest = VECTOR_INDEX(ctx.peers, i);
		if (dest == source || !fastd_peer_is_established(dest))
			continue;

		/* optimization, primarily for TUN mode: don't duplicate the buffer for the last (or only) peer */
		if (i == VECTOR_LEN(ctx.peers)-1) {
			conf.protocol->send(dest, buffer);
			return;
		}

		conf.protocol->send(dest, fastd_buffer_dup(buffer, conf.min_encrypt_head_space, conf.min_encrypt_tail_space));
	}

	fastd_buffer_free(buffer);
}

/** Handles sending of a payload packet to a single peer in TAP mode */
static inline bool send_data_tap_single(fastd_buffer_t buffer, fastd_peer_t *source) {
	if (conf.mode != MODE_TAP)
		return false;

	if (buffer.len < ETH_HLEN) {
		pr_debug("truncated ethernet packet");
		fastd_buffer_free(buffer);
		return true;
	}

	if (!source) {
		fastd_eth_addr_t src_addr = fastd_buffer_source_address(buffer);

		if (fastd_eth_addr_is_unicast(src_addr))
			fastd_peer_eth_addr_add(NULL, src_addr);
	}

	fastd_eth_addr_t dest_addr = fastd_buffer_dest_address(buffer);
	if (!fastd_eth_addr_is_unicast(dest_addr))
		return false;

	fastd_peer_t *dest;
	bool found = fastd_peer_find_by_eth_addr(dest_addr, &dest);

	if (!found)
		return false;

	if (!dest || dest == source) {
		fastd_buffer_free(buffer);
		return true;
	}

	conf.protocol->send(dest, buffer);
	return true;
}

/** Sends a buffer of payload data to other peers */
void fastd_send_data(fastd_buffer_t buffer, fastd_peer_t *source) {
	if (send_data_tap_single(buffer, source))
		return;

	/* TUN mode or multicast packet */
	send_all(buffer, source);
}
