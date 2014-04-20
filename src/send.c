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


#include "fastd.h"
#include "peer.h"


static inline void add_pktinfo(struct msghdr *msg, const fastd_peer_address_t *local_addr) {
	if (!local_addr)
		return;

	struct cmsghdr *cmsg = (struct cmsghdr*)((char*)msg->msg_control + msg->msg_controllen);

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

static inline void count_stat(fastd_stats_t *stats, size_t stat_size) {
	if (stat_size) {
		stats->packets++;
		stats->bytes += stat_size;
	}
}

static void send_type(const fastd_socket_t *sock, const fastd_peer_address_t *local_addr, const fastd_peer_address_t *remote_addr, fastd_peer_t *peer, uint8_t packet_type, fastd_buffer_t buffer, size_t stat_size) {
	if (!sock)
		exit_bug("send: sock == NULL");

	struct msghdr msg = {};
	uint8_t cbuf[1024] __attribute__((aligned(8))) = {};
	fastd_peer_address_t remote_addr6;

	switch (remote_addr->sa.sa_family) {
	case AF_INET:
		msg.msg_name = (void*)&remote_addr->in;
		msg.msg_namelen = sizeof(struct sockaddr_in);
		break;

	case AF_INET6:
		msg.msg_name = (void*)&remote_addr->in6;
		msg.msg_namelen = sizeof(struct sockaddr_in6);
		break;

	default:
		exit_bug("unsupported address family");
	}

	if (sock->bound_addr->sa.sa_family == AF_INET6) {
		remote_addr6 = *remote_addr;
		fastd_peer_address_widen(&remote_addr6);

		msg.msg_name = (void*)&remote_addr6.in6;
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

	int ret;
	do {
		ret = sendmsg(sock->fd, &msg, 0);
	} while (ret < 0 && errno == EINTR);

	if (ret < 0 && errno == EINVAL && msg.msg_controllen) {
		pr_debug2("sendmsg failed, trying again without pktinfo");

		if (peer && !fastd_peer_handshake_scheduled(peer))
			fastd_peer_schedule_handshake_default(peer);

		msg.msg_control = NULL;
		msg.msg_controllen = 0;

		do {
			ret = sendmsg(sock->fd, &msg, 0);
		} while (ret < 0 && errno == EINTR);

	}

	if (ret < 0) {
		switch (errno) {
		case EAGAIN:
#if EAGAIN != EWOULDBLOCK
		case EWOULDBLOCK:
#endif
			pr_debug2_errno("sendmsg");
			count_stat(&ctx.tx_dropped, stat_size);
			break;

		case ENETDOWN:
		case ENETUNREACH:
		case EHOSTUNREACH:
			pr_debug_errno("sendmsg");
			count_stat(&ctx.tx_error, stat_size);
			break;

		default:
			pr_warn_errno("sendmsg");
			count_stat(&ctx.tx_error, stat_size);
		}
	}
	else {
		count_stat(&ctx.tx, stat_size);
	}

	fastd_buffer_free(buffer);
}

void fastd_send(const fastd_socket_t *sock, const fastd_peer_address_t *local_addr, const fastd_peer_address_t *remote_addr, fastd_peer_t *peer, fastd_buffer_t buffer, size_t stat_size) {
	send_type(sock, local_addr, remote_addr, peer, PACKET_DATA, buffer, stat_size);
}

void fastd_send_handshake(const fastd_socket_t *sock, const fastd_peer_address_t *local_addr, const fastd_peer_address_t *remote_addr, fastd_peer_t *peer, fastd_buffer_t buffer) {
	send_type(sock, local_addr, remote_addr, peer, PACKET_HANDSHAKE, buffer, 0);
}

void fastd_send_all(fastd_peer_t *source_peer, fastd_buffer_t buffer) {
	size_t i;
	for (i = 0; i < VECTOR_LEN(ctx.peers); i++) {
		fastd_peer_t *dest_peer = VECTOR_INDEX(ctx.peers, i);
		if (dest_peer == source_peer || !fastd_peer_is_established(dest_peer))
			continue;

		/* optimization, primarily for TUN mode: don't duplicate the buffer for the last (or only) peer */
		if (i == VECTOR_LEN(ctx.peers)-1) {
			conf.protocol->send(dest_peer, buffer);
			return;
		}

		conf.protocol->send(dest_peer, fastd_buffer_dup(buffer, conf.min_encrypt_head_space, conf.min_encrypt_tail_space));
	}

	fastd_buffer_free(buffer);
}
