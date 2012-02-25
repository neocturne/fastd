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


#include <fcntl.h>
#include <linux/if_ether.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include "fastd.h"
#include "packet.h"


extern fastd_method fastd_method_null;


static int init_tuntap(const fastd_context *ctx) {
	int tunfd;
	struct ifreq ifr;

	pr_debug(ctx, "Initializing tun/tap device...");

	if ((tunfd = open("/dev/net/tun", O_RDWR)) < 0)
		exit_fatal_errno(ctx, "Could not open tun/tap device file");

	memset(&ifr, 0, sizeof(ifr));
	// strcpy(ifr.ifr_name, name);
	ifr.ifr_flags = IFF_TAP;
	ifr.ifr_flags |= IFF_NO_PI;
	if (ioctl(tunfd, TUNSETIFF, (void *)&ifr) < 0)
		exit_fatal_errno(ctx, "TUNSETIFF ioctl failed");

	return tunfd;
}

static void configure(fastd_context *ctx, fastd_config *conf) {
	conf->loglevel = LOG_DEBUG;
	conf->mtu = 1500;
	conf->protocol = PROTOCOL_ETHERNET;
	conf->method = &fastd_method_null;
	conf->n_peers = 0;
	conf->peers = NULL;
}

static size_t get_max_packet_size(const fastd_context *ctx) {
	switch (ctx->conf->protocol) {
	case PROTOCOL_ETHERNET:
		return ctx->conf->mtu+ETH_HLEN;
	case PROTOCOL_IP:
		return ctx->conf->mtu;
	default:
		exit_fatal_bug(ctx, "invalid protocol");
	}
}

static void *get_source_address(const fastd_context *ctx, void *buffer) {
	switch (ctx->conf->protocol) {
	case PROTOCOL_ETHERNET:
		return &((struct ethhdr*)buffer)->h_source;
	case PROTOCOL_IP:
		return NULL;
	default:
		exit_fatal_bug(ctx, "invalid protocol");
	}
}

static void *get_dest_address(const fastd_context *ctx, void *buffer) {
	switch (ctx->conf->protocol) {
	case PROTOCOL_ETHERNET:
		return &((struct ethhdr*)buffer)->h_dest;
	case PROTOCOL_IP:
		return NULL;
	default:
		exit_fatal_bug(ctx, "invalid protocol");
	}
}

static void run(const fastd_context *ctx) {
	int tunfd;

	tunfd = init_tuntap(ctx);

	struct pollfd fds[ctx->conf->n_peers+1];
	fds[0].fd = tunfd;
	fds[0].events = POLLIN;

	while (1) {
		int ret = poll(fds, 1, -1);
		if (ret < 0)
			exit_fatal_errno(ctx, "poll error");

		if (fds[0].revents & POLLIN) {
			size_t max_len = get_max_packet_size(ctx);
			char buffer[max_len];

			unsigned len = read(tunfd, buffer, max_len);
			if (len < 0)
				exit_fatal_errno(ctx, "read");

			uint8_t *src_addr = get_source_address(ctx, buffer);
			uint8_t *dest_addr = get_dest_address(ctx, buffer);

			pr_debug(ctx, "A packet with length %u was received from %02x:%02x:%02x:%02x:%02x:%02x to %02x:%02x:%02x:%02x:%02x:%02x",
				 len, src_addr[0], src_addr[1], src_addr[2], src_addr[3], src_addr[4], src_addr[5],
				 dest_addr[0], dest_addr[1], dest_addr[2], dest_addr[3], dest_addr[4], dest_addr[5]);

			ctx->conf->method->method_send(ctx, buffer, len);
		}
	}
}


int main()
{
	fastd_context ctx = {
		.conf = NULL,
	};

	fastd_config conf;
	configure(&ctx, &conf);
	ctx.conf = &conf;

	run(&ctx);

	return 0;
}
