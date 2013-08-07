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

#include <fcntl.h>
#include <net/if.h>
#include <sys/ioctl.h>


#if defined(__linux__)

#include <linux/if_tun.h>

void fastd_tuntap_open(fastd_context_t *ctx) {
	struct ifreq ifr = {};

	pr_debug(ctx, "initializing tun/tap device...");

	if ((ctx->tunfd = open("/dev/net/tun", O_RDWR|O_CLOEXEC|O_NONBLOCK)) < 0)
		exit_errno(ctx, "could not open tun/tap device file");

	if (ctx->conf->ifname)
		strncpy(ifr.ifr_name, ctx->conf->ifname, IFNAMSIZ-1);

	switch (ctx->conf->mode) {
	case MODE_TAP:
		ifr.ifr_flags = IFF_TAP;
		break;

	case MODE_TUN:
		ifr.ifr_flags = IFF_TUN;
		break;

	default:
		exit_bug(ctx, "invalid mode");
	}

	ifr.ifr_flags |= IFF_NO_PI;
	if (ioctl(ctx->tunfd, TUNSETIFF, &ifr) < 0)
		exit_errno(ctx, "TUNSETIFF ioctl failed");

	ctx->ifname = strndup(ifr.ifr_name, IFNAMSIZ-1);

	int ctl_sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (ctl_sock < 0)
		exit_errno(ctx, "socket");

	if (ioctl(ctl_sock, SIOCGIFMTU, &ifr) < 0)
		exit_errno(ctx, "SIOCGIFMTU ioctl failed");

	if (ifr.ifr_mtu != ctx->conf->mtu) {
		ifr.ifr_mtu = ctx->conf->mtu;
		if (ioctl(ctl_sock, SIOCSIFMTU, &ifr) < 0)
			exit_errno(ctx, "SIOCSIFMTU ioctl failed");
	}

	if (close(ctl_sock))
		pr_error_errno(ctx, "close");

	pr_debug(ctx, "tun/tap device initialized.");
}

fastd_buffer_t fastd_tuntap_read(fastd_context_t *ctx) {
	size_t max_len = fastd_max_packet_size(ctx);
	fastd_buffer_t buffer = fastd_buffer_alloc(ctx, max_len, ctx->conf->min_encrypt_head_space, ctx->conf->min_encrypt_tail_space);

	ssize_t len = read(ctx->tunfd, buffer.data, max_len);
	if (len < 0) {
		if (errno == EINTR) {
			fastd_buffer_free(buffer);
			return (fastd_buffer_t){};
		}

		exit_errno(ctx, "read");
	}

	buffer.len = len;
	return buffer;
}

void fastd_tuntap_write(fastd_context_t *ctx, fastd_buffer_t buffer) {
	if (write(ctx->tunfd, buffer.data, buffer.len) < 0)
		pr_warn_errno(ctx, "write");
}

#elif defined(__FreeBSD__)

#include <net/if_tun.h>
#include <net/if_tap.h>

static void setup_tap(fastd_context_t *ctx) {
	struct ifreq ifr = {};

	if (ioctl(ctx->tunfd, TAPGIFNAME, &ifr) < 0)
		exit_errno(ctx, "TAPGIFNAME ioctl failed");

	free(ctx->ifname);
	ctx->ifname = strndup(ifr.ifr_name, IFNAMSIZ-1);
}

static void setup_tun(fastd_context_t *ctx) {
	int one = 1;
	if (ioctl(ctx->tunfd, TUNSIFHEAD, &one) < 0)
		exit_errno(ctx, "TUNSIFHEAD ioctl failed");
}

static void set_tap_mtu(fastd_context_t *ctx) {
	struct tapinfo tapinfo;

	if (ioctl(ctx->tunfd, TAPGIFINFO, &tapinfo) < 0)
		exit_errno(ctx, "TAPGIFINFO ioctl failed");

	tapinfo.mtu = ctx->conf->mtu;

	if (ioctl(ctx->tunfd, TAPSIFINFO, &tapinfo) < 0)
		exit_errno(ctx, "TAPSIFINFO ioctl failed");
}

static void set_tun_mtu(fastd_context_t *ctx) {
	struct tuninfo tuninfo;

	if (ioctl(ctx->tunfd, TUNGIFINFO, &tuninfo) < 0)
		exit_errno(ctx, "TUNGIFINFO ioctl failed");

	tuninfo.mtu = ctx->conf->mtu;

	if (ioctl(ctx->tunfd, TUNSIFINFO, &tuninfo) < 0)
		exit_errno(ctx, "TUNSIFINFO ioctl failed");
}

void fastd_tuntap_open(fastd_context_t *ctx) {
	pr_debug(ctx, "initializing tun/tap device...");

	char ifname[5+IFNAMSIZ] = "/dev/";
	if (ctx->conf->ifname) {
		strncat(ifname, ctx->conf->ifname, IFNAMSIZ-1);
	}
	else {
		switch (ctx->conf->mode) {
		case MODE_TAP:
			strncat(ifname, "tap", IFNAMSIZ-1);
			break;

		case MODE_TUN:
			strncat(ifname, "tun", IFNAMSIZ-1);
			break;

		default:
			exit_bug(ctx, "invalid mode");
		}
	}

	if ((ctx->tunfd = open(ifname, O_RDWR|O_CLOEXEC|O_NONBLOCK)) < 0)
		exit_errno(ctx, "could not open tun/tap device file");

	if (!(ctx->ifname = fdevname_r(ctx->tunfd, malloc(IFNAMSIZ), IFNAMSIZ)))
		exit_errno(ctx, "could not get tun/tap interface name");

	switch (ctx->conf->mode) {
	case MODE_TAP:
		if (strncmp(ctx->ifname, "tap", 3) != 0)
			exit_error(ctx, "opened device doesn't to be a tap device");

		setup_tap(ctx);
		set_tap_mtu(ctx);
		break;

	case MODE_TUN:
		if (strncmp(ctx->ifname, "tun", 3) != 0)
			exit_error(ctx, "opened device doesn't to be a tun device");

		setup_tun(ctx);
		set_tun_mtu(ctx);
		break;

	default:
		exit_bug(ctx, "invalid mode");
	}

	pr_debug(ctx, "tun/tap device initialized.");
}

fastd_buffer_t fastd_tuntap_read(fastd_context_t *ctx) {
	size_t max_len = fastd_max_packet_size(ctx);

	fastd_buffer_t buffer;
	if (ctx->conf->mode == MODE_TUN)
		buffer = fastd_buffer_alloc(ctx, max_len+4, ctx->conf->min_encrypt_head_space+12, ctx->conf->min_encrypt_tail_space);
	else
		buffer = fastd_buffer_alloc(ctx, max_len, ctx->conf->min_encrypt_head_space, ctx->conf->min_encrypt_tail_space);

	ssize_t len = read(ctx->tunfd, buffer.data, max_len);
	if (len < 0) {
		if (errno == EINTR) {
			fastd_buffer_free(buffer);
			return (fastd_buffer_t){};
		}

		exit_errno(ctx, "read");
	}

	buffer.len = len;

	if (ctx->conf->mode == MODE_TUN)
		fastd_buffer_push_head(ctx, &buffer, 4);

	return buffer;
}

void fastd_tuntap_write(fastd_context_t *ctx, fastd_buffer_t buffer) {
	if (ctx->conf->mode == MODE_TUN) {
		uint8_t version = *((uint8_t*)buffer.data) >> 4;
		int af;

		switch (version) {
		case 4:
			af = AF_INET;
			break;

		case 6:
			af = AF_INET6;
			break;

		default:
			pr_warn(ctx, "fastd_tuntap_write: unknown IP version %u", version);
			return;
		}

		fastd_buffer_pull_head(ctx, &buffer, 4);
		*((uint32_t*)buffer.data) = htonl(af);
	}

	if (write(ctx->tunfd, buffer.data, buffer.len) < 0)
		pr_warn_errno(ctx, "write");
}

#else

#error unknown tun/tap implementation

#endif


void fastd_tuntap_close(fastd_context_t *ctx) {
	if (close(ctx->tunfd))
		pr_warn_errno(ctx, "closing tun/tap: close");

	free(ctx->ifname);
}
