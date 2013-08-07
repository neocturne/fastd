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

void fastd_tuntap_close(fastd_context_t *ctx) {
	if (close(ctx->tunfd))
		pr_warn_errno(ctx, "closing tun/tap: close");

	free(ctx->ifname);
}
