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

   Management of the TUN/TAP interface
*/

#include "fastd.h"
#include "poll.h"

#include <net/if.h>
#include <sys/ioctl.h>


#ifdef __linux__

#include <linux/if_tun.h>

#else

#include <net/if_tun.h>

#ifdef __FreeBSD__
#include <net/if_tap.h>
#endif

#endif


/** Defines if the platform uses an address family header on TUN interfaces */
#ifdef __linux__
static const bool multiaf_tun = false;
#else
static const bool multiaf_tun = true;
#endif


#if defined(__linux__)

/** Opens the TUN/TAP device */
void fastd_tuntap_open(void) {
	struct ifreq ifr = {};

	pr_debug("initializing tun/tap device...");

	if ((ctx.tunfd = open("/dev/net/tun", O_RDWR|O_NONBLOCK)) < 0)
		exit_errno("could not open tun/tap device file");

	if (conf.ifname)
		strncpy(ifr.ifr_name, conf.ifname, IFNAMSIZ-1);

	switch (conf.mode) {
	case MODE_TAP:
		ifr.ifr_flags = IFF_TAP;
		break;

	case MODE_TUN:
		ifr.ifr_flags = IFF_TUN;
		break;

	default:
		exit_bug("invalid mode");
	}

	ifr.ifr_flags |= IFF_NO_PI;
	if (ioctl(ctx.tunfd, TUNSETIFF, &ifr) < 0)
		exit_errno("TUNSETIFF ioctl failed");

	ctx.ifname = fastd_strndup(ifr.ifr_name, IFNAMSIZ-1);

	int ctl_sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (ctl_sock < 0)
		exit_errno("socket");

	if (ioctl(ctl_sock, SIOCGIFMTU, &ifr) < 0)
		exit_errno("SIOCGIFMTU ioctl failed");

	if (ifr.ifr_mtu != conf.mtu) {
		ifr.ifr_mtu = conf.mtu;
		if (ioctl(ctl_sock, SIOCSIFMTU, &ifr) < 0)
			exit_errno("SIOCSIFMTU ioctl failed");
	}

	if (close(ctl_sock))
		pr_error_errno("close");

	fastd_poll_set_fd_tuntap();

	pr_debug("tun/tap device initialized.");
}

#elif defined(__FreeBSD__) || defined(__OpenBSD__)

/** Sets the MTU of the TUN/TAP device */
static void set_tun_mtu(void) {
	struct tuninfo tuninfo;

	if (ioctl(ctx.tunfd, TUNGIFINFO, &tuninfo) < 0)
		exit_errno("TUNGIFINFO ioctl failed");

	tuninfo.mtu = conf.mtu;

	if (ioctl(ctx.tunfd, TUNSIFINFO, &tuninfo) < 0)
		exit_errno("TUNSIFINFO ioctl failed");
}


#ifdef __FreeBSD__

/** Sets the MTU of the TAP device */
static void set_tap_mtu(void) {
	struct tapinfo tapinfo;

	if (ioctl(ctx.tunfd, TAPGIFINFO, &tapinfo) < 0)
		exit_errno("TAPGIFINFO ioctl failed");

	tapinfo.mtu = conf.mtu;

	if (ioctl(ctx.tunfd, TAPSIFINFO, &tapinfo) < 0)
		exit_errno("TAPSIFINFO ioctl failed");
}

/** Sets up the TUN device */
static void setup_tun(void) {
	int one = 1;
	if (ioctl(ctx.tunfd, TUNSIFHEAD, &one) < 0)
		exit_errno("TUNSIFHEAD ioctl failed");

	set_tun_mtu();
}

/** Sets up the TAP device */
static void setup_tap(void) {
	struct ifreq ifr = {};

	if (ioctl(ctx.tunfd, TAPGIFNAME, &ifr) < 0)
		exit_errno("TAPGIFNAME ioctl failed");

	free(ctx.ifname);
	ctx.ifname = fastd_strndup(ifr.ifr_name, IFNAMSIZ-1);

	set_tap_mtu();
}

/** Opens the TUN/TAP device */
void fastd_tuntap_open(void) {
	pr_debug("initializing tun/tap device...");

	char ifname[5+IFNAMSIZ] = "/dev/";
	const char *type;

	switch (conf.mode) {
	case MODE_TAP:
		type = "tap";
		break;

	case MODE_TUN:
		type = "tun";
		break;

	default:
		exit_bug("invalid mode");
	}

	if (conf.ifname) {
		if (strncmp(conf.ifname, type, 3) != 0)
			exit_error("`%s' doesn't seem to be a %s device", conf.ifname, type);

		strncat(ifname, conf.ifname, IFNAMSIZ-1);
	}
	else {
		strncat(ifname, type, IFNAMSIZ-1);
	}

	if ((ctx.tunfd = open(ifname, O_RDWR|O_NONBLOCK)) < 0)
		exit_errno("could not open tun/tap device file");

	if (!(ctx.ifname = fdevname_r(ctx.tunfd, fastd_alloc(IFNAMSIZ), IFNAMSIZ)))
		exit_errno("could not get tun/tap interface name");

	switch (conf.mode) {
	case MODE_TAP:
		setup_tap();
		break;

	case MODE_TUN:
		setup_tun();
		break;

	default:
		exit_bug("invalid mode");
	}

	fastd_poll_set_fd_tuntap();

	pr_debug("tun/tap device initialized.");
}

#else /* __OpenBSD__ */

static void set_link0(bool set) {
	struct ifreq ifr = {};

	int ctl_sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (ctl_sock < 0)
		exit_errno("socket");

	strncpy(ifr.ifr_name, ctx.ifname, IFNAMSIZ-1);
	if (ioctl(ctl_sock, SIOCGIFFLAGS, &ifr) < 0)
		exit_errno("SIOCGIFFLAGS ioctl failed");

	if (set)
		ifr.ifr_flags |= IFF_LINK0;
	else
		ifr.ifr_flags &= ~IFF_LINK0;

	if (ioctl(ctl_sock, SIOCSIFFLAGS, &ifr) < 0)
		exit_errno("SIOCSIFFLAGS ioctl failed");

	if (close(ctl_sock))
		pr_error_errno("close");
}

/** Sets up the TUN device */
static void setup_tun(void) {
	set_link0(false);
	set_tun_mtu();
}

/** Sets up the TAP device */
static void setup_tap(void) {
	set_link0(true);
	set_tun_mtu();
}

/** Opens the TUN/TAP device */
void fastd_tuntap_open(void) {
	char ifname[5+IFNAMSIZ] = "/dev/";
	if (!conf.ifname)
		exit_error("config error: no interface name given.");
	else if (strncmp(conf.ifname, "tun", 3) != 0)
		exit_error("config error: `%s' doesn't seem to be a tun device", conf.ifname);
	else
		strncat(ifname, conf.ifname, IFNAMSIZ-1);

	pr_debug("initializing tun device...");

	if ((ctx.tunfd = open(ifname, O_RDWR|O_NONBLOCK)) < 0)
		exit_errno("could not open tun device file");

	ctx.ifname = fastd_strndup(conf.ifname, IFNAMSIZ-1);

	switch (conf.mode) {
	case MODE_TAP:
		setup_tap();
		break;

	case MODE_TUN:
		setup_tun();
		break;

	default:
		exit_bug("invalid mode");
	}

	fastd_poll_set_fd_tuntap();

	pr_debug("tun device initialized.");
}

#endif

#else

#error unknown tun/tap implementation

#endif


/** Reads a packet from the TUN/TAP device */
void fastd_tuntap_handle(void) {
	size_t max_len = fastd_max_payload();

	fastd_buffer_t buffer;
	if (multiaf_tun && conf.mode == MODE_TUN)
		buffer = fastd_buffer_alloc(max_len+4, conf.min_encrypt_head_space+12, conf.min_encrypt_tail_space);
	else
		buffer = fastd_buffer_alloc(max_len, conf.min_encrypt_head_space, conf.min_encrypt_tail_space);

	ssize_t len = read(ctx.tunfd, buffer.data, max_len);
	if (len < 0)
		exit_errno("read");

	buffer.len = len;

	if (multiaf_tun && conf.mode == MODE_TUN)
		fastd_buffer_push_head(&buffer, 4);

	fastd_send_data(buffer, NULL);
}

/** Writes a packet to the TUN/TAP device */
void fastd_tuntap_write(fastd_buffer_t buffer) {
	if (multiaf_tun && conf.mode == MODE_TUN) {
		uint8_t version = *((uint8_t*)buffer.data) >> 4;
		uint32_t af;

		switch (version) {
		case 4:
			af = htonl(AF_INET);
			break;

		case 6:
			af = htonl(AF_INET6);
			break;

		default:
			pr_warn("fastd_tuntap_write: unknown IP version %u", version);
			return;
		}

		fastd_buffer_pull_head(&buffer, 4);
		memcpy(buffer.data, &af, 4);
	}

	if (write(ctx.tunfd, buffer.data, buffer.len) < 0)
		pr_warn_errno("write");
}

/** Closes the TUN/TAP device */
void fastd_tuntap_close(void) {
	if (close(ctx.tunfd))
		pr_warn_errno("closing tun/tap: close");
}
