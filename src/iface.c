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

   Management of the TUN/TAP interface
*/

#include "config.h"
#include "peer.h"
#include "poll.h"

#include <net/if.h>
#include <sys/ioctl.h>

#ifdef __linux__

#include <linux/if_tun.h>

#else

#ifndef __APPLE__
#include <net/if_tun.h>
#endif

#ifdef __FreeBSD__
#include <net/if_tap.h>
#endif

#endif


/** Defines if the platform uses an address family header on TUN interfaces */
#if defined(__linux__) || defined(__APPLE__)
static const bool multiaf_tun = false;
#else
static const bool multiaf_tun = true;
#endif


/** The actual interface type */
typedef enum fastd_iface_type {
	IFACE_TYPE_UNSPEC = 0,	/**< Unknown interface */
	IFACE_TYPE_TAP,		/**< TAP interface */
	IFACE_TYPE_TUN,		/**< TUN interface */
} fastd_iface_type_t;

/** Returns the interface type for the configured mode of operation */
static inline fastd_iface_type_t get_iface_type(void) {
	switch (conf.mode) {
	case MODE_TAP:
	case MODE_MULTITAP:
		return IFACE_TYPE_TAP;

	case MODE_TUN:
		return IFACE_TYPE_TUN;

	default:
		return IFACE_TYPE_UNSPEC;
	}
}

static void open_iface(fastd_iface_t *iface, const char *ifname);


#ifdef __linux__

/** Opens the TUN/TAP device helper shared by Android and Linux targets */
static void open_iface_linux(fastd_iface_t *iface, const char *ifname, const char *dev_name) {
	int ctl_sock = -1;
	struct ifreq ifr = {};

	iface->fd = FASTD_POLL_FD(POLL_TYPE_IFACE, open(dev_name, O_RDWR|O_NONBLOCK));
	if (iface->fd.fd < 0)
		exit_errno("could not open TUN/TAP device file");

	if (ifname)
		strncpy(ifr.ifr_name, ifname, IFNAMSIZ-1);

	switch (get_iface_type()) {
	case IFACE_TYPE_TAP:
		ifr.ifr_flags = IFF_TAP;
		break;

	case IFACE_TYPE_TUN:
		ifr.ifr_flags = IFF_TUN;
		break;

	default:
		exit_bug("invalid mode");
	}

	ifr.ifr_flags |= IFF_NO_PI;
	if (ioctl(iface->fd.fd, TUNSETIFF, &ifr) < 0) {
		pr_error_errno("unable to open TUN/TAP interface: TUNSETIFF ioctl failed");
		goto error;
	}

	iface->name = fastd_strndup(ifr.ifr_name, IFNAMSIZ-1);

	ctl_sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (ctl_sock < 0)
		exit_errno("socket");

	if (ioctl(ctl_sock, SIOCGIFMTU, &ifr) < 0)
		exit_errno("SIOCGIFMTU ioctl failed");

	if (ifr.ifr_mtu != conf.mtu) {
		ifr.ifr_mtu = conf.mtu;
		if (ioctl(ctl_sock, SIOCSIFMTU, &ifr) < 0) {
			pr_error_errno("unable to set TUN/TAP interface MTU: SIOCSIFMTU ioctl failed");
			goto error;
		}
	}

	if (close(ctl_sock))
		pr_error_errno("close");

	return;

  error:
	if (ctl_sock >= 0) {
		if (close(ctl_sock))
			pr_error_errno("close");
	}

	close(iface->fd.fd);
	iface->fd.fd = -1;
}

#endif

#if defined(__ANDROID__)

/** Opens the TUN/TAP device */
static void open_iface(fastd_iface_t *iface, const char *ifname) {
	if (conf.android_integration) {
		if (get_iface_type() != IFACE_TYPE_TUN)
			exit_bug("Non-TUN iface type with Android integration");

		pr_debug("using android TUN fd");
		iface->fd = FASTD_POLL_FD(POLL_TYPE_IFACE, fastd_android_receive_tunfd());
		iface->name = NULL;

		fastd_android_send_pid();
	} else {
		/* this requires root on Android */
		open_iface_linux(iface, ifname, "/dev/tun");
	}
}

#elif defined(__linux__)

/** Opens the TUN/TAP device */
static void open_iface(fastd_iface_t *iface, const char *ifname) {
	open_iface_linux(iface, ifname, "/dev/net/tun");
}

#elif defined(__FreeBSD__) || defined(__OpenBSD__)

/** Sets the MTU of the TUN/TAP device */
static void set_tun_mtu(fastd_iface_t *iface) {
	struct tuninfo tuninfo;

	if (ioctl(iface->fd.fd, TUNGIFINFO, &tuninfo) < 0)
		exit_errno("TUNGIFINFO ioctl failed");

	tuninfo.mtu = conf.mtu;

	if (ioctl(iface->fd.fd, TUNSIFINFO, &tuninfo) < 0)
		exit_errno("TUNSIFINFO ioctl failed");
}


#ifdef __FreeBSD__

/** Sets the MTU of the TAP device */
static void set_tap_mtu(fastd_iface_t *iface) {
	struct tapinfo tapinfo;

	if (ioctl(iface->fd.fd, TAPGIFINFO, &tapinfo) < 0)
		exit_errno("TAPGIFINFO ioctl failed");

	tapinfo.mtu = conf.mtu;

	if (ioctl(iface->fd.fd, TAPSIFINFO, &tapinfo) < 0)
		exit_errno("TAPSIFINFO ioctl failed");
}

/** Sets up the TUN device */
static void setup_tun(fastd_iface_t *iface) {
	int one = 1;
	if (ioctl(iface->fd.fd, TUNSIFHEAD, &one) < 0)
		exit_errno("TUNSIFHEAD ioctl failed");

	set_tun_mtu(iface);
}

/** Sets up the TAP device */
static void setup_tap(fastd_iface_t *iface) {
	struct ifreq ifr = {};

	if (ioctl(iface->fd.fd, TAPGIFNAME, &ifr) < 0)
		exit_errno("TAPGIFNAME ioctl failed");

	free(iface->name);
	iface->name = fastd_strndup(ifr.ifr_name, IFNAMSIZ-1);

	set_tap_mtu(iface);
}

/** Opens the TUN/TAP device */
static void open_iface(fastd_iface_t *iface, const char *ifname) {
	char dev_name[5+IFNAMSIZ] = "/dev/";
	const char *type;

	switch (get_iface_type()) {
	case IFACE_TYPE_TAP:
		type = "tap";
		break;

	case IFACE_TYPE_TUN:
		type = "tun";
		break;

	default:
		exit_bug("invalid mode");
	}

	if (ifname) {
		if (strncmp(ifname, type, 3) != 0)
			exit_error("`%s' doesn't seem to be a %s device", ifname, type);

		strncat(dev_name, ifname, IFNAMSIZ-1);
	}
	else {
		strncat(dev_name, type, IFNAMSIZ-1);
	}

	iface->fd = FASTD_POLL_FD(POLL_TYPE_IFACE, open(dev_name, O_RDWR|O_NONBLOCK));
	if (iface->fd.fd < 0)
		exit_errno("could not open TUN/TAP device file");

	if (!(iface->name = fdevname_r(iface->fd.fd, fastd_alloc(IFNAMSIZ), IFNAMSIZ)))
		exit_errno("could not get TUN/TAP interface name");

	switch (get_iface_type()) {
	case IFACE_TYPE_TAP:
		setup_tap(iface);
		break;

	case IFACE_TYPE_TUN:
		setup_tun(iface);
		break;

	default:
		exit_bug("invalid mode");
	}
}

#else /* __OpenBSD__ */

static void set_link0(fastd_iface_t *iface, bool set) {
	struct ifreq ifr = {};

	int ctl_sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (ctl_sock < 0)
		exit_errno("socket");

	strncpy(ifr.ifr_name, iface->name, IFNAMSIZ-1);
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
static void setup_tun(fastd_iface_t *iface) {
	set_link0(iface, false);
	set_tun_mtu(iface);
}

/** Sets up the TAP device */
static void setup_tap(fastd_iface_t *iface) {
	set_link0(iface, true);
	set_tun_mtu(iface);
}

/** Opens the TUN/TAP device */
static void open_iface(fastd_iface_t *iface, const char *ifname) {
	char dev_name[5+IFNAMSIZ] = "/dev/";
	if (!ifname)
		exit_error("config error: no interface name given.");
	else if (strncmp(ifname, "tun", 3) != 0)
		exit_error("config error: `%s' doesn't seem to be a tun device", ifname);
	else
		strncat(dev_name, ifname, IFNAMSIZ-1);

	iface->fd = FASTD_POLL_FD(POLL_TYPE_IFACE, open(dev_name, O_RDWR|O_NONBLOCK));
	if (iface->fd.fd < 0)
		exit_errno("could not open tun device file");

	iface->name = fastd_strndup(ifname, IFNAMSIZ-1);

	switch (get_iface_type()) {
	case IFACE_TYPE_TAP:
		setup_tap(iface);
		break;

	case IFACE_TYPE_TUN:
		setup_tun(iface);
		break;

	default:
		exit_bug("invalid mode");
	}
}

#endif

#elif __APPLE__

/** Opens the TUN/TAP device */
static void open_iface(fastd_iface_t *iface, const char *ifname) {
	const char *devtype;
	switch (get_iface_type()) {
	case IFACE_TYPE_TAP:
		devtype = "tap";
		break;

	case IFACE_TYPE_TUN:
		devtype = "tun";
		break;

	default:
		exit_bug("invalid mode");
	}

	char dev_name[5+IFNAMSIZ] = "/dev/";
	if (!ifname)
		exit_error("config error: no interface name given.");
	else if (strncmp(ifname, devtype, 3) != 0)
		exit_error("config error: `%s' doesn't seem to be a %s device", ifname, devtype);
	else
		strncat(dev_name, ifname, IFNAMSIZ-1);

	iface->fd = FASTD_POLL_FD(POLL_TYPE_IFACE, open(dev_name, O_RDWR|O_NONBLOCK));
	if (iface->fd.fd < 0)
		exit_errno("could not open tun device file");

	iface->name = fastd_strndup(ifname, IFNAMSIZ-1);

	int ctl_sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (ctl_sock < 0)
		exit_errno("socket");

	struct ifreq ifr = {};
	strncpy(ifr.ifr_name, ifname, IFNAMSIZ-1);
	ifr.ifr_mtu = conf.mtu;
	if (ioctl(ctl_sock, SIOCSIFMTU, &ifr) < 0)
		exit_errno("SIOCSIFMTU ioctl failed");

	if (close(ctl_sock))
		pr_error_errno("close");
}

#else

#error unknown TUN/TAP implementation

#endif


/** Reads a packet from the TUN/TAP device */
void fastd_iface_handle(fastd_iface_t *iface) {
	size_t max_len = fastd_max_payload();

	fastd_buffer_t buffer;
	if (multiaf_tun && get_iface_type() == IFACE_TYPE_TUN)
		buffer = fastd_buffer_alloc(max_len+4, conf.min_encrypt_head_space+12, conf.min_encrypt_tail_space);
	else
		buffer = fastd_buffer_alloc(max_len, conf.min_encrypt_head_space, conf.min_encrypt_tail_space);

	ssize_t len = read(iface->fd.fd, buffer.data, max_len);
	if (len < 0)
		exit_errno("read");

	buffer.len = len;

	if (multiaf_tun && get_iface_type() == IFACE_TYPE_TUN)
		fastd_buffer_push_head(&buffer, 4);

	fastd_send_data(buffer, NULL, iface->peer);
}

/** Writes a packet to the TUN/TAP device */
void fastd_iface_write(fastd_iface_t *iface, fastd_buffer_t buffer) {
	if (!buffer.len) {
		pr_debug("fastd_iface_write: truncated packet");
		return;
	}

	if (multiaf_tun && get_iface_type() == IFACE_TYPE_TUN) {
		uint8_t version = *((uint8_t *)buffer.data) >> 4;
		uint32_t af;

		switch (version) {
		case 4:
			af = htonl(AF_INET);
			break;

		case 6:
			af = htonl(AF_INET6);
			break;

		default:
			pr_debug("fastd_iface_write: unknown IP version %u", version);
			return;
		}

		fastd_buffer_pull_head(&buffer, 4);
		memcpy(buffer.data, &af, 4);
	}

	if (write(iface->fd.fd, buffer.data, buffer.len) < 0)
		pr_debug2_errno("write");
}

/** Opens a new TUN/TAP interface, optionally associated with a specific peer */
fastd_iface_t * fastd_iface_open(fastd_peer_t *peer) {
	const char *ifname = conf.ifname;
	char ifnamebuf[IFNAMSIZ];

	if (peer) {
		if (peer->ifname)
			ifname = peer->ifname;
		else if (!fastd_config_single_iface() && !(ifname && strchr(ifname, '%')))
			ifname = NULL;
	}

	const char *percent = ifname ? strchr(ifname, '%') : NULL;
	if (percent) {
		if (peer) {
			char prefix[percent - ifname + 1];
			memcpy(prefix, ifname, percent - ifname);
			prefix[percent - ifname] = 0;

			ifname = NULL;

			switch (percent[1]) {
			case 'n':
				if (peer->name) {
					snprintf(ifnamebuf, sizeof(ifnamebuf), "%s%s%s", prefix, peer->name, percent+2);
					ifname = ifnamebuf;
				}

				break;

			case 'k':
			{
				char buf[17];
				if (conf.protocol->describe_peer(peer, buf, sizeof(buf))) {
					snprintf(ifnamebuf, sizeof(ifnamebuf), "%s%s%s", prefix, buf, percent+2);
					ifname = ifnamebuf;
				}
			}
				break;

			default:
				exit_bug("fastd_iface_open: invalid interface pattern");
			}
		}
		else {
			pr_error("Invalid TUN/TAP device name: `%%n' and `%%k' patterns can't be used in TAP mode");
			return NULL;
		}
	}

	fastd_iface_t *iface = fastd_new(fastd_iface_t);
	iface->peer = peer;

	pr_debug("initializing TUN/TAP device...");
	open_iface(iface, ifname);

	if (iface->fd.fd < 0) {
		free(iface);
		return NULL;
	}

	if (iface->name)
		pr_debug("TUN/TAP device `%s' initialized.", iface->name);
	else
		pr_debug("TUN/TAP device initialized.");

	fastd_poll_fd_register(&iface->fd);

	return iface;
}

/** Closes the TUN/TAP device */
void fastd_iface_close(fastd_iface_t *iface) {
	if (!fastd_poll_fd_close(&iface->fd))
		pr_warn_errno("closing TUN/TAP: close");

	free(iface->name);
	free(iface);
}
