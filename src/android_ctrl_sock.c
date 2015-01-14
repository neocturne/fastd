/***************************************************************************
 * libancillary - black magic on Unix domain sockets
 * (C) Nicolas George
 ***************************************************************************/

/*
 * fastd Android port
 * Copyright (c) 2014-2015, Haofeng "Rick" Lei <ricklei@gmail.com>
 * All rights reserved.
 */

/*
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *  1. Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *  2. Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *  3. The name of the author may not be used to endorse or promote products
 *     derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO
 * EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/* libancillary code from:
 *   http://www.normalesup.org/~george/comp/libancillary/
 * with minor indent/style adjusts to fit fastd project
 */
/* vim: set noexpandtab ts=8 sw=8 sts=8 */

/**
   \file

   Android specific methods for communicating with GUI
*/

#ifdef __ANDROID__

#include "fastd.h"

#include <sys/un.h>


/** declare a work buffer for sending/receiving \e n handles */
#define ANCIL_FD_BUFFER(n) \
	struct { \
		struct cmsghdr h; \
		int fd[n]; \
	}

/** receive \e n_fds handles from unix domain socket \e sock and store in \e fds  */
static int ancil_recv_fds_with_buffer(int sock, int *fds, unsigned n_fds, void *buffer) {
	struct msghdr msghdr;
	char nothing;
	struct iovec nothing_ptr;
	struct cmsghdr *cmsg;
	int i;

	nothing_ptr.iov_base = &nothing;
	nothing_ptr.iov_len = 1;
	msghdr.msg_name = NULL;
	msghdr.msg_namelen = 0;
	msghdr.msg_iov = &nothing_ptr;
	msghdr.msg_iovlen = 1;
	msghdr.msg_flags = 0;
	msghdr.msg_control = buffer;
	msghdr.msg_controllen = sizeof(struct cmsghdr) + sizeof(int) * n_fds;
	cmsg = CMSG_FIRSTHDR(&msghdr);
	cmsg->cmsg_len = msghdr.msg_controllen;
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	for (i = 0; i < n_fds; i++) {
		((int *)CMSG_DATA(cmsg))[i] = -1;
	}

	if (recvmsg(sock, &msghdr, 0) < 0) {
		return(-1);
	}
	for (i = 0; i < n_fds; i++) {
		fds[i] = ((int *)CMSG_DATA(cmsg))[i];
	}
	n_fds = (cmsg->cmsg_len - sizeof(struct cmsghdr)) / sizeof(int);
	return n_fds;
}

/** shortcut for receiving only one \e fd from \e sock */
static int ancil_recv_fd(int sock, int *fd) {
	ANCIL_FD_BUFFER(1) buffer;

	return ancil_recv_fds_with_buffer(sock, fd, 1, &buffer) == 1 ? 0 : -1;
}

/** send \e n_fds handles in \e fds to unix domain socket \e sock */
static int ancil_send_fds_with_buffer(int sock, const int *fds, unsigned n_fds, void *buffer) {
	struct msghdr msghdr;
	char nothing = '!';
	struct iovec nothing_ptr;
	struct cmsghdr *cmsg;
	int i;

	nothing_ptr.iov_base = &nothing;
	nothing_ptr.iov_len = 1;
	msghdr.msg_name = NULL;
	msghdr.msg_namelen = 0;
	msghdr.msg_iov = &nothing_ptr;
	msghdr.msg_iovlen = 1;
	msghdr.msg_flags = 0;
	msghdr.msg_control = buffer;
	msghdr.msg_controllen = sizeof(struct cmsghdr) + sizeof(int) * n_fds;
	cmsg = CMSG_FIRSTHDR(&msghdr);
	cmsg->cmsg_len = msghdr.msg_controllen;
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	for (i = 0; i < n_fds; i++) {
		((int *)CMSG_DATA(cmsg))[i] = fds[i];
	}
	return sendmsg(sock, &msghdr, 0) >= 0 ? 0 : -1;
}

/** shortcut for sending only one \e fd to \e sock */
static int ancil_send_fd(int sock, int fd)
{
	ANCIL_FD_BUFFER(1) buffer;

	return ancil_send_fds_with_buffer(sock, &fd, 1, &buffer);
}

/*
 * libancillary end
 */


/** name of unix domain socket for communication with Android FastdVpnService */
#define CTRL_SOCK_NAME "fastd_tun_sock"

/** message sent by Android FastdVpnService to indicate successful protection of socket */
#define PROTECT_OK 'X'

/** message sent by Android FastdVpnService when protecting socket failed */
#define PROTECT_ERROR 'E'

/** establish the unix domain socket with Android GUI */
static void init_ctrl_sock(void) {
	/* Must keep consistent with FastdVpnService */
	struct sockaddr_un addr;

	if ((ctx.android_ctrl_sock_fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
		exit_errno("could not create unix domain socket");
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	addr.sun_path[0] = 0;     /* Linux's abstract unix domain socket name */
	strncpy(addr.sun_path + 1, CTRL_SOCK_NAME, sizeof(addr.sun_path) - 2);
	int socklen = offsetof(struct sockaddr_un, sun_path) + strlen(CTRL_SOCK_NAME) + 1;

	if (connect(ctx.android_ctrl_sock_fd, (struct sockaddr*)&addr, socklen) == -1) {
		exit_errno("could not connect to Android LocalServerSocket");
	}
}

/** receive TUN fd from Android GUI; this is the only way to open TUN device on non-rooted Android */
int fastd_android_receive_tunfd(void) {
	init_ctrl_sock();

	int handle;
	if (ancil_recv_fd(ctx.android_ctrl_sock_fd, &handle)) {
		exit_errno("could not receive TUN handle from Android");
	} else {
		pr_debug("received fd: %u", handle);
	}

	return handle;
}

/** send fastd pid to Android GUI for later signal sending (HUP, TERM etc) */
void fastd_android_send_pid(void) {
	char pid[20];
	snprintf(pid, sizeof(pid), "%u", (unsigned)getpid());
	if (write(ctx.android_ctrl_sock_fd, pid, strlen(pid)) != strlen(pid)) {
		exit_errno("send pid");
	}
}

/** report \e fd to Android GUI to be protected (i.e. not to be routed via TUN) */
bool fastd_android_protect_socket(int fd) {
	if (!conf.android_integration) {
		/* rooted/non-GUI mode */
		return true;
	}

	pr_debug("sending fd to protect");
	if (ancil_send_fd(ctx.android_ctrl_sock_fd, fd) == -1) {
		exit_errno("could not send handle to Android for protecting");
	}

	char buf[20];
	if (read(ctx.android_ctrl_sock_fd, buf, sizeof(buf)) == -1) {
		exit_errno("read ack");
	}
	return buf[0] == PROTECT_OK;
}

#endif /* __ANDROID__ */

