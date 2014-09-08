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

   Status socket support
*/


#include "peer.h"


#ifdef WITH_STATUS_SOCKET

#include <sys/un.h>

#include <json.h>


/** Argument for dump_thread */
typedef struct dump_thread_arg {
	int fd;				/**< The file descriptor of an accepted socket connection */
	struct json_object *json;	/**< The JSON object to write to the status socket */
} dump_thread_arg_t;


/** Thread to write the status JSON to the status socket */
static void * dump_thread(void *p) {
	dump_thread_arg_t *arg = p;

	const char *str = json_object_to_json_string(arg->json);
	size_t left = strlen(str);

	while (left > 0) {
		ssize_t written = write(arg->fd, str, left);
		if (written < 0) {
			pr_error_errno("can't dump status: write");
			break;
		}

		left -= written;
		str += written;
	}

	close(arg->fd);
	json_object_put(arg->json);
	free(arg);

	return NULL;
}


/** Dumps a fastd_stats_t as a JSON object */
static json_object * dump_stats(const fastd_stats_t *stats) {
	struct json_object *ret = json_object_new_object();

	json_object_object_add(ret, "packets", json_object_new_int64(stats->packets));
	json_object_object_add(ret, "bytes", json_object_new_int64(stats->bytes));

	return ret;
}

/** Dumps a peer's status as a JSON object */
static json_object * dump_peer(const fastd_peer_t *peer) {
	struct json_object *ret = json_object_new_object();

	/* '[' + IPv6 addresss + '%' + interface + ']:' + port + NUL */
	char addr_buf[1 + INET6_ADDRSTRLEN + 2 + IFNAMSIZ + 1 + 5 + 1];
	fastd_snprint_peer_address(addr_buf, sizeof(addr_buf), &peer->address, NULL, false, false);

	json_object_object_add(ret, "address", json_object_new_string(addr_buf));

	struct json_object *connection = NULL;

	if (fastd_peer_is_established(peer)) {
		connection = json_object_new_object();

		if (conf.mode == MODE_TAP) {
			struct json_object *mac_addresses = json_object_new_array();
			json_object_object_add(connection, "mac_addresses", mac_addresses);

			size_t i;
			for (i = 0; i < VECTOR_LEN(ctx.eth_addrs); i++) {
				fastd_peer_eth_addr_t *addr = &VECTOR_INDEX(ctx.eth_addrs, i);

				if (addr->peer != peer)
					continue;

				const uint8_t *d = addr->addr.data;

				char eth_addr_buf[18];
				snprintf(eth_addr_buf, sizeof(eth_addr_buf),
					 "%02x:%02x:%02x:%02x:%02x:%02x",
					 d[0], d[1], d[2], d[3], d[4], d[5]);

				json_object_array_add(mac_addresses, json_object_new_string(eth_addr_buf));
			}
		}
	}

	json_object_object_add(ret, "connection", connection);

	return ret;
}

/** Dumps fastd's status to a connected socket */
static void dump_status(int fd) {
	struct json_object *json = json_object_new_object();

	struct json_object *statistics = json_object_new_object();
	json_object_object_add(json, "statistics", statistics);

	json_object_object_add(statistics, "rx", dump_stats(&ctx.rx));
	json_object_object_add(statistics, "rx_reordered", dump_stats(&ctx.rx_reordered));

	json_object_object_add(statistics, "tx", dump_stats(&ctx.tx));
	json_object_object_add(statistics, "tx_dropped", dump_stats(&ctx.tx_dropped));
	json_object_object_add(statistics, "tx_error", dump_stats(&ctx.tx_error));

	struct json_object *peers = json_object_new_object();
	json_object_object_add(json, "peers", peers);

	size_t i;
	for (i = 0; i < VECTOR_LEN(ctx.peers); i++) {
		fastd_peer_t *peer = VECTOR_INDEX(ctx.peers, i);

		if (!fastd_peer_is_enabled(peer))
			continue;

		json_object_object_add(peers, peer->name, dump_peer(peer));
	}


	dump_thread_arg_t *arg = fastd_new(dump_thread_arg_t);

	arg->json = json;
	arg->fd = fd;

	pthread_t thread;
	if ((errno = pthread_create(&thread, &ctx.detached_thread, dump_thread, arg)) != 0) {
		pr_error_errno("unable to create status dump thread");

		close(arg->fd);
		json_object_put(arg->json);
		free(arg);
	}
}

/** Initialized the status socket */
void fastd_status_init(void) {
	if (!conf.status_socket)
		return;

	uid_t uid = geteuid();
	gid_t gid = getegid();

	if (conf.user || conf.group) {
		if (setegid(conf.gid) < 0)
			pr_debug_errno("setegid");
		if (seteuid(conf.uid) < 0)
			pr_debug_errno("seteuid");
	}


	ctx.status_fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (ctx.status_fd < 0)
		exit_errno("fastd_status_init: socket");


	size_t len = offsetof(struct sockaddr_un, sun_path) + strlen(conf.status_socket) + 1;
	uint8_t buf[len];
	memset(buf, 0, len);

	struct sockaddr_un *sa = (void*)buf;

	sa->sun_family = AF_UNIX;
	strcpy(sa->sun_path, conf.status_socket);

	if (bind(ctx.status_fd, (struct sockaddr*)sa, len))
		exit_errno("fastd_status_init: bind");

	if (listen(ctx.status_fd, 4))
		exit_errno("fastd_status_init: listen");


	if (seteuid(uid) < 0)
		pr_debug_errno("seteuid");
	if (setegid(gid) < 0)
		pr_debug_errno("setegid");
}

/** Closes the status socket */
void fastd_status_close(void) {
	if (!conf.status_socket)
		return;

	if (close(ctx.status_fd))
		pr_warn_errno("fastd_status_cleanup: close");

	if (unlink(conf.status_socket))
		pr_warn_errno("fastd_status_cleanup: unlink");
}

/** Handles a single connection on the status socket */
void fastd_status_handle(void) {
	int fd = accept(ctx.status_fd, NULL, NULL);

	if (fd < 0) {
		pr_warn_errno("fastd_status_handle: accept");
		return;
	}

	dump_status(fd);
}

#endif
