// SPDX-License-Identifier: BSD-2-Clause
/*
  Copyright (c) 2021, Matthias Schiffer <mschiffer@universe-factory.net>
  All rights reserved.
*/

/**
   \file

   L2TP kernel offloading
*/

#include "l2tp.h"
#include "../../peer.h"

#include <libmnl/libmnl.h>
#include <linux/genetlink.h>
#include <linux/l2tp.h>

/* Netlink socket state */
typedef struct fastd_nl_ctx {
	struct mnl_socket *sock; /**< Netlink socket */
	unsigned seq;            /**< Last used sequence number */
} fastd_nl_ctx_t;

/** Global L2TP offload state */
struct fastd_offload_l2tp {
	fastd_nl_ctx_t nl;        /**< Netlink socket state */
	unsigned short family_id; /**< L2TP Generic Netlink family ID */
};

/** Offload session state */
struct fastd_offload_state {
	fastd_socket_t *sock;  /**< UDP socket underlying the tunnel */
	uint32_t conn_id;      /**< L2TP tunnel connection ID */
	char ifname[IFNAMSIZ]; /**< L2TP session interface */
	uint16_t mtu;          /**< Configured MTU of L2TP session interface */
};

/** Callback data for \e parse_cb / \e do_nl */
typedef struct fastd_parse_cb_data {
	unsigned offset;  /**< Length of family-specific data */
	mnl_attr_cb_t cb; /**< Per-attr callback */
	void *data;       /**< Per-attr callback data */
} fastd_parse_cb_data_t;

/** Callback to handle netlink reply */
static int parse_cb(const struct nlmsghdr *nlh, void *data) {
	fastd_parse_cb_data_t *cb_data = data;

	return mnl_attr_parse(nlh, cb_data->offset, cb_data->cb, cb_data->data);
}

/**
 * Handles a Netlink reply
 *
 * Will run the passed callback for each attribute of the received message
 * if the passed sequence number matches the message.
 */
static int run_parse_cb(
	const void *buf, size_t len, unsigned seq, unsigned portid, unsigned offset, mnl_attr_cb_t cb, void *data) {
	fastd_parse_cb_data_t cb_data = {
		.offset = offset,
		.cb = cb,
		.data = data,
	};
	return mnl_cb_run(buf, len, seq, portid, cb ? parse_cb : NULL, &cb_data);
}

/**
 * Run a Netlink communication
 *
 * The passed message \e nlh is sent on \e nl. Then it will receive messages
 * until a reply arrives (with a family-specific header of length \e offset),
 * running callback \e cb for each attribute.
 */
static bool do_nl(fastd_nl_ctx_t *nl, struct nlmsghdr *nlh, unsigned offset, mnl_attr_cb_t cb, void *data) {
	char buf[MNL_SOCKET_BUFFER_SIZE];
	int err;

	nlh->nlmsg_seq = ++nl->seq;

	err = mnl_socket_sendto(nl->sock, nlh, nlh->nlmsg_len);
	if (err < 0)
		return err;

	unsigned portid = mnl_socket_get_portid(nl->sock);

	do {
		ssize_t len = mnl_socket_recvfrom(nl->sock, buf, sizeof(buf));
		if (len < 0)
			return len;

		err = run_parse_cb(buf, len, nlh->nlmsg_seq, portid, offset, cb, data);
	} while (err > MNL_CB_STOP);

	return (err != MNL_CB_ERROR);
}

/** Callback for \e genl_get_family_id */
static int getfamily_cb(const struct nlattr *attr, void *data) {
	int *family_id = data;

	switch (mnl_attr_get_type(attr)) {
	case CTRL_ATTR_FAMILY_ID:
		if (mnl_attr_validate(attr, MNL_TYPE_U16) < 0)
			return MNL_CB_ERROR;
		*family_id = mnl_attr_get_u16(attr);
		break;
	}

	return MNL_CB_OK;
}

/** Retrieves the ID of a Generic Netlink family of a given name */
static int genl_get_family_id(fastd_nl_ctx_t *nl, const char *name) {
	char buf[MNL_SOCKET_BUFFER_SIZE];
	memset(buf, 0, sizeof(buf));

	int err;

	struct nlmsghdr *nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type = GENL_ID_CTRL;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;

	struct genlmsghdr *gh = mnl_nlmsg_put_extra_header(nlh, sizeof(*gh));
	gh->cmd = CTRL_CMD_GETFAMILY;
	gh->version = 1;

	mnl_attr_put_strz(nlh, CTRL_ATTR_FAMILY_NAME, name);

	int family_id = -1;
	err = do_nl(nl, nlh, sizeof(struct genlmsghdr), getfamily_cb, &family_id);
	if (err < 0)
		return err;

	return family_id;
}

/** Returns a 32bit random number, to be used as a L2TP connection ID */
static uint32_t new_conn_id(void) {
	uint32_t val = random();
	val <<= 1;
	val ^= random();
	return val;
}

/** Creates an L2TP tunnel on the passed UDP socket */
static bool fastd_l2tp_tunnel_create(int fd, uint32_t conn_id) {
	char buf[MNL_SOCKET_BUFFER_SIZE];
	memset(buf, 0, sizeof(buf));

	struct nlmsghdr *nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type = ctx.offload_l2tp->family_id;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;

	struct genlmsghdr *gh = mnl_nlmsg_put_extra_header(nlh, sizeof(*gh));
	gh->cmd = L2TP_CMD_TUNNEL_CREATE;
	gh->version = L2TP_GENL_VERSION;

	mnl_attr_put_u32(nlh, L2TP_ATTR_CONN_ID, conn_id);
	mnl_attr_put_u32(nlh, L2TP_ATTR_PEER_CONN_ID, 1);
	mnl_attr_put_u8(nlh, L2TP_ATTR_PROTO_VERSION, PACKET_L2TP_VERSION);
	mnl_attr_put_u16(nlh, L2TP_ATTR_ENCAP_TYPE, L2TP_ENCAPTYPE_UDP);
	mnl_attr_put_u32(nlh, L2TP_ATTR_FD, fd);

	return do_nl(&ctx.offload_l2tp->nl, nlh, sizeof(struct genlmsghdr), NULL, NULL);
}

/**
 * Creates an L2TP session in the tunnel with the given connection ID, optionally setting the L2TP interface name
 *
 * The session ID is always set to 1.
 */
static bool fastd_l2tp_session_create(uint32_t conn_id, const char *ifname) {
	char buf[MNL_SOCKET_BUFFER_SIZE];
	memset(buf, 0, sizeof(buf));

	struct nlmsghdr *nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type = ctx.offload_l2tp->family_id;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;

	struct genlmsghdr *gh = mnl_nlmsg_put_extra_header(nlh, sizeof(*gh));
	gh->cmd = L2TP_CMD_SESSION_CREATE;
	gh->version = L2TP_GENL_VERSION;

	mnl_attr_put_u32(nlh, L2TP_ATTR_CONN_ID, conn_id);
	mnl_attr_put_u32(nlh, L2TP_ATTR_SESSION_ID, 1);
	mnl_attr_put_u32(nlh, L2TP_ATTR_PEER_SESSION_ID, 1);
	mnl_attr_put_u16(nlh, L2TP_ATTR_PW_TYPE, L2TP_PWTYPE_ETH);
	mnl_attr_put_u8(nlh, L2TP_ATTR_L2SPEC_TYPE, L2TP_L2SPECTYPE_NONE);

	if (ifname)
		mnl_attr_put_strz(nlh, L2TP_ATTR_IFNAME, ifname);

	return do_nl(&ctx.offload_l2tp->nl, nlh, sizeof(struct genlmsghdr), NULL, NULL);
}

/** Callback for \e fastd_l2tp_session_get_ifname */
static int session_get_ifname_cb(const struct nlattr *attr, void *data) {
	char *ifname = data;

	switch (mnl_attr_get_type(attr)) {
	case L2TP_ATTR_IFNAME:
		if (mnl_attr_validate(attr, MNL_TYPE_NUL_STRING) < 0)
			return MNL_CB_ERROR;
		strncpy(ifname, mnl_attr_get_str(attr), IFNAMSIZ - 1);
		ifname[IFNAMSIZ - 1] = 0;
		break;
	}

	return MNL_CB_OK;
}

/** Retrieves the interface name for session 1 in the the L2TP tunnel with the given connection ID */
static bool fastd_l2tp_session_get_ifname(uint32_t conn_id, char ifname[IFNAMSIZ]) {
	char buf[MNL_SOCKET_BUFFER_SIZE];
	memset(buf, 0, sizeof(buf));

	struct nlmsghdr *nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type = ctx.offload_l2tp->family_id;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;

	struct genlmsghdr *gh = mnl_nlmsg_put_extra_header(nlh, sizeof(*gh));
	gh->cmd = L2TP_CMD_SESSION_GET;
	gh->version = L2TP_GENL_VERSION;

	mnl_attr_put_u32(nlh, L2TP_ATTR_CONN_ID, conn_id);
	mnl_attr_put_u32(nlh, L2TP_ATTR_SESSION_ID, 1);

	ifname[0] = 0;
	if (!do_nl(&ctx.offload_l2tp->nl, nlh, sizeof(struct genlmsghdr), session_get_ifname_cb, ifname))
		return false;

	return (ifname[0] != 0);
}

/** Deletes session 1 in the L2TP tunnel with the given connection ID */
static bool fastd_l2tp_session_delete(uint32_t conn_id) {
	char buf[MNL_SOCKET_BUFFER_SIZE];
	memset(buf, 0, sizeof(buf));

	struct nlmsghdr *nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type = ctx.offload_l2tp->family_id;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;

	struct genlmsghdr *gh = mnl_nlmsg_put_extra_header(nlh, sizeof(*gh));
	gh->cmd = L2TP_CMD_SESSION_DELETE;
	gh->version = L2TP_GENL_VERSION;

	mnl_attr_put_u32(nlh, L2TP_ATTR_CONN_ID, conn_id);
	mnl_attr_put_u32(nlh, L2TP_ATTR_SESSION_ID, 1);

	return do_nl(&ctx.offload_l2tp->nl, nlh, sizeof(struct genlmsghdr), NULL, NULL);
}

/**
 * Checks if L2TP tunnel and session creation is working
 *
 * Error out during fastd start when L2TP Ethernet pseudowire support is not available
 */
static void l2tp_selftest(void) {
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0)
		exit_errno("unable to create socket");


	uint32_t conn_id;
	while (true) {
		conn_id = new_conn_id();
		if (!conn_id)
			continue;

		if (!fastd_l2tp_tunnel_create(fd, conn_id)) {
			if (errno == EEXIST)
				continue;

			exit_errno("unable to initialize L2TP offload: failed to create L2TP tunnel");
		}

		break;
	}

	if (!fastd_l2tp_session_create(conn_id, NULL))
		exit_errno("unable to initialize L2TP offload: failed to create L2TP session");

	if (!fastd_l2tp_session_delete(conn_id))
		exit_errno("unable to initialize L2TP offload: failed to delete L2TP offload session");

	close(fd);
}

/** Global L2TP offload initialization */
void fastd_offload_l2tp_init(void) {
	ctx.offload_l2tp = fastd_new0(fastd_offload_l2tp_t);

	ctx.offload_l2tp->nl.sock = mnl_socket_open(NETLINK_GENERIC);
	if (!ctx.offload_l2tp->nl.sock)
		exit_errno("unable to initialize L2TP offload: failed to open Generic Netlink socket");

	int family_id = genl_get_family_id(&ctx.offload_l2tp->nl, L2TP_GENL_NAME);
	if (family_id < 0)
		exit_errno("unable to initialize L2TP offload: no kernel L2TP support");

	ctx.offload_l2tp->family_id = family_id;

	l2tp_selftest();
}

/** Frees resources allocated by \e fastd_offload_l2tp_init  */
void fastd_offload_l2tp_cleanup(void) {
	if (ctx.offload_l2tp->nl.sock)
		mnl_socket_close(ctx.offload_l2tp->nl.sock);
	free(ctx.offload_l2tp);
}

/**
 * Connects a \e fastd_socket_t to the given address
 *
 * The L2TP kernel code expects the offload socket to be connected to the
 * peer address.
 */
static bool connect_socket(fastd_socket_t *sock, const fastd_peer_address_t *addr) {
	int err;

	switch (addr->sa.sa_family) {
	case AF_INET:
		err = connect(sock->fd.fd, (const struct sockaddr *)&addr->in, sizeof(addr->in));
		break;

	case AF_INET6:
		err = connect(sock->fd.fd, (const struct sockaddr *)&addr->in6, sizeof(addr->in6));
		break;

	default:
		exit_bug("unsupported address family");
	}

	return (err == 0);
}

/** Helper to close an offload session */
static void free_offload_session(fastd_offload_state_t *session, bool delete) {
	if (session->sock) {
		if (delete) {
			/* Explicitly delete the session, so the interface name becomes usable again.
			 * Just closing the socket will not delete the session instantaneously,
			 * probably because of O_NONBLOCK */
			if (!fastd_l2tp_session_delete(session->conn_id))
				pr_warn_errno("failed to delete L2TP offload session");
		}

		fastd_socket_close(session->sock);
		free(session->sock);
	}
	free(session);
}

/** L2TP implementation of \e fastd_offload_t::free_session */
static void fastd_offload_l2tp_free_session(fastd_offload_state_t *session) {
	free_offload_session(session, true);
}

/** L2TP implementation of \e fastd_offload_t::update_session */
static bool fastd_offload_l2tp_update_session(UNUSED const fastd_peer_t *peer, UNUSED fastd_offload_state_t *session) {
	if (!fastd_peer_address_equal(&peer->local_address, session->sock->bound_addr))
		return false;

	return connect_socket(session->sock, &peer->address);
}

/** L2TP implementation of \e fastd_offload_t::init_session */
static fastd_offload_state_t *fastd_offload_l2tp_init_session(const fastd_peer_t *peer) {
	if (!peer->sock)
		exit_bug("tried to init offload session for peer without socket");

	char ifname[IFNAMSIZ];
	if (!fastd_iface_format_name(ifname, peer))
		return NULL;

	pr_debug("initializing L2TP offload device...");

	fastd_offload_state_t *session = fastd_new0(fastd_offload_state_t);
	bool delete = false;

	session->sock = fastd_socket_open_offload(peer->sock, &peer->local_address);
	if (!session->sock) {
		pr_warn_errno("socket creation for L2TP offloading failed");
		goto err;
	}

	if (!connect_socket(session->sock, &peer->address)) {
		pr_warn_errno("failed to set peer address for L2TP offloading");
		goto err;
	}

	/* Retry when the conn_id is already in use */
	while (true) {
		session->conn_id = new_conn_id();
		if (!session->conn_id)
			continue;

		if (!fastd_l2tp_tunnel_create(session->sock->fd.fd, session->conn_id)) {
			if (errno == EEXIST)
				continue;

			pr_warn_errno("failed to create L2TP tunnel");
			goto err;
		}

		break;
	}

	if (!fastd_l2tp_session_create(session->conn_id, ifname[0] ? ifname : NULL)) {
		pr_warn_errno("failed to create L2TP session");
		goto err;
	}

	delete = true;

	if (!fastd_l2tp_session_get_ifname(session->conn_id, session->ifname)) {
		pr_warn_errno("failed to get L2TP interface name");
		goto err;
	}

	session->mtu = fastd_peer_get_mtu(peer);

	if (!fastd_iface_set_mtu(session->ifname, session->mtu)) {
		pr_error_errno("failed to set L2TP interface MTU");
		goto err;
	}

	pr_debug("L2TP offload device `%s' initialized.", session->ifname);

	return session;

err:
	free_offload_session(session, delete);
	return NULL;
}

/** L2TP implementation of \e fastd_offload_t::get_iface */
static void fastd_offload_l2tp_get_iface(const fastd_offload_state_t *session, const char **ifname, uint16_t *mtu) {
	*ifname = session->ifname;
	*mtu = session->mtu;
}

/** The L2TP fastd_offload_t implementation */
static const fastd_offload_t fastd_offload_l2tp = {
	.init_session = fastd_offload_l2tp_init_session,
	.get_iface = fastd_offload_l2tp_get_iface,
	.update_session = fastd_offload_l2tp_update_session,
	.free_session = fastd_offload_l2tp_free_session,
};

/** Returns the L2TP fastd_offload_t implementation */
const fastd_offload_t *fastd_offload_l2tp_get(void) {
	return &fastd_offload_l2tp;
}
