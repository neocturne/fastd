/*
  Copyright (c) 2012-2016, Matthias Schiffer <mschiffer@universe-factory.net>
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

   Configuration management
*/


#include "fastd.h"
#include "config.h"
#include "crypto.h"
#include "lex.h"
#include "method.h"
#include "peer.h"
#include "peer_group.h"
#include "socket.h"
#include <generated/config.yy.h>

#include <dirent.h>
#include <grp.h>
#include <libgen.h>
#include <pwd.h>
#include <stdarg.h>
#include <strings.h>

#include <sys/stat.h>
#include <sys/types.h>


/** The global configuration */
fastd_config_t conf = {};


extern const fastd_protocol_t fastd_protocol_ec25519_fhmqvc;


/** Initializes the global configuration with default values */
static void default_config(void) {
	conf.log_syslog_ident = fastd_strdup("fastd");

	conf.mtu = 1500;
	conf.mode = MODE_TAP;
	conf.iface_persist = true;

	conf.secure_handshakes = true;
	conf.drop_caps = DROP_CAPS_ON;

	conf.protocol = &fastd_protocol_ec25519_fhmqvc;

	conf.peer_group = fastd_new0(fastd_peer_group_t);
	conf.peer_group->name = fastd_strdup("default");
	conf.peer_group->max_connections = -1;
}

/** Handles the configuration of a handshake protocol */
void fastd_config_protocol(const char *name) {
	if (strcmp(name, conf.protocol->name))
		exit_error("config error: protocol `%s' not supported", name);
}

/** Handles the configuration of a crypto method */
void fastd_config_method(fastd_peer_group_t *group, const char *name) {
	fastd_string_stack_t **method;

	for (method = &group->methods; *method; method = &(*method)->next) {
		if (!strcmp((*method)->str, name)) {
			pr_debug("duplicate method name `%s', ignoring", name);
			return;
		}
	}

	*method = fastd_string_stack_dup(name);
}

/** Configures an interface name or name pattern */
bool fastd_config_ifname(fastd_peer_t *peer, const char *ifname) {
	if (strchr(ifname, '/'))
		return false;

	const char *percent = strchr(ifname, '%');
	if (percent) {
		if (strrchr(ifname, '%') != percent)
			return false; /* Multiple patterns */

		if (percent[1] != 'n' && percent[1] != 'k')
			return false;
	}

	char **name = peer ? &peer->ifname : &conf.ifname;

	free(*name);
	*name = fastd_strdup(ifname);

	return true;
}

/** Handles the configuration of a cipher implementation */
void fastd_config_cipher(const char *name, const char *impl) {
	if (!fastd_cipher_config(name, impl))
		exit_error("config error: implementation `%s' is not supported for cipher `%s' (or cipher `%s' is not supported)", impl, name, name);
}

/** Handles the configuration of a MAC implementation */
void fastd_config_mac(const char *name, const char *impl) {
	if (!fastd_mac_config(name, impl))
		exit_error("config error: implementation `%s' is not supported for MAC `%s' (or MAC `%s' is not supported)", impl, name, name);
}

/** Handles the configuration of a bind address */
void fastd_config_bind_address(const fastd_peer_address_t *address, const char *bindtodev, const fastd_peer_address_t *sourceaddr, fastd_timeout_t interval, bool default_v4, bool default_v6) {
	if (fastd_peer_address_host_multicast(address)) {
		if (address->sa.sa_family == AF_INET) {
			if (!address->in.sin_port)
				exit_error("config error: multicast IPv4 bind requires port specification");
#ifndef USE_PKTINFO
			exit_error("config error: multicast IPv4 requires PKTINFO");
#endif
		} else if (!address->in6.sin6_port)
			exit_error("config error: multicast IPv6 bind requires port specification");

		if (!bindtodev) {
			if (address->sa.sa_family == AF_INET6)
				exit_error("config error: multicast IPv6 bind requires interface specification");
			if (sourceaddr->sa.sa_family == AF_UNSPEC)
				exit_error("config error: multicast bind with no interface requires source address specification");
		}

		if (sourceaddr->sa.sa_family != AF_UNSPEC && address->sa.sa_family != sourceaddr->sa.sa_family)
			exit_error("config error: family of source address does not match multicast address family");

		if (interval != FASTD_TIMEOUT_INV) {
			interval *= 1000;
			if (interval < MIN_DISCOVERY_INTERVAL)
				exit_error("config error: discovery interval smaller than minimum");
		} else
			interval = DEFAULT_DISCOVERY_INTERVAL;
	} else {
#ifndef USE_BINDTODEVICE
		if (bindtodev && !fastd_peer_address_host_v6_ll(address))
			exit_error("config error: device bind configuration not supported on this system");
#endif

		if (address->sa.sa_family != AF_UNSPEC && sourceaddr->sa.sa_family != AF_UNSPEC) {
			if (address->sa.sa_family != sourceaddr->sa.sa_family)
				exit_error("config error: address family of source address does not match bind address family");
			if (!fastd_peer_address_host_any(address) && !fastd_peer_address_host_equal(address, sourceaddr))
				exit_error("config error: source address is different from explicit bind address");
		}

		if (interval != FASTD_TIMEOUT_INV)
			exit_error("config error: interval on non-discovery socket is not allowed");
	}

	if (sourceaddr->sa.sa_family != AF_UNSPEC && !fastd_peer_address_host_unicast(sourceaddr))
		exit_error("config error: source address is a multicast address");

#ifndef USE_MULTIAF_BIND
	if (address->sa.sa_family == AF_UNSPEC) {
		fastd_peer_address_t addr4 = { .in = { .sin_family = AF_INET, .sin_port = address->in.sin_port } };
		fastd_peer_address_t addr6 = { .in6 = { .sin6_family = AF_INET6, .sin6_port = address->in.sin_port } };

		if (sourceaddr->sa.sa_family != AF_INET6)
			fastd_config_bind_address(&addr4, bindtodev, sourceaddr, default_v4, default_v6);
		if (sourceaddr->sa.sa_family != AF_INET)
			fastd_config_bind_address(&addr6, bindtodev, sourceaddr, default_v4, default_v6);
		return;
	}
#endif

	fastd_bind_address_t *addr = fastd_new(fastd_bind_address_t);
	addr->next = conf.bind_addrs;
	conf.bind_addrs = addr;
	conf.n_bind_addrs++;

	addr->addr = *address;
	addr->bindtodev = fastd_strdup(bindtodev);
	addr->sourceaddr = *sourceaddr;
	addr->discovery_interval = interval;

	if (addr->addr.sa.sa_family != AF_INET6 && (default_v4 || !conf.bind_addr_default_v4))
		conf.bind_addr_default_v4 = addr;

	if (addr->addr.sa.sa_family != AF_INET && (default_v6 || !conf.bind_addr_default_v6))
		conf.bind_addr_default_v6 = addr;
}

/** Handles the start of a peer group configuration */
void fastd_config_peer_group_push(fastd_parser_state_t *state, const char *name) {
	fastd_peer_group_t *group = fastd_new0(fastd_peer_group_t);
	group->name = fastd_strdup(name);
	group->max_connections = -1;

	group->parent = state->peer_group;
	group->next = group->parent->children;

	group->parent->children = group;

	state->peer_group = group;
}

/** Handles the end of a peer group configuration */
void fastd_config_peer_group_pop(fastd_parser_state_t *state) {
	state->peer_group = state->peer_group->parent;
}

/** Frees a peer group and its children */
static void free_peer_group(fastd_peer_group_t *group) {
	while (group->children) {
		fastd_peer_group_t *next = group->children->next;
		free_peer_group(group->children);
		group->children = next;
	}

	fastd_string_stack_free(group->peer_dirs);
	fastd_string_stack_free(group->methods);

	fastd_shell_command_unset(&group->on_up);
	fastd_shell_command_unset(&group->on_down);
	fastd_shell_command_unset(&group->on_connect);
	fastd_shell_command_unset(&group->on_establish);
	fastd_shell_command_unset(&group->on_disestablish);

	free(group->name);
	free(group);
}

/** Checks if a peer group has configured any peer dirs */
static bool has_peer_group_peer_dirs(const fastd_peer_group_t *group) {
	if (group->peer_dirs)
		return true;

	const fastd_peer_group_t *child;
	for (child = group->children; child; child = child->next) {
		if (has_peer_group_peer_dirs(child))
			return true;
	}

	return false;
}

/** Reads and processes all peer definitions in the current directory (which must also be supplied as the argument) */
static void read_peer_dir(fastd_peer_group_t *group, const char *dir) {
	DIR *dirh = opendir(".");

	if (dirh) {
		while (true) {
			errno = 0;
			struct dirent *result = readdir(dirh);
			if (!result) {
				if (errno)
					pr_error_errno("readdir");

				break;
			}

			if (result->d_name[0] == '.')
				continue;

			if (result->d_name[strlen(result->d_name)-1] == '~') {
				pr_verbose("ignoring file `%s' as it seems to be a backup file", result->d_name);
				continue;
			}

			struct stat statbuf;
			if (stat(result->d_name, &statbuf)) {
				pr_warn("ignoring file `%s': stat failed: %s", result->d_name, strerror(errno));
				continue;
			}
			if ((statbuf.st_mode & S_IFMT) != S_IFREG) {
				pr_info("ignoring file `%s': no regular file", result->d_name);
				continue;
			}

			fastd_peer_t *peer = fastd_new0(fastd_peer_t);
			peer->name = fastd_strdup(result->d_name);
			peer->config_source_dir = dir;

			if (!fastd_config_read(result->d_name, group, peer, 0)) {
				fastd_peer_free(peer);
				continue;
			}

			fastd_peer_add(peer);
		}

		if (closedir(dirh) < 0)
			pr_error_errno("closedir");

	}
	else {
		pr_error("opendir for `%s' failed: %s", dir, strerror(errno));
	}
}

/** Reads all configured peer directories for a peer grup */
static void read_peer_dirs(fastd_peer_group_t *group) {
	char *oldcwd = get_current_dir_name();

	fastd_string_stack_t *dir;
	for (dir = group->peer_dirs; dir; dir = dir->next) {
		if (!chdir(dir->str))
			read_peer_dir(group, dir->str);
		else
			pr_error("change from directory `%s' to `%s' failed: %s", oldcwd, dir->str, strerror(errno));
	}

	if (chdir(oldcwd))
		pr_error("can't chdir to `%s': %s", oldcwd, strerror(errno));

	free(oldcwd);
}

/** Adds a peer directory to the configuration */
void fastd_config_add_peer_dir(fastd_peer_group_t *group, const char *dir) {
	char *oldcwd = get_current_dir_name();

	if (!chdir(dir)) {
		char *newdir = get_current_dir_name();
		group->peer_dirs = fastd_string_stack_push(group->peer_dirs, newdir);
		free(newdir);

		if (chdir(oldcwd))
			pr_error("can't chdir to `%s': %s", oldcwd, strerror(errno));
	}
	else {
		pr_error("change from directory `%s' to `%s' failed: %s", oldcwd, dir, strerror(errno));
	}

	free(oldcwd);
}

/** Reads and processes a configuration file */
bool fastd_config_read(const char *filename, fastd_peer_group_t *peer_group, fastd_peer_t *peer, int depth) {
	if (depth >= MAX_CONFIG_DEPTH)
		exit_error("maximum config include depth exceeded");

	bool ret = true;
	char *oldcwd = get_current_dir_name();
	char *filename2 = NULL;
	char *dir = NULL;
	FILE *file;
	fastd_lex_t *lex = NULL;
	fastd_config_pstate *ps;
	fastd_string_stack_t *strings = NULL;

	ps = fastd_config_pstate_new();

	if (!filename) {
		file = stdin;
	}
	else {
		file = fopen(filename, "r");
		if (!file) {
			pr_error("can't open config file `%s': %s", filename, strerror(errno));
			ret = false;
			goto end_free;
		}
	}

	lex = fastd_lex_init(file);

	if (filename) {
		filename2 = fastd_strdup(filename);
		dir = dirname(filename2);

		if (chdir(dir)) {
			pr_error("change from directory `%s' to `%s' failed", oldcwd, dir);
			ret = false;
			goto end_free;
		}
	}

	int token;
	YYSTYPE token_val;
	YYLTYPE loc = {1, 0, 1, 0};
	fastd_parser_state_t state = {
		.peer_group = peer_group,
		.peer = peer,
		.filename = filename,
		.depth = depth+1,
	};

	if (peer) {
		token = START_PEER_CONFIG;
		peer->group = peer_group;
	}
	else {
		token = peer_group->parent ? START_PEER_GROUP_CONFIG : START_CONFIG;
	}

	int parse_ret = fastd_config_push_parse(ps, token, &token_val, &loc, &state);

	while (parse_ret == YYPUSH_MORE) {
		token = fastd_lex(&token_val, &loc, lex);

		if (token < 0) {
			pr_error("config error: %s at %s:%i:%i", token_val.error, filename, loc.first_line, loc.first_column);
			ret = false;
			goto end_free;
		}

		if (token == TOK_STRING) {
			token_val.str->next = strings;
			strings = token_val.str;
		}

		parse_ret = fastd_config_push_parse(ps, token, &token_val, &loc, &state);
	}

	if (parse_ret)
		ret = false;

 end_free:
	fastd_string_stack_free(strings);

	fastd_lex_destroy(lex);
	fastd_config_pstate_delete(ps);

	if(chdir(oldcwd))
		pr_error("can't chdir to `%s': %s", oldcwd, strerror(errno));

	free(filename2);
	free(oldcwd);

	if (filename && file)
		fclose(file);

	return ret;
}

/** Loads information about the configured user and group */
static void configure_user(void) {
#ifdef USE_USER
	conf.uid = getuid();
	conf.gid = getgid();

	if (conf.user) {
		struct passwd pwd, *pwdr;
		size_t bufspace = 1024;
		int error;

		do {
			char buf[bufspace];
			error = getpwnam_r(conf.user, &pwd, buf, bufspace, &pwdr);
			bufspace *= 2;
		} while(error == ERANGE);

		if (error)
			exit_errno("getpwnam_r");

		if (!pwdr)
			exit_error("config error: unable to find user `%s'.", conf.user);

		conf.uid = pwdr->pw_uid;
		conf.gid = pwdr->pw_gid;
	}

	if (conf.group) {
		struct group grp, *grpr;
		size_t bufspace = 1024;
		int error;

		do {
			char buf[bufspace];
			error = getgrnam_r(conf.group, &grp, buf, bufspace, &grpr);
			bufspace *= 2;
		} while(error == ERANGE);

		if (error)
			exit_errno("getgrnam_r");

		if (!grpr)
			exit_error("config error: unable to find group `%s'.", conf.group);

		conf.gid = grpr->gr_gid;
	}

	if (conf.user) {
		int ngroups = 0;
		if (getgrouplist(conf.user, conf.gid, NULL, &ngroups) < 0) {
			/* the user has supplementary groups */

			GROUPLIST_TYPE groups[ngroups];

			if (getgrouplist(conf.user, conf.gid, groups, &ngroups) < 0)
				exit_errno("getgrouplist");

			conf.n_groups = ngroups;
			conf.groups = fastd_new_array(ngroups, gid_t);

			int i;
			for (i = 0; i < ngroups; i++)
				conf.groups[i] = groups[i];
		}
	}
#endif
}

/** Initializes global configuration that depends on the configured methods */
static void configure_method_parameters(void) {
	conf.max_overhead = 0;
	conf.min_encrypt_head_space = 0;
	conf.min_decrypt_head_space = 0;
	conf.min_encrypt_tail_space = 0;
	conf.min_decrypt_tail_space = 0;

	size_t i;
	for (i = 0; conf.methods[i].name; i++) {
		const fastd_method_provider_t *provider = conf.methods[i].provider;

		conf.max_overhead = max_size_t(conf.max_overhead, provider->max_overhead);
		conf.min_encrypt_head_space = max_size_t(conf.min_encrypt_head_space, provider->min_encrypt_head_space);
		conf.min_decrypt_head_space = max_size_t(conf.min_decrypt_head_space, provider->min_decrypt_head_space);
		conf.min_encrypt_tail_space = max_size_t(conf.min_encrypt_tail_space, provider->min_encrypt_tail_space);
		conf.min_decrypt_tail_space = max_size_t(conf.min_decrypt_tail_space, provider->min_decrypt_tail_space);
	}

	conf.min_encrypt_head_space = alignto(conf.min_encrypt_head_space, 16);

	/* ugly hack to get alignment right for aes128-gcm, which needs data aligned to 16 and has a 24 byte header */
	conf.min_decrypt_head_space = alignto(conf.min_decrypt_head_space, 16) + 8;
}


/** Collects a list of the configured methods of all peer groups */
static void collect_methods(const fastd_peer_group_t *group, size_t *count) {
	const fastd_string_stack_t *method;

	for (method = group->methods; method; method = method->next) {
		if (!fastd_string_stack_contains(conf.method_list, method->str)) {
			conf.method_list = fastd_string_stack_push(conf.method_list, method->str);
			(*count)++;
		}
	}

	const fastd_peer_group_t *sub;
	for (sub = group->children; sub; sub = sub->next)
		collect_methods(sub, count);
}


/** Handles the initialization of the configured methods */
static void configure_methods(void) {
	size_t n_methods = 0, i;
	fastd_string_stack_t *method_name;

	collect_methods(conf.peer_group, &n_methods);

	conf.methods = fastd_new0_array(n_methods+1, fastd_method_info_t);

	for (i = 0, method_name = conf.method_list; method_name; i++, method_name = method_name->next) {
		conf.methods[i].name = method_name->str;
		if (!fastd_method_create_by_name(method_name->str, &conf.methods[i].provider, &conf.methods[i].method))
			exit_error("config error: method `%s' not supported", method_name->str);
	}

	configure_method_parameters();
}

/** Frees the resources used by the configured methods */
static void destroy_methods(void) {
	size_t i;
	for (i = 0; conf.methods[i].name; i++) {
		conf.methods[i].provider->destroy(conf.methods[i].method);
	}

	free(conf.methods);
}

/** Loads the configuration */
void fastd_configure(int argc, char *const argv[]) {
	default_config();

	fastd_config_handle_options(argc, argv);

	if (!conf.log_stderr_level && !conf.log_syslog_level)
		conf.log_stderr_level = LL_DEFAULT;
}

/** Performs some basic checks on the configuration */
static void config_check_base(void) {
	if (fastd_use_android_integration()) {
		if (conf.mode != MODE_TUN)
			exit_error("In Android integration mode only TUN interfaces are supported");

		if (!fastd_config_single_iface())
			exit_error("In Android integration mode exactly one peer must be configured");
	}
}

/** Performs more checks on the configuration */
void fastd_config_check(void) {
	config_check_base();

	if (!VECTOR_LEN(ctx.peers) && !has_peer_group_peer_dirs(conf.peer_group) && !fastd_allow_verify())
		exit_error("config error: neither fixed peers nor peer dirs have been configured");

	if (!conf.peer_group->methods) {
		pr_warn("no encryption method configured, falling back to method `null' (unencrypted)");
		fastd_config_method(conf.peer_group, "null");
	}

	configure_user();
	configure_methods();
}

/** Determines if the configuration will never create more than a single interface */
bool fastd_config_single_iface(void) {
	if (conf.mode == MODE_TAP)
		return true;

	if (has_peer_group_peer_dirs(conf.peer_group))
		return false;

	if (fastd_allow_verify())
		return false;

	return (VECTOR_LEN(ctx.peers) == 1);
}

/** Determines of all interfaces are persistent (i.e. don't need to be created and destroyed dynamically) */
bool fastd_config_persistent_ifaces(void) {
	if (fastd_use_android_integration())
		return true;

	if (conf.mode == MODE_TAP)
		return true;

	if (!conf.iface_persist)
		return false;

	if (has_peer_group_peer_dirs(conf.peer_group))
		return false;

	if (fastd_allow_verify())
		return false;

	return true;

}

/** Performs the verify-config checks */
void fastd_config_verify(void) {
	config_check_base();
	configure_methods();
}

/** Reads the peer dirs of a peer group and its children */
static void peer_dirs_read_peer_group(fastd_peer_group_t *group) {
	read_peer_dirs(group);

	fastd_peer_group_t *child;
	for (child = group->children; child; child = child->next)
		peer_dirs_read_peer_group(child);
}

/** Initializes the configured peers */
static void configure_peers(bool dirs_only) {
	ctx.has_floating = false;
	ctx.max_mtu = conf.mtu;

	ssize_t i;
	for (i = VECTOR_LEN(ctx.peers)-1; i >= 0; i--) {
		fastd_peer_t *peer = VECTOR_INDEX(ctx.peers, i);

		if (peer->config_state == CONFIG_STATIC) {
			/* The peer hasn't been touched since the last run of configure_peers(), so its definition must have disappeared */
			fastd_peer_delete(peer);
			continue;
		}

		if (fastd_peer_is_dynamic(peer))
			continue;

		if (peer->config_state != CONFIG_DISABLED && !conf.protocol->check_peer(peer))
			peer->config_state = CONFIG_DISABLED;

		if (peer->config_state == CONFIG_DISABLED) {
			fastd_peer_reset(peer);
			continue;
		}

		if (fastd_peer_is_floating(peer))
			ctx.has_floating = true;

		if (conf.mode != MODE_TAP && peer->mtu > ctx.max_mtu)
			ctx.max_mtu = peer->mtu;

		peer->config_state = CONFIG_STATIC;

		if (!fastd_peer_is_established(peer)) {
			if (peer->config_source_dir || !dirs_only)
				fastd_peer_reset(peer);
		}
	}
}

/** Initialized the peers not configured through peer directories */
void fastd_configure_peers(void) {
	configure_peers(false);
}

/** Refreshes the peer configurations from the configured peer dirs */
void fastd_config_load_peer_dirs(bool dirs_only) {
	size_t i;
	for (i = 0; i < VECTOR_LEN(ctx.peers); i++) {
		fastd_peer_t *peer = VECTOR_INDEX(ctx.peers, i);

		if (fastd_peer_is_dynamic(peer))
			continue;

		/* Reset all peers' config states */
		if (!peer->config_source_dir)
			peer->config_state = CONFIG_NEW;
		else if (peer->config_state == CONFIG_DISABLED)
			peer->config_state = CONFIG_STATIC;
	}

	peer_dirs_read_peer_group(conf.peer_group);
	configure_peers(dirs_only);
}

/** Frees all resources used by the global configuration */
void fastd_config_release(void) {
	while (conf.bind_addrs) {
		fastd_bind_address_t *next = conf.bind_addrs->next;
		free(conf.bind_addrs->bindtodev);
		free(conf.bind_addrs);
		conf.bind_addrs = next;
	}

	free_peer_group(conf.peer_group);

	destroy_methods();
	fastd_string_stack_free(conf.method_list);

	fastd_shell_command_unset(&conf.on_pre_up);
	fastd_shell_command_unset(&conf.on_post_down);
#ifdef WITH_DYNAMIC_PEERS
	fastd_shell_command_unset(&conf.on_verify);
#endif

#ifdef WITH_STATUS_SOCKET
	free(conf.status_socket);
#endif

#ifdef USE_USER
	free(conf.user);
	free(conf.group);
	free(conf.groups);
#endif

	free(conf.ifname);
	free(conf.secret);
	free(conf.protocol_config);
	free(conf.log_syslog_ident);
}
