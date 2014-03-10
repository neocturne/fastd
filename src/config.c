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
#include "config.h"
#include "crypto.h"
#include "lex.h"
#include "method.h"
#include "peer.h"
#include <config.yy.h>

#include <dirent.h>
#include <grp.h>
#include <libgen.h>
#include <pwd.h>
#include <stdarg.h>
#include <strings.h>

#include <sys/stat.h>
#include <sys/types.h>


extern const fastd_protocol_t fastd_protocol_ec25519_fhmqvc;


static void default_config(fastd_config_t *conf) {
	memset(conf, 0, sizeof(fastd_config_t));

	conf->log_syslog_ident = strdup("fastd");

	conf->keepalive_interval = 10;
	conf->keepalive_timeout = 15;
	conf->peer_stale_time = 90;
	conf->eth_addr_stale_time = 300;

	conf->reorder_time = 10;

	conf->min_handshake_interval = 15;
	conf->min_resolve_interval = 15;

	conf->mtu = 1500;
	conf->mode = MODE_TAP;

	conf->drop_caps = DROP_CAPS_ON;

	conf->protocol = &fastd_protocol_ec25519_fhmqvc;
	conf->key_valid = 3600;		/* 60 minutes */
	conf->key_valid_old = 60;	/* 1 minute */
	conf->key_refresh = 3300;	/* 55 minutes */
	conf->key_refresh_splay = 300;	/* 5 minutes */

	conf->peer_group = calloc(1, sizeof(fastd_peer_group_config_t));
	conf->peer_group->name = strdup("default");
	conf->peer_group->max_connections = -1;

	conf->ciphers = fastd_cipher_config_alloc();
	conf->macs = fastd_mac_config_alloc();
}

void fastd_config_protocol(fastd_context_t *ctx UNUSED, fastd_config_t *conf, const char *name) {
	if (!strcmp(name, "ec25519-fhmqvc"))
		conf->protocol = &fastd_protocol_ec25519_fhmqvc;
	else
		exit_error(ctx, "config error: protocol `%s' not supported", name);
}

void fastd_config_method(fastd_context_t *ctx, fastd_config_t *conf, const char *name) {
	fastd_string_stack_t **method;

	for (method = &conf->method_list; *method; method = &(*method)->next) {
		if (!strcmp((*method)->str, name)) {
			pr_debug(ctx, "duplicate method name `%s', ignoring", name);
			return;
		}
	}

	*method = fastd_string_stack_dup(name);
}

void fastd_config_cipher(fastd_context_t *ctx, fastd_config_t *conf, const char *name, const char *impl) {
	if (!fastd_cipher_config(conf->ciphers, name, impl))
		exit_error(ctx, "config error: implementation `%s' is not supported for cipher `%s' (or cipher `%s' is not supported)", impl, name, name);
}

void fastd_config_mac(fastd_context_t *ctx, fastd_config_t *conf, const char *name, const char *impl) {
	if (!fastd_mac_config(conf->macs, name, impl))
		exit_error(ctx, "config error: implementation `%s' is not supported for MAC `%s' (or MAC `%s' is not supported)", impl, name, name);
}

void fastd_config_bind_address(fastd_context_t *ctx UNUSED, fastd_config_t *conf, const fastd_peer_address_t *address, const char *bindtodev, bool default_v4, bool default_v6) {
#ifndef USE_BINDTODEVICE
	if (bindtodev && !fastd_peer_address_is_v6_ll(address))
		exit_error(ctx, "config error: device bind configuration not supported on this system");
#endif

#ifndef USE_MULTIAF_BIND
	if (address->sa.sa_family == AF_UNSPEC) {
		fastd_peer_address_t addr4 = { .in = { .sin_family = AF_INET, .sin_port = address->in.sin_port } };
		fastd_peer_address_t addr6 = { .in6 = { .sin6_family = AF_INET6, .sin6_port = address->in.sin_port } };

		fastd_config_bind_address(ctx, conf, &addr4, bindtodev, default_v4, default_v6);
		fastd_config_bind_address(ctx, conf, &addr6, bindtodev, default_v4, default_v6);
		return;
	}
#endif

	fastd_bind_address_t *addr = malloc(sizeof(fastd_bind_address_t));
	addr->next = conf->bind_addrs;
	conf->bind_addrs = addr;
	conf->n_bind_addrs++;

	addr->addr = *address;
	addr->bindtodev = bindtodev ? strdup(bindtodev) : NULL;

	fastd_peer_address_simplify(&addr->addr);

	if (addr->addr.sa.sa_family != AF_INET6 && (default_v4 || !conf->bind_addr_default_v4))
		conf->bind_addr_default_v4 = addr;

	if (addr->addr.sa.sa_family != AF_INET && (default_v6 || !conf->bind_addr_default_v6))
		conf->bind_addr_default_v6 = addr;
}

void fastd_config_peer_group_push(fastd_context_t *ctx UNUSED, fastd_config_t *conf, const char *name) {
	fastd_peer_group_config_t *group = calloc(1, sizeof(fastd_peer_group_config_t));
	group->name = strdup(name);
	group->max_connections = -1;

	group->parent = conf->peer_group;
	group->next = group->parent->children;

	group->parent->children = group;

	conf->peer_group = group;
}

void fastd_config_peer_group_pop(fastd_context_t *ctx UNUSED, fastd_config_t *conf) {
	conf->peer_group = conf->peer_group->parent;
}

static void free_peer_group(fastd_peer_group_config_t *group) {
	while (group->children) {
		fastd_peer_group_config_t *next = group->children->next;
		free_peer_group(group->children);
		group->children = next;
	}

	fastd_string_stack_free(group->peer_dirs);
	free(group->name);
	free(group);
}

static bool has_peer_group_peer_dirs(const fastd_peer_group_config_t *group) {
	if (group->peer_dirs)
		return true;

	const fastd_peer_group_config_t *child;
	for (child = group->children; child; child = child->next) {
		if (has_peer_group_peer_dirs(child))
			return true;
	}

	return false;
}

void fastd_config_add_log_file(fastd_context_t *ctx, fastd_config_t *conf, const char *name, fastd_loglevel_t level) {
	char *name2 = strdup(name);
	char *name3 = strdup(name);

	char *dir = dirname(name2);
	char *base = basename(name3);

	char *oldcwd = get_current_dir_name();

	if (!chdir(dir)) {
		char *logdir = get_current_dir_name();

		fastd_log_file_t *file = malloc(sizeof(fastd_log_file_t));
		file->filename = malloc(strlen(logdir) + 1 + strlen(base) + 1);

		strcpy(file->filename, logdir);
		strcat(file->filename, "/");
		strcat(file->filename, base);

		file->level = level;

		file->next = conf->log_files;
		conf->log_files = file;

		if(chdir(oldcwd))
			pr_error(ctx, "can't chdir to `%s': %s", oldcwd, strerror(errno));

		free(logdir);
	}
	else {
		pr_error(ctx, "change from directory `%s' to `%s' failed: %s", oldcwd, dir, strerror(errno));
	}

	free(oldcwd);
	free(name2);
	free(name3);
}

static void read_peer_dir(fastd_context_t *ctx, fastd_config_t *conf, const char *dir) {
	DIR *dirh = opendir(".");

	if (dirh) {
		while (true) {
			errno = 0;
			struct dirent *result = readdir(dirh);
			if (!result) {
				if (errno)
					pr_error_errno(ctx, "readdir");

				break;
			}

			if (result->d_name[0] == '.')
				continue;

			if (result->d_name[strlen(result->d_name)-1] == '~') {
				pr_verbose(ctx, "ignoring file `%s' as it seems to be a backup file", result->d_name);
				continue;
			}

			struct stat statbuf;
			if (stat(result->d_name, &statbuf)) {
				pr_warn(ctx, "ignoring file `%s': stat failed: %s", result->d_name, strerror(errno));
				continue;
			}
			if ((statbuf.st_mode & S_IFMT) != S_IFREG) {
				pr_info(ctx, "ignoring file `%s': no regular file", result->d_name);
				continue;
			}

			fastd_peer_config_new(ctx, conf);
			conf->peers->name = strdup(result->d_name);
			conf->peers->config_source_dir = dir;

			if (!fastd_read_config(ctx, conf, result->d_name, true, 0)) {
				pr_warn(ctx, "peer config `%s' will be ignored", result->d_name);
				fastd_peer_config_delete(ctx, conf);
			}
		}

		if (closedir(dirh) < 0)
			pr_error_errno(ctx, "closedir");

	}
	else {
		pr_error(ctx, "opendir for `%s' failed: %s", dir, strerror(errno));
	}
}

static void read_peer_dirs(fastd_context_t *ctx, fastd_config_t *conf) {
	char *oldcwd = get_current_dir_name();

	fastd_string_stack_t *dir;
	for (dir = conf->peer_group->peer_dirs; dir; dir = dir->next) {
		if (!chdir(dir->str))
			read_peer_dir(ctx, conf, dir->str);
		else
			pr_error(ctx, "change from directory `%s' to `%s' failed: %s", oldcwd, dir->str, strerror(errno));
	}

	if (chdir(oldcwd))
		pr_error(ctx, "can't chdir to `%s': %s", oldcwd, strerror(errno));

	free(oldcwd);
}

void fastd_add_peer_dir(fastd_context_t *ctx, fastd_config_t *conf, const char *dir) {
	char *oldcwd = get_current_dir_name();

	if (!chdir(dir)) {
		char *newdir = get_current_dir_name();
		conf->peer_group->peer_dirs = fastd_string_stack_push(conf->peer_group->peer_dirs, newdir);
		free(newdir);

		if(chdir(oldcwd))
			pr_error(ctx, "can't chdir to `%s': %s", oldcwd, strerror(errno));
	}
	else {
		pr_error(ctx, "change from directory `%s' to `%s' failed: %s", oldcwd, dir, strerror(errno));
	}

	free(oldcwd);
}

bool fastd_read_config(fastd_context_t *ctx, fastd_config_t *conf, const char *filename, bool peer_config, int depth) {
	if (depth >= MAX_CONFIG_DEPTH)
		exit_error(ctx, "maximum config include depth exceeded");

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
			pr_error(ctx, "can't open config file `%s': %s", filename, strerror(errno));
			ret = false;
			goto end_free;
		}
	}

	lex = fastd_lex_init(file);

	if (filename) {
		filename2 = strdup(filename);
		dir = dirname(filename2);

		if (chdir(dir)) {
			pr_error(ctx, "change from directory `%s' to `%s' failed", oldcwd, dir);
			ret = false;
			goto end_free;
		}
	}

	int token;
	YYSTYPE token_val;
	YYLTYPE loc = {1, 0, 1, 0};

	if (peer_config)
		token = START_PEER_CONFIG;
	else
		token = conf->peer_group->parent ? START_PEER_GROUP_CONFIG : START_CONFIG;

	int parse_ret = fastd_config_push_parse(ps, token, &token_val, &loc, ctx, conf, filename, depth+1);

	while(parse_ret == YYPUSH_MORE) {
		token = fastd_lex(&token_val, &loc, lex);

		if (token < 0) {
			pr_error(ctx, "config error: %s at %s:%i:%i", token_val.error, filename, loc.first_line, loc.first_column);
			ret = false;
			goto end_free;
		}

		if (token == TOK_STRING) {
			token_val.str->next = strings;
			strings = token_val.str;
		}

		parse_ret = fastd_config_push_parse(ps, token, &token_val, &loc, ctx, conf, filename, depth+1);
	}

	if (parse_ret)
		ret = false;

 end_free:
	fastd_string_stack_free(strings);

	fastd_lex_destroy(lex);
	fastd_config_pstate_delete(ps);

	if(chdir(oldcwd))
		pr_error(ctx, "can't chdir to `%s': %s", oldcwd, strerror(errno));

	free(filename2);
	free(oldcwd);

	if (filename && file)
		fclose(file);

	return ret;
}

static void assess_peers(fastd_context_t *ctx, fastd_config_t *conf) {
	conf->has_floating = false;

	fastd_peer_config_t *peer;
	for (peer = conf->peers; peer; peer = peer->next) {
		if (fastd_peer_config_is_floating(peer))
			conf->has_floating = true;

		if (peer->dynamic_float_deprecated)
			pr_warn(ctx, "peer `%s' uses deprecated float syntax, please update your configuration", peer->name);
	}
}


static void configure_user(fastd_context_t *ctx, fastd_config_t *conf) {
	conf->uid = getuid();
	conf->gid = getgid();

	if (conf->user) {
		struct passwd pwd, *pwdr;
		size_t bufspace = 1024;
		int error;

		do {
			char buf[bufspace];
			error = getpwnam_r(conf->user, &pwd, buf, bufspace, &pwdr);
			bufspace *= 2;
		} while(error == ERANGE);

		if (error)
			exit_errno(ctx, "getpwnam_r");

		if (!pwdr)
			exit_error(ctx, "config error: unable to find user `%s'.", conf->user);

		conf->uid = pwdr->pw_uid;
		conf->gid = pwdr->pw_gid;
	}

	if (conf->group) {
		struct group grp, *grpr;
		size_t bufspace = 1024;
		int error;

		do {
			char buf[bufspace];
			error = getgrnam_r(conf->group, &grp, buf, bufspace, &grpr);
			bufspace *= 2;
		} while(error == ERANGE);

		if (error)
			exit_errno(ctx, "getgrnam_r");

		if (!grpr)
			exit_error(ctx, "config error: unable to find group `%s'.", conf->group);

		conf->gid = grpr->gr_gid;
	}

	if (conf->user) {
		int ngroups = 0;
		if (getgrouplist(conf->user, conf->gid, NULL, &ngroups) < 0) {
			/* the user has supplementary groups */

			conf->groups = calloc(ngroups, sizeof(gid_t));
			if (getgrouplist(conf->user, conf->gid, conf->groups, &ngroups) < 0)
				exit_errno(ctx, "getgrouplist");

			conf->n_groups = ngroups;
		}
	}
}

static void configure_method_parameters(fastd_config_t *conf) {
	conf->max_overhead = 0;
	conf->min_encrypt_head_space = 0;
	conf->min_decrypt_head_space = 0;
	conf->min_encrypt_tail_space = 0;
	conf->min_decrypt_tail_space = 0;

	size_t i;
	for (i = 0; conf->methods[i].name; i++) {
		const fastd_method_provider_t *provider = conf->methods[i].provider;

		conf->max_overhead = max_size_t(conf->max_overhead, provider->max_overhead);
		conf->min_encrypt_head_space = max_size_t(conf->min_encrypt_head_space, provider->min_encrypt_head_space);
		conf->min_decrypt_head_space = max_size_t(conf->min_decrypt_head_space, provider->min_decrypt_head_space);
		conf->min_encrypt_tail_space = max_size_t(conf->min_encrypt_tail_space, provider->min_encrypt_tail_space);
		conf->min_decrypt_tail_space = max_size_t(conf->min_decrypt_tail_space, provider->min_decrypt_tail_space);
	}

	conf->min_encrypt_head_space = alignto(conf->min_encrypt_head_space, 16);

	/* ugly hack to get alignment right for aes128-gcm, which needs data aligned to 16 and has a 24 byte header */
	conf->min_decrypt_head_space = alignto(conf->min_decrypt_head_space, 16) + 8;
}

static void configure_methods(fastd_context_t *ctx, fastd_config_t *conf) {
	size_t n_methods = 0, i;
	fastd_string_stack_t *method_name;
	for (method_name = conf->method_list; method_name; method_name = method_name->next)
		n_methods++;

	conf->methods = calloc(n_methods+1, sizeof(fastd_method_info_t));

	for (i = 0, method_name = conf->method_list; method_name; i++, method_name = method_name->next) {
		conf->methods[i].name = method_name->str;
		if (!fastd_method_create_by_name(method_name->str, &conf->methods[i].provider, &conf->methods[i].method))
			exit_error(ctx, "config error: method `%s' not supported", method_name->str);
	}

	configure_method_parameters(conf);
}

static void destroy_methods(fastd_config_t *conf) {
	size_t i;
	for (i = 0; conf->methods[i].name; i++) {
		conf->methods[i].provider->destroy(conf->methods[i].method);
	}

	free(conf->methods);
}

void fastd_configure(fastd_context_t *ctx, fastd_config_t *conf, int argc, char *const argv[]) {
	default_config(conf);

	fastd_config_handle_options(ctx, conf, argc, argv);

	if (!conf->log_stderr_level && !conf->log_syslog_level && !conf->log_files)
		conf->log_stderr_level = FASTD_DEFAULT_LOG_LEVEL;
}

static void config_check_base(fastd_context_t *ctx, fastd_config_t *conf) {
	if (conf->ifname) {
		if (strchr(conf->ifname, '/'))
			exit_error(ctx, "config error: invalid interface name");
	}

	if (conf->mode == MODE_TUN) {
		if (conf->peers->next)
			exit_error(ctx, "config error: in TUN mode exactly one peer must be configured");
		if (conf->peer_group->children)
			exit_error(ctx, "config error: in TUN mode peer groups can't be used");
		if (has_peer_group_peer_dirs(conf->peer_group))
			exit_error(ctx, "config error: in TUN mode peer directories can't be used");
	}

#ifndef USE_PMTU
	if (conf->pmtu.set)
		exit_error(ctx, "config error: setting pmtu is not supported on this system");
#endif

#ifndef USE_PACKET_MARK
	if (conf->packet_mark)
		exit_error(ctx, "config error: setting a packet mark is not supported on this system");
#endif
}

void fastd_config_check(fastd_context_t *ctx, fastd_config_t *conf) {
	config_check_base(ctx, conf);

	if (conf->mode == MODE_TUN) {
		if (!conf->peers)
			exit_error(ctx, "config error: in TUN mode exactly one peer must be configured");
	}

	if (!conf->peers && !has_peer_group_peer_dirs(conf->peer_group))
		exit_error(ctx, "config error: neither fixed peers nor peer dirs have been configured");

	if (!conf->method_list) {
		pr_warn(ctx, "no encryption method configured, falling back to method `null' (unencrypted)");
		fastd_config_method(ctx, conf, "null");
	}

	if (!conf->secure_handshakes_set)
		pr_warn(ctx, "`secure handshakes' not set, please read the documentation about this option; defaulting to no");

	configure_user(ctx, conf);
	configure_methods(ctx, conf);
}

void fastd_config_verify(fastd_context_t *ctx, fastd_config_t *conf) {
	config_check_base(ctx, conf);
	configure_methods(ctx, conf);

	fastd_peer_config_t *peer;
	for (peer = conf->peers; peer; peer = peer->next)
		conf->protocol->peer_verify(ctx, peer);
}

static void peer_dirs_read_peer_group(fastd_context_t *ctx, fastd_config_t *new_conf) {
	read_peer_dirs(ctx, new_conf);

	fastd_peer_group_config_t *group;
	for (group = new_conf->peer_group->children; group; group = group->next) {
		new_conf->peer_group = group;
		peer_dirs_read_peer_group(ctx, new_conf);
	}
}

static void peer_dirs_handle_old_peers(fastd_context_t *ctx, fastd_peer_config_t **old_peers, fastd_peer_config_t **new_peers) {
	fastd_peer_config_t **peer, **next, **new_peer, **new_next;
	for (peer = old_peers; *peer; peer = next) {
		next = &(*peer)->next;

		/* don't touch statically configured peers */
		if (!(*peer)->config_source_dir)
			continue;

		/* search for each peer in the list of new peers */
		for (new_peer = new_peers; *new_peer; new_peer = new_next) {
			new_next = &(*new_peer)->next;

			if (((*peer)->config_source_dir == (*new_peer)->config_source_dir) && strequal((*peer)->name, (*new_peer)->name)) {
				if (fastd_peer_config_equal(*peer, *new_peer)) {
					pr_verbose(ctx, "peer `%s' unchanged", (*peer)->name);

					fastd_peer_config_t *free_peer = *new_peer;
					*new_peer = *new_next;
					fastd_peer_config_free(free_peer);
					peer = NULL;
				}
				else {
					pr_verbose(ctx, "peer `%s' changed, resetting", (*peer)->name);
					new_peer = NULL;
				}

				break;
			}
		}

		/* no new peer was found, or the old one has changed */
		if (peer && (!new_peer || !*new_peer)) {
			pr_verbose(ctx, "removing peer `%s'", (*peer)->name);

			fastd_peer_config_t *free_peer = *peer;
			*peer = *next;
			next = peer;

			fastd_peer_config_purge(ctx, free_peer);
		}
	}
}

static void peer_dirs_handle_new_peers(fastd_context_t *ctx UNUSED, fastd_peer_config_t **peers, fastd_peer_config_t *new_peers) {
	fastd_peer_config_t *peer;
	for (peer = new_peers; peer; peer = peer->next) {
		if (peer->next)
			continue;

		peer->next = *peers;
		*peers = new_peers;
		return;
	}
}

void fastd_config_load_peer_dirs(fastd_context_t *ctx, fastd_config_t *conf) {
	fastd_config_t temp_conf;
	temp_conf.peer_group = conf->peer_group;
	temp_conf.peers = NULL;

	peer_dirs_read_peer_group(ctx, &temp_conf);
	peer_dirs_handle_old_peers(ctx, &conf->peers, &temp_conf.peers);
	peer_dirs_handle_new_peers(ctx, &conf->peers, temp_conf.peers);

	assess_peers(ctx, conf);
}

void fastd_config_release(fastd_context_t *ctx, fastd_config_t *conf) {
	while (conf->peers)
		fastd_peer_config_delete(ctx, conf);

	while (conf->log_files) {
		fastd_log_file_t *next = conf->log_files->next;
		free(conf->log_files->filename);
		free(conf->log_files);
		conf->log_files = next;
	}

	while (conf->bind_addrs) {
		fastd_bind_address_t *next = conf->bind_addrs->next;
		free(conf->bind_addrs->bindtodev);
		free(conf->bind_addrs);
		conf->bind_addrs = next;
	}

	free_peer_group(conf->peer_group);

	destroy_methods(conf);
	fastd_string_stack_free(conf->method_list);

	fastd_mac_config_free(conf->macs);
	fastd_cipher_config_free(conf->ciphers);

	free(conf->user);
	free(conf->group);
	free(conf->groups);
	free(conf->ifname);
	free(conf->secret);
	free(conf->on_pre_up);
	free(conf->on_pre_up_dir);
	free(conf->on_up);
	free(conf->on_up_dir);
	free(conf->on_down);
	free(conf->on_down_dir);
	free(conf->on_post_down);
	free(conf->on_post_down_dir);
	free(conf->on_establish);
	free(conf->on_establish_dir);
	free(conf->on_disestablish);
	free(conf->on_disestablish_dir);
	free(conf->on_verify);
	free(conf->on_verify_dir);
	free(conf->protocol_config);
	free(conf->log_syslog_ident);
}
