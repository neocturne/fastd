/*
  Copyright (c) 2012, Matthias Schiffer <mschiffer@universe-factory.net>
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


#define _GNU_SOURCE

#include "fastd.h"
#include "peer.h"
#include <config.ll.h>
#include <config.yy.h>

#include <config.h>

#include <arpa/inet.h>
#include <dirent.h>
#include <libgen.h>
#include <stdarg.h>
#include <sys/stat.h>
#include <sys/types.h>


extern const fastd_protocol fastd_protocol_ec25519_fhmqvc;

extern const fastd_method fastd_method_null;

#ifdef WITH_METHOD_XSALSA20_POLY1305
extern const fastd_method fastd_method_xsalsa20_poly1305;
#endif


static void default_config(fastd_config *conf) {
	conf->loglevel = LOG_INFO;

	conf->keepalive_interval = 60;
	conf->peer_stale_time = 300;
	conf->peer_stale_time_temp = 30;
	conf->eth_addr_stale_time = 300;

	conf->ifname = NULL;

	memset(&conf->bind_addr_in, 0, sizeof(struct sockaddr_in));
	memset(&conf->bind_addr_in6, 0, sizeof(struct sockaddr_in6));

	conf->mtu = 1500;
	conf->mode = MODE_TAP;

	conf->forward = false;

	conf->protocol = &fastd_protocol_ec25519_fhmqvc;
	conf->method = &fastd_method_null;
	conf->secret = NULL;
	conf->key_valid = 3600;		/* 60 minutes */
	conf->key_refresh = 3300;	/* 55 minutes */

	conf->peer_dirs = NULL;
	conf->peers = NULL;

	conf->on_up = NULL;
	conf->on_up_dir = NULL;

	conf->on_down = NULL;
	conf->on_down_dir = NULL;

	conf->on_establish = NULL;
	conf->on_establish_dir = NULL;

	conf->on_disestablish = NULL;
	conf->on_disestablish_dir = NULL;

}

static bool config_match(const char *opt, ...) {
	va_list ap;
	bool match = false;
	const char *str;
	
	va_start(ap, opt);

	while((str = va_arg(ap, const char*)) != NULL) {
		if (strcmp(opt, str) == 0) {
			match = true;
			break;
		}
	}

	va_end(ap);

	return match;
}

bool fastd_config_protocol(fastd_context *ctx, fastd_config *conf, const char *name) {
	if (!strcmp(name, "ec25519-fhmqvc"))
		conf->protocol = &fastd_protocol_ec25519_fhmqvc;
	else
		return false;

	return true;
}

bool fastd_config_method(fastd_context *ctx, fastd_config *conf, const char *name) {
	if (!strcmp(name, "null"))
		conf->method = &fastd_method_null;
#ifdef WITH_METHOD_XSALSA20_POLY1305
	else if (!strcmp(name, "xsalsa20-poly1305"))
		conf->method = &fastd_method_xsalsa20_poly1305;
#endif
	else
		return false;

	return true;
}

static void read_peer_dir(fastd_context *ctx, fastd_config *conf, const char *dir) {
	DIR *dirh = opendir(".");

	if (dirh) {
		while (true) {
			struct dirent entry, *result;
			int ret;

			ret = readdir_r(dirh, &entry, &result);
			if (ret) {
				pr_error(ctx, "readdir_r: %s", strerror(ret));
				break;
			}

			if (!result)
				break;
			if (result->d_name[0] == '.')
				continue;

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

		closedir(dirh);
	}
	else {
		pr_error(ctx, "opendir for `%s' failed: %s", dir, strerror(errno));
	}
}

void fastd_read_peer_dir(fastd_context *ctx, fastd_config *conf, const char *dir) {
	char *oldcwd = get_current_dir_name();

	if (!chdir(dir)) {
		char *newdir = get_current_dir_name();
		conf->peer_dirs = fastd_string_stack_push(conf->peer_dirs, newdir);
		free(newdir);

		read_peer_dir(ctx, conf, conf->peer_dirs->str);

		if(chdir(oldcwd))
			pr_error(ctx, "can't chdir to `%s': %s", oldcwd, strerror(errno));
	}
	else {
		pr_error(ctx, "change from directory `%s' to `%s' failed: %s", oldcwd, dir, strerror(errno));
	}

	free(oldcwd);
}

bool fastd_read_config(fastd_context *ctx, fastd_config *conf, const char *filename, bool peer_config, int depth) {
	if (depth >= MAX_CONFIG_DEPTH)
		exit_error(ctx, "maximum config include depth exceeded");

	bool ret = true;
	char *oldcwd = get_current_dir_name();
	char *filename2 = NULL;
	char *dir = NULL;
	FILE *file;
	yyscan_t scanner;
	fastd_config_pstate *ps;
	fastd_string_stack *strings = NULL;

	fastd_config_yylex_init(&scanner);
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

	fastd_config_yyset_in(file, scanner);

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
		token = START_CONFIG;

	int parse_ret = fastd_config_push_parse(ps, token, &token_val, &loc, ctx, conf, filename, depth+1);

	while(parse_ret == YYPUSH_MORE) {
		token = fastd_config_yylex(&token_val, &loc, scanner);

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

	fastd_config_pstate_delete(ps);
	fastd_config_yylex_destroy(scanner);

	if(chdir(oldcwd))
		pr_error(ctx, "can't chdir to `%s': %s", oldcwd, strerror(errno));

	free(filename2);
	free(oldcwd);

	if (filename && file)
		fclose(file);

	return ret;
}

static void count_peers(fastd_context *ctx, fastd_config *conf) {
	conf->n_floating = 0;
	conf->n_v4 = 0;
	conf->n_v6 = 0;
	conf->n_dynamic = 0;
	conf->n_dynamic_v4 = 0;
	conf->n_dynamic_v6 = 0;

	fastd_peer_config *peer;
	for (peer = conf->peers; peer; peer = peer->next) {
		switch (peer->address.sa.sa_family) {
		case AF_UNSPEC:
			if (peer->hostname)
				conf->n_dynamic++;
			else
				conf->n_floating++;
			break;

		case AF_INET:
			if (peer->hostname)
				conf->n_dynamic_v4++;
			else
				conf->n_v4++;
			break;

		case AF_INET6:
			if (peer->hostname)
				conf->n_dynamic_v6++;
			else
				conf->n_v6++;
			break;

		default:
			exit_bug(ctx, "invalid peer address family");
		}
	}
}

#define IF_OPTION(args...) if(config_match(argv[i], args, NULL) && (++i))
#define IF_OPTION_ARG(args...) if(config_match(argv[i], args, NULL) && ({ \
				arg = argv[i+1];			\
				i+=2;					\
				if (i > argc)				\
					exit_error(ctx, "config error: option `%s' needs an argument", argv[i-2]); \
				true;					\
			}))
#define IGNORE_OPTION (i++)

void fastd_configure(fastd_context *ctx, fastd_config *conf, int argc, char *const argv[]) {
	default_config(conf);

	int i = 1;
	const char *arg;
	long l;
	char *charptr;
	char *endptr;
	char *addrstr;
	bool keygen = false;


	while (i < argc) {
		IF_OPTION_ARG("--log-level") {
			if (!strcmp(arg, "fatal"))
				conf->loglevel = LOG_FATAL;
			else if (!strcmp(arg, "error"))
				conf->loglevel = LOG_ERROR;
			else if (!strcmp(arg, "warn"))
				conf->loglevel = LOG_WARN;
			else if (!strcmp(arg, "info"))
				conf->loglevel = LOG_INFO;
			else if (!strcmp(arg, "verbose"))
				conf->loglevel = LOG_VERBOSE;
			else if (!strcmp(arg, "debug"))
				conf->loglevel = LOG_DEBUG;
			else
				exit_error(ctx, "invalid mode `%s'", arg);
			continue;
		}

		IF_OPTION_ARG("-c", "--config") {
			const char *filename = arg;
			if (!strcmp(arg, "-"))
				filename = NULL;

			if (!fastd_read_config(ctx, conf, filename, false, 0))
				exit(1);
			continue;
		}

		IF_OPTION_ARG("--config-peer") {
			fastd_peer_config_new(ctx, conf);

			if(!fastd_read_config(ctx, conf, arg, true, 0))
				exit(1);
			continue;
		}

		IF_OPTION_ARG("--config-peer-dir") {
			fastd_read_peer_dir(ctx, conf, arg);
			continue;
		}

		IF_OPTION_ARG("-i", "--interface") {
			free(conf->ifname);
			conf->ifname = strdup(arg);
			continue;
		}

		IF_OPTION_ARG("-b", "--bind") {
			if (arg[0] == '[') {
				charptr = strchr(arg, ']');
				if (!charptr || (charptr[1] != ':' && charptr[1] != '\0'))
					exit_error(ctx, "invalid bind address `%s'", arg);

				addrstr = strndup(arg+1, charptr-arg-1);
			
				if (charptr[1] == ':')
					charptr++;
				else
					charptr = NULL;
			}
			else {
				charptr = strchr(arg, ':');
				if (charptr) {
					addrstr = strndup(arg, charptr-arg);
				}
				else {
					addrstr = strdup(arg);
				}
			}

			if (charptr) {
				l = strtol(charptr+1, &endptr, 10);
				if (*endptr || l < 0 || l > 65535)
					exit_error(ctx, "invalid bind port `%s'", charptr+1);
			}
			else {
				l = 0;
			}

			if (strcmp(addrstr, "any") == 0) {
				conf->bind_addr_in.sin_addr.s_addr = htonl(INADDR_ANY);
				conf->bind_addr_in.sin_port = htons(l);

				conf->bind_addr_in6.sin6_addr = in6addr_any;
				conf->bind_addr_in6.sin6_port = htons(l);
			}
			else if (arg[0] == '[') {
				conf->bind_addr_in6.sin6_family = AF_INET6;
				if (inet_pton(AF_INET6, addrstr, &conf->bind_addr_in6.sin6_addr) != 1)
					exit_error(ctx, "invalid bind address `%s'", addrstr);
				conf->bind_addr_in6.sin6_port = htons(l);
			}
			else {
				conf->bind_addr_in.sin_family = AF_INET;
				if (inet_pton(AF_INET, addrstr, &conf->bind_addr_in.sin_addr) != 1)
					exit_error(ctx, "invalid bind address `%s'", addrstr);
				conf->bind_addr_in.sin_port = htons(l);
			}

			free(addrstr);

			continue;
		}

		IF_OPTION_ARG("-M", "--mtu") {
			conf->mtu = strtol(arg, &endptr, 10);
			if (*endptr || conf->mtu < 576)
				exit_error(ctx, "invalid mtu `%s'", arg);
			continue;
		}

		IF_OPTION_ARG("-m", "--mode") {
			if (!strcmp(arg, "tap"))
				conf->mode = MODE_TAP;
			else if (!strcmp(arg, "tun"))
				conf->mode = MODE_TUN;
			else
				exit_error(ctx, "invalid mode `%s'", arg);
			continue;
		}


		IF_OPTION_ARG("-P", "--protocol") {
			if (!fastd_config_protocol(ctx, conf, arg))
				exit_error(ctx, "invalid protocol `%s'", arg);
			continue;
		}

		IF_OPTION_ARG("--method") {
			if (!fastd_config_method(ctx, conf, arg))
				exit_error(ctx, "invalid method `%s'", arg);
			continue;
		}

		IF_OPTION("--forward") {
			conf->forward = true;
			continue;
		}

		IF_OPTION_ARG("--on-up") {
			free(conf->on_up);
			free(conf->on_up_dir);

			conf->on_up = strdup(arg);
			conf->on_up_dir = get_current_dir_name();

			continue;
		}

		IF_OPTION_ARG("--on-down") {
			free(conf->on_down);
			free(conf->on_down_dir);

			conf->on_down = strdup(arg);
			conf->on_down_dir = get_current_dir_name();

			continue;
		}

		IF_OPTION_ARG("--on-establish") {
			free(conf->on_establish);
			free(conf->on_establish_dir);

			conf->on_establish = strdup(arg);
			conf->on_establish_dir = get_current_dir_name();

			continue;
		}

		IF_OPTION_ARG("--on-disestablish") {
			free(conf->on_disestablish);
			free(conf->on_disestablish_dir);

			conf->on_disestablish = strdup(arg);
			conf->on_disestablish_dir = get_current_dir_name();

			continue;
		}

		IF_OPTION("--generate-key") {
			keygen = true;
			continue;
		}

		exit_error(ctx, "config error: unknown option `%s'", argv[i]);
	}

	if (keygen) {
		ctx->conf = conf;
		conf->protocol->generate_key(ctx);
		exit(0);
	}

	if (conf->mode == MODE_TUN) {
		if (!conf->peers || conf->peers->next)
			exit_error(ctx, "config error: for tun mode exactly one peer must be configured");
		if (conf->peer_dirs)
			exit_error(ctx, "config error: for tun mode peer directories can't be used");
	}

	if (!conf->peers && !conf->peer_dirs)
		exit_error(ctx, "config error: neither fixed peers nor peer dirs have been configured");

	count_peers(ctx, conf);
}

static void reconfigure_read_peer_dirs(fastd_context *ctx, fastd_config *new_conf, fastd_string_stack *dirs) {
	char *oldcwd = get_current_dir_name();

	fastd_string_stack *dir;
	for (dir = dirs; dir; dir = dir->next) {
		if (!chdir(dir->str))
			read_peer_dir(ctx, new_conf, dir->str);
		else
			pr_error(ctx, "change from directory `%s' to `%s' failed: %s", oldcwd, dir->str, strerror(errno));
	}

	if (chdir(oldcwd))
		pr_error(ctx, "can't chdir to `%s': %s", oldcwd, strerror(errno));

	free(oldcwd);
}

static void reconfigure_handle_old_peers(fastd_context *ctx, fastd_peer_config **old_peers, fastd_peer_config **new_peers) {
	fastd_peer_config **peer, **next, **new_peer, **new_next;
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
					pr_debug(ctx, "peer `%s' unchanged", (*peer)->name);

					fastd_peer_config *free_peer = *new_peer;
					*new_peer = *new_next;
					fastd_peer_config_free(free_peer);
					peer = NULL;
				}
				else {
					pr_debug(ctx, "peer `%s' changed, resetting", (*peer)->name);
					new_peer = NULL;
				}

				break;
			}
		}

		/* no new peer was found, or the old one has changed */
		if (peer && (!new_peer || !*new_peer)) {
			pr_debug(ctx, "removing peer `%s'", (*peer)->name);

			fastd_peer_config *free_peer = *peer;
			*peer = *next;
			next = peer;

			fastd_peer_config_purge(ctx, free_peer);
		}
	}
}

static void reconfigure_reset_waiting(fastd_context *ctx) {
	fastd_peer *peer;
	for (peer = ctx->peers; peer; peer = peer->next) {
		if (fastd_peer_is_waiting(peer))
			fastd_peer_reset(ctx, peer);
	}
}

static void reconfigure_handle_new_peers(fastd_context *ctx, fastd_peer_config **peers, fastd_peer_config *new_peers) {
	fastd_peer_config *peer, *next;
	for (peer = new_peers; peer; peer = next) {
		next = peer->next;

		ctx->conf->protocol->peer_configure(ctx, peer);
		if (peer->enabled)
			fastd_peer_add(ctx, peer);

		peer->next = *peers;
		*peers = peer;
	}
}

void fastd_reconfigure(fastd_context *ctx, fastd_config *conf) {
	pr_info(ctx, "reconfigure triggered");

	fastd_config temp_conf;
	temp_conf.peers = NULL;

	reconfigure_read_peer_dirs(ctx, &temp_conf, conf->peer_dirs);
	reconfigure_handle_old_peers(ctx, &conf->peers, &temp_conf.peers);

	reconfigure_reset_waiting(ctx);

	reconfigure_handle_new_peers(ctx, &conf->peers, temp_conf.peers);

	count_peers(ctx, conf);

}

void fastd_config_release(fastd_context *ctx, fastd_config *conf) {
	while (conf->peers)
		fastd_peer_config_delete(ctx, conf);

	fastd_string_stack_free(conf->peer_dirs);

	free(conf->ifname);
	free(conf->secret);
	free(conf->on_up);
	free(conf->on_up_dir);
	free(conf->on_down);
	free(conf->on_down_dir);
	free(conf->on_establish);
	free(conf->on_establish_dir);
	free(conf->on_disestablish);
	free(conf->on_disestablish_dir);
	free(conf->protocol_config);
}
