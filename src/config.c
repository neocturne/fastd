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


extern fastd_protocol fastd_protocol_null;

#ifdef WITH_PROTOCOL_ECFXP
extern fastd_protocol fastd_protocol_ec25519_fhmqvc_xsalsa20_poly1305;
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

	conf->peer_to_peer = false;

	conf->protocol = &fastd_protocol_null;
	conf->secret = NULL;
	conf->key_valid = 3600;		/* 60 minutes */
	conf->key_refresh = 3300;	/* 55 minutes */

	conf->peers = NULL;

	conf->on_up = NULL;
	conf->on_up_dir = NULL;
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

void fastd_read_config_dir(fastd_context *ctx, fastd_config *conf, const char *dir, int depth) {
	if (depth >= MAX_CONFIG_DEPTH)
		exit_error(ctx, "maximum config include depth exceeded");

	char *oldcwd = get_current_dir_name();

	if (chdir(dir))
		exit_error(ctx, "change from directory `%s' to `%s' failed: %s", oldcwd, dir, strerror(errno));

	DIR *dirh = opendir(".");

	if (!dirh)
		exit_error(ctx, "opendir for `%s' failed: %s", dir, strerror(errno));

	while (true) {
		struct dirent entry, *result;
		int ret;

		ret = readdir_r(dirh, &entry, &result);
		if (ret)
			exit_error(ctx, "readdir_r: %s", strerror(ret));

		if (!result)
			break;
		if (result->d_name[0] == '.')
			continue;

		struct stat statbuf;
		if (stat(result->d_name, &statbuf)) {
			pr_info(ctx, "ignoring file `%s': stat failed: %s", result->d_name, strerror(errno));
			continue;
		}
		if ((statbuf.st_mode & S_IFMT) != S_IFREG) {
			pr_info(ctx, "ignoring file `%s': no regular file", result->d_name);
			continue;
		}

		fastd_peer_config_new(ctx, conf);
		conf->peers->name = strdup(result->d_name);
		conf->peers->config_source_dir = strdup(dir);

		if (!fastd_read_config(ctx, conf, result->d_name, true, depth)) {
			pr_warn(ctx, "peer config %s will be ignored", result->d_name);
			fastd_peer_config_delete(ctx, conf);
		}
	}

	closedir(dirh);

	chdir(oldcwd);
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
	fastd_config_str *strings = NULL;

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
	fastd_config_str_free(strings);

	fastd_config_pstate_delete(ps);
	fastd_config_yylex_destroy(scanner);

	chdir(oldcwd);

	free(filename2);
	free(oldcwd);

	if (filename && file)
		fclose(file);

	return ret;
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

	fastd_peer_config *peer;
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
			fastd_read_config_dir(ctx, conf, arg, 0);
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
			if (!strcmp(arg, "null"))
				conf->protocol = &fastd_protocol_null;
#ifdef WITH_PROTOCOL_ECFXP
			else if (!strcmp(arg, "ecfxp"))
				conf->protocol = &fastd_protocol_ec25519_fhmqvc_xsalsa20_poly1305;
#endif
			else
				exit_error(ctx, "invalid protocol `%s'", arg);
			continue;
		}

		IF_OPTION_ARG("-p", "--peer") {
			peer = fastd_peer_config_new(ctx, conf);

			if (strcmp(arg, "float") == 0)
				continue;

			if (arg[0] == '[') {
				charptr = strchr(arg, ']');
				if (!charptr || (charptr[1] != ':'))
					exit_error(ctx, "invalid peer address `%s'", arg);

				addrstr = strndup(arg+1, charptr-arg-1);
				charptr++;
			}
			else {
				charptr = strchr(arg, ':');
				if (!charptr)
					exit_error(ctx, "invalid peer address `%s'", arg);

				addrstr = strndup(arg, charptr-arg);
			}

			l = strtol(charptr+1, &endptr, 10);
			if (*endptr || l < 0 || l > 65535)
				exit_error(ctx, "invalid peer port `%s'", charptr+1);

			if (arg[0] == '[') {
				peer->address.in6.sin6_family = AF_INET6;
				if (inet_pton(AF_INET6, addrstr, &peer->address.in6.sin6_addr) != 1)
					exit_error(ctx, "invalid peer address `%s'", addrstr);
				peer->address.in6.sin6_port = htons(l);
			}
			else {
				peer->address.in.sin_family = AF_INET;
				if (inet_pton(AF_INET, addrstr, &peer->address.in.sin_addr) != 1)
					exit_error(ctx, "invalid peer address `%s'", addrstr);
				peer->address.in.sin_port = htons(l);
			}

			free(addrstr);
			continue;
		}

		IF_OPTION("--peer-to-peer") {
			conf->peer_to_peer = true;
			continue;
		}

		IF_OPTION_ARG("--on-up") {
			free(conf->on_up);
			free(conf->on_up_dir);

			conf->on_up = strdup(arg);
			conf->on_up_dir = get_current_dir_name();

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

	conf->n_floating = 0;
	conf->n_v4 = 0;
	conf->n_v6 = 0;

	for (peer = conf->peers; peer; peer = peer->next) {
		switch (peer->address.sa.sa_family) {
		case AF_UNSPEC:
			conf->n_floating++;
			break;

		case AF_INET:
			conf->n_v4++;
			break;

		case AF_INET6:
			conf->n_v6++;
			break;

		default:
			exit_bug(ctx, "invalid peer address family");
		}
	}

	if (conf->n_floating && conf->bind_addr_in.sin_family == AF_UNSPEC
	    && conf->bind_addr_in6.sin6_family == AF_UNSPEC) {
		conf->bind_addr_in.sin_family = AF_INET;
		conf->bind_addr_in6.sin6_family = AF_INET6;
	}
	else {
		if (conf->n_v4)
			conf->bind_addr_in.sin_family = AF_INET;

		if (conf->n_v6)
			conf->bind_addr_in6.sin6_family = AF_INET6;
	}

	if (conf->mode == MODE_TUN && (!conf->peers || conf->peers->next))
		exit_error(ctx, "config error: for tun mode exactly one peer must be configured");

	conf->protocol->init(ctx, conf);
}
