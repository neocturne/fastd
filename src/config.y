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


%define api.pure
%define api.push-pull push
%name-prefix "fastd_config_"
%locations
%parse-param {fastd_context *ctx}
%parse-param {fastd_config *conf}
%parse-param {const char *filename}
%parse-param {int depth}

%code requires {
	#define _GNU_SOURCE

	#include <fastd.h>
	#include <arpa/inet.h>
}

%union {
	int num;
	fastd_string_stack *str;
	char *error;
	bool boolean;
	struct in_addr addr4;
	struct in6_addr addr6;
	fastd_peer_address addr;
}

%token START_CONFIG
%token START_PEER_CONFIG

%token <num> TOK_INTEGER
%token <str> TOK_STRING

%token TOK_INTERFACE
%token TOK_BIND
%token TOK_MTU
%token TOK_MODE
%token TOK_PROTOCOL
%token TOK_METHOD
%token TOK_PEER
%token TOK_REMOTE
%token TOK_IPV4
%token TOK_IPV6
%token TOK_SECRET
%token TOK_KEY
%token TOK_INCLUDE
%token TOK_AS
%token TOK_ANY
%token TOK_TAP
%token TOK_TUN
%token TOK_ON
%token TOK_UP
%token TOK_DOWN
%token TOK_ESTABLISH
%token TOK_DISESTABLISH
%token TOK_PEERS
%token TOK_FROM
%token TOK_LOG
%token TOK_LEVEL
%token TOK_SYSLOG
%token TOK_STDERR
%token TOK_TO
%token TOK_FATAL
%token TOK_ERROR
%token TOK_WARN
%token TOK_INFO
%token TOK_VERBOSE
%token TOK_DEBUG
%token TOK_FORWARD
%token TOK_YES
%token TOK_NO
%token TOK_PORT
%token TOK_FLOAT
%token TOK_CRYPTO
%token TOK_USE
%token TOK_DEFAULT

%token <addr4> TOK_ADDR4
%token <addr6> TOK_ADDR6


%code {
	#include <peer.h>

	#include <stdint.h>
	#include <unistd.h>

	void fastd_config_error(YYLTYPE *loc, fastd_context *ctx, fastd_config *conf, const char *filename, int depth, char *s);
}


%type <num> maybe_log_level
%type <num> log_level
%type <num> port
%type <boolean> boolean
%type <num> maybe_port
%type <str> maybe_as
%type <num> maybe_af
%type <boolean> maybe_float
%type <addr> bind_address
%type <str> maybe_bind_interface
%type <num> maybe_bind_default
%type <num> bind_default

%%
start:		START_CONFIG config
	|	START_PEER_CONFIG peer_conf
	;

config:		config statement
	|
	;

statement:	TOK_LOG log ';'
	| 	TOK_INTERFACE interface ';'
	| 	TOK_BIND bind ';'
	|	TOK_MTU mtu ';'
	|	TOK_MODE mode ';'
	|	TOK_PROTOCOL protocol ';'
	|	TOK_METHOD method ';'
	|	TOK_CRYPTO crypto ';'
	|	TOK_SECRET secret ';'
	|	TOK_ON TOK_UP on_up ';'
	|	TOK_ON TOK_DOWN on_down ';'
	|	TOK_ON TOK_ESTABLISH on_establish ';'
	|	TOK_ON TOK_DISESTABLISH on_disestablish ';'
	|	TOK_PEER peer '{' peer_conf '}'
	|	TOK_FORWARD forward ';'
	|	TOK_INCLUDE include ';'
	;

log:		TOK_LEVEL log_level {
			conf->log_stderr_level = $2;
		}
	|	TOK_TO TOK_STDERR maybe_log_level {
			conf->log_stderr_level = $3;
		}
	|	TOK_TO TOK_SYSLOG maybe_log_level {
			conf->log_syslog_level = $3;
		}
	|	TOK_TO TOK_SYSLOG TOK_AS TOK_STRING maybe_log_level {
			free(conf->log_syslog_ident);
			conf->log_syslog_ident = strdup($4->str);

			conf->log_syslog_level = $5;
		}
	|	TOK_TO TOK_STRING maybe_log_level {
			if (!fastd_config_add_log_file(ctx, conf, $2->str, $3)) {
				fastd_config_error(&@$, ctx, conf, filename, depth, "unable to set log file");
				YYERROR;
			}
		}
	;

maybe_log_level:
		TOK_LEVEL log_level	{ $$ = $2; }
	|				{ $$ = FASTD_DEFAULT_LOG_LEVEL; }
	;

log_level:	TOK_FATAL	{ $$ = LOG_CRIT; }
	|	TOK_ERROR	{ $$ = LOG_ERR; }
	|	TOK_WARN	{ $$ = LOG_WARNING; }
	|	TOK_INFO	{ $$ = LOG_NOTICE; }
	|	TOK_VERBOSE	{ $$ = LOG_INFO; }
	|	TOK_DEBUG	{ $$ = LOG_DEBUG; }
	;

interface:	TOK_STRING	{ free(conf->ifname); conf->ifname = strdup($1->str); }
	;

bind:		bind_address maybe_bind_interface maybe_bind_default {
			fastd_config_bind_address(ctx, conf, &$1, $2 ? $2->str : NULL, $3 == AF_UNSPEC || $3 == AF_INET, $3 == AF_UNSPEC || $3 == AF_INET6);
		}
	;

bind_address:
		TOK_ADDR4 maybe_port {
			$$ = (fastd_peer_address){ .in = { .sin_family = AF_INET, .sin_addr = $1, .sin_port = htons($2) } };
		}
	|	TOK_ADDR6 maybe_port {
			$$ = (fastd_peer_address){ .in6 = { .sin6_family = AF_INET6, .sin6_addr = $1, .sin6_port = htons($2) } };
		}
	|	TOK_ANY maybe_port {
			$$ = (fastd_peer_address){ .in = { .sin_family = AF_UNSPEC, .sin_port = htons($2) } };
		}
	;

maybe_bind_interface:
		TOK_INTERFACE TOK_STRING {
			$$ = $2;
		}
	|	{
			$$ = NULL;
		}
	;

maybe_bind_default:
		TOK_DEFAULT bind_default {
			$$ = $2;
		}
	|	{
			$$ = -1;
		}
	;

bind_default:
		TOK_IPV4 {
			$$ = AF_INET;
		}
	|	TOK_IPV6 {
			$$ = AF_INET6;
		}
	|	{
			$$ = AF_UNSPEC;
		}
	;

mtu:		TOK_INTEGER	{ conf->mtu = $1; }
	;

mode:		TOK_TAP		{ conf->mode = MODE_TAP; }
	|	TOK_TUN		{ conf->mode = MODE_TUN; }
	;

protocol:	TOK_STRING {
			if (!fastd_config_protocol(ctx, conf, $1->str)) {
				fastd_config_error(&@$, ctx, conf, filename, depth, "invalid protocol");
				YYERROR;
			}
		}
	;

method:		TOK_STRING {
			if (!fastd_config_method(ctx, conf, $1->str)) {
				fastd_config_error(&@$, ctx, conf, filename, depth, "invalid method");
				YYERROR;
			}
		}
	;

crypto:	TOK_STRING TOK_USE TOK_STRING {
			if (!fastd_config_crypto(ctx, conf, $1->str, $3->str)) {
				fastd_config_error(&@$, ctx, conf, filename, depth, "invalid crypto algorithm/implementation");
				YYERROR;
			}
		}
	;

secret:		TOK_STRING	{ free(conf->secret); conf->secret = strdup($1->str); }
	;

on_up:		TOK_STRING {
			free(conf->on_up);
			free(conf->on_up_dir);

			conf->on_up = strdup($1->str);
			conf->on_up_dir = get_current_dir_name();
		}
	;

on_down:	TOK_STRING {
			free(conf->on_down);
			free(conf->on_down_dir);

			conf->on_down = strdup($1->str);
			conf->on_down_dir = get_current_dir_name();
		}
	;

on_establish:	TOK_STRING {
			free(conf->on_establish);
			free(conf->on_establish_dir);

			conf->on_establish = strdup($1->str);
			conf->on_establish_dir = get_current_dir_name();
		}
	;

on_disestablish: TOK_STRING {
			free(conf->on_disestablish);
			free(conf->on_disestablish_dir);

			conf->on_disestablish = strdup($1->str);
			conf->on_disestablish_dir = get_current_dir_name();
		}
	;

peer:		TOK_STRING {
			fastd_peer_config_new(ctx, conf);
			conf->peers->name = strdup($1->str);
		}
	;

peer_conf:	peer_conf peer_statement
	|
	;

peer_statement: TOK_REMOTE peer_remote ';'
	|	TOK_KEY peer_key ';'
	|	TOK_INCLUDE peer_include  ';'
	;

peer_remote:	TOK_ADDR4 port {
			free(conf->peers->hostname);
			conf->peers->hostname = NULL;

			conf->peers->address.in.sin_family = AF_INET;
			conf->peers->address.in.sin_addr = $1;
			conf->peers->address.in.sin_port = htons($2);
		}
	|	TOK_ADDR6 port {
			free(conf->peers->hostname);
			conf->peers->hostname = NULL;

			conf->peers->address.in6.sin6_family = AF_INET6;
			conf->peers->address.in6.sin6_addr = $1;
			conf->peers->address.in6.sin6_port = htons($2);
		}
	|	maybe_af TOK_STRING port maybe_float {
			free(conf->peers->hostname);

			conf->peers->hostname = strdup($2->str);
			conf->peers->address.sa.sa_family = $1;
			conf->peers->address.in.sin_port = htons($3);
			conf->peers->dynamic_float = $4;
		}
	;

peer_key:	TOK_STRING {
			free(conf->peers->key); conf->peers->key = strdup($1->str);
		}
	;

peer_include:	TOK_STRING {
			if (!fastd_read_config(ctx, conf, $1->str, true, depth))
				YYERROR;
		}
	;


forward:	boolean		{ conf->forward = $1; }
	;


include:	TOK_PEER TOK_STRING maybe_as {
			fastd_peer_config_new(ctx, conf);
			conf->peers->name = strdup($3->str);

			if (!fastd_read_config(ctx, conf, $2->str, true, depth))
				YYERROR;
		}
	|	TOK_PEERS TOK_FROM TOK_STRING {
			fastd_read_peer_dir(ctx, conf, $3->str);
		}
	|	TOK_STRING {
			if (!fastd_read_config(ctx, conf, $1->str, false, depth))
				YYERROR;
		}
	;


maybe_port:	port		{ $$ = $1; }
	|			{ $$ = 0; }
	;

maybe_as:	TOK_AS TOK_STRING {
			$$ = $2;
		}
	|			{ $$ = NULL; }
	;

maybe_af:	TOK_IPV4	{ $$ = AF_INET; }
	|	TOK_IPV6	{ $$ = AF_INET6; }
	|			{ $$ = AF_UNSPEC; }
	;

maybe_float:	TOK_FLOAT	{ $$ = true; }
	|			{ $$ = false; }
	;

boolean:	TOK_YES		{ $$ = true; }
	|	TOK_NO		{ $$ = false; }
	;

colon_or_port:	':'
	|	TOK_PORT
	;

port:		colon_or_port TOK_INTEGER {
			if ($2 < 0 || $2 > 65635) {
				fastd_config_error(&@$, ctx, conf, filename, depth, "invalid port");
				YYERROR;
			}
			$$ = $2;
		}
	;
%%
void fastd_config_error(YYLTYPE *loc, fastd_context *ctx, fastd_config *conf, const char *filename, int depth, char *s) {
	pr_error(ctx, "config error: %s at %s:%i:%i", s, filename, loc->first_line, loc->first_column);
}
