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
	#include <unistd.h>
}

%union {
	int num;
	fastd_config_str *str;
	char *error;
	bool boolean;
	struct in_addr addr;
	struct in6_addr addr6;
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
%token TOK_PEER
%token TOK_ADDRESS
%token TOK_SECRET
%token TOK_KEY
%token TOK_INCLUDE
%token TOK_AS
%token TOK_ANY
%token TOK_TAP
%token TOK_TUN
%token TOK_ON
%token TOK_UP
%token TOK_PEERS
%token TOK_FROM
%token TOK_LOG
%token TOK_LEVEL
%token TOK_FATAL
%token TOK_ERROR
%token TOK_WARN
%token TOK_INFO
%token TOK_VERBOSE
%token TOK_DEBUG
%token TOK_PEER_TO_PEER
%token TOK_YES
%token TOK_NO

%token <addr> TOK_ADDR
%token <addr6> TOK_ADDR6


%code {
	#include <config.h>
	#include <stdint.h>
	#include <peer.h>

	void fastd_config_error(YYLTYPE *loc, fastd_context *ctx, fastd_config *conf, const char *filename, int depth, char *s);

	extern fastd_protocol fastd_protocol_null;

	#ifdef WITH_PROTOCOL_ECFXP
	extern fastd_protocol fastd_protocol_ec25519_fhmqvc_xsalsa20_poly1305;
	#endif
}


%type <str> maybe_string

%type <num> port
%type <boolean> boolean
%type <num> maybe_port
%type <str> maybe_as

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
	|	TOK_SECRET secret ';'
	|	TOK_ON TOK_UP on_up ';'
	|	TOK_PEER peer '{' peer_conf '}'
	|	TOK_PEER_TO_PEER peer_to_peer ';'
	|	TOK_INCLUDE include ';'
	;

log:		TOK_LEVEL log_level
	;

log_level:	TOK_FATAL	{ conf->loglevel = LOG_FATAL; }
	|	TOK_ERROR	{ conf->loglevel = LOG_ERROR; }
	|	TOK_WARN	{ conf->loglevel = LOG_WARN; }
	|	TOK_INFO	{ conf->loglevel = LOG_INFO; }
	|	TOK_VERBOSE	{ conf->loglevel = LOG_VERBOSE; }
	|	TOK_DEBUG	{ conf->loglevel = LOG_DEBUG; }
	;

interface:	TOK_STRING	{ free(conf->ifname); conf->ifname = strdup($1->str); }
	;

bind:		TOK_ADDR maybe_port {
			conf->bind_addr_in.sin_family = AF_INET;
			conf->bind_addr_in.sin_addr = $1;
			conf->bind_addr_in.sin_port = $2;
		}
	|	TOK_ADDR6 maybe_port {
			conf->bind_addr_in6.sin6_family = AF_INET6;
			conf->bind_addr_in6.sin6_addr = $1;
			conf->bind_addr_in6.sin6_port = $2;
		}
	|	TOK_ANY maybe_port {
			conf->bind_addr_in.sin_addr.s_addr = htonl(INADDR_ANY);
			conf->bind_addr_in.sin_port = $2;
			conf->bind_addr_in6.sin6_addr = in6addr_any;
			conf->bind_addr_in6.sin6_port = $2;
		}
	;

mtu:		TOK_INTEGER	{ conf->mtu = $1; }
	;

mode:		TOK_TAP		{ conf->mode = MODE_TAP; }
	|	TOK_TUN		{ conf->mode = MODE_TUN; }
	;

protocol:	TOK_STRING {
			if (!strcmp($1->str, "null")) {
				conf->protocol = &fastd_protocol_null;
			}
#ifdef WITH_PROTOCOL_ECFXP
			else if (!strcmp($1->str, "ecfxp")) {
				conf->protocol = &fastd_protocol_ec25519_fhmqvc_xsalsa20_poly1305;
			}
#endif
			else {
				fastd_config_error(&@$, ctx, conf, filename, depth, "invalid protocol");
				YYERROR;
			}
}
	;

secret:		TOK_STRING	{ free(conf->secret); conf->secret = strdup($1->str); }
	;

on_up:		TOK_STRING	{
			free(conf->on_up);
			free(conf->on_up_dir);

			conf->on_up = strdup($1->str);
			conf->on_up_dir = get_current_dir_name();
		}
	;

peer:		maybe_string {
			fastd_peer_config_new(ctx, conf);
			conf->peers->name = strdup($1->str);
		}
	;

peer_conf:	peer_conf peer_statement
	|
	;

peer_statement: TOK_ADDRESS peer_address ';'
	|	TOK_KEY peer_key ';'
	|	TOK_INCLUDE peer_include  ';'
	;

peer_address:	TOK_ADDR ':' port {
			conf->peers->address.in.sin_family = AF_INET;
			conf->peers->address.in.sin_addr = $1;
			conf->peers->address.in.sin_port = $3;
		}
	|	TOK_ADDR6 ':' port {
			conf->peers->address.in6.sin6_family = AF_INET6;
			conf->peers->address.in6.sin6_addr = $1;
			conf->peers->address.in6.sin6_port = $3;
		}
	;

peer_key:	TOK_STRING	{ free(conf->peers->key); conf->peers->key = strdup($1->str); }
	;

peer_include:	TOK_STRING	{
					if (!fastd_read_config(ctx, conf, $1->str, true, depth))
						YYERROR;
				}
	;


peer_to_peer:	boolean		{ conf->peer_to_peer = $1; }
	;


include:	TOK_PEER TOK_STRING maybe_as {
			fastd_peer_config_new(ctx, conf);
			conf->peers->name = strdup($3->str);

			if (!fastd_read_config(ctx, conf, $2->str, true, depth))
				YYERROR;
		}
	|	TOK_PEERS TOK_FROM TOK_STRING {
			fastd_read_config_dir(ctx, conf, $3->str, depth);
		}
	|	TOK_STRING {
			if (!fastd_read_config(ctx, conf, $1->str, false, depth))
				YYERROR;
		}
	;


maybe_string:	TOK_STRING
	|			{ $$ = NULL; }
	;

maybe_port:	':' port	{ $$ = $2; }
	|			{ $$ = 0; }
	;

maybe_as:	TOK_AS TOK_STRING { $$ = $2; }
	|			{ $$ = NULL; }
	;

boolean:	TOK_YES		{ $$ = true; }
	|	TOK_NO		{ $$ = false; }
	;

port:		TOK_INTEGER {
			if ($1 < 0 || $1 > 65635) {
				fastd_config_error(&@$, ctx, conf, filename, depth, "invalid port");
				YYERROR;
			}
			$$ = htons($1);
		}
	;
%%
void fastd_config_error(YYLTYPE *loc, fastd_context *ctx, fastd_config *conf, const char *filename, int depth, char *s) {
	pr_error(ctx, "config error: %s at %s:%i:%i", s, filename, loc->first_line, loc->first_column);
}
