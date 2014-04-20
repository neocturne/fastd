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


%define api.pure
%define api.push-pull push
%name-prefix "fastd_config_"
%locations
%parse-param {const char *filename}
%parse-param {int depth}

%code requires {
	#include <src/fastd.h>
	#include <arpa/inet.h>
}

%union {
	uint64_t uint64;
	int64_t int64;
	fastd_string_stack_t *str;
	bool boolean;
	fastd_tristate_t tristate;
	struct in_addr addr4;
	struct in6_addr addr6;
	fastd_peer_address_t addr;
	struct {
		struct in6_addr addr;
		char ifname[IFNAMSIZ];
	} addr6_scoped;

	const char *error;
}

%token START_CONFIG
%token START_PEER_GROUP_CONFIG
%token START_PEER_CONFIG

%token <uint64> TOK_UINT
%token <str> TOK_STRING

%token <addr4> TOK_ADDR4
%token <addr6> TOK_ADDR6
%token <addr6_scoped> TOK_ADDR6_SCOPED

%token TOK_ADDRESSES
%token TOK_ANY
%token TOK_AS
%token TOK_ASYNC
%token TOK_AUTO
%token TOK_BIND
%token TOK_CAPABILITIES
%token TOK_CIPHER
%token TOK_CONNECT
%token TOK_DEBUG
%token TOK_DEBUG2
%token TOK_DEFAULT
%token TOK_DISESTABLISH
%token TOK_DOWN
%token TOK_DROP
%token TOK_EARLY
%token TOK_ERROR
%token TOK_ESTABLISH
%token TOK_FATAL
%token TOK_FLOAT
%token TOK_FORWARD
%token TOK_FROM
%token TOK_GROUP
%token TOK_HANDSHAKES
%token TOK_HIDE
%token TOK_INCLUDE
%token TOK_INFO
%token TOK_INTERFACE
%token TOK_IP
%token TOK_IPV4
%token TOK_IPV6
%token TOK_KEY
%token TOK_LEVEL
%token TOK_LIMIT
%token TOK_LOG
%token TOK_MAC
%token TOK_MARK
%token TOK_METHOD
%token TOK_MODE
%token TOK_MTU
%token TOK_NO
%token TOK_ON
%token TOK_PACKET
%token TOK_PEER
%token TOK_PEERS
%token TOK_PMTU
%token TOK_PORT
%token TOK_POST_DOWN
%token TOK_PRE_UP
%token TOK_PROTOCOL
%token TOK_REMOTE
%token TOK_SECRET
%token TOK_SECURE
%token TOK_STDERR
%token TOK_SYNC
%token TOK_SYSLOG
%token TOK_TAP
%token TOK_TO
%token TOK_TUN
%token TOK_UP
%token TOK_USE
%token TOK_USER
%token TOK_VERBOSE
%token TOK_VERIFY
%token TOK_WARN
%token TOK_YES


%code {
	#include <src/peer.h>
	#include <src/config.h>

	#include <limits.h>

	void fastd_config_error(YYLTYPE *loc, const char *filename, int depth, const char *s);
}


%type <uint64> maybe_log_level
%type <uint64> log_level
%type <uint64> port
%type <boolean> boolean
%type <uint64> maybe_port
%type <str> maybe_as
%type <uint64> maybe_af
%type <boolean> maybe_float
%type <addr> bind_address
%type <str> maybe_bind_interface
%type <int64> maybe_bind_default
%type <uint64> bind_default
%type <uint64> drop_capabilities_enabled
%type <tristate> autobool
%type <boolean> sync
%type <boolean> sync_def_sync
%type <boolean> sync_def_async

%%
start:		START_CONFIG config
	|	START_PEER_GROUP_CONFIG peer_group_config
	|	START_PEER_CONFIG peer_conf
	;

config:		config statement
	|
	;

peer_group_config:
		peer_group_config peer_group_statement
	|
	;

statement:	peer_group_statement
	|	TOK_USER user ';'
	|	TOK_GROUP group ';'
	|	TOK_DROP TOK_CAPABILITIES drop_capabilities ';'
	|	TOK_SECURE TOK_HANDSHAKES secure_handshakes ';'
	|	TOK_CIPHER cipher ';'
	|	TOK_MAC mac ';'
	|	TOK_LOG log ';'
	|	TOK_HIDE hide ';'
	|	TOK_INTERFACE interface ';'
	|	TOK_BIND bind ';'
	|	TOK_PACKET TOK_MARK packet_mark ';'
	|	TOK_MTU mtu ';'
	|	TOK_PMTU pmtu ';'
	|	TOK_MODE mode ';'
	|	TOK_PROTOCOL protocol ';'
	|	TOK_METHOD method ';'
	|	TOK_SECRET secret ';'
	|	TOK_ON TOK_PRE_UP on_pre_up ';'
	|	TOK_ON TOK_UP on_up ';'
	|	TOK_ON TOK_DOWN on_down ';'
	|	TOK_ON TOK_POST_DOWN on_post_down ';'
	|	TOK_ON TOK_CONNECT on_connect ';'
	|	TOK_ON TOK_ESTABLISH on_establish ';'
	|	TOK_ON TOK_DISESTABLISH on_disestablish ';'
	|	TOK_ON TOK_VERIFY on_verify ';'
	|	TOK_FORWARD forward ';'
	;

peer_group_statement:
		TOK_PEER peer '{' peer_conf '}'
	|	TOK_PEER TOK_GROUP peer_group '{' peer_group_config '}' peer_group_after
	|	TOK_PEER TOK_LIMIT peer_limit ';'
	|	TOK_INCLUDE include ';'
	;

user:		TOK_STRING {
			free(conf.user);
			conf.user = strdup($1->str);
		}

group:		TOK_STRING {
			free(conf.group);
			conf.group = strdup($1->str);
		}

drop_capabilities:
		drop_capabilities_enabled {
			conf.drop_caps = $1;
		}

drop_capabilities_enabled:
		TOK_EARLY {
			$$ = DROP_CAPS_EARLY;
		}
	|	boolean {
			$$ = $1 ? DROP_CAPS_ON : DROP_CAPS_OFF;
		}

secure_handshakes:
		boolean {
			conf.secure_handshakes = $1;
		}
	;

cipher:		TOK_STRING TOK_USE TOK_STRING {
			fastd_config_cipher($1->str, $3->str);
		}

mac:		TOK_STRING TOK_USE TOK_STRING {
			fastd_config_mac($1->str, $3->str);
		}

log:		TOK_LEVEL log_level {
			conf.log_stderr_level = $2;
		}
	|	TOK_TO TOK_STDERR maybe_log_level {
			conf.log_stderr_level = $3;
		}
	|	TOK_TO TOK_SYSLOG maybe_log_level {
			conf.log_syslog_level = $3;
		}
	|	TOK_TO TOK_SYSLOG TOK_AS TOK_STRING maybe_log_level {
			free(conf.log_syslog_ident);
			conf.log_syslog_ident = strdup($4->str);

			conf.log_syslog_level = $5;
		}
	|	TOK_TO TOK_STRING maybe_log_level {
			fastd_config_add_log_file($2->str, $3);
		}
	;

hide:		TOK_IP TOK_ADDRESSES boolean {
			conf.hide_ip_addresses = $3;
		}
	|	TOK_MAC TOK_ADDRESSES boolean {
			conf.hide_mac_addresses = $3;
		}
	;

maybe_log_level:
		TOK_LEVEL log_level	{ $$ = $2; }
	|				{ $$ = FASTD_DEFAULT_LOG_LEVEL; }
	;

log_level:	TOK_FATAL	{ $$ = LL_FATAL; }
	|	TOK_ERROR	{ $$ = LL_ERROR; }
	|	TOK_WARN	{ $$ = LL_WARN; }
	|	TOK_INFO	{ $$ = LL_INFO; }
	|	TOK_VERBOSE	{ $$ = LL_VERBOSE; }
	|	TOK_DEBUG	{ $$ = LL_DEBUG; }
	|	TOK_DEBUG2	{ $$ = LL_DEBUG2; }
	;

interface:	TOK_STRING	{ free(conf.ifname); conf.ifname = strdup($1->str); }
	;

bind:		bind_address maybe_bind_interface maybe_bind_default {
			fastd_config_bind_address(&$1, $2 ? $2->str : NULL, $3 == AF_UNSPEC || $3 == AF_INET, $3 == AF_UNSPEC || $3 == AF_INET6);
		}
	|	TOK_ADDR6_SCOPED maybe_port maybe_bind_default {
			fastd_peer_address_t addr = { .in6 = { .sin6_family = AF_INET6, .sin6_addr = $1.addr, .sin6_port = htons($2) } };
			fastd_config_bind_address(&addr, $1.ifname, $3 == AF_UNSPEC || $3 == AF_INET, $3 == AF_UNSPEC || $3 == AF_INET6);
		}
	;

bind_address:
		TOK_ADDR4 maybe_port {
			$$ = (fastd_peer_address_t){ .in = { .sin_family = AF_INET, .sin_addr = $1, .sin_port = htons($2) } };
		}
	|	TOK_ADDR6 maybe_port {
			$$ = (fastd_peer_address_t){ .in6 = { .sin6_family = AF_INET6, .sin6_addr = $1, .sin6_port = htons($2) } };
		}
	|	TOK_ANY maybe_port {
			$$ = (fastd_peer_address_t){ .in = { .sin_family = AF_UNSPEC, .sin_port = htons($2) } };
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

packet_mark:	TOK_UINT {
			conf.packet_mark = $1;
		}

mtu:		TOK_UINT {
			if ($1 < 576 || $1 > 65535) {
				fastd_config_error(&@$, filename, depth, "invalid MTU");
				YYERROR;
			}

			conf.mtu = $1;
		}
	;

pmtu:		autobool	{ conf.pmtu = $1; }
	;

mode:		TOK_TAP		{ conf.mode = MODE_TAP; }
	|	TOK_TUN		{ conf.mode = MODE_TUN; }
	;

protocol:	TOK_STRING {
			fastd_config_protocol($1->str);
		}
	;

method:		TOK_STRING {
			fastd_config_method($1->str);
		}
	;

secret:		TOK_STRING	{ free(conf.secret); conf.secret = strdup($1->str); }
	;

on_pre_up:	sync_def_sync TOK_STRING {
			fastd_shell_command_set(&conf.on_pre_up, $2->str, $1);
		}
	;

on_up:		sync_def_sync TOK_STRING {
			fastd_shell_command_set(&conf.on_up, $2->str, $1);
		}
	;

on_down:	sync_def_sync TOK_STRING {
			fastd_shell_command_set(&conf.on_down, $2->str, $1);
		}
	;

on_post_down:	sync_def_sync TOK_STRING {
			fastd_shell_command_set(&conf.on_post_down, $2->str, $1);
		}
	;

on_connect:	sync_def_async TOK_STRING {
			fastd_shell_command_set(&conf.on_connect, $2->str, $1);
		}
	;

on_establish:	sync_def_async TOK_STRING {
			fastd_shell_command_set(&conf.on_establish, $2->str, $1);
		}
	;

on_disestablish: sync_def_async TOK_STRING {
			fastd_shell_command_set(&conf.on_disestablish, $2->str, $1);
		}
	;

on_verify:	sync_def_async TOK_STRING {
			fastd_shell_command_set(&conf.on_verify, $2->str, $1);
		}
	;

peer:		TOK_STRING {
			fastd_peer_config_new();
			conf.peers->name = strdup($1->str);
		}
	;

peer_conf:	peer_conf peer_statement
	|
	;

peer_statement: TOK_REMOTE peer_remote ';'
	|	TOK_FLOAT peer_float ';'
	|	TOK_KEY peer_key ';'
	|	TOK_INCLUDE peer_include ';'
	;

peer_remote:	TOK_ADDR4 port {
			fastd_remote_config_t **remote = &conf.peers->remotes;
			while (*remote)
				remote = &(*remote)->next;

			*remote = calloc(1, sizeof(fastd_remote_config_t));

			(*remote)->address.in.sin_family = AF_INET;
			(*remote)->address.in.sin_addr = $1;
			(*remote)->address.in.sin_port = htons($2);
			fastd_peer_address_simplify(&(*remote)->address);
		}
	|	TOK_ADDR6 port {
			fastd_remote_config_t **remote = &conf.peers->remotes;
			while (*remote)
				remote = &(*remote)->next;

			*remote = calloc(1, sizeof(fastd_remote_config_t));

			(*remote)->address.in6.sin6_family = AF_INET6;
			(*remote)->address.in6.sin6_addr = $1;
			(*remote)->address.in6.sin6_port = htons($2);
			fastd_peer_address_simplify(&(*remote)->address);
		}
	|	TOK_ADDR6_SCOPED port {
			char addrbuf[INET6_ADDRSTRLEN];
			size_t addrlen;
			fastd_remote_config_t **remote = &conf.peers->remotes;
			while (*remote)
				remote = &(*remote)->next;

			inet_ntop(AF_INET6, &$1.addr, addrbuf, sizeof(addrbuf));
			addrlen = strlen(addrbuf);

			*remote = calloc(1, sizeof(fastd_remote_config_t));

			(*remote)->hostname = malloc(addrlen + strlen($1.ifname) + 2);
			memcpy((*remote)->hostname, addrbuf, addrlen);
			(*remote)->hostname[addrlen] = '%';
			strcpy((*remote)->hostname+addrlen+1, $1.ifname);

			(*remote)->address.sa.sa_family = AF_INET6;
			(*remote)->address.in.sin_port = htons($2);
		}
	|	maybe_af TOK_STRING port maybe_float {
			fastd_remote_config_t **remote = &conf.peers->remotes;
			while (*remote)
				remote = &(*remote)->next;

			*remote = calloc(1, sizeof(fastd_remote_config_t));

			(*remote)->hostname = strdup($2->str);
			(*remote)->address.sa.sa_family = $1;
			(*remote)->address.in.sin_port = htons($3);

			if ($4) {
				conf.peers->floating = true;
				conf.peers->dynamic_float_deprecated = true;
			}
		}
	;

peer_float:	boolean {
			conf.peers->floating = $1;
		}
	;

peer_key:	TOK_STRING {
			free(conf.peers->key); conf.peers->key = strdup($1->str);
		}
	;

peer_include:	TOK_STRING {
			if (!fastd_read_config($1->str, true, depth))
				YYERROR;
		}
	;


peer_group:	TOK_STRING {
			fastd_config_peer_group_push($1->str);
		}
	;

peer_group_after:
		{
			fastd_config_peer_group_pop();
		}
	;

peer_limit:	TOK_UINT {
			if ($1 > INT_MAX) {
				fastd_config_error(&@$, filename, depth, "invalid peer limit");
				YYERROR;
			}

			conf.peer_group->max_connections = $1;
		}
	;

forward:	boolean		{ conf.forward = $1; }
	;


include:	TOK_PEER TOK_STRING maybe_as {
			fastd_peer_config_new();
			if ($3)
				conf.peers->name = strdup($3->str);

			if (!fastd_read_config($2->str, true, depth))
				YYERROR;
		}
	|	TOK_PEERS TOK_FROM TOK_STRING {
			fastd_add_peer_dir($3->str);
		}
	|	TOK_STRING {
			if (!fastd_read_config($1->str, false, depth))
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

sync_def_sync:	sync		{ $$ = $1; }
	|			{ $$ = true; }
	;

sync_def_async: sync		{ $$ = $1; }
	|			{ $$ = false; }
	;

sync:		TOK_SYNC	{ $$ = true; }
	|	TOK_ASYNC	{ $$ = false; }

boolean:	TOK_YES		{ $$ = true; }
	|	TOK_NO		{ $$ = false; }
	;

autobool:	TOK_AUTO	{ $$ = fastd_tristate_undef; }
	|	boolean		{ $$ = $1 ? fastd_tristate_true : fastd_tristate_false; }
	;

colon_or_port:	':'
	|	TOK_PORT
	;

port:		colon_or_port TOK_UINT {
			if ($2 < 1 || $2 > 65535) {
				fastd_config_error(&@$, filename, depth, "invalid port");
				YYERROR;
			}
			$$ = $2;
		}
	;

%%
void fastd_config_error(YYLTYPE *loc, const char *filename, int depth UNUSED, const char *s) {
	pr_error("config error: %s at %s:%i:%i", s, filename, loc->first_line, loc->first_column);
}
