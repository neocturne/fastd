// SPDX-License-Identifier: BSD-2-Clause
/*
  Copyright (c) Matthias Schiffer <mschiffer@universe-factory.net>
  All rights reserved.
*/


%define api.pure
%define api.push-pull push
%define api.prefix {fastd_config_}
%locations
%parse-param {fastd_parser_state_t *state}

%code requires {
	#include "fastd.h"
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
%token TOK_FORCE
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
%token TOK_L2TP
%token TOK_LEVEL
%token TOK_LIMIT
%token TOK_LOG
%token TOK_MAC
%token TOK_MARK
%token TOK_METHOD
%token TOK_MODE
%token TOK_MTU
%token TOK_MULTITAP
%token TOK_NO
%token TOK_OFFLOAD
%token TOK_ON
%token TOK_PACKET
%token TOK_PEER
%token TOK_PEERS
%token TOK_PERSIST
%token TOK_PMTU
%token TOK_PORT
%token TOK_POST_DOWN
%token TOK_PRE_UP
%token TOK_PROTOCOL
%token TOK_REMOTE
%token TOK_SECRET
%token TOK_SECURE
%token TOK_SOCKET
%token TOK_STATUS
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
	#include "config.h"
	#include "peer.h"
	#include "peer_group.h"

	#include <limits.h>

	static void fastd_config_handle_bind_address(
		fastd_peer_address_t address, int64_t maybe_port, const char *bindtodevice, unsigned bind_default);

	static void fastd_config_error(YYLTYPE *loc, fastd_parser_state_t *state, const char *s);
}


%type <uint64> maybe_log_level
%type <uint64> log_level
%type <uint64> port
%type <uint64> bind_port
%type <boolean> boolean
%type <int64> maybe_bind_port
%type <str> maybe_as
%type <uint64> maybe_af
%type <addr> bind_address
%type <str> maybe_bind_interface
%type <uint64> maybe_bind_default
%type <uint64> bind_default
%type <uint64> drop_capabilities_enabled
%type <tristate> autobool
%type <boolean> sync

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
	|	TOK_PERSIST persist ';'
	|	TOK_OFFLOAD offload ';'
	|	TOK_PROTOCOL protocol ';'
	|	TOK_SECRET secret ';'
	|	TOK_ON TOK_PRE_UP on_pre_up ';'
	|	TOK_ON TOK_POST_DOWN on_post_down ';'
	|	TOK_STATUS TOK_SOCKET status_socket ';'
	|	TOK_FORWARD forward ';'
	;

peer_group_statement:
		TOK_PEER peer '{' peer_conf '}' peer_after
	|	TOK_PEER TOK_GROUP peer_group '{' peer_group_config '}' peer_group_after
	|	TOK_PEER TOK_LIMIT peer_limit ';'
	|	TOK_METHOD method ';'
	|	TOK_ON TOK_UP on_up ';'
	|	TOK_ON TOK_DOWN on_down ';'
	|	TOK_ON TOK_CONNECT on_connect ';'
	|	TOK_ON TOK_ESTABLISH on_establish ';'
	|	TOK_ON TOK_DISESTABLISH on_disestablish ';'
	|	TOK_ON TOK_VERIFY on_verify ';'
	|	TOK_INCLUDE include ';'
	;

user:		TOK_STRING {
#ifdef USE_USER
			free(conf.user);
			conf.user = fastd_strdup($1->str);
#else
			fastd_config_error(&@$, state, "user setting is not supported on this platform");
			YYERROR;
#endif
		}

group:		TOK_STRING {
#ifdef USE_USER
			free(conf.group);
			conf.group = fastd_strdup($1->str);
#else
			fastd_config_error(&@$, state, "group setting is not supported on this platform");
			YYERROR;
#endif
		}

drop_capabilities:
		drop_capabilities_enabled {
			conf.drop_caps = $1;
		}

drop_capabilities_enabled:
		TOK_EARLY {
			$$ = DROP_CAPS_EARLY;
		}
	|	TOK_FORCE {
			$$ = DROP_CAPS_FORCE;
		}
	|	boolean {
			$$ = $1 ? DROP_CAPS_ON : DROP_CAPS_OFF;
		}

secure_handshakes:
		boolean {
			pr_warn("'secure handshakes' configuration is deprecated, insecure handshakes are not supported anymore");
		}
	;

cipher:		TOK_STRING TOK_USE TOK_STRING {
			fastd_config_cipher($1->str, $3->str);
		}

mac:		TOK_STRING TOK_USE TOK_STRING {
			fastd_config_mac($1->str, $3->str);
		}

log:		TOK_LEVEL log_level {
			if (conf.log_syslog_level)
				conf.log_syslog_level = $2;
			if (conf.log_stderr_level || !conf.log_syslog_level)
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
			conf.log_syslog_ident = fastd_strdup($4->str);

			conf.log_syslog_level = $5;
		}
	;

persist:	TOK_INTERFACE boolean {
			conf.iface_persist = $2;
		}
	;

offload:	TOK_L2TP boolean {
#ifdef WITH_OFFLOAD_L2TP
			conf.offload_l2tp = $2;
#else
			if ($2) {
# ifdef __linux__
				fastd_config_error(&@$, state, "L2TP offload is not supported by this build of fastd");
# else
				fastd_config_error(&@$, state, "L2TP offload is not supported on this platform");
# endif
				YYERROR;
			}
#endif
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
	|				{ $$ = LL_DEFAULT; }
	;

log_level:	TOK_FATAL	{ $$ = LL_FATAL; }
	|	TOK_ERROR	{ $$ = LL_ERROR; }
	|	TOK_WARN	{ $$ = LL_WARN; }
	|	TOK_INFO	{ $$ = LL_INFO; }
	|	TOK_VERBOSE	{ $$ = LL_VERBOSE; }
	|	TOK_DEBUG	{ $$ = LL_DEBUG; }
	|	TOK_DEBUG2	{ $$ = LL_DEBUG2; }
	;

interface:	TOK_STRING	{
			if (!fastd_config_ifname(NULL, $1->str)) {
				fastd_config_error(&@$, state, "invalid interface name");
				YYERROR;
			}
		}
	;

bind:		bind_address maybe_bind_port maybe_bind_interface maybe_bind_default {
			fastd_config_handle_bind_address($1, $2, $3 ? $3->str : NULL, $4);
		}
	|	TOK_ADDR6_SCOPED maybe_bind_port maybe_bind_default {
			fastd_peer_address_t addr = { .in6 = { .sin6_family = AF_INET6, .sin6_addr = $1.addr } };
			fastd_config_handle_bind_address(addr, $2, $1.ifname, $3);
		}
	;

bind_address:
		TOK_ADDR4 {
			$$ = (fastd_peer_address_t){ .in = { .sin_family = AF_INET, .sin_addr = $1 } };
		}
	|	TOK_ADDR6 {
			$$ = (fastd_peer_address_t){ .in6 = { .sin6_family = AF_INET6, .sin6_addr = $1 } };
		}
	|	TOK_ANY {
			$$ = (fastd_peer_address_t){ .in = { .sin_family = AF_UNSPEC } };
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
			$$ = 0;
		}
	;

bind_default:
		TOK_IPV4 {
			$$ = FASTD_BIND_DEFAULT_IPV4;
		}
	|	TOK_IPV6 {
			$$ = FASTD_BIND_DEFAULT_IPV6;
		}
	|	{
			$$ = FASTD_BIND_DEFAULT_IPV4 | FASTD_BIND_DEFAULT_IPV6;
		}
	;

packet_mark:	TOK_UINT {
#ifdef USE_PACKET_MARK
			conf.packet_mark = $1;
#else
			fastd_config_error(&@$, state, "setting a packet mark is not supported on this system");
			YYERROR;
#endif
		}

mtu:		TOK_UINT {
			if ($1 < 576 || $1 > 65535) {
				fastd_config_error(&@$, state, "invalid MTU");
				YYERROR;
			}

			conf.mtu = $1;
		}
	;

pmtu:		autobool
	;

mode:		TOK_TAP		{ conf.mode = MODE_TAP; }
	|	TOK_MULTITAP	{ conf.mode = MODE_MULTITAP; }
	|	TOK_TUN		{ conf.mode = MODE_TUN; }
	;

protocol:	TOK_STRING {
			fastd_config_protocol($1->str);
		}
	;

secret:		TOK_STRING	{ free(conf.secret); conf.secret = fastd_strdup($1->str); }
	;

on_pre_up:	TOK_STRING {
			fastd_shell_command_set(&conf.on_pre_up, $1->str, true);
		}
	;

on_post_down:	TOK_STRING {
			fastd_shell_command_set(&conf.on_post_down, $1->str, true);
		}
	;

status_socket:	TOK_STRING {
#ifdef WITH_STATUS_SOCKET
			free(conf.status_socket); conf.status_socket = fastd_strdup($1->str);
#else
			fastd_config_error(&@$, state, "status sockets aren't supported by this version of fastd");
			YYERROR;
#endif
		}
	;

peer:		TOK_STRING {
			state->peer = fastd_new0(fastd_peer_t);
			state->peer->name = fastd_strdup($1->str);
			state->peer->group = state->peer_group;
		}
	;

peer_after:	{
			if (!fastd_peer_add(state->peer)) {
				fastd_config_error(&@$, state, "invalid peer definition");
				YYERROR;
			}
		}

peer_conf:	peer_conf peer_statement
	|
	;

peer_statement: TOK_REMOTE peer_remote ';'
	|	TOK_FLOAT peer_float ';'
	|	TOK_KEY peer_key ';'
	|	TOK_INTERFACE peer_interface ';'
	|	TOK_MTU peer_mtu ';'
	|	TOK_INCLUDE peer_include ';'
	;

peer_remote:	maybe_ipv4 TOK_ADDR4 port {
			fastd_remote_t remote = {};

			remote.address.in.sin_family = AF_INET;
			remote.address.in.sin_addr = $2;
			remote.address.in.sin_port = htons($3);
			fastd_peer_address_simplify(&remote.address);

			VECTOR_ADD(state->peer->remotes, remote);
		}
	|	maybe_ipv6 TOK_ADDR6 port {
			fastd_remote_t remote = {};

			remote.address.in6.sin6_family = AF_INET6;
			remote.address.in6.sin6_addr = $2;
			remote.address.in6.sin6_port = htons($3);
			fastd_peer_address_simplify(&remote.address);

			VECTOR_ADD(state->peer->remotes, remote);
		}
	|	maybe_ipv6 TOK_ADDR6_SCOPED port {
			char addrbuf[INET6_ADDRSTRLEN];
			size_t addrlen;

			inet_ntop(AF_INET6, &$2.addr, addrbuf, sizeof(addrbuf));
			addrlen = strlen(addrbuf);

			fastd_remote_t remote = {};
			size_t ifname_len = strlen($2.ifname);
			remote.hostname = fastd_alloc(addrlen + ifname_len + 2);
			memcpy(remote.hostname, addrbuf, addrlen);
			remote.hostname[addrlen] = '%';
			memcpy(remote.hostname+addrlen+1, $2.ifname, ifname_len+1);

			remote.address.sa.sa_family = AF_INET6;
			remote.address.in.sin_port = htons($3);

			VECTOR_ADD(state->peer->remotes, remote);
		}
	|	maybe_af TOK_STRING port {
			fastd_remote_t remote = {};

			remote.hostname = fastd_strdup($2->str);
			remote.address.sa.sa_family = $1;
			remote.address.in.sin_port = htons($3);

			VECTOR_ADD(state->peer->remotes, remote);
		}
	;

peer_float:	boolean {
			state->peer->floating = $1;
		}
	;

peer_key:	TOK_STRING {
			free(state->peer->key);
			state->peer->key = conf.protocol->read_key($1->str);
		}
	;

peer_interface:	TOK_STRING {
			if (!fastd_config_ifname(state->peer, $1->str)) {
				fastd_config_error(&@$, state, "invalid interface name");
				YYERROR;
			}
		}
	;

peer_mtu:	TOK_UINT {
			if ($1 < 576 || $1 > 65535) {
				fastd_config_error(&@$, state, "invalid MTU");
				YYERROR;
			}

			state->peer->mtu = $1;
		}
	;
peer_include:	TOK_STRING {
			if (!fastd_config_read($1->str, state->peer_group, state->peer, state->depth))
				YYERROR;
		}
	;


peer_group:	TOK_STRING {
			fastd_config_peer_group_push(state, $1->str);
		}
	;

peer_group_after:
		{
			fastd_config_peer_group_pop(state);
		}
	;

peer_limit:	TOK_UINT {
			if ($1 > INT_MAX) {
				fastd_config_error(&@$, state, "invalid peer limit");
				YYERROR;
			}

			state->peer_group->max_connections = $1;
		}
	;

method:		TOK_STRING {
			fastd_config_method(state->peer_group, $1->str);
		}
	;

on_up:		sync TOK_STRING {
			fastd_shell_command_set(&state->peer_group->on_up, $2->str, $1);
		}
	;

on_down:	sync TOK_STRING {
			fastd_shell_command_set(&state->peer_group->on_down, $2->str, $1);
		}
	;

on_connect:	sync TOK_STRING {
			fastd_shell_command_set(&state->peer_group->on_connect, $2->str, $1);
		}
	;

on_establish:	sync TOK_STRING {
			fastd_shell_command_set(&state->peer_group->on_establish, $2->str, $1);
		}
	;

on_disestablish: sync TOK_STRING {
			fastd_shell_command_set(&state->peer_group->on_disestablish, $2->str, $1);
		}
	;

on_verify:	sync TOK_STRING {
#ifdef WITH_DYNAMIC_PEERS
			fastd_shell_command_set(&conf.on_verify, $2->str, $1);
			conf.on_verify_group = state->peer_group;
#else
			fastd_config_error(&@$, state, "`on verify' is not supported by this version of fastd");
			YYERROR;
#endif
		}
	;

forward:	boolean		{ conf.forward = $1; }
	;


include:	TOK_PEER TOK_STRING maybe_as {
			fastd_peer_t *peer = fastd_new0(fastd_peer_t);
			peer->name = fastd_strdup(fastd_string_stack_get($3));

			if (!fastd_config_read($2->str, state->peer_group, peer, state->depth))
				YYERROR;

			if (!fastd_peer_add(peer)) {
				fastd_config_error(&@$, state, "invalid peer definition");
				YYERROR;
			}
		}
	|	TOK_PEERS TOK_FROM TOK_STRING {
			fastd_config_add_peer_dir(state->peer_group, $3->str);
		}
	|	TOK_STRING {
			if (!fastd_config_read($1->str, state->peer_group, NULL, state->depth))
				YYERROR;
		}
	;


maybe_bind_port:
		bind_port	{ $$ = $1; }
	|			{ $$ = -1; }
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

maybe_ipv4:	TOK_IPV4
	|
	;

maybe_ipv6:	TOK_IPV6
	|
	;

sync:		TOK_SYNC	{ $$ = true; }
	|	TOK_ASYNC	{ $$ = false; }
	|			{ $$ = false; }

boolean:	TOK_YES		{ $$ = true; }
	|	TOK_NO		{ $$ = false; }
	;

autobool:	TOK_AUTO	{ $$ = FASTD_TRISTATE_UNDEF; }
	|	boolean		{ $$ = $1 ? FASTD_TRISTATE_TRUE : FASTD_TRISTATE_FALSE; }
	;

colon_or_port:	':'
	|	TOK_PORT
	;

port:		colon_or_port TOK_UINT {
			if ($2 < 1 || $2 > 65535) {
				fastd_config_error(&@$, state, "invalid port");
				YYERROR;
			}
			$$ = $2;
		}
	;

bind_port:	colon_or_port TOK_UINT {
			if ($2 > 65535) {
				fastd_config_error(&@$, state, "invalid port");
				YYERROR;
			}
			$$ = $2;
		}
	;

%%
static void fastd_config_handle_bind_address(
	fastd_peer_address_t address, int64_t maybe_port, const char *bindtodevice, unsigned bind_default) {

	unsigned flags = bind_default;
	uint16_t port = 0;

	if (maybe_port < 0)
		flags |= FASTD_BIND_DYNAMIC;
	else
		port = htons(maybe_port);

	if (address.sa.sa_family != AF_INET6)
		address.in.sin_port = port;
	else
		address.in6.sin6_port = port;

	fastd_config_bind_address(&address, bindtodevice, flags);
}

static void fastd_config_error(YYLTYPE *loc, fastd_parser_state_t *state, const char *s) {
	pr_error("config error: %s at %s:%i:%i", s, state->filename, loc->first_line, loc->first_column);
}
