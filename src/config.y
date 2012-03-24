%define api.pure
%name-prefix "fastd_config_"
%lex-param {yyscan_t scanner}
%parse-param {fastd_context *ctx}
%parse-param {fastd_config *conf}
%parse-param {yyscan_t scanner}

%code requires {
	#include <arpa/inet.h>
}

%union {
	int num;
	char* str;
	struct in_addr addr;
	struct in6_addr addr6;
}

%token <str> TOK_ERROR;

%token <num> TOK_INTEGER
%token <str> TOK_STRING
%token <str> TOK_IDENTIFIER

%token <str> TOK_INTERFACE
%token <str> TOK_BIND
%token <str> TOK_MTU
%token <str> TOK_MODE
%token <str> TOK_PROTOCOL
%token <str> TOK_PEER
%token <str> TOK_ADDRESS

%token <addr> TOK_ADDR
%token <addr6> TOK_ADDR6

%token <str> TOK_ANY
%token <str> TOK_TAP
%token <str> TOK_TUN

%code {
	#include <config.h>
	#include <config.ll.h>
	#include <stdint.h>
	#include <peer.h>

	void fastd_config_error(fastd_context *ctx, fastd_config *conf, yyscan_t scanner, char *s);

	extern fastd_protocol fastd_protocol_null;

	#ifdef WITH_PROTOCOL_ECFXP
	extern fastd_protocol fastd_protocol_ec25519_fhmqvc_xsalsa20_poly1305;
	#endif
}

%code provides {
	#include <fastd.h>
	int fastd_config_parse (fastd_context *ctx, fastd_config *conf, void *scanner);
}

%type <str> maybe_string

%type <num> port
%type <num> maybe_port
%type <num> maybe_port_default

%%
config:		config statement
	|
	;

statement:	TOK_INTERFACE interface ';'
	| 	TOK_BIND bind ';'
	|	TOK_MTU mtu ';'
	|	TOK_MODE mode ';'
	|	TOK_PROTOCOL protocol ';'
	|	TOK_PEER peer '{' peer_conf '}'
	;

interface:	TOK_STRING	{ conf->ifname = strdup($1); }
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

protocol:	maybe_string {
			if (!strcmp($1, "null"))
				conf->protocol = &fastd_protocol_null;
#ifdef WITH_PROTOCOL_ECFXP
			else if (!strcmp($1, "ecfxp"))
				conf->protocol = &fastd_protocol_ec25519_fhmqvc_xsalsa20_poly1305;
#endif
			else
				exit_error(ctx, "config error: invalid protocol `%s'", $1);
}
	;

peer:		maybe_string {
			fastd_peer_config *current_peer = malloc(sizeof(fastd_peer_config));
			current_peer->next = conf->peers;
			conf->peers = current_peer;

			memset(&current_peer->address, 0, sizeof(fastd_peer_address));

			current_peer->address.sa.sa_family = AF_UNSPEC;
		}
	;

peer_conf:	peer_conf peer_statement
	|
	;

peer_statement: TOK_ADDRESS peer_address ';'
	;

peer_address:	TOK_ADDR maybe_port_default {
			conf->peers->address.in.sin_family = AF_INET;
			conf->peers->address.in.sin_addr = $1;
			conf->peers->address.in.sin_port = $2;
		}
	|	TOK_ADDR6 maybe_port_default {
			conf->peers->address.in6.sin6_family = AF_INET6;
			conf->peers->address.in6.sin6_addr = $1;
			conf->peers->address.in6.sin6_port = $2;
		}
	;

maybe_string:	TOK_STRING
	|			{ $$[0] = '\0'; }
	;

maybe_port:	':' port	{ $$ = $2; }
	|			{ $$ = 0; }
	;

maybe_port_default:	':' port	{ $$ = $2; }
	|				{ $$ = htons(1337); }
	;

port:		TOK_INTEGER {
			if ($1 < 0 || $1 > 65635)
				exit_error(ctx, "invalid port %i", $1);
			$$ = htons($1);
		}
	;
%%
void fastd_config_error(fastd_context *ctx, fastd_config *conf, yyscan_t scanner, char *s) {
	exit_error(ctx, "config error: %s", s);
}
