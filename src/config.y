%define api.pure
%name-prefix "fastd_config_"
%lex-param {fastd_context *ctx}
%lex-param {yyscan_t scanner}
%parse-param {fastd_context *ctx}
%parse-param {fastd_config *config}
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

%token <num> TOK_INTEGER
%token <str> TOK_STRING
%token <str> TOK_IDENTIFIER

%token <str> TOK_INTERFACE
%token <str> TOK_BIND
%token <str> TOK_MTU
%token <str> TOK_MODE
%token <str> TOK_PROTOCOL
%token <str> TOK_PEER

%token <addr> TOK_ADDR
%token <addr6> TOK_ADDR6

%token <str> TOK_ANY
%token <str> TOK_FLOAT
%token <str> TOK_TAP
%token <str> TOK_TUN

/*			%code top {
	#define YY_DECL int fastd_config_lex(YYSTYPE *yylval_param, fastd_context *ctx, yyscan_t yyscanner)
}*/			


%code {
	#include <config.ll.h>
	YY_DECL;

	void fastd_config_error(fastd_context *ctx, fastd_config *config, void *scanner, char *s);
}

%code provides {
	 #include <fastd.h>
	int fastd_config_parse (fastd_context *ctx, fastd_config *config, void *scanner);
}

%%
config:		config statement
	|
	;

statement:	TOK_INTERFACE interface ';'
	| 	TOK_BIND bind ';'
	|	TOK_MTU mtu ';'
	|	TOK_MODE mode ';'
	|	TOK_PROTOCOL protocol ';'
	|	TOK_PEER peer '{' peer_config '}'
	;

interface:	TOK_STRING	{ config->ifname = strdup($1); }
	;

bind:		TOK_ADDR
	|	TOK_ADDR ':' port
	|	TOK_ADDR6
	|	TOK_ADDR6 ':' port
	|	TOK_ANY
	|	TOK_ANY ':' port
	;

mtu:		TOK_INTEGER	{ config->mtu = $1; }
	;

mode:		TOK_TAP	{ config->mode = MODE_TAP; }
	|	TOK_TUN	{ config->mode = MODE_TUN; }
	;

protocol:	TOK_STRING
	;

peer:		TOK_STRING
	|
	;

peer_config:	peer_config peer_statement
	|
	;

peer_statement: ':'
	;

port:		TOK_INTEGER
	;
%%
void fastd_config_error(fastd_context *ctx, fastd_config *config, yyscan_t scanner, char *s) {
	exit_error(ctx, "config error: %s", s);
}
