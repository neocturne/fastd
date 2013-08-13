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


%option prefix="fastd_config_yy"
%option noyywrap
%option nounput
%option noinput
%option bison-bridge
%option bison-locations
%option reentrant
%option warn


%s NEEDSPACE
%s STRING
%s COMMENT


%top {
#include <config.yy.h>
}

%{
typedef struct keyword {
	const char *keyword;
	int token;
} keyword_t;

/* the keyword list must be sorted */
static const keyword_t keywords[] = {
	{ "addresses", TOK_ADDRESSES },
	{ "any", TOK_ANY },
	{ "as", TOK_AS },
	{ "auto", TOK_AUTO },
	{ "bind", TOK_BIND },
	{ "capabilities", TOK_CAPABILITIES },
	{ "crypto", TOK_CRYPTO },
	{ "debug", TOK_DEBUG },
	{ "default", TOK_DEFAULT },
	{ "disestablish", TOK_DISESTABLISH },
	{ "down", TOK_DOWN },
	{ "drop", TOK_DROP },
	{ "early", TOK_EARLY },
	{ "error", TOK_ERROR },
	{ "establish", TOK_ESTABLISH },
	{ "fatal", TOK_FATAL },
	{ "float", TOK_FLOAT },
	{ "forward", TOK_FORWARD },
	{ "from", TOK_FROM },
	{ "group", TOK_GROUP },
	{ "hide", TOK_HIDE },
	{ "include", TOK_INCLUDE },
	{ "info", TOK_INFO },
	{ "interface", TOK_INTERFACE },
	{ "ip", TOK_IP },
	{ "ipv4", TOK_IPV4 },
	{ "ipv6", TOK_IPV6 },
	{ "key", TOK_KEY },
	{ "level", TOK_LEVEL },
	{ "limit", TOK_LIMIT },
	{ "log", TOK_LOG },
	{ "mac", TOK_MAC },
	{ "method", TOK_METHOD },
	{ "mode", TOK_MODE },
	{ "mtu", TOK_MTU },
	{ "no", TOK_NO },
	{ "on", TOK_ON },
	{ "peer", TOK_PEER },
	{ "peers", TOK_PEERS },
	{ "pmtu", TOK_PMTU },
	{ "port", TOK_PORT },
	{ "post-down", TOK_POST_DOWN },
	{ "pre-up", TOK_PRE_UP },
	{ "protocol", TOK_PROTOCOL },
	{ "remote", TOK_REMOTE },
	{ "secret", TOK_SECRET },
	{ "stderr", TOK_STDERR },
	{ "syslog", TOK_SYSLOG },
	{ "tap", TOK_TAP },
	{ "to", TOK_TO },
	{ "tun", TOK_TUN },
	{ "up", TOK_UP },
	{ "use", TOK_USE },
	{ "user", TOK_USER },
	{ "verbose", TOK_VERBOSE },
	{ "verify", TOK_VERIFY },
	{ "warn", TOK_WARN },
	{ "yes", TOK_YES },
};

static int compare_keywords(const void *v1, const void *v2) {
	const keyword_t *k1 = v1, *k2 = v2;
	return strcmp(k1->keyword, k2->keyword);
}

#define UPDATE_LOCATION do {					      \
		yylloc->first_line = yylloc->last_line;		      \
		yylloc->first_column = yylloc->last_column+1;	      \
		yylloc->last_column += yyleng;			      \
	} while (0)
%}

%%

<INITIAL>{
[a-z][-a-z0-9]* {
	const keyword_t key = {yytext};
	const keyword_t *ret = bsearch(&key, keywords, sizeof(keywords)/sizeof(keyword_t), sizeof(keyword_t), compare_keywords);

	UPDATE_LOCATION;

	if (!ret) {
		yylval->error = "syntax error";
		return -1;
	}

	BEGIN(NEEDSPACE);
	return ret->token;
}

[0-9]+ {
	char *endptr;

	UPDATE_LOCATION;

	yylval->uint64 = strtoull(yytext, &endptr, 10);
	if (*endptr) {
		yylval->error = "invalid integer constant";
		return -1;
	}


	BEGIN(NEEDSPACE);
	return TOK_UINT;
}

[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3} {
			UPDATE_LOCATION;

			if (!inet_pton(AF_INET, yytext, &yylval->addr4)) {
				yylval->error = "invalid address";
				return -1;
			}

			BEGIN(NEEDSPACE);
			return TOK_ADDR4;
		}

\[[0-9a-fA-F:]+\] {
			UPDATE_LOCATION;

			yytext[yyleng-1] = 0;

			if (!inet_pton(AF_INET6, yytext+1, &yylval->addr6)) {
				yylval->error = "invalid address";
				return -1;
			}

			BEGIN(NEEDSPACE);
			return TOK_ADDR6;
		}
}

<INITIAL,NEEDSPACE>{
[;:\{\}]	{ UPDATE_LOCATION; BEGIN(INITIAL); return yytext[0]; }

\n		{ yylloc->last_column = 0; yylloc->last_line++; BEGIN(INITIAL); }

[ \t\r]		|
#.*		|
\/\/.*		{ UPDATE_LOCATION; BEGIN(INITIAL); }

\/\*		{ UPDATE_LOCATION; BEGIN(COMMENT); }
}

<INITIAL>\"	{ UPDATE_LOCATION; BEGIN(STRING); }
<STRING>[^"\\\n] { yylloc->last_column++; yymore(); }
<STRING>\n	{ yylloc->last_line++; yylloc->last_column = 0; yymore(); }
<STRING>\\.	{ yylloc->last_column+=2; yymore(); }
<STRING>\\\n	{ yylloc->last_line++; yylloc->last_column = 0; yymore(); }
<STRING>\" {
			int i, esc = 0;

			for (i = 0; i < yyleng; i++) {
				if (yytext[i] == '\\') {
					i++;
					if (yytext[i] == '\n') {
						esc+=2;
					}
					else {
						yytext[i-esc-1] = yytext[i];
						esc++;
					}
				}
				else if(esc) {
					yytext[i-esc] = yytext[i];
				}
			}
			yytext[yyleng-esc-1] = 0;
			yylval->str = fastd_string_stack_dup(yytext);
			BEGIN(NEEDSPACE);
			yylloc->last_column++;
			return TOK_STRING;

		}

<COMMENT>\*\/	{ yylloc->last_column += yyleng; BEGIN(INITIAL); }
<COMMENT>[^\n]  { yylloc->last_column++; }
<COMMENT>\n	{ yylloc->last_line++; yylloc->last_column = 0; }

.		{
			yylloc->first_line = yylloc->last_line;
			yylloc->first_column = yylloc->last_column+1;
			yylval->error = "syntax error";
			return -1;
		}

<INITIAL><<EOF>> { return 0; }
<COMMENT><<EOF>> { yylval->error = "unterminated block comment"; return -1; }
<STRING><<EOF>>	{ yylval->error = "unterminated string"; return -1; }
%%
