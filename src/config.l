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


%option prefix="fastd_config_yy"
%option noyywrap
%option nounput
%option noinput
%option bison-bridge
%option bison-locations
%option reentrant
%option warn


%top {
	 #include <config.yy.h>
}

%s STRING
%s ADDR6
%s COMMENT

%%
%{
	#define UPDATE_LOCATION do { \
			yylloc->first_line = yylloc->last_line; \
			yylloc->first_column = yylloc->last_column+1; \
			yylloc->last_column += yyleng; \
		} while (0)
%}

<INITIAL>{
[0-9]+		{ UPDATE_LOCATION; yylval->num = atoi(yytext); return TOK_INTEGER; }

interface	{ UPDATE_LOCATION; return TOK_INTERFACE; }
bind		{ UPDATE_LOCATION; return TOK_BIND; }
mtu		{ UPDATE_LOCATION; return TOK_MTU; }
mode		{ UPDATE_LOCATION; return TOK_MODE; }
protocol	{ UPDATE_LOCATION; return TOK_PROTOCOL; }
method		{ UPDATE_LOCATION; return TOK_METHOD; }
peer		{ UPDATE_LOCATION; return TOK_PEER; }
remote		{ UPDATE_LOCATION; return TOK_REMOTE; }
ipv4		{ UPDATE_LOCATION; return TOK_IPV4; }
ipv6		{ UPDATE_LOCATION; return TOK_IPV6; }
secret		{ UPDATE_LOCATION; return TOK_SECRET; }
key		{ UPDATE_LOCATION; return TOK_KEY; }
include		{ UPDATE_LOCATION; return TOK_INCLUDE; }
as		{ UPDATE_LOCATION; return TOK_AS; }
any		{ UPDATE_LOCATION; return TOK_ANY; }
tap		{ UPDATE_LOCATION; return TOK_TAP; }
tun		{ UPDATE_LOCATION; return TOK_TUN; }
on		{ UPDATE_LOCATION; return TOK_ON; }
up		{ UPDATE_LOCATION; return TOK_UP; }
down		{ UPDATE_LOCATION; return TOK_DOWN; }
establish	{ UPDATE_LOCATION; return TOK_ESTABLISH; }
disestablish	{ UPDATE_LOCATION; return TOK_DISESTABLISH; }
peers		{ UPDATE_LOCATION; return TOK_PEERS; }
from		{ UPDATE_LOCATION; return TOK_FROM; }
log		{ UPDATE_LOCATION; return TOK_LOG; }
level 		{ UPDATE_LOCATION; return TOK_LEVEL; }
syslog		{ UPDATE_LOCATION; return TOK_SYSLOG; }
stderr		{ UPDATE_LOCATION; return TOK_STDERR; }
to		{ UPDATE_LOCATION; return TOK_TO; }
fatal		{ UPDATE_LOCATION; return TOK_FATAL; }
error		{ UPDATE_LOCATION; return TOK_ERROR; }
warn		{ UPDATE_LOCATION; return TOK_WARN; }
info		{ UPDATE_LOCATION; return TOK_INFO; }
verbose		{ UPDATE_LOCATION; return TOK_VERBOSE; }
debug		{ UPDATE_LOCATION; return TOK_DEBUG; }
forward		{ UPDATE_LOCATION; return TOK_FORWARD; }
yes		{ UPDATE_LOCATION; return TOK_YES; }
no		{ UPDATE_LOCATION; return TOK_NO; }
port		{ UPDATE_LOCATION; return TOK_PORT; }
float		{ UPDATE_LOCATION; return TOK_FLOAT; }

[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3} {
			UPDATE_LOCATION;

			if (!inet_pton(AF_INET, yytext, &yylval->addr)) {
				yylval->error = "invalid address";
				return -1;
			}

			return TOK_ADDR;
		}

[;:\{\}]	{ UPDATE_LOCATION; return yytext[0]; }

[ \t]		{ yylloc->last_column++; }
\n		{ yylloc->last_column = 0; yylloc->last_line++; }
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
			BEGIN(INITIAL);
			yylloc->last_column++;
			return TOK_STRING;

		}

<INITIAL>\[	{ UPDATE_LOCATION; BEGIN(ADDR6); }
<ADDR6>[0-9a-fA-F:]+	{
			yylloc->last_column += yyleng;
			if (!inet_pton(AF_INET6, yytext, &yylval->addr6)) {
				yylval->error = "invalid address";
				return -1;
			}
		}
<ADDR6>\]	{ yylloc->last_column++; BEGIN(INITIAL); return TOK_ADDR6; }

<INITIAL>#.*	{ yylloc->last_column += yyleng; }
<INITIAL>\/\/.*	{ yylloc->last_column += yyleng; }

<INITIAL>\/\*	{ UPDATE_LOCATION; BEGIN(COMMENT); }
<COMMENT>\*\/	{ yylloc->last_column += yyleng; BEGIN(INITIAL); }
<COMMENT>.	{ yylloc->last_column++; }
<COMMENT>\n	{ yylloc->last_line++; yylloc->last_column = 0; }

.		{
			yylloc->first_line = yylloc->last_line;
			yylloc->first_column = yylloc->last_column+1;
			yylval->error = "invalid character";
			return -1;
		}

<INITIAL><<EOF>> { return 0; }
<COMMENT><<EOF>> { yylval->error = "unterminated block comment"; return -1; }
<STRING><<EOF>>	{ yylval->error = "unterminated string"; return -1; }
<ADDR6><<EOF>>	{ yylval->error = "unterminated address"; return -1; }
%%
