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

%s NEEDSPACE
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

	#define TOKEN(tok) do { UPDATE_LOCATION; BEGIN(NEEDSPACE); return tok; } while (0)
%}

<INITIAL>{
[0-9]+		{ UPDATE_LOCATION; yylval->num = atoi(yytext); BEGIN(NEEDSPACE); return TOK_INTEGER; }

interface	{ TOKEN(TOK_INTERFACE); }
bind		{ TOKEN(TOK_BIND); }
mtu		{ TOKEN(TOK_MTU); }
mode		{ TOKEN(TOK_MODE); }
protocol	{ TOKEN(TOK_PROTOCOL); }
method		{ TOKEN(TOK_METHOD); }
peer		{ TOKEN(TOK_PEER); }
remote		{ TOKEN(TOK_REMOTE); }
ipv4		{ TOKEN(TOK_IPV4); }
ipv6		{ TOKEN(TOK_IPV6); }
secret		{ TOKEN(TOK_SECRET); }
key		{ TOKEN(TOK_KEY); }
include		{ TOKEN(TOK_INCLUDE); }
as		{ TOKEN(TOK_AS); }
any		{ TOKEN(TOK_ANY); }
tap		{ TOKEN(TOK_TAP); }
tun		{ TOKEN(TOK_TUN); }
on		{ TOKEN(TOK_ON); }
up		{ TOKEN(TOK_UP); }
down		{ TOKEN(TOK_DOWN); }
establish	{ TOKEN(TOK_ESTABLISH); }
disestablish	{ TOKEN(TOK_DISESTABLISH); }
peers		{ TOKEN(TOK_PEERS); }
from		{ TOKEN(TOK_FROM); }
log		{ TOKEN(TOK_LOG); }
level 		{ TOKEN(TOK_LEVEL); }
syslog		{ TOKEN(TOK_SYSLOG); }
stderr		{ TOKEN(TOK_STDERR); }
to		{ TOKEN(TOK_TO); }
fatal		{ TOKEN(TOK_FATAL); }
error		{ TOKEN(TOK_ERROR); }
warn		{ TOKEN(TOK_WARN); }
info		{ TOKEN(TOK_INFO); }
verbose		{ TOKEN(TOK_VERBOSE); }
debug		{ TOKEN(TOK_DEBUG); }
forward		{ TOKEN(TOK_FORWARD); }
yes		{ TOKEN(TOK_YES); }
no		{ TOKEN(TOK_NO); }
port		{ TOKEN(TOK_PORT); }
float		{ TOKEN(TOK_FLOAT); }
crypto		{ TOKEN(TOK_CRYPTO); }
use		{ TOKEN(TOK_USE); }
default		{ TOKEN(TOK_DEFAULT); }
user		{ TOKEN(TOK_USER); }
group		{ TOKEN(TOK_GROUP); }
drop		{ TOKEN(TOK_DROP); }
capabilities	{ TOKEN(TOK_CAPABILITIES); }
early		{ TOKEN(TOK_EARLY); }
lock		{ TOKEN(TOK_LOCK); }
limit		{ TOKEN(TOK_LIMIT); }

[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3} {
			UPDATE_LOCATION;

			if (!inet_pton(AF_INET, yytext, &yylval->addr4)) {
				yylval->error = "invalid address";
				return -1;
			}

			return TOK_ADDR4;
		}

[;:\{\}]	{ UPDATE_LOCATION; return yytext[0]; }

[ \t]		{ yylloc->last_column++; }
\n		{ yylloc->last_column = 0; yylloc->last_line++; }
}

<NEEDSPACE>{
[;:\{\}]	{ UPDATE_LOCATION; BEGIN(INITIAL); return yytext[0]; }

[ \t]		{ yylloc->last_column++; BEGIN(INITIAL); }
\n		{ yylloc->last_column = 0; yylloc->last_line++; BEGIN(INITIAL); }
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

<INITIAL>\[	{ UPDATE_LOCATION; BEGIN(ADDR6); }
<ADDR6>[0-9a-fA-F:]+	{
			yylloc->last_column += yyleng;
			if (!inet_pton(AF_INET6, yytext, &yylval->addr6)) {
				yylval->error = "invalid address";
				return -1;
			}
		}
<ADDR6>\]	{ yylloc->last_column++; BEGIN(INITIAL); return TOK_ADDR6; }

<INITIAL,NEEDSPACE>#.*		{ yylloc->last_column += yyleng; }
<INITIAL,NEEDSPACE>\/\/.*	{ yylloc->last_column += yyleng; }

<INITIAL,NEEDSPACE>\/\*		{ UPDATE_LOCATION; BEGIN(COMMENT); }
<COMMENT>\*\/	{ yylloc->last_column += yyleng; BEGIN(INITIAL); }
<COMMENT>.	{ yylloc->last_column++; }
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
<ADDR6><<EOF>>	{ yylval->error = "unterminated address"; return -1; }
%%
