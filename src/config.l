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
%option bison-bridge
%option reentrant

%top {
	 #include <config.yy.h>
}

%s STRING
%s ADDR6
%s COMMENT

%%
<INITIAL>{
[0-9]+		{ yylval->num = atoi(yytext); return TOK_INTEGER; }

interface	{ return TOK_INTERFACE; }
bind		{ return TOK_BIND; }
mtu		{ return TOK_MTU; }
mode		{ return TOK_MODE; }
protocol	{ return TOK_PROTOCOL; }
peer		{ return TOK_PEER; }
address		{ return TOK_ADDRESS; }
secret		{ return TOK_SECRET; }
key		{ return TOK_KEY; }
include		{ return TOK_INCLUDE; }
as		{ return TOK_AS; }
any		{ return TOK_ANY; }
tap		{ return TOK_TAP; }
tun		{ return TOK_TUN; }

[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3} {
			if (!inet_pton(AF_INET, yytext, &yylval->addr)) {
				yylval->str = "invalid address";
				return -1;
			}

			return TOK_ADDR;
		}

[;:\{\}]	{ return yytext[0]; }

[ \t\n]	;
}

<INITIAL>\"	BEGIN(STRING);
<STRING>[^"\\]*	yymore();
<STRING>\\(.|\n) yymore();
<STRING>\" {
			int i, esc = 0;

			for (i = 0; i < yyleng; i++) {
				if (yytext[i] == '\\')
					esc++;
				else if(esc)
					yytext[i-esc] = yytext[i];
			}
			yytext[yyleng-esc-1] = 0;
			yylval->str = strdup(yytext);
			BEGIN(INITIAL);
			return TOK_STRING;

		}

<INITIAL>\[	BEGIN(ADDR6);
<ADDR6>[^\]]+	{
			if (!inet_pton(AF_INET6, yytext, &yylval->addr6)) {
				yylval->str = "invalid address";
				return -1;
			}

			return TOK_ADDR6;
		}
<ADDR6>\]	BEGIN(INITIAL);

<INITIAL>#.*	/* ignore */
<INITIAL>\/\/.*	/* ignore */

<INITIAL>\/\*	BEGIN(COMMENT);
<COMMENT>\*\/	BEGIN(INITIAL);
<COMMENT>.|\n	/* ignore everything */

.		{
			yylval->str = "invalid character";
			return -1;
		}

<INITIAL><<EOF>> { return 0; }
<COMMENT><<EOF>> { yylval->str = "unterminated block comment"; return -1; }
<STRING><<EOF>>	{ yylval->str = "unterminated string"; return -1; }
<ADDR6><<EOF>>	{ yylval->str = "unterminated address"; return -1; }
%%
