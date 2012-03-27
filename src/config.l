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

interface	{ yylval->str = yytext; return TOK_INTERFACE; }
bind		{ yylval->str = yytext; return TOK_BIND; }
mtu		{ yylval->str = yytext; return TOK_MTU; }
mode		{ yylval->str = yytext; return TOK_MODE; }
protocol	{ yylval->str = yytext; return TOK_PROTOCOL; }
peer		{ yylval->str = yytext; return TOK_PEER; }
address		{ yylval->str = yytext; return TOK_ADDRESS; }
secret		{ yylval->str = yytext; return TOK_SECRET; }
key		{ yylval->str = yytext; return TOK_KEY; }
include		{ yylval->str = yytext; return TOK_INCLUDE; }

[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3} {
			if (!inet_pton(AF_INET, yytext, &yylval->addr)) {
				yylval->str = "invalid address";
				return -1;
			}

			return TOK_ADDR;
		}

any		{ yylval->str = yytext; return TOK_ANY; }
tap		{ yylval->str = yytext; return TOK_TAP; }
tun		{ yylval->str = yytext; return TOK_TUN; }

[A-Za-z_][A-Za-z0-9_]* { yylval->str = yytext; return TOK_IDENTIFIER; }

[;:\{\}]	{ return yytext[0]; }

[ \t\n]	;
}

<INITIAL>\"\"	{ yylval->str = ""; return TOK_STRING; }
<INITIAL>\"	BEGIN(STRING);
<STRING>[^"]*	{ yylval->str = yytext; return TOK_STRING; }
<STRING>\"	BEGIN(INITIAL);

<INITIAL>\[	BEGIN(ADDR6);
<ADDR6>[^\]]+	{
			if (!inet_pton(AF_INET6, yytext, &yylval->addr6)) {
				yylval->str = "invalid address";
				return -1;
			}

			return TOK_ADDR6;
		}
<ADDR6>\]	BEGIN(INITIAL);

<INITIAL>#.*	{}
<INITIAL>\/\/.*	{}

<INITIAL>\/\*	BEGIN(COMMENT);
<COMMENT>\*\/	BEGIN(INITIAL);
<COMMENT>.	{}
<COMMENT>\n	{}

.		{
			yylval->str = "invalid character";
			return -1;
		}

<INITIAL><<EOF>> { return 0; }
<COMMENT><<EOF>> { yylval->str = "unterminated block comment"; return -1; }
<STRING><<EOF>>	{ yylval->str = "unterminated string"; return -1; }
<ADDR6><<EOF>>	{ yylval->str = "unterminated address"; return -1; }
%%
