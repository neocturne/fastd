%option prefix="fastd_config_"
%option noyywrap
%option bison-bridge
%option reentrant

%top {
	 #include <config.yy.h>
}

%x STRING
%x ADDR6

%%
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

[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3} {
			if (!inet_pton(AF_INET, yytext, &yylval->addr)) {
				yylval->str = "invalid address";
				return TOK_ERROR;
			}

			return TOK_ADDR;
		}

any		{ yylval->str = yytext; return TOK_ANY; }
tap		{ yylval->str = yytext; return TOK_TAP; }
tun		{ yylval->str = yytext; return TOK_TUN; }

[A-Za-z_][A-Za-z0-9_]* { yylval->str = yytext; return TOK_IDENTIFIER; }

[;:\{\}]	{ return *yytext; }

[ \t\n]	;

\"		BEGIN(STRING);
<STRING>[^"]*	{ yylval->str = yytext; return TOK_STRING; }
<STRING>\"	BEGIN(INITIAL);

\[		BEGIN(ADDR6);
<ADDR6>[^\]]+		{
				if (!inet_pton(AF_INET6, yytext, &yylval->addr6)) {
					yylval->str = "invalid address";
					return TOK_ERROR;
				}

				return TOK_ADDR6;
			}
<ADDR6>\]		BEGIN(INITIAL);

<INITIAL,STRING,ADDR6>.	{
				yylval->str = "invalid character";
				return TOK_ERROR;
			}
%%
