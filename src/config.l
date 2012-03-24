%option prefix="fastd_config_"
%option noyywrap
%option bison-bridge
%option reentrant

%top {
	 #include <fastd.h>
	 #include <config.yy.h>
	 #define YY_DECL int fastd_config_lex(YYSTYPE *yylval_param, fastd_context *ctx, void *yyscanner)
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

[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3} {
			if (!inet_pton(AF_INET, yytext, &yylval->addr))
				exit_error(ctx, "config error: invalid address");

			return TOK_ADDR;
		}

any		{ yylval->str = yytext; return TOK_ANY; }
float		{ yylval->str = yytext; return TOK_FLOAT; }
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
				if (!inet_pton(AF_INET6, yytext, &yylval->addr6))
					exit_error(ctx, "config error: invalid address");

				return TOK_ADDR6;
			}
<ADDR6>\]		BEGIN(INITIAL);

<INITIAL,STRING,ADDR6>.		exit_error(ctx, "config error: invalid character");
%%
