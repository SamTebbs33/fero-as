%{
#include "asm.y.h"
#define YY_NO_INPUT
#define YY_NO_UNPUT
%}

%option yylineno

%%
"."                     { return DOT; }
","                     { return COMMA; }
":"                     { return COLON; }
"$"                     { return DOLLAR; }
"#"                     { return HASH; }
"["                     { return BRACKET_LEFT; }
"]"                     { return BRACKET_RIGHT; }
"+"                     { return PLUS; }
".def"                  { return KEYW_DEF; }
".data"                 { return KEYW_DATA; }
".fill"                 { return KEYW_FILL; }
\"([^"])*\"             { yylval.string = strdup(yytext + 1);  yylval.string[strlen(yylval.string) - 1] = '\0'; return STRING; }
0b[0-1]+                { yylval.integer = strtol(yytext + 2, NULL, 2); return INTEGER; }
0x[0-9a-fA-F]+          { yylval.integer = strtol(yytext + 2, NULL, 16); return INTEGER; }
[0-9]+                  { yylval.integer = strtol(yytext, NULL, 10); return INTEGER; }
[a-zA-Z][a-zA-Z0-9_]*   { yylval.identifier = strdup(yytext); return IDENTIFIER; }
;;                      { return DOUBLE_SEMICOLON; }
;[^\n;]*                ;
\n                      { yylineno++; }
[ \t]+                  ;
.                       { printf("Unrecognised token '%s'\n", yytext); }
%%
