%{
#include <asm.h>
struct program* program;

extern int yyerror(const char* s);
extern int yylex();
extern int yylineno;
extern FILE* yyin;

%}

%union{
	char* identifier;
	long int integer;
	char* string;
	struct program* program;
	struct instruction* instruction;
	struct list* operand_list;
	struct operand* operand;
	struct statement* statement;
	struct test_comment* test_comment;
}

%token COMMA COLON NEWLINE DOLLAR HASH DOT DOUBLE_SEMICOLON KEYW_DEF KEYW_DATA KEYW_FILL BRACKET_LEFT BRACKET_RIGHT PLUS
%token <integer> INTEGER;
%token <identifier> IDENTIFIER;
%token <string> STRING;

%type <program> program;
%type <instruction> instruction;
%type <operand_list> operand_list;
%type <operand> operand;
%type <statement> statement;

%define parse.error verbose
%locations

%%

program: { $$ = MALLOC_T(struct program); $$->statements = make_list(); program = $$; }
       | program statement { $$ = $1; add_to_list($1->statements, $2); }
       ;

statement: IDENTIFIER COLON { MAKE_STMT($$, STMT_LABEL); $$->label = $1; }
     | instruction { MAKE_STMT($$, STMT_INSTRUCTION); $$->instruction = $1; }
     | DOUBLE_SEMICOLON INTEGER IDENTIFIER INTEGER { MAKE_STMT($$, STMT_TEST_COMMENT); $$->test_comment = MALLOC_T(struct test_comment); $$->test_comment->cycle = $2; $$->test_comment->parameter = $3; $$->test_comment->value = $4; }
     | KEYW_DEF IDENTIFIER INTEGER { MAKE_STMT($$, STMT_CONSTANT_DEF); $$->constant_def = MALLOC_T(struct constant_def); $$->constant_def->identifier = $2; $$->constant_def->value = $3; }
     | KEYW_DATA INTEGER { MAKE_STMT($$, STMT_DATA_DIRECTIVE); MAKE_DATA_DIRECTIVE($$->data_directive, DATA_DIR_INTEGER); $$->data_directive->integer = $2; }
     | KEYW_DATA STRING { MAKE_STMT($$, STMT_DATA_DIRECTIVE); MAKE_DATA_DIRECTIVE($$->data_directive, DATA_DIR_STRING); $$->data_directive->string = $2; }
     | KEYW_FILL INTEGER INTEGER INTEGER { MAKE_STMT($$, STMT_FILL_DIRECTIVE); $$->fill_directive = MALLOC_T(struct fill_directive); $$->fill_directive->number = $2; $$->fill_directive->data = $3; $$->fill_directive->size = $4; }
     ;

instruction: IDENTIFIER operand_list { MAKE_INSTRUCTION($$, $1, $2, NULL); }
	   | IDENTIFIER DOT IDENTIFIER operand_list { MAKE_INSTRUCTION($$, $1, $4, $3); }
	   ;

operand_list: { $$ = make_list(); }
	    | operand { $$ = make_list(); add_to_list($$, $1); }
	    | operand_list COMMA operand { add_to_list($$, $3); }
	    ;

operand: HASH IDENTIFIER { MAKE_OPERAND($$, OPERAND_IDENTIFIER); $$->label = $2; }
       | BRACKET_LEFT HASH IDENTIFIER BRACKET_RIGHT { MAKE_OPERAND($$, OPERAND_IDENTIFIER); $$->indirect = true; $$->offset = 0; $$->label = $3; }
       | DOLLAR IDENTIFIER { MAKE_OPERAND($$, OPERAND_REGISTER); $$->indirect = false; $$->offset = 0; $$->reg = $2; }
       | BRACKET_LEFT DOLLAR IDENTIFIER BRACKET_RIGHT { MAKE_OPERAND($$, OPERAND_REGISTER); $$->indirect = true; $$->offset = 0; $$->reg = $3; }
       | BRACKET_LEFT DOLLAR IDENTIFIER PLUS INTEGER BRACKET_RIGHT { MAKE_OPERAND($$, OPERAND_REGISTER); $$->indirect = true; $$->offset = $5; $$->reg = $3; }
       | BRACKET_LEFT INTEGER BRACKET_RIGHT { MAKE_OPERAND($$, OPERAND_INTEGER); $$->indirect = true; $$->offset = 0; $$->integer = $2; }
       | INTEGER { MAKE_OPERAND($$, OPERAND_INTEGER); $$->integer = $1; }
       ;

%%
