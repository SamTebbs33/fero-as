#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

#define MALLOC_T(T) (T*) malloc(sizeof(T))
#define MAKE_STMT(var, t) var = MALLOC_T(struct statement); var->tag = t;
#define MAKE_DATA_DIRECTIVE(var, t) var = MALLOC_T(struct data_directive); var->tag = t;
#define MAKE_INSTRUCTION(var, m, o, c) var = MALLOC_T(struct instruction); var->mnemonic = m; var->operands = o; var->condition = c;
#define MAKE_OPERAND(var, t) var = MALLOC_T(struct operand); var->tag = t;

struct list_node {
    struct list_node* next;
    void* val;
};

struct list {
    struct list_node* head, * tail;
    unsigned int len;
};

enum operand_tag {
    OPERAND_INTEGER = 1,
    OPERAND_IDENTIFIER = 2,
    OPERAND_REGISTER = 4
};

struct operand {
    union {
        char* label;
        long int integer;
        char* reg;
    };
    unsigned short offset;
    bool indirect;
    enum operand_tag tag;
};

struct instruction {
    char* mnemonic;
    struct list* operands;
    char* condition;
};

struct test_comment {
    unsigned int cycle;
    char* parameter;
    unsigned int value;
    unsigned int addr;
};

void free_test_comment(void* v);

struct constant_def {
    char* identifier;
    unsigned int value;
};

enum data_directive_tag {
    DATA_DIR_INTEGER,
    DATA_DIR_STRING
};

struct data_directive {
    union {
        unsigned int integer;
        char* string;
    };
    enum data_directive_tag tag;
};

struct fill_directive {
    unsigned int number, data;
    unsigned char size;
};

enum statement_tag {
    STMT_INSTRUCTION,
    STMT_LABEL,
    STMT_TEST_COMMENT,
    STMT_CONSTANT_DEF,
    STMT_DATA_DIRECTIVE,
    STMT_FILL_DIRECTIVE
};

struct statement {
    union {
        struct instruction* instruction;
        char* label;
        struct test_comment* test_comment;
        struct constant_def* constant_def;
        struct data_directive* data_directive;
        struct fill_directive* fill_directive;
    };
    enum statement_tag tag;
};

struct program {
    struct list* statements;
};

struct list* make_list();

void free_list(struct list* list, void (*func)(void* val));

void add_to_list(struct list* l, void* val);
