#include "opcodes.h"
#include "constants.h"
#include "asm.h"
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <assert.h>

extern FILE* yyin;
extern int yyparse(void);
extern int yylineno;
extern struct program* program;

#define UNRECOGNISED_OPCODE UINT8_MAX
#define UNRECOGNISED_REGISTER UINT8_MAX
#define UNRECOGNISED_CONDITION UINT8_MAX

#ifndef DEBUG
#define DEBUG(fmt, ...)
#endif

#define UNREACHABLE assert(0)

#define FORMAT_MEM_CHARS_PER_BYTE 3
enum output_format {
    FORMAT_BIN,
    FORMAT_MEM
};

enum mnemonic {
    MNEMONIC_JMP,
    MNEMONIC_JMR,
    MNEMONIC_JML,
    MNEMONIC_INC,
    MNEMONIC_DEC,
    MNEMONIC_ADD,
    MNEMONIC_SUB,
    MNEMONIC_AND,
    MNEMONIC_OR,
    MNEMONIC_SHL,
    MNEMONIC_CMP,
    MNEMONIC_TST,
    MNEMONIC_YLD,
    MNEMONIC_END,
    MNEMONIC_SCH,
    MNEMONIC_QSZ,
    MNEMONIC_TSK,
    MNEMONIC_LD,
    MNEMONIC_MOV,
    MNEMONIC_SWP,
    MNEMONIC_PSH,
    MNEMONIC_POP,
    MNEMONIC_STR,
    MNEMONIC_IN,
    MNEMONIC_OUT,
    MNEMONIC_NOP,
    MNEMONIC_HLT,
    MNEMONIC_ESW,
    MNEMONIC_DSW,
    MNEMONIC_NOT,
    MNEMONIC_XOR,
    MNEMONIC_IEX,
    MNEMONIC_ISH,
    MNEMONIC_ISM,
    MNEMONIC_ICM,
    MNEMONIC_LSW,
    MNEMONIC_LEW,
    MNEMONIC_LED,
    MNEMONIC_UNRECOGNISED
};

struct mnemonic_option {
    unsigned char opcode;
    unsigned int size;
    unsigned int num_operands;
    unsigned int operand_offsets[3];
    unsigned int operand_types[3];
    int indirect_operand;
    int offset_operand;
} mnemonic_option_default = {UNRECOGNISED_OPCODE, 0, 0, {0, 0, 0}, {0, 0, 0}, -1, -1};

struct mnemonic_option get_mnemonic_option(unsigned int num_options, struct mnemonic_option options[3], struct list* operands, bool* uses_indirect, unsigned char* offset_value) {
    for (int j = 0; j < num_options; j++) {
        struct mnemonic_option option = options[j];
        if (operands->len != option.num_operands)
            continue;
        bool matches = true;
        struct list_node* operand_node = operands->head;
        for (int i = 0; i < option.num_operands; i++) {
            struct operand* operand = operand_node->val;
            if ((operand->tag & option.operand_types[i]) == 0) {
                matches = false;
                break;
            }
            if (operand->indirect) {
                if (option.indirect_operand != i) {
                    matches = false;
                    break;
                }
                *uses_indirect = true;
            }

            if (operand->offset != 0) {
                if (option.offset_operand != i) {
                    matches = false;
                    break;
                }
                *offset_value = operand->offset;
            }
            operand_node = operand_node->next;
        }
        if (matches) {
            return option;
            break;
        }
    }
    return mnemonic_option_default;
}

struct list* make_list() {
    struct list* l = MALLOC_T(struct list);
    l->len = 0;
    l->head = l->tail = NULL;
    return l;
}

void free_list(struct list* list, void (*func)(void* val)) {
    struct list_node* node = list->head;
    while (node) {
        struct list_node* next = node->next;
        if (func) func(node->val);
        else free(node->val);
        free(node);
        node = next;
    }
}

void add_to_list(struct list* l, void* val) {
    l->len++;
    struct list_node* node = MALLOC_T(struct list_node);
    node->next = NULL;
    node->val = val;
    if (!l->head) l->head = node;
    else l->tail->next = node;
    l->tail = node;
}

void free_test_comment(void* v) {
    free(((struct test_comment*) v)->parameter);
    free(v);
}

struct label_addr {
    char* label;
    unsigned int addr;
};

void free_label_addr(void* v) {
    struct label_addr* la = (struct label_addr*) v;
    free(la->label);
    free(la);
}

int label_exists(char* label, struct list* list) {
    struct list_node* node = list->head;
    while (node) {
        if (strcmp(((struct label_addr*)node->val)->label, label) == 0) return 1;
        node = node->next;
    }
    return 0;
}

unsigned int get_label_addr(char* label, struct list* list) {
    struct list_node* node = list->head;
    while (node) {
        struct label_addr* la = (struct label_addr*) node->val;
        if (strcmp(la->label, label) == 0) return la->addr;
        node = node->next;
    }
    return 0;
}

int write_bytes(enum output_format format, char* buff, unsigned int len, FILE* file) {
   switch (format) {
        case FORMAT_BIN:
            return fwrite(buff, 1, len, file);
            break;
        case FORMAT_MEM: {
            unsigned int i = 0;
            unsigned int written = 0;
            while (i < len) {
                char b = buff[i];
                int ret = fprintf(file, "%02x ", b & 0xFF);
                if (ret <= 0)
                    return ret;
                written += ret;
                i++;
            }
            return written + fprintf(file, "\n");;
        }
   }
   UNREACHABLE;
   return 0;
}

enum mnemonic get_mnemonic(char* mnemonic) {
    if (strcmp(mnemonic, "add") == 0) return MNEMONIC_ADD;
    else if (strcmp(mnemonic, "nop") == 0) return MNEMONIC_NOP;
    else if (strcmp(mnemonic, "ld") == 0) return MNEMONIC_LD;
    else if (strcmp(mnemonic, "jmp") == 0) return MNEMONIC_JMP;
    else if (strcmp(mnemonic, "sub") == 0) return MNEMONIC_SUB;
    else if (strcmp(mnemonic, "cmp") == 0) return MNEMONIC_CMP;
    else if (strcmp(mnemonic, "mov") == 0) return MNEMONIC_MOV;
    else if (strcmp(mnemonic, "and") == 0) return MNEMONIC_AND;
    else if (strcmp(mnemonic, "or") == 0) return MNEMONIC_OR;
    else if (strcmp(mnemonic, "jml") == 0) return MNEMONIC_JML;
    else if (strcmp(mnemonic, "jmr") == 0) return MNEMONIC_JMR;
    else if (strcmp(mnemonic, "shl") == 0) return MNEMONIC_SHL;
    else if (strcmp(mnemonic, "tst") == 0) return MNEMONIC_TST;
    else if (strcmp(mnemonic, "in") == 0) return MNEMONIC_IN;
    else if (strcmp(mnemonic, "out") == 0) return MNEMONIC_OUT;
    else if (strcmp(mnemonic, "inc") == 0) return MNEMONIC_INC;
    else if (strcmp(mnemonic, "hlt") == 0) return MNEMONIC_HLT;
    else if (strcmp(mnemonic, "dec") == 0) return MNEMONIC_DEC;
    else if (strcmp(mnemonic, "str") == 0) return MNEMONIC_STR;
    else if (strcmp(mnemonic, "psh") == 0) return MNEMONIC_PSH;
    else if (strcmp(mnemonic, "pop") == 0) return MNEMONIC_POP;
    else if (strcmp(mnemonic, "tsk") == 0) return MNEMONIC_TSK;
    else if (strcmp(mnemonic, "sch") == 0) return MNEMONIC_SCH;
    else if (strcmp(mnemonic, "yld") == 0) return MNEMONIC_YLD;
    else if (strcmp(mnemonic, "end") == 0) return MNEMONIC_END;
    else if (strcmp(mnemonic, "qsz") == 0) return MNEMONIC_QSZ;
    else if (strcmp(mnemonic, "swp") == 0) return MNEMONIC_SWP;
    else if (strcmp(mnemonic, "esw") == 0) return MNEMONIC_ESW;
    else if (strcmp(mnemonic, "dsw") == 0) return MNEMONIC_DSW;
    else if (strcmp(mnemonic, "not") == 0) return MNEMONIC_NOT;
    else if (strcmp(mnemonic, "xor") == 0) return MNEMONIC_XOR;
    else if (strcmp(mnemonic, "iex") == 0) return MNEMONIC_IEX;
    else if (strcmp(mnemonic, "ish") == 0) return MNEMONIC_ISH;
    else if (strcmp(mnemonic, "ism") == 0) return MNEMONIC_ISM;
    else if (strcmp(mnemonic, "icm") == 0) return MNEMONIC_ICM;
    else if (strcmp(mnemonic, "lsw") == 0) return MNEMONIC_LSW;
    else if (strcmp(mnemonic, "lew") == 0) return MNEMONIC_LEW;
    else if (strcmp(mnemonic, "led") == 0) return MNEMONIC_LED;
    else return MNEMONIC_UNRECOGNISED;
}

unsigned char get_regindex(char* mnemonic) {
    unsigned int len = strlen(mnemonic);
    if (len < 2 || mnemonic[0] != 'r') return UNRECOGNISED_REGISTER;
    char* end;
    errno = 0;
    unsigned long idx = strtol(mnemonic + 1, &end, 10);
    if (errno != 0 || end == (mnemonic + 1)) return UNRECOGNISED_REGISTER;
    return idx;
}

unsigned char get_condition(char* condition) {
    if (!condition) return COND_NONE;
    else if (strcmp(condition, "lt") == 0) return COND_LT;
    else if (strcmp(condition, "le") == 0) return COND_LE;
    else if (strcmp(condition, "eq") == 0) return COND_EQ;
    else if (strcmp(condition, "gt") == 0) return COND_GT;
    else if (strcmp(condition, "ge") == 0) return COND_GE;
    else if (strcmp(condition, "ne") == 0) return COND_NE;
    else if (strcmp(condition, "c") == 0) return COND_C;
    else if (strcmp(condition, "nc") == 0) return COND_NC;
    else return UNRECOGNISED_CONDITION;
}

int process_instruction(struct instruction* instr, FILE* out, struct list* labels, struct list* unevaluated_labels, unsigned int* insn_offset, unsigned int* output_offset, enum output_format format) {
    enum mnemonic mnemonic = get_mnemonic(instr->mnemonic);
    if (mnemonic == MNEMONIC_UNRECOGNISED) {
        printf("unrecognised mnemonic '%s'\n", instr->mnemonic);
        return 0;
    }

    unsigned char condition = get_condition(instr->condition);
    if (condition == UNRECOGNISED_CONDITION) {
        printf("unrecognised condition '%s'\n", instr->condition);
        return 0;
    }

    struct mnemonic_option options[3] = {mnemonic_option_default, mnemonic_option_default, mnemonic_option_default};
    unsigned int num_options = 1;

    switch (mnemonic) {
        // Type 0
        case MNEMONIC_DSW:
        case MNEMONIC_ESW:
        case MNEMONIC_END:
        case MNEMONIC_YLD:
        case MNEMONIC_HLT:
        case MNEMONIC_IEX:
        case MNEMONIC_NOP: {
            options[0].num_operands = 0;
            options[0].size = 2;
            switch (mnemonic) {
                case MNEMONIC_IEX:
                    options[0].opcode = OPCODE_IEX;
                    break;
                case MNEMONIC_DSW:
                    options[0].opcode = OPCODE_DSW;
                    break;
                case MNEMONIC_ESW:
                    options[0].opcode = OPCODE_ESW;
                    break;
                case MNEMONIC_END:
                    options[0].opcode = OPCODE_END;
                    break;
                case MNEMONIC_YLD:
                    options[0].opcode = OPCODE_YLD;
                    break;
                case MNEMONIC_HLT:
                    options[0].opcode = OPCODE_HLT;
                    break;
                case MNEMONIC_NOP:
                    options[0].opcode = OPCODE_NOP;
                    break;
                default:
                    UNREACHABLE;
                    break;
            }
            break;
        }
        // Type 1
        case MNEMONIC_SCH:
        case MNEMONIC_TSK:
        case MNEMONIC_TST:
        case MNEMONIC_JMR:
        case MNEMONIC_QSZ:
        case MNEMONIC_DEC:
        case MNEMONIC_NOT:
        case MNEMONIC_ISM:
        case MNEMONIC_ICM:
        case MNEMONIC_INC: {
            options[0].num_operands = 1;
            options[0].operand_types[0] = OPERAND_REGISTER;
            options[0].operand_offsets[0] = 11;
            options[0].size = 2;
            options[0].indirect_operand = 0;
            switch (mnemonic) {
                case MNEMONIC_ISM:
                    options[0].opcode = OPCODE_ISM;
                    break;
                case MNEMONIC_ICM:
                    options[0].opcode = OPCODE_ICM;
                    break;
                case MNEMONIC_SCH:
                    options[0].opcode = OPCODE_SCH;
                    break;
                case MNEMONIC_TSK:
                    options[0].opcode = OPCODE_TSK;
                    break;
                case MNEMONIC_TST:
                    options[0].opcode = OPCODE_TST;
                    break;
                case MNEMONIC_JMR:
                    options[0].opcode = OPCODE_JMR;
                    break;
                case MNEMONIC_QSZ:
                    options[0].opcode = OPCODE_QSZ;
                    options[0].indirect_operand = -1;
                    break;
                case MNEMONIC_DEC:
                    options[0].opcode = OPCODE_DEC;
                    break;
                case MNEMONIC_INC:
                    options[0].opcode = OPCODE_INC;
                    break;
                case MNEMONIC_NOT:
                    options[0].opcode = OPCODE_NOT;
                    break;
                default:
                    UNREACHABLE;
                    break;
            }
            break;
        }
        // Type 2
        case MNEMONIC_JMP:
        case MNEMONIC_OUT:
        case MNEMONIC_IN:
        case MNEMONIC_JML:
        case MNEMONIC_LSW:
        case MNEMONIC_LEW:
        case MNEMONIC_LED:
        case MNEMONIC_LD: {
            options[0].num_operands = 2;
            options[0].operand_types[0] = OPERAND_REGISTER;
            options[0].operand_types[1] = OPERAND_INTEGER | OPERAND_IDENTIFIER;
            options[0].size = 4;
            options[0].operand_offsets[0] = 11;
            options[0].operand_offsets[1] = 16;
            options[0].indirect_operand = 1;
            switch (mnemonic) {
                case MNEMONIC_LED:
                    options[0].opcode = OPCODE_LED;
                    break;
                case MNEMONIC_LEW:
                    options[0].opcode = OPCODE_LEW;
                    break;
                case MNEMONIC_LSW:
                    options[0].opcode = OPCODE_LSW;
                    break;
                case MNEMONIC_JMP:
                    options[0].opcode = OPCODE_JMP;
                    options[0].num_operands = 1;
                    options[0].operand_types[0] = OPERAND_INTEGER | OPERAND_IDENTIFIER;
                    options[0].operand_offsets[0] = 16;
                    options[0].indirect_operand = 0;
                    break;
                case MNEMONIC_OUT:
                    options[0].opcode = OPCODE_OUT;
                    options[0].operand_offsets[1] = 11;
                    options[0].operand_offsets[0] = 16;
                    options[0].operand_types[1] = OPERAND_REGISTER;
                    options[0].operand_types[0] = OPERAND_INTEGER | OPERAND_IDENTIFIER;
                    break;
                case MNEMONIC_IN:
                    options[0].opcode = OPCODE_IN;
                    break;
                case MNEMONIC_JML:
                    options[0].opcode = OPCODE_JML;
                    break;
                case MNEMONIC_LD:
                    options[0].opcode = OPCODE_LD;
                    break;
                default:
                    UNREACHABLE;
                    break;
            }
            break;
        }
        // Type 3
        case MNEMONIC_PSH:
        case MNEMONIC_POP:
        case MNEMONIC_STR:
        case MNEMONIC_SWP:
        case MNEMONIC_CMP:
        case MNEMONIC_MOV:
        case MNEMONIC_SHL:
        case MNEMONIC_AND:
        case MNEMONIC_XOR:
        case MNEMONIC_OR:
        case MNEMONIC_ISH:
        case MNEMONIC_ADD:
        case MNEMONIC_SUB: {
            options[0].num_operands = 2;
            options[0].size = 3;
            options[0].operand_types[0] = OPERAND_REGISTER;
            options[0].operand_types[1] = OPERAND_REGISTER;
            options[0].operand_offsets[0] = 16;
            options[0].operand_offsets[1] = 20;
            options[0].indirect_operand = 1;
            options[0].offset_operand = 1;
            switch (mnemonic) {
                case MNEMONIC_ISH:
                    options[0].opcode = OPCODE_ISH;
                    break;
                case MNEMONIC_PSH:
                    options[0].opcode = OPCODE_PSH;
                    options[0].indirect_operand = -1;
                    options[0].offset_operand = -1;
                    break;
                case MNEMONIC_POP:
                    options[0].opcode = OPCODE_POP;
                    options[0].indirect_operand = -1;
                    options[0].offset_operand = -1;
                    break;
                case MNEMONIC_STR:
                    options[0].opcode = OPCODE_STR;
                    options[0].indirect_operand = -1;
                    options[0].offset_operand = -1;
                    options[1].opcode = OPCODE_STRI;
                    options[1].num_operands = 2;
                    options[1].operand_types[0] = OPERAND_REGISTER;
                    options[1].operand_types[1] = OPERAND_INTEGER | OPERAND_IDENTIFIER;
                    options[1].size = 4;
                    options[1].operand_offsets[0] = 11;
                    options[1].operand_offsets[1] = 16;
                    options[1].indirect_operand = -1;
                    options[1].indirect_operand = -1;
                    num_options = 2;
                    break;
                case MNEMONIC_SWP:
                    options[0].opcode = OPCODE_SWP;
                    break;
                case MNEMONIC_CMP:
                    num_options = 2;
                    options[0].opcode = OPCODE_CMP;
                    options[1].opcode = OPCODE_CMPI;
                    options[1].num_operands = 2;
                    options[1].operand_types[0] = OPERAND_REGISTER;
                    options[1].operand_types[1] = OPERAND_INTEGER | OPERAND_IDENTIFIER;
                    options[1].size = 4;
                    options[1].operand_offsets[0] = 11;
                    options[1].operand_offsets[1] = 16;
                    options[1].indirect_operand = 1;
                    break;
                case MNEMONIC_MOV:
                    options[0].opcode = OPCODE_MOV;
                    break;
                case MNEMONIC_SHL:
                    num_options = 2;
                    options[0].opcode = OPCODE_SHL;
                    options[1].opcode = OPCODE_SHLI;
                    options[1].num_operands = 2;
                    options[1].operand_types[0] = OPERAND_REGISTER;
                    options[1].operand_types[1] = OPERAND_INTEGER | OPERAND_IDENTIFIER;
                    options[1].size = 4;
                    options[1].operand_offsets[0] = 11;
                    options[1].operand_offsets[1] = 16;
                    options[1].indirect_operand = 1;
                    break;
                case MNEMONIC_AND:
                    options[0].opcode = OPCODE_AND;
                    break;
                case MNEMONIC_XOR:
                    options[0].opcode = OPCODE_XOR;
                    break;
                case MNEMONIC_OR:
                    options[0].opcode = OPCODE_OR;
                    break;
                case MNEMONIC_ADD:
                    num_options = 2;
                    options[0].opcode = OPCODE_ADD;
                    options[1].opcode = OPCODE_ADDI;
                    options[1].num_operands = 2;
                    options[1].operand_types[0] = OPERAND_REGISTER;
                    options[1].operand_types[1] = OPERAND_INTEGER | OPERAND_IDENTIFIER;
                    options[1].size = 4;
                    options[1].operand_offsets[0] = 11;
                    options[1].operand_offsets[1] = 16;
                    options[1].indirect_operand = 1;
                    break;
                case MNEMONIC_SUB:
                    options[0].opcode = OPCODE_SUB;
                    break;
                default:
                    UNREACHABLE;
                    break;
            }
            break;
        }
        default:
            UNREACHABLE;
            break;
    }

    struct list* operands = instr->operands;

    bool uses_indirect = false;
    unsigned char offset_operand = 0;

    struct mnemonic_option chosen_option = get_mnemonic_option(num_options, options, operands, &uses_indirect, &offset_operand);

    // If no suitable option was found, error out
    if (memcmp(&chosen_option, &mnemonic_option_default, sizeof(struct mnemonic_option)) == 0) {
        printf("operands for mnemonic %s are incorrect\n", instr->mnemonic);
        return 0;
    }

    unsigned int bin = chosen_option.opcode | (condition << 7);

    struct list_node* operand_node = instr->operands->head;
    for (int i = 0; i < chosen_option.num_operands; i++) {
        struct operand* operand = operand_node->val;
        unsigned short op_val = 0;

        switch (operand->tag) {
            case OPERAND_REGISTER: {
                op_val = get_regindex(operand->reg);
                if (op_val == UNRECOGNISED_REGISTER) {
                    printf("unrecognised register '%s'\n", operand->reg);
                    return 0;
                }
                break;
            }
            case OPERAND_INTEGER: {
                if (operand->integer > UINT16_MAX) {
                    printf("integer operand %d is out of range\n", op_val);
                    return 0;
                }
                op_val = operand->integer;
                break;
            }
            case OPERAND_IDENTIFIER: {
                if (label_exists(operand->label, labels)) {
                    // FIXME: Merge this with existence check to speedup
                    op_val = get_label_addr(operand->label, labels);
                } else {
                    op_val = 0;
                    struct label_addr* val = MALLOC_T(struct label_addr);
                    val->label = operand->label;
                    assert(chosen_option.operand_offsets[i] % 8 == 0);
                    // Figure out the offset into the output file that should be overwritten when we eventually find the label
                    // The mem format uses multiple chars to encode a single byte, so multiply the operand offset by the required number to get the correct address
                    val->addr = *output_offset + chosen_option.operand_offsets[i] / 8 * (format == FORMAT_MEM ? FORMAT_MEM_CHARS_PER_BYTE : 1);
                    add_to_list(unevaluated_labels, val);
                }
                break;
            }
            default: {
                UNREACHABLE;
                return 0;
            }
        }
        bin |= op_val << chosen_option.operand_offsets[i];
        operand_node = operand_node->next;
    }
    if (uses_indirect) bin |= 0x8000;
    if (offset_operand != 0) bin |= (offset_operand & 0xF) << 11;
    *insn_offset += chosen_option.size;

    // No instructions in the architecture have a size greater than 4
    if(chosen_option.size > 4)
        UNREACHABLE;

    char buff[4];
    for (int i = 0; i < chosen_option.size; i++) {
        buff[i] = (bin >> (8 * i)) & 0xFF;
    }
    *output_offset += write_bytes(format, buff, chosen_option.size, out);
    return 1;
}

void cleanup(FILE* source, FILE* out, FILE* tc, struct list* labels, struct list* labels2, struct list* test_comments) {
    fclose(source);
    fclose(out);
    if (tc) fclose(tc);
    free_list(labels, free_label_addr);
    free_list(labels2, free_label_addr);
    free_list(test_comments, free_test_comment);
}

int main(int argc, char** argv) {
    if (argc < 3) {
        printf("Usage: %s <source file> <out file> [options]\n\nnOptions:\n", argv[0]);
        printf("--tc <tc file>: Output test comments to a file\n");
        printf("-f <format>: Output in a certain format. Can be 'bin' for flat binary format or 'mem' for Verilog mem file format. Default is 'bin'\n");
        return 1;
    }
    FILE* source_file = fopen(argv[1], "r");
    if (!source_file) {
        printf("couldn't open source file '%s'\n", argv[1]);
        return 1;
    }
    yyin = source_file;
    if (yyparse() != 0) {
        fclose(source_file);
        return 1;
    }
    FILE* out_file = fopen(argv[2], "w+");
    if (!out_file) {
        printf("couldn't open output file '%s'\n", argv[2]);
        return 1;
    }

    enum output_format format = FORMAT_BIN;
    char* tc_filename = NULL;

    if (argc >= 4) {
        unsigned int i = 3;
        while (i < argc) {
            char* arg = argv[i];
            if (strcmp(arg, "-tc") == 0) {
                if (i + 1 >= argc) {
                    printf("filename expected after -tc\n");
                    return 1;
                }
                tc_filename = argv[i + 1];
                i++;
            } else if (strcmp(arg, "-f") == 0) {
                if (i + 1 >= argc) {
                    printf("format type expected after -f\n");
                    return 1;
                }
                i++;
                if (strcmp(argv[i], "bin") == 0)
                    format = FORMAT_BIN;
                else if (strcmp(argv[i], "mem") == 0)
                    format = FORMAT_MEM;
                else {
                    printf("unrecognised format '%s'\n", argv[i]);
                    return 1;
                }
            } else {
                printf("unrecognised argument '%s'\n", argv[i]);
                return 1;
            }
            i++;
        }
    }

    FILE* tc_file = NULL;
    if (tc_filename) {
        tc_file = fopen(tc_filename, "w+");
        if (!tc_file) {
            printf("couldn't open test comment file '%s'\n", argv[3]);
            return 1;
        }
    }
    unsigned int output_offset = 0, insn_offset = 0;
    // A list of all labels found, with the offset the correspond to
    struct list* labels = make_list();
    // A list of all label operands found, with the offset to the operand
    struct list* unevaluated_labels = make_list();
    // A list of all test comments
    struct list* test_comments = make_list();

    struct list_node* stmt_node = program->statements->head;
    while (stmt_node) {
        struct statement* stmt = stmt_node->val;
        switch (stmt->tag) {
            case STMT_LABEL: {
                if (label_exists(stmt->label, labels)) {
                    printf("label '%s' already exists\n", stmt->label);
                    cleanup(source_file, out_file, tc_file, labels, unevaluated_labels, test_comments);
                    return 1;
                }
                struct label_addr* val = MALLOC_T(struct label_addr);
                val->label = stmt->label;
                val->addr = insn_offset;
                add_to_list(labels, val);
                break;
            }
            case STMT_INSTRUCTION: {
                if (!process_instruction(stmt->instruction, out_file, labels, unevaluated_labels, &insn_offset, &output_offset, format)) {
                    cleanup(source_file, out_file, tc_file, labels, unevaluated_labels, test_comments);
                    return 1;
                }
                break;
            }
            case STMT_TEST_COMMENT: {
                stmt->test_comment->addr = insn_offset;
                add_to_list(test_comments, stmt->test_comment);
                break;
            }
            case STMT_CONSTANT_DEF: {
                struct constant_def* const_def = stmt->constant_def;
                if (label_exists(const_def->identifier, labels)) {
                    printf("label/const '%s' already exists\n", const_def->identifier);
                    cleanup(source_file, out_file, tc_file, labels, unevaluated_labels, test_comments);
                    return 1;
                }
                struct label_addr* val = MALLOC_T(struct label_addr);
                val->label = const_def->identifier;
                val->addr = const_def->value;
                add_to_list(labels, val);
                break;
            }
            case STMT_DATA_DIRECTIVE: {
                struct data_directive* data_dir = stmt->data_directive;
                switch (data_dir->tag) {
                    case DATA_DIR_STRING: {
                        char ch;
                        char* str = data_dir->string;
                        do {
                            ch = *str++;
                            output_offset += write_bytes(format, &ch, 1, out_file);
                            insn_offset += 1;
                        } while(ch);
                        break;
                    }
                    case DATA_DIR_INTEGER:
                        output_offset += write_bytes(format, (char*) &data_dir->integer, 2, out_file);
                        insn_offset += 2;
                        break;
                }
                break;
            }
            case STMT_FILL_DIRECTIVE: {
                struct fill_directive* fill = stmt->fill_directive;
                for (int i = 0; i < fill->number; i++)
                    output_offset += write_bytes(format, (char*) &fill->data, 2, out_file);
                insn_offset += fill->number * fill->size;
                break;
            }
        }
        stmt_node = stmt_node->next;
    }

    struct list_node* label_node = unevaluated_labels->head;
    while (label_node) {
        struct label_addr* la = (struct label_addr*) label_node->val;
        if (label_exists(la->label, labels)) {
            unsigned int addr = get_label_addr(la->label, labels);
            fseek(out_file, la->addr, SEEK_SET);
            char buff[2];
            buff[0] = addr & 0xFF;
            buff[1] = (addr >> 8) & 0xFF;
            write_bytes(format, buff, 2, out_file);
        } else {
            printf("label '%s' not found\n", la->label);
            cleanup(source_file, out_file, tc_file, labels, unevaluated_labels, test_comments);
            return 1;
        }
        label_node = label_node->next;
    }

    if (tc_file) {
        struct list_node* tc_node = test_comments->head;
        while (tc_node) {
            struct test_comment* tc = (struct test_comment*) tc_node->val;
            fwrite(&tc->cycle, sizeof(tc->cycle), 1, tc_file);
            fwrite(tc->parameter, strlen(tc->parameter) + 1, 1, tc_file);
            fwrite(&tc->value, sizeof(tc->value), 1, tc_file);
            fwrite(&tc->addr, sizeof(tc->addr), 1, tc_file);
            tc_node = tc_node->next;
        }
    }

    cleanup(source_file, out_file, tc_file, labels, unevaluated_labels, test_comments);
}

int yyerror(const char *s)
{
  fprintf(stderr, "%d: error: %s\n", yylineno, s);
  return 0;
}
