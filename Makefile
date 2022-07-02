all: src/asm.c src/asm.h src/asm.l src/asm.y fero-arch/opcodes.vh
	mkdir -p obj
	bison -Werror --defines=obj/asm.y.h --output=obj/asm.y.c src/asm.y
	flex --outfile=obj/lex.c src/asm.l
	clang -o as src/asm.c obj/asm.y.c obj/lex.c -Isrc -Ifero-arch -lfl -g
