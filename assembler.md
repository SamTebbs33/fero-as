# Assembler
The assembler is used to convert human readable assembly instructions into machine-readable instructions in raw binary format. It is executed with two arguments, the first being the input assembly source file abd the second the output binary file. Example: `as helloworld.s helloworld.bin`.

## Assembly file format
An assembly file is a list of instructions, labels and directives. Comments (start with `;`) are ignored and can appear anywhere.

## Instructions
Assembly instructions have a one-to-one mapping to machine code instructions and are made up of an *mnemonic, **operands* and an optional *condition code*. The mnemonic maps to a specific opcode in the instruction set.

### Control flow
Instructions that are used to modify the control flow of a program.

#### JMP (Jump)
Sets the current program counter to the operand or a value in memory.

```
jmp x ; PC = x
jmp [x] ; PC = [x]
```

#### JMR (Jump to register)
Sets the current program counter to the operand or a value in memory.

```
jmr $rA ; PC = $rA
jmr [$rA] ; PC = [$rA]
```

#### JML (Jump and link)
Stores the current program counter in the register operand then sets the current program counter to the operand or a value in memory.

Takes one register operand and one label or integer operand.

```
jml $rA, x ; $rA = PC, PC = x
jml $rA, [x] ; $rA = PC, PC = [x]
```

### Arithmetic
All arithmetic instructions modify the status flags according to the result of the operation.

#### INC (Increment)
Increments the operand or value in memory and stores the result in the register operand.

```
inc $rA ; rA = rA + 1
inc [$rA] ; rA = [rA] + 1
```

#### DEC (Decrement)
Decrements the operand or value in memory and stores the result in the register operand.

```
dec $rA ; rA = rA - 1
dec [$rA] ; rA = [rA] - 1
```

#### ADD (Add)
Adds a register, immediate or value in memory to a register and stores the result in the first register operand.

```
add $rA, $rB ; rA = rA + rB
add $rA, [$rB] ; rA = rA + [rB]
add $rA, [$rB+x] ; rA = rA + [rB+x]
add $rA, x ; rA = rA + x
add $rA, [x] ; rA = rA + [x]
```

#### SUB (Subtract)
Subtracts a register or value in memory from a register and stores the result in the first register operand.

```
sub $rA, $rB ; rA = rA - rB
sub $rA, [$rB] ; rA = rA - [rB]
sub $rA, [$rB+x] ; rA = rA - [rB+x]
```

#### AND (Bitwise AND)
Performs bitwise AND on a register and another register or value in memory and stores the result in the first register operand.

```
and $rA, $rB ; rA = rA & rB
and $rA, [$rB] ; rA = rA & [rB]
and $rA, [$rB+x] ; rA = rA & [rB+x]
```

#### XOR (Bitwise XOR)
Performs bitwise XOR on a register and another register or value in memory and stores the result in the first register operand.

```
xor $rA, $rB ; rA = rA & rB
xor $rA, [$rB] ; rA = rA & [rB]
xor $rA, [$rB+x] ; rA = rA & [rB+x]
```

#### OR (Bitwise OR)
Performs bitwise OR on a register and another register or value in memory stores the result in the first register operand.

```
or $rA, $rB ; rA = rA | rB
or $rA, [$rB] ; rA = rA | [rB]
or $rA, [$rB+x] ; rA = rA | [rB+x]
```

#### NOT (Bitwise NOT)
Performs a bitwise NOT on a register or value in memory and stores the result in the register.

```
not $rA ; rA = ~rA
not [$rA] ; rA = ~[rA]
```

#### SHL (Shift left)
Shifts the first operand by a register, immediate or value in memory and stores the result in the first register operand.

```
shl $rA, $rB ; rA = rA << rB
shl $rA, [$rB] ; rA = rA << [rB]
shl $rA, [$rB+x] ; rA = rA << [rB+x]
shl $rA, x ; rA = rA << x
shl $rA, [x] ; rA = rA << [x]
```

#### CMP (Compare)
Subtracts a register, immediate or value in memory from a register and discards the result.
This is used for setting the flags.

```
cmp $rA, $rB ; $rB - $rA
cmp $rA, [$rB] ; [$rB] - $rA
cmp $rA, x ; x - $rA
cmp $rA, [x] ; [x] - $rA
```

#### TST (Test)
Subtracts zero from a register or value in memory and discards the result.

```
tst $rA ; $rA - 0
tst [$rA] ; [$rA] - 0
```

### Interrupts
Interrupts are triggered by external hardware in order to raise the attention of the CPU and its software. An interrupt is handled on the rising edge of the corresponding CPU pin if it is masked. Nested interrupts are not handled.

#### ISH (Set interrupt handler)
Set the address to jump to when an interrupt is raised.

```
ish $rA, $rB ; Set the address in $rB as the interrupt handler for $rA
ish $rA, [$rB] ; Set the address at [$rB] as the interrupt handler for $rA
ish $rA, [$rB + x] ; Set the address at [$rB + x] as the interrupt handler for $rA
```

#### ISM (Mask interrupt)
Mask an interrupt so that it is handled when raised.

```
ism $rA ; Mask the interrupt number in $rA
ism [$rA] ; Mask the interrupt number in [$rA]
```

#### ICM (Unmask interrupt)
Unmask an interrupt so that it isn't handled when raised.

```
icm $rA ; Unmask the interrupt number in $rA
icm [$rA] ; Unmask the interrupt number in [$rA]
```

#### IEX (Exit interrupt handler)
Return to the instruction that was interrupted.

```
iex ; Return to the instruction that was interrupted
```

### Hardware loops
Hardware loops manage jumping and the iteration count, removing the need for explicit comparisons, decrements and jumps.
They can be nested without conflicts.

#### LSW and LEW (Start while loop, End while loop)
Start and end a while loop with a given iteration count and end address. The register is decremented each time the `lew` is executed.
```
loop_start:
	lsw $r1, #loop_exit
	...
	lew $r1, #loop_start
loop_exit:
```
The loop_start label must be directly before the `lsw` and loop_exit must be directly after the `lew`.

#### LED (End do-while loop)
End a do-while loop with a given iteration count and end address. The register is decremented, then if the register is greater than 0 then it jumps to the label operand.
```
loop_start:
	...
	led $r1, #loop_start
```

### Multitasking
Instructions that are used to manage the multitasking system.

#### YLD (Yield)
Yield control of the CPU to the next task in the queue, and reschedule the current task. The task's state is saved and the state for the next task is restored.

```
yld ; Yield control
```

#### ESW (Enable switching)
Enable preemptive task switching using timer interrupts.

```
esw
```

#### DSW (Disable switching)
Disable preemptive task switching using timer interrupts.

```
dsw
```

#### END (End task)
End execution of the current task and yield control of the CPU to the next task. The task's state is saved and the state for the next task is restored.

```
end ; End execution
```

#### SCH (Schedule task)
Schedule a task for execution by adding it to the end of the queue.

```
sch $rA ; Schedule task in rA
```

#### QSZ (Queue size)
Stores the current task queue size in a register.

```
qsz $rA ; rA = taskQueueSize
```

#### TSK (Setup task)
Sets up the task indicated by the register. Copies all register values to the destination task's, sets the destination task's program counter to r15 and sets its r14 to r12.

```
sch $rA ; Setup task indicated by value in rA
```

### Load/store
Operations that move values to and from registers and memory.

#### LD (Load)
Load an immediate or value in memory into a register.

```
ld $rA, x ; rA = x
ld $rA, [x] ; rA = [x]
```

#### MOV (Move)
Move a value from register or memory location to another register.

```
mov $rA, $rB ; rA = rB
mov $rA, [$rB] ; rA = [rB]
```

#### SWP (Swap)
Swap the values in two registers.

```
swp $rA, $rB ; Swap the values in both registers
swp $rA, [$rB] ; Set rA to the value in memory at the address in rB and set rB to the old value of rA
```

#### PSH (Push)
Write the value in the second register to memory at the address in the first register and subtract two from the first register.

```
psh $rA, $rB ; [rA] = rB, rA = rA - 2
```

#### POP (Pop)
Add two to the second register then read a value from memory at that address into the first register.

```
pop $rA, $rB ; rB = rB + 2, rA = [rB]
```

#### STR (Store)
Store a value in a register into memory at an address in a register or constant.

```
str $rA, $rB ; [rA] = rB
str $rA, x ; [rA] = x
```

### Input/Output

#### IN (Input)
Read a value from a GPIO pin into a register.

```
in $rA, x ; Read input from GPIO pin x into rA
in $rA, [x] ; Read input from the GPIO pin number in memory at address x into rA
```

#### OUT (Output)
Write a value from a register to a GPIO pin.

```
out x, $rA ; Write the lsb of rA to pin number x
out [x], $rA ; Write the lsb of rA to the pin number in memory at address x
```

### Miscellaneous

#### NOP (No operation)
Does nothing.

```
nop
```

#### HLT (Halt)
Assert the halt line high for one cycle. This should stop execution of the CPU but the behaviour depends on the external chipset.

```
hlt
```

## Operands
Most instructions take one or more operands of the following types:

### Integers
Decimal, binary and hexadecimal integers are supported.

```
123
0x12AF
0b0101
```

### Registers
A register operand is of the form `$rX` where `X` is a number between 0 and 15 (inclusive).

```
$r0
$r5
$r12
```

### Labels
Labels are used as placeholders for some constant value or address in memory. They can be defined with a `.def` directive (see the directives section) or by labelling a location in the source file.

```
label1:
	; Instructions and other content
```

Uses of `label1` will evaluate to the address at which the label was defined.

A label can be used before it is defined.

## Condition codes
All instructions can be executed conditionally by adding a *condition code* to the mnemonic.

```
mov.eq $rA, $rB ; Execute the mov based on the eq condition code.
jmp.lt x ; Execute the jmp based on the lt condition code.
```

| Codes | Executes if |
|------|-------------|
|  le  | Either the N or Z flag is set		|
|  lt  | The N flag is set			|
|  eq  | The Z flag is set			|
|  ne  | The Z flag is not set			|
|  ge  | The N flag is not set			|
|  gt  | Neither the N flag or Z flag is set	|
|  c   | The C flag is set			|
|  nc  | The C flag is not set			|

Omitting a condition code makes the instruction unconditionally executed.

## Directives
Directives don't directly map to machine code instructions and instead tell the assembler to do something.

### def
The `def` directive defines a label to be a constant integer.

```
.def label1 x
```
`label1` will then be evaluated as x.

### data
The `data` directive inserts constant bytes into the binary at the current address.

```
.data x
```
Inserts the 16-bit value x into the binary.

### fill
The `fill` directive fills a space with a specific integer value.

```
.fill num val size
```
Inserts `val` `num` times, each one being `size` bytes
