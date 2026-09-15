# SPHINX Oberon Language Specification

## A Low-Level Oberon Dialect Compiling to NASM

SPHINX Oberon is a strict 16-bit systems programming language that combines the structured syntax of Oberon with direct access to the x86 CPU. This document defines the complete language semantics and, crucially, shows how each construct translates into human-readable NASM assembly. The target is real-mode DOS .COM or .EXE programs; segment registers are 16-bit and memory is addressed with `segment:offset` pairs.

Few notes:
- This dialect allow _ into identifiers.
- Comments come in two forms: `(* ... *)` (block, can span multiple lines) and `// ...` (single-line, runs to end of line, same convention as C/C++/Oberon-2). `(* *)` does **not** nest: the first `*)` closes the comment regardless of any `(*` seen since, so `(* outer (* inner *) still code *)` is a comment ending after `inner`, leaving `still code *)` to be parsed as ordinary source (and very likely a syntax error)  -- unlike Oberon-07, which does nest. `//` has no such hazard (nothing after it on the same line is ever parsed, block or not).
- Exported procedures (marked with * ) is GLOBAL (nasm) and can be NEAR/FAR (default - far).
- If module initialization part exists (same as main() in C) - need generate label "start" and this block begin.
- `IMPORT` reads generated declaration headers, not implementation bodies. A header is wrapped in `MODULE name; ... END name.`; imported declarations enter the importing scope without a module-name qualifier. Link the corresponding object files separately.
- **IMPORT resolves to `.SHD`, not `.SMD`** (Sphinx Oberon HeaDer  -- like a C `.h`): `IMPORT Files;` opens `Files.SHD`, never `Files.SMD` directly, regardless of what the importing file's own extension is. `.SHD` is not hand-maintained  -- the translator generates it automatically as a side effect of translating a `.SMD` file (see below), the same way `.ASM` is; only the top-level file passed on the command line is ever opened as `.SMD`. Resolution tries the current directory first (`Files.SHD`), then a hardcoded `LIB\Files.SHD` fallback if that doesn't exist (`SRC/SCAN.PAS`'s own `OpenInclude`)  -- `IMPORT` itself has no path syntax to name a directory, so this lets many project directories share one real copy of a common module's own `.SHD` via a single `LIB` directory symlink per project (`ln -s /path/to/LIB LIB`) instead of a separate `.SMD`/`.SHD`/`.RDF` symlink per shared module. `TASM.EXE`/`TLINK.EXE` have no such search path  -- a project's own `Makefile` still lists every `LIB/<Name>.RDF` it links against explicitly.
- **Every top-level `.SMD` translation also writes a matching `.SHD` sibling** (`FILE.SMD` -> `FILE.SHD`, alongside `FILE.SMD` -> `FILE.ASM`)  -- **unless** that file has its own `BEGIN...END` init part (a real `start` label/entry point, i.e. it's a standalone program, not a library other modules could usefully `IMPORT`). The generated `.SHD` contains regenerated forms of only the **`*`-exported** declarations: each `CONST Name* = value;` (its own final folded value), each `TYPE Name* = RECORD ... END;`, and one `PROCEDURE Name(params): RetTy; NEAR|FAR; EXTERNAL;` line (preserving the procedure's actual calling convention) per `*`-exported `PROCEDURE`  -- bodies, comments, any non-`*` `CONST`/`TYPE`/`PROCEDURE`, `FORWARD`-only `PROCEDURE`s, and `VAR` globals are never included. A module's own `CONST`/`TYPE`/`PROCEDURE` therefore each need their own real `*` export marker to be usable by anything that `IMPORT`s it  -- this differs from the old textual-splicing behavior, where every declaration was visible to an importer regardless of `*`.
- STRONG: Allowed 8086 intruction set only. (no 286, 386 etc)

---

## Lexical Rules

Identifiers start with an ASCII letter or `_`, followed by ASCII letters,
digits, or `_`. User-declared names are case-sensitive; spell references
exactly as declared. Keywords and register names are recognized without
case distinctions. Keep identifiers to at most 63 characters: an
identifier or numeric literal exceeding that length is a translator
error naming the offending token (not silent truncation/splitting).
Source is byte-oriented, not Unicode; use ASCII syntax and explicit byte
escapes for non-ASCII string data. Keep filenames in DOS 8.3 format.

Keywords (do not reuse them as identifiers):

```ob2
MODULE IMPORT CONST TYPE RECORD END VAR PROCEDURE FORWARD INTERRUPT
FAR NEAR REG BEGIN RETURN IF THEN ELSIF ELSE WHILE DO BREAK CONTINUE
ASM INC DEC PUSH POP USES BYTE WORD INTEGER LONGINT BOOLEAN INT SHL
SHR XOR POINTER CHAR DIV MOD EXTERNAL OR
SETIFLAG SETCFLAG SETDFLAG LOADB LOADW STOREB STOREW COPYB COPYW
INPORTB INPORTW OUTPORTB OUTPORTW
ADDCARRY SUBBORROW ROL ROR RCL RCR
```

Register names and the predefined names `TRUE`, `FALSE`, `FLAGS`,
`CFLAG`, `ZFLAG`, `ADR`, `SEG`, `SIZE`, `ODD`, `BASE64`, and `FILE` also
have special meanings in the relevant contexts; avoid shadowing them.

Numeric forms are decimal (`123`), hexadecimal (`0x7B`, `7BH`), and
binary (`1111011B`). Hexadecimal suffix notation must start with a digit
(`0FFH`, not `FFH`). A minus sign is an operator, not part of the token.
The scanner accepts at most eight hex digits, 32 binary digits, or ten
decimal digits, storing a 32-bit bit pattern; the decimal digit-count
check does not reliably reject overflow. Stay within the destination's
range (BYTE 0..255, WORD 0..65535, INTEGER -32768..32767). Wider scanned
constants do not enable wider arithmetic, and overflow is not a checked
runtime error. There are no floating-point literals.

---

## 1. Module Structure

```ob2
MODULE ModuleName;
  IMPORT OtherModule;   (* optional *)
  CONST ...
  TYPE  ...
  VAR   ...             (* global variables *)
  PROCEDURE ...;         (* definitions, and optionally FORWARD
                             declarations -- see section 6.3.1 *)
  PROCEDURE ...;
  ...
BEGIN
  ...                   (* module initialisation *)
END ModuleName.
```

**NASM translation:**  
Globals are placed in `.data` when initialized, or `.bss` otherwise. Code goes in the `.text` section. The module body becomes the entry point. It does not imply automatic DOS
termination or DS/SS setup; establish the segments required by the selected
COM/EXE layout and explicitly terminate the program. Example:

```ob2
MODULE Hello;
BEGIN
  AX := 0x4C00;
  INT(21H)
END Hello.
```

translates to:

```nasm
section .data
section .text
global start
start:
    mov  ax, 0x4C00
    int  0x21
```

`CONST`/`TYPE`/`VAR` sections and `PROCEDURE` definitions may repeat and appear in any order, mixed freely (e.g. `VAR ... CONST ... PROCEDURE ... VAR ... PROCEDURE ...`)  -- each keyword still applies its own usual rules to the declarations that follow it. A `VAR` section (global or local, inside a `PROCEDURE`) may also group several names under one shared type with a comma: `a, b, c : WORD;` is equivalent to three separate one-name declarations, `a : WORD; b : WORD; c : WORD;`  -- this does not extend to a shared initializer (`a, b : WORD = 5;` is a translator error; give each name its own `= value` on its own line instead).

The current translator groups buffered declarations and code into output
sections. Source declaration order does not imply the same sequence of
section switches in assembly.

---

## 2. Registers

The CPU registers are predefined variables. They are typed as follows:

| Register | Type     |
|----------|----------|
| AX, BX, CX, DX, SI, DI, BP, SP | WORD (16-bit unsigned/signed) |
| AL, AH, BL, BH, CL, CH, DL, DH | BYTE |
| CS, DS, ES, SS                 | WORD (segment) |

Registers can be read and written just like ordinary variables. The compiler generates a `mov` instruction (or an appropriate alternative) for every assignment.

**Examples:**

```ob2
AX := 0x1234;
AL := AH;
BX := CX + 4;
DS := CS;
```

translates to:

```nasm
mov  ax, 0x1234
mov  al, ah
mov  bx, cx
add  bx, 4          ; because + is left-to-right, but BX := CX + 4 becomes mov bx,cx then add bx,4
push cs             ; mov ds, cs does not exists for 8086
pop  ds
```

Only registers named in `USES` are promised preservation across a procedure call (section 6.5). The compiler may also save scratch registers temporarily while evaluating expressions. In expressions, reading a register yields its current value; writing it updates the hardware.

**Register and flag effects.** `USES` preserves listed registers across
one procedure call, not across each expression inside its body. Generated
instructions may use scratch registers and change flags:

| Construct | Registers/flags to account for |
|---|---|
| General value expression | AX accumulator; CX may hold a call result in a chain |
| Multiplication/division/remainder | AX and DX; arithmetic flags follow the emitted instructions |
| Runtime array indexing | BX base and CX scaled index; arithmetic flags change |
| Array parameter with constant index | BX holds the passed base address |
| Byte widening | May use AX and clear AH, changing flags |
| Procedure call | Result registers plus every register not preserved by the callee |

Arguments are evaluated left to right from live register values. In
`Foo(1, AX)`, evaluating the first argument may already change AX before
the second argument reads it. Staging register-bound arguments prevents
later argument evaluation from destroying an already computed argument;
it does not snapshot hardware registers at the start of the call. Save
needed values in variables or explicitly preserved registers first.
`CFLAG`/`ZFLAG` read the flags at that point in execution; intervening
arithmetic or generated zero-extension can change them. For exact effects,
inspect the emitted assembly, since instruction selection can vary.

---

## 3. Types and Type Declarations

### 3.1 Basic Types

| Type    | Size (bytes) | Description                           |
|---------|--------------|---------------------------------------|
| BYTE    | 1            | unsigned 8-bit                        |
| CHAR    | 1            | synonym for BYTE (Pascal port extension) |
| BOOLEAN | 1            | like BYTE, 0 = FALSE, <>0 = TRUE       |
| WORD    | 2            | unsigned 16-bit (same size as INTEGER, but unsigned  -- see section 7.1) |
| INTEGER | 2            | signed 16-bit                         |
| LONGINT | 4            | signed 32-bit, stored little-endian   |
| POINTER | 4            | synonym for LONGINT (Pascal port extension) |
| Array   | element_size * count | packed sequentially           |
| RECORD  | field sizes plus padding | even-offset alignment as specified in section 3.2 |

`TRUE` and `FALSE` are predeclared BOOLEAN constants (`TRUE` = 1, `FALSE` = 0), usable anywhere a literal is:

```ob2
RETURN TRUE
```

translates to:

```nasm
mov  ax, 1
```

Arrays and records are declared as in Oberon:

```ob2
VAR
  buf: BYTE[128];
  items: StructXmsRec[4];
```

In NASM these become `resb`, `resw`, `resd` or `db`, `dw`, `dd`.

An array's `[N]` bound must be a positive numeric literal or `CONST`
name, no larger than 32767  -- zero, negative, or oversized bounds are
translator errors (see the Implementation Limits table, section 14).
The array's own total byte count (`element_size * N`, or, for a RECORD
array, its RECORD type's own full size times `N`) is also checked
against the 65535-byte real-mode segment limit, independent of `N`'s own
32767 cap  -- a large element size can still overflow well under that
count limit (e.g. `LONGINT[20000]`, 80000 bytes). The same byte-count
check applies to a RECORD field that is itself declared as an array
(section 3.2).

**Passing an array to a procedure:** use an array formal such as
`buf: BYTE[]` and pass the array name (automatic address passing, section
6.6), or explicitly pass `ADR(arr)` to a WORD/INTEGER address parameter.
Neither form passes a length or segment. This manual byte-store example
uses AL to make the access width explicit:

```ob2
VAR buf: BYTE[16];
PROCEDURE FillIt(bufAddr: INTEGER); NEAR;
BEGIN
  BX := bufAddr;
  AL := 65;
  [DS:BX] := AL
END FillIt;
...
FillIt(ADR(buf));
```

translates to:

```nasm
FillIt:
    push bp
    mov  bp, sp
    mov  bx, [bp+4]     ; bufAddr
    mov  al, 65
    mov  byte [ds:bx], al
    mov  sp, bp
    pop  bp
    retn 2
...
    mov  ax, buf        ; ADR(buf) -- buf's own address, a compile-time constant for a global
    push ax
    call FillIt
```

### 3.2 Global Type Declarations

Record types are defined at module level in the `TYPE` section. Each record becomes a NASM structure that can be used for field offset calculations.

**Syntax:**

```ob2
TYPE
  RecordName = RECORD
    field1 : type;
    field2 : type;
    ...
  END;
```

**NASM translation:**  
A NASM `struc` is emitted. The structure name is `RecordName` and its fields are accessible as `RecordName.fieldName` inside the assembler.

```ob2
TYPE
  Point = RECORD
    x : INTEGER;
    y : INTEGER;
  END;

  BigData = RECORD
    id    : WORD;
    value : LONGINT;
    flag  : BYTE;
  END;
```

translates to:

```nasm
struc Point
    .x: resw 1
    .y: resw 1
endstruc

struc BigData
    .id:    resw 1
    .value: resd 1
    .flag:  resb 1
endstruc
```

A RECORD field whose own size is 2 bytes or more (WORD/INTEGER/LONGINT/POINTER, or a nested RECORD field whose own total size is even) starts on an even offset: a single padding byte is inserted before it if the running offset is currently odd (e.g. a BYTE field immediately followed by a WORD field). A BYTE/BOOLEAN/CHAR field itself needs no alignment. All field offsets are byte offsets from the start of the structure.

**Array fields:** a field may itself be an array (`name : type[N];`, the same `[N]` bound as an ordinary array VAR, section 3.1)  -- packed sequentially with no padding *inside* the array, same as a standalone array VAR:

```ob2
TYPE
  FileBuf = RECORD
    handle : INTEGER;
    ofs    : WORD;
    fill   : WORD;
    data   : BYTE[1024];
  END;
```

translates to:

```nasm
struc FileBuf
    .handle: resw 1
    .ofs:    resw 1
    .fill:   resw 1
    .data:   resb 1024
endstruc
```

`SIZE(FileBuf)` is 1030 (2+2+2+1024), and `handle`/`ofs`/`fill` still work as ordinary scalar fields (`[seg:base].FileBuf.ofs := ...`). An array field has no standalone name of its own to `ADR()` the way a global/local array does, so it's addressed through the same `[seg:base].RecordType.field` structured-access syntax, given to `ADR()` instead of a bare name: `ADR([DS:BX].FileBuf.data)`. Using an array field directly as a scalar operand (`AX := [DS:BX].FileBuf.data;`) is a translator error  -- only `ADR()` of it is valid.

Once a record type is defined, it can be used in variable declarations and direct memory access (see section 10).

**Scalar type aliases (Pascal port).** The `TYPE` section also accepts a non-`RECORD` declaration, `Name = ScalarType;`, naming an existing scalar type (`BYTE`/`BOOLEAN`/`WORD`/`INTEGER`/`LONGINT`, the Pascal-port synonyms `CHAR`/`POINTER`, or another already-declared alias):

```ob2
TYPE
  Handle = WORD;
  Offset = INTEGER;
```

An alias has **exactly** its underlying type's own representation and signedness  -- it is not a distinct, incompatible type, just another spelling for the same one. `VAR h: Handle;` reserves the same 2 bytes a plain `WORD` VAR would, and a comparison through an `INTEGER`-based alias (`Offset`, above) is still signed, exactly as if `INTEGER` had been written directly. An alias is usable everywhere an ordinary scalar type name is: `VAR` declarations, `RECORD` fields, `PROCEDURE` parameters, and `PROCEDURE` return types. `TYPE Foo = SomeRecordType;` (aliasing a `RECORD` type, rather than a scalar) is a translator error  -- only a scalar aliases this way.

An **exported** alias (`Name* = ScalarType;`) is preserved in the module's own regenerated `.SHD` header exactly as written (`Handle = WORD;`), the same way an exported `RECORD` type's full field list is  -- an importing module's own `VAR h: Handle;` resolves it correctly.

### 3.3 Character and String Literals

Two distinct quoting styles, matching NASM's own distinction between a character-literal immediate and a quoted string operand:

- **`'x'`** (single-quoted, exactly one character) is a plain numeric immediate  -- its `ORD` value. No storage is allocated; it behaves exactly like a numeric literal.
- **`"..."`** (double-quoted, any length including empty) is a genuine string literal. It is stored once in a `.data` table (deduplicated: two occurrences of the identical text share one label) and evaluates everywhere to its own **offset**  -- SPHINX has no string-*value* operations, only pass-by-offset, the same model arrays and records already use. A string literal can be passed as a call argument, assigned to a register, or assigned to a 16-bit variable.

```ob2
AL := 'A';
PrintMsg("Hello, world!$");
msgPtr := "Another one$";
```

translates to:

```nasm
mov  AL, 65
mov  ax, _literal0
push ax
call PrintMsg
mov  ax, _literal1
mov  [msgPtr], ax
...
section .data
_literal0: db 'Hello, world!$', 0
_literal1: db 'Another one$', 0
```

Every literal used anywhere in a module is collected and emitted once, as a NUL-terminated `db` line, in a `.data` block appended at the very end of the translated output  -- the label may be referenced (as a forward reference) from anywhere earlier in the file. A byte in the literal's own text that would corrupt a plain NASM `'...'` operand if placed there directly (the `'` quote character itself, or any control byte such as tab/CR/LF/ESC  -- most commonly reached via an escape sequence, below) is emitted as a bare `NNh` hex immediate instead, comma-separated with any surrounding quoted run of ordinary printable characters  -- `_literal0: db 01Bh,'[95mHello',01Bh,'[0m',0`, for example. Plain printable text with none of these bytes still emits as a single quoted `db 'text', 0` line, unchanged.

**Escape sequences**: inside either quoting style, a `\` introduces a C-like escape, decoded to a single raw byte at translate time:

| Escape | Byte | Meaning |
|--------|------|---------|
| `\t`   | `09h` | tab |
| `\n`   | `0Ah` | line feed |
| `\r`   | `0Dh` | carriage return |
| `\\`   | `5Ch` | literal backslash |
| `\'`   | `27h` | literal single quote |
| `\"`   | `22h` | literal double quote |
| `\ooo` |  --    | 1 to 3 **octal** digits, e.g. `\033` = `1Bh` (ESC) |
| `\xHH` |  --    | 1 to 2 **hex** digits, e.g. `\x1b` = `1Bh` (ESC, same byte as `\033`) |

This is what makes a literal delimiter, or a genuinely unprintable byte such as an ANSI escape, representable at all: `"\033[95mRed\033[0m"` and `"\x1b[95mRed\x1b[0m"` both encode the same five-byte-prefixed/four-byte-suffixed ANSI color sequence. `'\t'` is a one-character `'...'` literal whose `ORD` value is 9, exactly as if it had been written `9` or `09H` directly. An escape not matching this table (e.g. `\q`), or a `\` at the very end of a literal with nothing after it, is a translator error  -- an unrecognized escape is far more likely a typo than an intentional literal backslash, so it is caught rather than silently passed through as two separate characters.

### 3.4 Array Literals (`BASE64` / `FILE` / `"..."`)

A global array declared with an **empty** bound (`T[]`, no size) can be given a real initial value instead of being uninitialized `.bss` space  -- the array's length comes from the decoded data itself, not from a written-out `N`:

```ob2
VAR
  v : BYTE[]    = BASE64("TWFu");
  w : CHAR[]    = FILE("sprites.bin");
  s : BYTE[]    = "Hello!";
```

- `BASE64("...")` streams its encoded text and is exempt from the ordinary 255-byte string-literal limit. The decoded output is limited to 65535 bytes; that payload requires 87380 base64 characters, excluding whitespace. There is no separate 65535-character encoded-text limit. An ordinary string literal exceeding 255 decoded bytes is a translator error, not silent truncation; keep them within that limit.
- `BASE64("...")` decodes a standard base64 string into raw bytes at translate time. Whitespace (space, tab, CR, LF) anywhere in the text is ignored, so a long blob may be broken across multiple source lines for readability:
  ```
  VAR v : BYTE[] = BASE64("TWFu
     IGlzIHRoZSBjb25kaXRpb24=");
  ```
  decodes identically to the same characters written on one line.
- `FILE("...")` reads a file's raw bytes at translate time. The path is resolved **relative to the `.SMD` file the declaration appears in** (not the process's current directory, and not `IMPORT`'s own convention, which is CWD-relative)  -- the same file, correctly, even across an `IMPORT`ed file's own `FILE()` calls.
- `"..."` (a plain string literal directly as the initializer, not wrapped in `BASE64()`/`FILE()`) encodes the literal's own raw bytes, plus one trailing zero byte (an ASCIIZ C-style string)  -- same 255-character limit as any other `"..."` string literal (section 3.3). Unlike `BASE64()`/`FILE()`, no decoding happens; the bytes are exactly the literal's own text, in source order.
- `T` may be any element type SPHINX already accepts in an array declaration (`BYTE`/`CHAR`/`BOOLEAN`/`WORD`/`INTEGER`/`LONGINT`, or a declared `RECORD` type). The declared type is descriptive only  -- the decoded data is always emitted as a flat sequence of bytes, one `db` per byte (as a hex-byte immediate, e.g. `048h`, never a quoted NASM string  -- so an initializer text containing a `'` needs no special escaping), regardless of `T`.
- The array always goes in `.data` (it holds a real stored value), never `.bss`, unlike every other array form.
- `SIZE(v)` (section 9) returns the decoded byte count for an array declared this way (for `"..."`, that's the text length plus 1 for the trailing zero byte). `LEN(v)` (section 9) returns that same byte count divided by `T`'s own element size (a translator error if not evenly divisible).
- `T[]` **requires** a `BASE64()`/`FILE()`/`"..."` initializer  -- an empty bound with no initializer, or one of these initializers on an explicit `T[N]` bound, are both translator errors.
- Only supported for a **global** `VAR`  -- SPHINX has no local-`.data` concept (a local array is always `.bss`/frame space), so `T[] = BASE64(...)`/`FILE(...)`/`"..."` inside a `PROCEDURE`'s own `VAR` section is a translator error.

```ob2
VAR sprite : BYTE[] = BASE64("/wD/AA==");
```

translates to:

```nasm
section .data
sprite: db 255,0,255,0
```

---

## 4. Constants

Constants are simple named values of type INTEGER, WORD, BYTE, or LONGINT. They can be used wherever a literal is allowed. No storage is allocated.

```ob2
CONST
  MaxBuf = 128;
  ComPort = 0x3F8;
```

---

## 5. Variables

### 5.1 Global Variables
Defined at module level, they reside in either the `.bss` or `.data` segment depending on whether an initializer is given: an **uninitialized** global (the common case  -- a plain scalar, an array, or a RECORD instance) is reserved space in `.bss`; only a global with an explicit `= value` initializer holds a real stored value and belongs in `.data`. The translator does not emit a runtime zeroing loop for `.bss`; zero initialization depends on the linked image and loader. Initialize globals explicitly before reading them when that guarantee is required. Declarations select the appropriate output section.

```ob2
VAR
  counter: INTEGER;
  flag: BYTE;
  bigValue: LONGINT;
```

translates to:

```nasm
section .bss
counter: resw 1
flag:    resb 1
bigValue: resd 1
```

If an initial value is given (Oberon allows it), a real value is stored, and it goes to `.data` instead:

```ob2
VAR version: WORD = 0x1700;
```

translates to:

```nasm
section .data
version dw 0x1700
```

### 5.2 Local Variables
Declared inside a procedure, they are allocated on the stack. The compiler reserves space by adjusting `SP`.

```ob2
PROCEDURE Example;FAR;
VAR
  i: INTEGER;
  tmp: BYTE[4];
BEGIN
  ...
END
```

translates to:

```nasm
Example:
    push bp
    mov  bp, sp
    sub  sp, 6          ; 2 bytes for i + 4 bytes for tmp
    ...
    mov  sp, bp
    pop  bp
    retf                ; or retn
```

Access to local variables uses `[bp - offset]`.

---

## 6. Procedures and Calling Convention

### 6.1 Pascal Calling Convention
Parameters are pushed **left to right**. The callee cleans the stack with `ret n`. This is the default for `NEAR` procedures.

```ob2
PROCEDURE Add(a, b: INTEGER): INTEGER; NEAR;
BEGIN
  AX := a;
  AX := AX + b;
  RETURN AX
END Add;
```

Call: `result := Add(3, 4);`

translates to:

```nasm
; Call site
mov  ax, 3
push ax
mov  ax, 4
push ax
call Add
; (callee cleans, so no add here)

; Procedure definition
Add:
%define _a bp+6
%define _b bp+4
    push bp
    mov  bp, sp
    mov  ax, [_a]   ; a (first param, higher address)
    add  ax, [_b]   ; b (second param)
    mov  sp, bp
    pop  bp
    retn  4           ; clean 4 bytes of parameters
%undef _a
%undef _b
```

Stack layout after `push bp` / `mov bp, sp`:

```
[bp+0] = saved BP
[bp+2] = return IP (NEAR)
[bp+4] = last pushed param (rightmost)
[bp+6] = first pushed param (leftmost)
```

### 6.2 Register Parameters
If a formal parameter name matches a register, the value is passed **directly in that register** - no stack operation.

```ob2
PROCEDURE CB_API(AX); NEAR;
BEGIN
  INT(2FH)
END CB_API;
```

Call: `CB_API(0x1700);`

translates to:

```nasm
; call site
mov  ax, 0x1700
call CB_API

; procedure (near, no stack frame needed)
CB_API:
    int  0x2F
    retn
```

A procedure with no locals, stack parameters, or `USES` needs no stack frame.

The call site shown above is the minimal-case ideal, not the current Pascal translator's literal output: the real translator always pushes every argument first (any argument's own evaluation might otherwise clobber an already-computed register-bound one, `DOCS/SPHO.MD`'s own "Call sites now load a register-named formal's argument directly" entry has the full reasoning), then extracts each register-bound one back off the stack via a small self-contained `push bp`/`[bp+N]`/`pop bp` sequence  -- a few bytes larger than the ideal `mov ax, 0x1700; call CB_API` shown here for this trivial single-argument case, but correct for any number/mix of register- and stack-bound arguments in any order, which the minimal form cannot express in general.

The keyword `REG` is optional for clarity: `PROCEDURE CB_API(REG AX);` is equivalent.

### 6.3 Procedure Attributes

| Attribute   | Call instruction | Return instruction | Description |
|-------------|------------------|--------------------|-------------|
| `NEAR` | `call`      | `ret` / `ret n`    | 16-bit near call |
| `FAR`       | `call far`       | `retf` / `retf n`  | 16-bit far call, stack includes segment |
| `INTERRUPT` | (none)           | `iret`             | Interrupt handler, no parameters allowed |

Without an explicit attribute, an unexported procedure defaults to NEAR;
a `*`-exported procedure defaults to FAR. Explicit NEAR/FAR overrides
that default. The generated `.SHD` preserves the resulting attribute.

**INTERRUPT** procedures cannot be `NEAR`/`FAR`. They must end with `iret`. `USES` and local `VAR`s are allowed (an `INTERRUPT` procedure has its own stack frame for those, same `push bp`/`mov bp,sp` prologue as any other), but **parameters are not**  -- an interrupt has no caller-pushed argument list to clean up. A `USES` clause saves/restores only the listed items; list `FLAGS` explicitly when that preservation is required. The interrupt return itself restores the CPU-saved flags through `iret`. Without `USES`, the programmer must do it manually in `ASM` blocks.

A parameter list on an `INTERRUPT` procedure is a translator error
("INTERRUPT procedures may not have parameters")  -- the `iret` return
would not clean up a caller-pushed argument list the way `retn n`/
`retf n` would for `NEAR`/`FAR`.

### 6.3.1 `FORWARD` Declarations

`PROCEDURE Name(params): RetTy; NEAR|FAR; FORWARD;` declares a procedure's
full signature without a body  -- the real definition (identical signature,
a real `BEGIN...END` body) appears later in the same file. This lets a
procedure call another one that is textually defined further down:

```ob2
PROCEDURE Helper(): INTEGER; NEAR; FORWARD;

PROCEDURE Caller(): INTEGER; NEAR;
BEGIN
  RETURN Helper()
END Caller;

PROCEDURE Helper(): INTEGER; NEAR;
BEGIN
  RETURN 42
END Helper;
```

**Declare the full signature before a call that passes arguments.** A
call to an undeclared same-file procedure with **no arguments at all**
is recorded; after parsing, the compiler resolves its name and patches
`call` versus `call far` (no `FORWARD` needed for this case  -- see the
example just above). An undefined name is still an error. This late
patch only ever fixes up the `call`/`call far` mnemonic, never argument
placement or return-value handling  -- so a call that passes **any**
argument to a same-file procedure with no signature recorded yet
(no prior real definition, `FORWARD`, or `EXTERNAL` declaration) is
rejected outright, at the call site, with a translator error naming the
missing `FORWARD` declaration. Register parameters, LONGINT parameters/
results, array auto-address passing, and byte-sized results all depend
on a signature already known when the call is emitted, and there is no
safe default to guess in its absence. For example, declare
`PROCEDURE Send(AX); NEAR; FORWARD;` before a call that must place its
argument in AX. A prior full definition or imported EXTERNAL signature
also supplies the necessary information, and satisfies this requirement
exactly the same way a `FORWARD` declaration does.

A `FORWARD` declaration is not itself a callable definition: a second,
real `PROCEDURE Name...` with the same name is required later in the
file, or the name is still unresolved at end-of-file (same error as
never declaring it). That real definition's own signature must match
the `FORWARD` declaration's  -- parameter count, each parameter's
register-vs-stack placement (and register, if register-bound) and
`LONGINT`-vs-not type, and whether/what return type was declared. A
mismatch is a translator error (e.g. "parameter count differs from
FORWARD declaration", "return type differs from FORWARD declaration").
Two full `PROCEDURE` definitions sharing a name (not a `FORWARD`
followed by its real body) is a translator error ("duplicate PROCEDURE
definition"). `FORWARD` is not supported on an `INTERRUPT` procedure.

### 6.3.2 `EXTERNAL` Declarations

`PROCEDURE Name(params): RetTy; NEAR|FAR; EXTERNAL ["realname"];`
declares a procedure with **no body at all**  -- it is defined elsewhere
(another object file/library, linked in separately) and only its
signature is known here. `EXTERNAL` takes the same position `FORWARD`
does (right after `NEAR`/`FAR`/`INTERRUPT`) and, like `FORWARD`, ends the
declaration with no `BEGIN...END` body  -- the two are mutually exclusive,
never both on the same declaration.

Two forms:

```ob2
PROCEDURE ddd(p: INTEGER): BOOLEAN; FAR; EXTERNAL "ddd1";
PROCEDURE eee(); NEAR; EXTERNAL;
```

- **Named** (`EXTERNAL "realname"`)  -- `ddd` is only a local SPHINX-side
  synonym; every call to `ddd(...)` compiles to a call against
  `realname` (`ddd1` above) instead, and `extern ddd1` is emitted, not
  `extern ddd`. Use this when the real symbol's name isn't a legal (or
  desired) SPHINX identifier, or simply to give it a more convenient
  local name.
- **Unnamed** (bare `EXTERNAL;`)  -- the SPHINX name **is** the real
  linker symbol: `eee()` calls `eee`, and `extern eee` is emitted.

Either form emits a NASM `extern` directive (once, at the declaration
site) and makes the name callable exactly like any other declared
procedure  -- `NEAR`/`FAR`-ness, parameter passing, and return-register
convention (section 6.4) all apply normally; the only difference is that no
code is generated for a body, and linking must supply the real symbol
from elsewhere. Not supported on an `INTERRUPT` procedure.

### 6.4 Return Values
Functions return via registers:

| Return type | Register |
|-------------|----------|
| BYTE, BOOLEAN | AL     |
| INTEGER, WORD | AX     |
| LONGINT       | DX:AX (DX=high, AX=low) |

**`CHAR` is a synonym for `BYTE`** (Pascal port extension; the original Oberon implementation has no `CHAR` type anywhere  -- `ParseBaseType`'s original scalar-keyword list was `BYTE`/`BOOLEAN`/`WORD`/`INTEGER`/`LONGINT` only, matching section 3.1's own table). A single character is represented as a `BYTE` holding its ASCII value (or a `'x'` character literal, section 3.3, which is itself just a numeric immediate); `CHAR` is accepted everywhere `BYTE` is and produces identical code.

`RetTy` may also be a scalar type alias (section 3.2)  -- it selects the same register(s) its underlying scalar type would, per the table above. A `RECORD` type name (aliased or not) is rejected as a return type outright: this table has no slot for an arbitrary-sized structured value.

The compiler generates a move to the appropriate register(s) before `RET`.

```ob2
PROCEDURE GetMax(): INTEGER; NEAR;
BEGIN
  RETURN 0xFFFF
END;
```

translates to:

```nasm
GetMax:
    mov  ax, 0xFFFF
    retn
```

A procedure call taking no arguments may omit the parentheses entirely  -- `Foo;` is equivalent to `Foo();`:

```ob2
XMS_CLEAR_REC;
```

translates to:

```nasm
call far XMS_CLEAR_REC
```

### 6.5 `USES` Clause
`USES` lists registers that the procedure must preserve. The compiler emits `push` in prologue and `pop` in epilogue. `FLAGS` is also valid and generates `pushf`/`popf`.

```ob2
PROCEDURE Calc; NEAR;
USES BX, CX, FLAGS;
BEGIN
  ...
END;
```

translates to:

```nasm
Calc:
    push bx
    push cx
    pushf
    ... body ...
    popf
    pop  cx
    pop  bx
    retn
```

`USES` can appear together with local variables; the allocation order is: push BP, set BP, push USES registers, then allocate local space. Epilogue reverses.

### 6.6 Procedure Parameters

Procedures can have parameters with different types. A comma-separated run of names shares one trailing type (`a, b: INTEGER`  -- both `a` and `b` are INTEGER); `;` starts a new group with its own type, so a single parameter list can mix types freely:

```ob2
PROCEDURE Mixed(x: BYTE; y: INTEGER): INTEGER;
BEGIN
  AX := x;
  BX := y;
  RETURN AX + BX
END Mixed;
```

Call: `result := Mixed(1, 20);`

translates to:

```nasm
; Call site
mov  ax, 1
push ax
mov  ax, 20
push ax
call Mixed

; Procedure definition
Mixed:
    push bp
    mov  bp, sp
    mov  al, [bp+6]   ; x (BYTE in a two-byte stack slot)
    xor  ah, ah
    mov  BX, [bp+4]   ; y (second param)
    add  ax, BX
    mov  sp, bp
    pop  bp
    retn  4           ; unexported and unmarked: default NEAR
```

A register-named formal (section 6.2) never takes a type at all and never shares a following group's type  -- it may sit alongside ordinary names in the same comma-separated run.

**By-value RECORD parameters are not supported.** A parameter's type may
be `BYTE`/`BOOLEAN`/`WORD`/`INTEGER`/`LONGINT` (or the Pascal-port
synonyms `CHAR`/`POINTER`, section 6.4) or a declared RECORD type,
but a RECORD-typed one is rejected as a translator error ("by-value
RECORD parameter not supported")  -- the Pascal calling convention above
pushes/reads exactly one word (or byte) per parameter, which cannot
represent a multi-byte struct's full value: an earlier version of
the original Oberon implementation accepted this silently and truncated the record to its own
first field at both the call site and the callee's own stack-cleanup
size, a correctness bug, not merely an unsupported feature. Pass a
record the same way an array is passed (section 3.1): `ADR(rec)` into a plain
`WORD`/`INTEGER` parameter, and access fields inside the callee via
direct memory access (section 10, `[seg:paramReg].RecordType.field`).

**Array parameters (Pascal port).** A formal parameter's type may be
followed by `[N]` or an empty `[]`, e.g. `buf: WORD[3]` or
`buf: WORD[]`  -- address-only sugar over the manual `ADR()` convention
above, not a new calling convention: the parameter is still exactly one
`WORD`/address parameter underneath (`N`, if given, is descriptive
only  -- parsed but not enforced). The only difference from writing
`buf: WORD` by hand is at the CALL SITE: passing a plain array-typed
`VAR` name where an array-typed parameter is expected automatically
takes its address, the same as if the caller had written `ADR(arr)`
explicitly  -- a global array's own bare label already IS its address
(no code emitted for that half); a local array gets a real
`lea ax, [bp-N]`. This exemption also applies to an array of a declared
`RECORD` type (`buf: SomeRecord[N]`)  -- by-value RECORD parameters are
still rejected (just above), but an array-of-RECORD parameter is
address-only, same as a scalar array. Inside the callee, the parameter
is an ordinary address (`WORD`)  -- see "Array element indexing" below
for reading/writing through it directly with `buf[i]`, or access
elements the older way through `[seg:base]` memory operands, advancing
the base register by hand between reads/writes.

```ob2
PROCEDURE SumThree(buf: WORD[3]): WORD; NEAR;
VAR i, total: WORD;
BEGIN
  total := 0; i := 0;
  WHILE i < 3 DO
    total := total + buf[i];
    INC(i)
  END;
  RETURN total
END SumThree;

VAR arr: WORD[3];
...
result := SumThree(arr);   (* was: SumThree(ADR(arr)) *)
```

**Array element indexing (Pascal port).** `name[indexExpr]`, where
`name` is any array-typed identifier  -- a plain global/local array `VAR`
or an array-typed formal parameter (just above)  -- reads or writes one
element directly, e.g. `arr[2]`, `arr[i] := 5`, `total := total +
buf[i]`. `indexExpr` is a single operand: a numeric literal, a `CONST`
name, a `VAR`, or a register  -- not a general nested expression (SPHINX
has no expression grouping/parens anywhere, matching every other
position in the language). Scalar element types only (`BYTE`/
`BOOLEAN`/`WORD`/`INTEGER`/`LONGINT`, or the Pascal-port synonyms
`CHAR`/`POINTER`)  -- indexing an array-of-`RECORD` element is a
translator error (structured field access on one element still works
the existing way, `[seg:base].RecordType.field`, after computing that
element's own address by hand). A literal or `CONST` index is folded
into the generated address directly at translate time (no runtime
arithmetic at all); any other index computes the address at runtime
(base + index * element size).

Indices are zero-based. There is no RUNTIME bounds check on any access
(a non-constant index is never compared against the array's own length at
run time; index scaling/address addition there uses 16-bit arithmetic and
may wrap). A CONSTANT index (a numeric literal or `CONST` name), however,
IS checked at translate time against the array's own declared length --
`buf[5]` on a `WORD[3]` is a translator error ("array index ... is out of
range for ..."), as is a negative constant index ("array index is
negative"). This constant-index check only applies to a plain declared
array `VAR`, never to an array-typed formal parameter (section 6.6,
just above): a parameter carries only an address, not a real length, so
there is nothing to check its index against. Keep non-constant indices
within the actual allocated storage yourself. Only one scalar operand is
accepted as an index, not `arr[i + 1]`.

An array formal passes an offset only, with no hidden length or segment.
A local array lives in SS; a global normally uses DS. Constant local
indexing uses BP-relative storage (always SS-relative via BP, regardless
of DS). Runtime (non-constant-index) local-array indexing computes BX
and accesses it through an explicit `SS:` override, correctly regardless
of DS's own current value. Array-formal indexing still uses DS
unconditionally, since a formal parameter carries only a bare offset,
with no segment information of its own for the callee to recover --
passing a local array to such a formal (or otherwise handing its address
across a segment boundary by hand) still requires DS = SS at the call
site, or explicit segment-aware memory access instead. This is a
restriction of the current implementation, not an automatic segment
conversion. `ADR(local)` alone does not supply SS.

```ob2
VAR arr: WORD[3];
...
arr[0] := 10; arr[1] := 20; arr[2] := 30;
x := arr[1];        (* constant index -> no runtime arithmetic *)
y := arr[i];         (* i a VAR -> real address computation *)
```

translates to:

```nasm
mov word [arr], 10
mov word [arr+2], 20
mov word [arr+4], 30
mov ax, [arr+2]      ; x := arr[1], folded
mov bx, arr           ; y := arr[i]
mov cx, [i]
shl cx, 1              ; WORD = 2 bytes
add bx, cx
mov ax, [bx]
```

---

## 7. Expressions and Operators

Chainable value operators (`+`, `-`, `&`, `OR`, `XOR`, `SHL`, `SHR`)
evaluate strictly left to right. Expression-grouping parentheses are not
supported; parentheses delimit calls and built-ins only. Multiplication,
division, remainder, comparisons, and unary value negation have the
terminal restrictions below. Condition composition has its own precedence:
`&` binds more tightly than `OR` (section 7.4). Use temporary variables
when an expression cannot be written within these rules.

### 7.1 Arithmetic Operators

| Operator | Meaning          | x86 instruction |
|----------|------------------|-----------------|
| `+`      | addition         | `add`           |
| `-`      | subtraction      | `sub`           |
| `*`      | multiply (16-bit, truncated to AX) | `mul` (WORD) / `imul` (INTEGER) |
| `DIV`    | division (quotient) | `div` (WORD) / `idiv` (INTEGER) |
| `MOD`    | remainder        | same `div`/`idiv`, result taken from DX |

`+`/`-` chain left-to-right with `&`/`OR`/`SHL`/`SHR`/`XOR` (section 7.2) in one
expression as usual. **`*`/`DIV`/`MOD` are terminal-only**: `a * b`,
`a DIV b`, `a MOD b` is a single binary operation  -- it may not be chained
with `+`/`-`/etc. either before or after (`a + b * c` is a translator
error; introduce a temporary VAR instead: `t := b * c; x := a + t;`).
This is the same restriction relational operators (section 7.3) already have,
and for the same reason: `mul`/`imul`/`div`/`idiv` hard-clobber `DX:AX`,
which would otherwise corrupt a chain's own running total mid-expression.

**Signedness (WORD vs INTEGER)**: `*`/`DIV`/`MOD` use the unsigned
(`mul`/`div`) or signed (`imul`/`idiv`) instruction form depending on the
left operand's type  -- a `WORD` VAR or a bare register (registers default
to `WORD`, section 3.1) uses the unsigned form; an `INTEGER` VAR, or a register
explicitly cast with `.INTEGER` (see the new subsection below), uses the
signed form. Mixing an INTEGER-cast operand with a WORD/uncast one on the
other side is a translator error (both operands must agree in
signedness). `*`'s result is truncated to `AX` (the `DX` high word is
discarded  -- SPHINX has no LONGINT-widening multiply). `DIV`'s result is
the quotient (`AX`); `MOD`'s result is the remainder (`DX`, moved into
`AX` for the caller). Dividing by a literal `0` is a translator-time
error; a runtime-computed zero divisor is not checked (8086 `INT 0`
applies, same as any other unchecked runtime condition in SPHINX).

```ob2
AX := 3 + 4;        (* left-to-right chain, fine *)
t := 4 * 5;         (* '*' alone -- fine *)
AX := 3 + t;         (* combine via a temp instead of "3 + 4 * 5" *)
```

translates to:

```nasm
mov  ax, 3
add  ax, 4
mov  ax, 4
mov  cx, 5
mul  cx              ; WORD (bare literals/uncast): unsigned
mov  [t], ax
mov  ax, 3
add  ax, [t]
```

For `DIV`/`MOD`, the dividend is sign/zero-extended into `DX:AX` before
the division (`cwd` for INTEGER, `xor dx,dx` for WORD):

```ob2
AX := BX.INTEGER DIV CX.INTEGER;   (* signed division *)
```

translates to:

```nasm
mov  ax, bx
cwd                   ; sign-extend AX to DX:AX (INTEGER)
idiv cx               ; AX=quotient, DX=remainder
; result (quotient) in AX
```

**Unary `-`**: `-5` (immediately followed by a numeric literal) folds into a compile-time-constant immediate  -- no runtime cost. `-x` for any other operand (a VAR, register, `[mem]`, or call result  -- e.g. `n := -n;`) computes a real two's-complement negation via the 8086 `neg` instruction:

```ob2
n := -n;
```

translates to:

```nasm
mov ax, n
neg ax
mov [n], ax
```

### 7.1.1 Signedness cast: `REG.INTEGER` / `REG.WORD`

A bare 16-bit register operand (`AX`, `BX`, `CX`, `DX`, `SI`, `DI`, `BP`,
`SP`) defaults to `WORD` (unsigned)  -- matching section 3.1's own type table.
Immediately following a bare register token (nowhere else  -- not after a
VAR name, not inside a `[...]` memory operand) with `.INTEGER` casts that
one operand to signed for this use; `.WORD` is also accepted, explicit
but equivalent to the default. This only affects comparisons (section 7.3) and
`*`/`DIV`/`MOD` (section 7.1)  -- it does not change the register's own bits, and
has no effect on a plain move (`x := AX.INTEGER;` emits the same `mov` as
`x := AX;`).

```ob2
IF AX.INTEGER < BX.INTEGER THEN ... END
IF SI.INTEGER >= 0 THEN ... END
IF AX < 0 THEN ... END        (* unsigned "AX < 0" -- always FALSE *)
```

translates to: (first line)

```nasm
cmp  ax, bx
jge  .else            ; signed: "not less than" skips the THEN branch
```

### 7.2 Bitwise Operators

| Operator | Meaning   | x86 instruction |
|----------|-----------|-----------------|
| `&`      | AND       | `and`           |
| `OR`     | OR        | `or`            |
| `XOR`    | exclusive OR | `xor`        |
| `~`      | BOOLEAN NOT (unary)| `xor ax, 1` (not 8086 `not`) |
| `SHL`    | left shift | `shl` |
| `SHR`    | right shift| `shr`          |

`OR` and `XOR` are keywords. `&` and `OR` are bitwise operators in
value expressions, and short-circuit composition operators between
condition factors (section 7.4).

**BOOLEAN representation.** Assignments do not normalize arbitrary bytes
to 0/1. Conditions accept any nonzero value as true, but value-level
BOOLEAN operations require canonical 0/1 inputs for ordinary Boolean
algebra. For example, with `b = 2`, `IF b` is true, `b = TRUE` is false,
and `~b` computes 3 rather than false. Normalize an external byte with
`IF b THEN b := TRUE ELSE b := FALSE END` before value-level negation.

**`~` has two distinct forms.** In **condition position** (directly in
front of `CFLAG`/`ZFLAG`, section 7.5, or a bare BOOLEAN condition, section 8.1) it
negates by picking the opposite `Jcc` (`onTrue # negated`)  -- no value is
computed at all. As a **general expression operand** (`x := ~y;`), it
computes a value: `y` is expected to already be a clean 0/1 BOOLEAN
(`TRUE`=1, `FALSE`=0, section 3.1), so negation is `xor ax, 1` (flip bit 0),
**not** the 8086 `not` instruction (which would flip every bit  -- wrong
for a 0/1 value; `not 1` = `0FFFEh`, not `0`). `&` and `OR` (this table's
other two rows) are real, general binary expression operators, wired
into the left-to-right emitter the same as `+`/`-` (section 7.1); `~` as an
expression operand is terminal (like `ODD(x)`, section 9)  -- it is not itself
chainable with a following `+`/`-`/etc., though its own operand can be
any ordinary operand form (register, VAR, `[mem]`).

```ob2
muted := ~muted;   (* toggle a BOOLEAN *)
```

translates to:

```nasm
mov  al, [muted]
xor  ah, ah
xor  ax, 1
mov  byte [muted], al
```

For portable 8086 shifts, use a count of 1 or explicitly place a variable
count in CL. The translator emits the written operand; it does not promise
to copy an arbitrary count register into CL or clamp counts to the operand
width. Wider immediate counts depend on the bundled assembler's lowering.
SHR is a logical right shift, including on INTEGER values; there is no
implicit arithmetic-right-shift conversion.

```ob2
AL := AL SHL 1;
BX := CX SHR CL;
```

translates to:

```nasm
shl  al, 1
mov  bx, cx
shr  bx, cl
```

### 7.3 Relational Operators
Relationals compare two values and set the destination to 0 or 1. Internally, they use `cmp` and a conditional jump  -- **never `SETcc`** (that's a 386+ instruction; this dialect targets 8086 only, see the notes at the top of this document).

`=`/`#` are sign-independent (`je`/`jne` either way). `<`/`>`/`<=`/`>=`
use the LEFT operand's own signedness (section 7.1's "Signedness" subsection  -- 
`WORD`/bare register default = unsigned `jb`/`ja`/`jbe`/`jae`;
`INTEGER` VAR, or a `.INTEGER`-cast register, = signed `jl`/`jg`/`jle`/`jge`). This
is a single-sided design: only the left operand's type decides the jump
form, matching how a byte-sized VAR's own zero-extension is likewise only
ever checked on the left operand. This holds identically in BOTH
condition position (`IF w > x THEN ...`) and value position
(`flag := w > x;`)  -- an `INTEGER` VAR compares signed either way, not
just when used directly inside `IF`/`WHILE`.

```ob2
IF AX > BX THEN ...          (* unsigned: bare registers default WORD *)
IF AX.INTEGER > BX.INTEGER THEN ...   (* signed *)
```

translates to:

```nasm
cmp  ax, bx
ja   .L1                     ; unsigned "greater than"
...
```

In an `IF`/`WHILE` **condition**, an `INTEGER`-typed VAR (not just a
register) also gets the signed form automatically, from its own declared
type  -- no cast needed there:

```ob2
VAR i : INTEGER;
...
IF i < 0 THEN ...            (* signed -- i's own declared type *)
```

**Known gap**: when a relational appears as a *value* (`AL := AX > BX;`,
below) rather than an `IF`/`WHILE` condition, the signedness split only
applies when the left operand is directly a register (with or without a
`.INTEGER`/`.WORD` cast)  -- a plain VAR name reaching this form still uses
the signed default regardless of its own declared WORD/INTEGER type. Use
an `IF`/`WHILE` condition (which peeks the VAR's real type) instead of a
relational-as-value expression when a `WORD` VAR's unsigned comparison
matters.

When used as a value, an 8086-legal `cmp`/`Jcc`/`mov 0`/`jmp`/`mov 1` sequence is emitted instead of `xor`/`setCC`:

```ob2
AL := AX > BX;   (* AL = 1 if AX>BX else 0 *)
```

translates to:

```nasm
cmp  ax, bx
ja   .L1              ; bare AX is unsigned WORD
mov  al, 0
jmp  .L2
.L1:
mov  al, 1
.L2:
```

This is terminal  -- no example chains a relational result into a further operator.

### 7.4 Logical Operators
`~`, `&`, `OR` operate on boolean (byte) values as ORDINARY binary
expression operators (section 7.2)  -- no short-circuit there, both operands are
computed, e.g. `flag := a & b;`.

**Condition composition (Pascal port, SPHO.PAS).** An `IF`/`WHILE`
condition accepts two or more `a REL b`/bare-BOOLEAN factors joined by
`&`/`OR`, `&` binding tighter than `OR` (no parentheses needed or
accepted  -- SPHINX has no expression-grouping parens anywhere else
either). Unlike section 7.2's own ordinary `&`/`OR`, condition-position `&`/
`OR` DOES short-circuit: an `OR`'s later disjuncts are never evaluated
once an earlier one is true, and an `&`'s later conjuncts are never
evaluated once an earlier one is false  -- matching Oberon/Pascal
convention, and meaningful here because each factor can itself have a
side effect (a function call) or be expensive.

```ob2
IF a < 10 OR b > 20 THEN ...
IF a < 10 & b < 10 OR c < 10 THEN ...   (* (a<10 & b<10) OR c<10 *)
```

translates to: (first line)

```nasm
cmp ax, 10
jl  .Ltrue      ; a<10 true -> skip straight to the body
cmp bx, 20
jle .Lfalse     ; b>20 false too -> whole condition false
.Ltrue:
  ...THEN body...
.Lfalse:
```

A single-factor condition (no `&`/`OR` at all  -- the common case) emits
exactly the same code as before this existed: one comparison, one
conditional jump, no extra label. The original Oberon implementation never
implemented this (the `OR` keyword didn't exist there at all); this is
a Pascal-port extension beyond what the original DOS tool accepted, not
a fidelity bug  -- see `CLAUDE.md`'s own "Fidelity notes."

### 7.5 Conditional Flags
In a condition, `CFLAG` and `ZFLAG` can be tested directly, avoiding a `cmp`.

```ob2
WHILE ~ZFLAG DO ... END;
```

translates to:

```nasm
.Lloop:
    jz  .Lexit
    ...
    jmp .Lloop
.Lexit:
```

---

## 8. Control Flow

### 8.1 IF Statement

```ob2
IF condition THEN
  stats
{ELSIF condition THEN
  stats}
[ELSE
  stats]
END
```

The compiler generates labels and conditional jumps.

```ob2
IF AX = 0 THEN
  BX := 1
ELSE
  BX := 2
END;
```

translates to:

```nasm
    cmp  ax, 0
    jne  .Lelse
    mov  bx, 1
    jmp  .Lend
.Lelse:
    mov  bx, 2
.Lend:
```

`condition` (here and in `WHILE` below) is either a full `a REL b` relational (section 7.3) or a bare BOOLEAN value used directly  -- a variable, register, or a BOOLEAN-returning call  -- tested against zero (TRUE=1/FALSE=0, section 3.1), using a zero test:

```ob2
IF sss THEN ... END;          (* true whenever sss # 0 *)
IF ~sss THEN ... END;         (* same as IF sss = FALSE THEN ... END *)
WHILE HasMore() DO ... END;   (* true whenever the returned byte # 0 *)
```

`~` in front of a bare condition negates it via jump selection (same as it does for `CFLAG`/`ZFLAG`, section 7.5)  -- no `xor`/value is computed here, unlike `~` as a general expression operand (section 7.2), which does compute one. Such factors may be joined by `&`/`OR` as described in section 7.4. There is no grouped `~(a & b)` syntax; negate individual factors or compute an intermediate value.

### 8.2 WHILE Loop

```ob2
WHILE condition DO
  stats
END
```

`BREAK` exits the innermost loop. `CONTINUE` jumps to the condition check.

```ob2
WHILE CX # 0 DO
  DX := DX - 1;
  IF DX = 0 THEN BREAK END;
  CX := CX - 1
END;
```

translates to:

```nasm
.Lloop:
    cmp  cx, 0
    je   .Lexit
    dec  dx
    cmp  dx, 0
    jne  .Lskip_break
    jmp  .Lexit
.Lskip_break:
    dec  cx
    jmp  .Lloop
.Lexit:
```

### 8.3 RETURN Statement

```ob2
RETURN expression;
```

Evaluates expression into `AX`, then jumps to the procedure's own single epilogue label. `RETURN` is legal anywhere inside a procedure body, not only as its textually last statement  -- a `RETURN` inside a conditional branch, a loop, or any nested statement correctly skips the rest of the body:

```ob2
PROCEDURE Cond(x: INTEGER): BOOLEAN;
BEGIN
  IF x < 5 THEN RETURN TRUE
  ELSE RETURN FALSE END;
  AX := 999   (* unreachable *)
END Cond;
```

translates to:

```nasm
Cond:
    push bp
    mov  bp, sp
    mov  ax, [bp+4]
    cmp  ax, 5
    jge  .L1
    mov  ax, 1
    jmp  .Lexit
.L1:
    mov  ax, 0
    jmp  .Lexit
    mov  AX, 999   ; unreachable
.Lexit:
    mov  sp, bp
    pop  bp
    retn 2
```

The epilogue (local-frame cleanup, `USES` pop, `ret`/`retf`/`iret`) is emitted exactly once, right after `.Lexit`; a body that falls off the end without an explicit `RETURN` reaches the same label by falling through, unaffected.

If no expression is given (for a procedure), it just jumps to the epilogue.

**`RETURN` of a `LONGINT`** is more restricted than the general case above: only a bare `LONGINT` VAR name, or a register pair (`SEGREG:REG` / `REG:REG`, section 11's own syntax), may be returned  -- never a general expression, since nothing in this dialect's `LONGINT` model produces a real 32-bit result from an arithmetic chain or a nested call. `RETURN` of a register pair moves the pair into `DX:AX` (section 6.4's own `LONGINT`-return-register convention) if it isn't already there  -- `RETURN DX:AX` itself is a no-op, since the value is already in place:

```ob2
PROCEDURE GetPtr() : LONGINT; NEAR;
BEGIN
  PUSH(CS); POP(ES);
  DI := 654;
  RETURN ES:DI
END GetPtr;
```

translates to:

```nasm
GetPtr:
    push cs
    pop  es
    mov  di, 654
    mov  ax, di
    mov  dx, es
    jmp  .return
```

---

## 9. Built-in Procedures and Functions

These are part of the language and generate inline code.

| Built-in          | NASM translation                    |
|-------------------|-------------------------------------|
| `INC(var)`        | `inc word [var]` (or byte)          |
| `DEC(var)`        | `dec word [var]`                    |
| `INC(var, expr)`  | `add [var], expr` (or a register destination directly) |
| `DEC(var, expr)`  | `sub [var], expr` |
| `PUSH(r1,r2,...)` | `push r1` etc. -- `FLAGS` is a valid argument, producing `pushf` |
| `POP(r1,r2,...)`  | `pop rN` in reverse order -- `FLAGS` is a valid argument, producing `popf` |
| `INT(n)`          | `int n`                             |
| `ADR(v)`          | `offset v`                          |
| `SEG(v)`          | `seg v`                             |
| `SIZE(T)`         | `sizeof(T)` (constant)              |
| `SIZE(v)`         | `v`'s own total storage size in bytes (constant) |
| `LEN(v)`          | `v`'s own declared element count (constant) |
| `ODD(x)`          | `test ax,1` / `jz`/`mov 0`/`jmp`/`mov 1` (no `SETcc`; 8086 only) |

`ADR(v)` returns the offset of `v` within its segment. `v` may name a global VAR, a local VAR, a (non-register) parameter, or a PROCEDURE: a global or a PROCEDURE both yield a constant offset (`offset v`, a PROCEDURE's own bare label is already its own offset as a NASM immediate  -- useful for installing an interrupt vector or any other function-pointer-style use), while a local/parameter yields its stack-frame address computed at runtime (`lea ax, [bp+/-N]`). A register-named parameter has no address and is rejected.
For far pointers, the segment can be obtained via `CS`, `DS`, etc.
For example, `ADR(xmsRec)` yields a constant offset.

`ADR` also accepts a `[seg:base].RecordType.field` structured-access operand (section 10, section 3.2) instead of a bare name  -- the only way to get an array field's own address, since it has no standalone name of its own: `ADR([DS:BX].FileBuf.data)` yields `lea ax, [bx + FileBuf.data]` (segment-override-adjusted). This is the array-field case in practice, but a scalar field works here too, same as `ADR()` of a plain scalar VAR.

`SEG(v)` returns the segment of `v` (also global-VAR only).

`SIZE(v)` also accepts a VAR name, not only a type name: `SIZE(v)` returns `v`'s own complete storage size in bytes, for ANY declared VAR  -- an ordinary scalar (`TySize` of its own declared type), a single RECORD instance (`TySize` of its own RECORD type), a plain `T[N]` array (`TySize(T)*N`), or an array declared with a `BASE64()`/`FILE()`/`"..."` initializer (section 3.4, its own decoded byte count, including the trailing zero for a string initializer). `SIZE(v)` on an array-typed formal PARAMETER is a translator error, not a size at all: a parameter's own stack slot holds a 2-byte address into the caller's array, never the array's own storage, so there is no single correct answer to give.

`LEN(v)` returns `v`'s own element count, known at compile time, for a declared array VAR: the plain `T[N]` form's own declared `N` directly, or (for a `BASE64()`/`FILE()`/`"..."`-initialized array) its own decoded byte count divided by its element size  -- a malformed payload whose byte count isn't evenly divisible by that size is a translator error. `LEN(v)` on an array-typed formal PARAMETER is also a translator error: a parameter carries only an offset, not a real length, and its own declared bound (if any) does not prove the caller's real allocation size. `LEN` on anything that isn't a declared array VAR (a scalar, a RECORD, a type name, an array parameter) is likewise a translator error.

If a program already declares its own identifier literally named `len` (any case) -- a VAR, parameter, CONST, or PROCEDURE -- that declaration is used instead of the `LEN()` built-in wherever it appears; `LEN` only resolves to the built-in when no such declaration exists. (`ADR`/`SEG`/`SIZE`/`ODD` do not have this same fallback -- those four have always taken priority over a same-named declaration, unchanged here.)

`ADR`/`SEG`/`SIZE`/`LEN`/`ODD` are value built-ins  -- usable as an expression's RHS, AND directly as an `IF`/`WHILE` condition (bare, e.g. `IF ODD(x) THEN`, negated with `~`, e.g. `WHILE ~ODD(x) DO`, or as either side of a relational comparison, e.g. `IF SIZE(buf) > 0 THEN`): the condition tests the built-in's own result against zero, the same way a bare `VAR`/register/call condition operand already does. `CFLAG`/`ZFLAG` (section 7.5), by contrast, are condition-position-only, tested directly via their own matching `Jcc` with no comparison at all -- the two built-in families are still not interchangeable.

`INC`/`DEC` take an optional second argument  -- `INC(v, expr)`/`DEC(v, expr)` is `v := v + expr`/`v := v - expr`, `expr` any expression (including a call), evaluated the same way an ordinary right-hand side is. `v` may be a variable or a bare register name.

```ob2
INC(counter, 5);
DEC(BX, delta);
```

translates to:

```nasm
mov  ax, 5
add  word [counter], ax
mov  ax, [delta]
sub  bx, ax
```

When `v` is the register `AX` itself, its old value must survive evaluating `expr` (which may itself use `AX`, e.g. any call result)  -- `AX` is saved and restored around `expr`'s evaluation instead of being combined directly:

```ob2
INC(AX, delta);
```

translates to:

```nasm
push ax
mov  ax, [delta]
mov  cx, ax
pop  ax
add  ax, cx
```

---

## 10. Direct Memory Access

Square-bracket notation accesses memory at a given segment:offset. The general forms are:

```
[segment:offset]                     ; simple byte/word access
[segment:base].RecordType.field      ; structured field access
```

The segment override is optional; if omitted, `DS` is assumed (except when `BP` is the base, where `SS` applies). The base register can be any 16-bit register that can be used in an effective address (`BX`, `BP`, `SI`, `DI`). For structured access, the record type and field name are appended with a dot, allowing the compiler to compute the correct offset.

The structured syntax is `[segment:base].RecordType.field` (the dot
before the type is required). The base is one register or immediate
operand, not a general effective-address expression such as `BX+SI+4`.
Compute such addresses separately. Bare memory has no declared type:

| Source form | Access width |
|---|---|
| `AL := [BX]` | byte read |
| `AX := [BX]` | word read |
| `[BX] := AL` | byte store |
| `[BX] := AX` | word store |
| `[BX] := 65` | word store (ordinary expression result in AX) |
| `[BX] := byteVar` | byte store for a bare BYTE/CHAR/BOOLEAN variable |
| `[BX] := [SI]` | word transfer through AX |
| `[BX].Point.x := AX` | WORD/INTEGER field store in this example |

For an immediate byte store, write `AL := 65; [BX] := AL`. A structured
BYTE field supplies a byte-size hint and narrows a wider result through
AL. Do not assume that an untyped expression containing a byte operand
always stores one byte. A register-pair store writes two consecutive
words; reserve four bytes and use it only for a four-byte destination.

**Examples:**

```ob2
AL := [DS:0484H];               (* direct memory byte read *)
[ES:BX] := AL;                  (* direct byte write *)
[DS:SI].StructXmsRec.len := AX; (* write to record field *)
AX := [ES:BX].Point.x;          (* read record field *)
```

**NASM translation:**

```nasm
mov  al, [ds:0x0484]
mov  byte [es:bx], al
mov  [ds:si + StructXmsRec.len], ax   ; offset of 'len' is StructXmsRec.len
mov  ax, [es:bx + Point.x]            ; offset of 'x' is Point.x
```

If no segment is given:

```ob2
AL := [0484H];                 ; DS is implied
```

translates to:

```nasm
mov  al, [0x0484]
```

The compiler resolves the field offset using the NASM structure definition. For example, `StructXmsRec` defined as a `struc` with `.len` at offset 0, `.src_hnd` at offset 4, etc. `[SI].StructXmsRec.src_hnd` becomes `[si + StructXmsRec.src_hnd]`.

When the target is a `LONGINT`, the compiler generates two moves if necessary, but the built-in `LONGINT` register-pair moves (see section 11) provide more efficient bulk transfer.

### 10.1 Typed Memory Access and Effective Addresses (Pascal port)

`.BYTE`/`.WORD` explicitly select a `[segment:base]` operand's access width, and the base itself may be a real 8086 effective address (a base register plus an optional index register plus an optional constant displacement) -- both new, and both a SEPARATE grammar from `.RecordType.field` (section 10, above): the two never combine, and address arithmetic (`BX+SI+4`) is only accepted directly before `.BYTE`/`.WORD`, never before `.RecordType.field` or bare memory (which keep their own existing single-register/immediate-base behavior, unchanged).

```ob2
[ES:DI].BYTE := 65;
[ES:DI].WORD := 1234H;
[DS:BX + SI + 4].WORD := AX;
AX := [SS:BP - 6].WORD;
```

**Accepted address forms** -- a constant address; `BX`/`BP`/`SI`/`DI` alone, optionally plus a constant displacement; or `BX+SI`/`BX+DI`/`BP+SI`/`BP+DI`, optionally plus a displacement. `AX`-based addresses, `BX+BP`, a repeated/scaled index, and any other combination are translator errors, not silently accepted. Without an explicit segment, a `BP`-based address uses `SS`; every other form uses `DS` (the same default section 10's own bare-memory form already documents, just also applied to the new arithmetic forms here). Address syntax is not general expression syntax -- only the forms above, nothing else.

**Store rules, stricter than section 10's own `.RecordType.field`/bare-memory forms**: a register-to-memory store requires an exactly matching-width register (`[ES:DI].BYTE := AX;` is a translator error -- `AX` is a word register); an immediate store must fit the destination's own width (`.BYTE`: 0..255, `.WORD`: 0..65535) or it is rejected outright, never silently narrowed. A bare immediate with nothing chained after it (`[BX].WORD := 777;`) emits a single direct `mov word [mem], 777` -- no `AX` round-trip -- the same optimization also applies to an ordinary `.RecordType.field` immediate store, though that path's own acceptance rules (mismatched-width register, out-of-range immediate) stay exactly as permissive as before this addition. A literal with something chained after it (`[BX].WORD := 5 + 1;`) still computes through `AX` as any other expression would.

```nasm
mov  byte [es:di], 65
mov  word [es:di], 0x1234
mov  word [ds:bx+si+4], ax
mov  ax, [ss:bp-6]
```

---

## 11. LONGINT Register-Pair Moves

Basic syntax  -- `variable` is a declared `LONGINT` VAR (global or local) referenced by its bare name, `SEGREG:REG` is `ES`/`DS` paired with any general 16-bit register, and `REG:REG` is any other register pair (`DX:AX`, `ES:DI`, ...):

```ob2
SEGREG:REG := variable;
REG:REG    := variable;
variable   := SEGREG:REG;
variable   := REG:REG;
SEGREG:REG := REG:REG;
SEGREG:REG := myfunction();
```

These allow efficient loading/storing of 32-bit values using `LES`/`LDS` instructions where possible. A register-pair operand may not currently be a `[seg:base]` memory-access expression  -- only a plain named `LONGINT` variable.

| Syntax | NASM |
|--------|------|
| `ES:BX := longvar;` | `les bx, [longvar]` |
| `DS:BX := longvar;` | `lds bx, [longvar]` |
| `DS:SI := longvar;` | `lds si, [longvar]` |
| `ES:DI := longvar;` | `les di, [longvar]` |
| `DX:AX := longvar;` | `mov ax, [longvar]` / `mov dx, [longvar+2]` |
| `ES:DI := DX:AX;` | `MOV DI,AX`/`MOV ES,DX` |
| `longvar := ES:BX;` | `mov [longvar], bx` / `mov [longvar+2], es` |
| etc. | ... |

The compiler uses `les`/`lds` when possible, which are more efficient.

```ob2
xmsApiEntry := ES:BX;
```

translates to:

```nasm
mov  [xmsApiEntry], bx
mov  [xmsApiEntry+2], es
```

```ob2
ES:BX := xmsApiEntry;
```

translates to:

```nasm
les  bx, [xmsApiEntry]
```

```ob2
ES:BX := myfunction()
```

translates to:

```nasm
call myfunction
mov  bx, ax
mov  es, dx
```

... and vice versa!

---

## 12. Inline Assembly

An `ASM` block passes assembler lines through without translating
instructions or renaming labels. Put `ASM` and its terminating `END` on
separate lines. The first word `END` (case-insensitive) terminates the
block; it is not an instruction that can be emitted within the block.
Leading/trailing whitespace and empty lines may be removed. Use the
assembler's local-label spelling (a leading dot) when local scope is
required; ordinary labels are not automatically procedure-local. Avoid
collisions with compiler-generated labels, and use only 8086 instructions
accepted by the bundled assembler.

```ob2
ASM
  cld
  rep stosb
END
```

translates to:

```nasm
cld
rep stosb
```

### 12.1 Explicit Flag Control and Memory Primitives (Pascal port)

Six statements and two expression forms cover the most common raw-`ASM` idioms (`CLD`/`STD`/`STC`/`CLC`/`STI`/`CLI` and the `LODS`/`STOS`/`MOVS` family) without an `ASM` block at all. All eight are reserved keywords, not ordinary identifiers.

**Flag control** -- each takes exactly one **compile-time** `TRUE`/`FALSE` constant (a runtime `BOOLEAN` VAR is a translator error) and emits exactly one instruction, no `ASM` block needed:

```ob2
SetDFlag(FALSE);   (* cld *)
SetDFlag(TRUE);    (* std *)
SetCFlag(FALSE);   (* clc *)
SetCFlag(TRUE);    (* stc *)
SetIFlag(FALSE);   (* cli *)
SetIFlag(TRUE);    (* sti *)
```

None of these ever emits `CLD`/`STD` on their own before a memory primitive below -- the last `SetDFlag` call (if any) decides direction, exactly like raw assembly. Disabling then enabling interrupts (`SetIFlag(FALSE)` ... `SetIFlag(TRUE)`) is **not** equivalent to restoring their original state if they were already disabled going in -- there is no structured save/restore construct for this yet.

**Memory copy/load/store** -- `LOADB()`/`LOADW()` are expression forms, only legal as the entire right-hand side of a direct assignment to `AL`/`AX` respectively (not embedded in a larger expression, not assigned to any other destination); `STOREB`/`STOREW`/`COPYB`/`COPYW` are statements taking one compile-time `TRUE`/`FALSE` argument:

| SPHINX | Assembly | Implicit operands |
|---|---|---|
| `AL := LOADB();` | `lodsb` | reads `DS:SI` into `AL`, advances `SI` by 1 |
| `AX := LOADW();` | `lodsw` | reads `DS:SI` into `AX`, advances `SI` by 2 |
| `STOREB(FALSE);` | `stosb` | writes `AL` to `ES:DI`, advances `DI` by 1 |
| `STOREB(TRUE);` | `rep stosb` | same, repeated `CX` times |
| `STOREW(FALSE);` | `stosw` | writes `AX` to `ES:DI`, advances `DI` by 2 |
| `STOREW(TRUE);` | `rep stosw` | same, repeated `CX` times |
| `COPYB(FALSE);` | `movsb` | copies one byte `DS:SI` -> `ES:DI`, advances both by 1 |
| `COPYB(TRUE);` | `rep movsb` | same, repeated `CX` times |
| `COPYW(FALSE);` | `movsw` | copies one word `DS:SI` -> `ES:DI`, advances both by 2 |
| `COPYW(TRUE);` | `rep movsw` | same, repeated `CX` times |

The `TRUE`/`FALSE` argument controls `REP` only, independent of direction (`SetDFlag`, above): `TRUE` emits `REP` and consumes `CX` (on normal completion `CX` is 0); `FALSE` executes exactly once and leaves `CX` completely unchanged, even when `CX = 0` going in. `LOADB`/`LOADW` take no argument, always process exactly one element, and never emit `REP`. Every pointer register (`SI`/`DI`/segments) must already hold a valid address before the call -- these primitives generate no hidden operand setup, no bounds checking, and never advance a segment register when a 16-bit offset wraps. `COPY` is a directional copy, not automatically overlap-safe like `memmove`; the caller is responsible for choosing a safe direction/starting point when source and destination overlap. None of these instructions ever emits `CLD`/`STD` on their own -- direction is always whatever `SetDFlag` last set, unchanged by this call.

```ob2
VAR buf: BYTE[16];
...
ES := DS;
DI := ADR(buf);
AL := ' ';
CX := 16;
SetDFlag(FALSE);
STOREB(TRUE);
```

translates to:

```nasm
mov  di, buf
mov  al, 32
mov  cx, 16
cld
rep stosb
```

Afterward every byte of `buf` is 32, `DI` has advanced by 16, `CX` is 0, and `AL` is still 32.

### 12.2 Port Input/Output (Pascal port)

`INPORTB`/`INPORTW` are expression forms (like `LOADB`/`LOADW`, section 12.1); `OUTPORTB`/`OUTPORTW` are statements taking `(port, value)`:

| SPHINX | Assembly |
|---|---|
| `AL := INPORTB(DX);` | `in al, dx` |
| `AX := INPORTW(DX);` | `in ax, dx` |
| `AL := INPORTB(60H);` | `in al, 60h` |
| `OUTPORTB(DX, AL);` | `out dx, al` |
| `OUTPORTW(DX, AX);` | `out dx, ax` |
| `OUTPORTB(20H, AL);` | `out 20h, al` |

`B` means byte; `W` means word. Only two port forms are accepted: the literal register `DX`, or an immediate 0..255 -- a larger port number must be loaded into `DX` first, and any other register (or expression) as the port operand is a translator error. `INPORTB`/`INPORTW`'s own result must be assigned directly to `AL`/`AX` respectively, exactly like `LOADB`/`LOADW` (section 12.1) -- not embedded in a larger expression, not assigned to any other destination. `OUTPORTB`/`OUTPORTW`'s own value argument must be written as the literal register `AL`/`AX` respectively, not a VAR or expression that merely happens to hold the right value. None of these four ever touches `FLAGS`.

### 12.3 Carry-Aware Arithmetic and Rotations (Pascal port)

```ob2
ADDCarry(AX, BX);   (* adc ax, bx *)
SUBBorrow(DX, CX);  (* sbb dx, cx *)
ROL(AX, 1);         (* rol ax, 1 *)
ROR(AX, CL);        (* ror ax, cl *)
RCL(AX, 1);         (* rcl ax, 1 *)
RCR(AX, CL);        (* rcr ax, cl *)
```

`ADDCarry(dest, src)` is `dest := dest + src + incoming carry`; `SUBBorrow(dest, src)` is `dest := dest - src - incoming carry`. `dest` is a bare register name or a `[...]` memory operand; `src` is a bare register name, a `[...]` memory operand, or an immediate -- matching real 8086 `ADC`/`SBB` encodings exactly (`reg,reg` / `reg,mem` / `mem,reg` / `reg,imm` / `mem,imm`). A memory operand on **both** sides is a translator error -- no such encoding exists at all (every 8086 two-operand arithmetic instruction needs at least one register operand). Two register operands must be matching-width (`AX`/`BX` or `AL`/`BL`, never a mix); a segment register (`ES` etc) is never accepted on either side. Neither operand is ever evaluated as a general expression, whatever its own form -- reading them is limited to a bare register/memory/immediate lookup, with no expression computation of any kind in between: any operand evaluation between reading the operands and emitting `adc`/`sbb` could itself touch `CF` first, silently destroying the incoming carry before the instruction ever sees it. Result flags are exactly the CPU's own `ADC`/`SBB` flags, nothing added or promised beyond that.

```ob2
CX := CX SHR 1;      (* halve a count; CF := the bit shifted out *)
ADDCarry(CX, 0);      (* CX := CX + 0 + CF -- adds back an odd remainder *)
ADDCarry(AX, [total]); (* AX := AX + [total] + CF *)
ADDCarry([total], BX); (* [total] := [total] + BX + CF *)
```

`ROL`/`ROR`/`RCL`/`RCR` take a bare byte or word general register (same restriction as above -- no segment register) and a count that must be written as literally `1` or the register `CL`, matching the two real 8086 encodings for a rotate instruction (an arbitrary immediate count like `ROL(AX, 2)` is not a real 8086 form and is a translator error). `RCL`/`RCR` rotate through the carry flag -- the incoming `CF` becomes the new bit that enters on one end, and the bit that rotates off the other end becomes the new `CF` -- while `ROL`/`ROR` rotate the register's own bits only, `CF` receiving a copy of the bit that rotated out but never feeding back in. No flags beyond the CPU instruction's own documented behavior are promised.

---

## 13. Complete Example with Record Types

This standalone example constructs a four-byte value from two WORDs and
stores it in a record. It uses register-pair moves, not 32-bit arithmetic.
The exit code is zero on success and one on failure.

```ob2
MODULE RecDemo;
TYPE
  Transfer = RECORD
    value : LONGINT;
    handle : WORD
  END;
VAR item: Transfer;

PROCEDURE SetItem(lo, hi: WORD); NEAR;
USES DS, SI;
BEGIN
  DS := CS;
  SI := ADR(item);
  AX := lo;
  DX := hi;
  [DS:SI].Transfer.value := DX:AX;
  [DS:SI].Transfer.handle := 7
END SetItem;

BEGIN
  DS := CS;
  SetItem(1234H, 5678H);
  BX := ADR(item);
  AX := [DS:BX];
  IF AX # 1234H THEN AX := 4C01H; INT(21H) END;
  BX := BX + 2;
  AX := [DS:BX];
  IF AX # 5678H THEN AX := 4C01H; INT(21H) END;
  BX := ADR(item);
  AX := [DS:BX].Transfer.handle;
  IF AX # 7 THEN AX := 4C01H; INT(21H) END;
  AX := 4C00H;
  INT(21H)
END RecDemo.
```

The pair store writes AX at `Transfer.value` and DX two bytes later.
`USES DS, SI` restores those registers before the near return; AX and DX
are not preserved. This example assumes a single-segment COM layout
(`DS = CS`), and explicitly terminates through DOS interrupt 21H.

---

## 14. Compiler Notes

- Numeric tokens are scanned into a 32-bit container, but ordinary expression arithmetic is 16-bit. There is no `L` suffix or general 32-bit arithmetic promotion. A known LONGINT formal has special argument handling; use a LONGINT variable or explicit register pair for full-width values, and do not infer general LONGINT expression support from that calling convention.
- Destination width controls stores, but signedness is selected from the left operand as described in section 7; the destination does not generally determine expression signedness.
- `WORD` and `INTEGER` are the same size (16-bit) and interchangeable everywhere a type is merely checked for compatibility, but are **not** identical: `WORD` is unsigned, `INTEGER` is signed, and this affects codegen for comparisons (`<`,`>`,`<=`,`>=`) and `*`/`DIV`/`MOD`  -- see section 7's own "Signedness: WORD vs INTEGER" subsection.
- Addresses and segment sizes are limited by the 16-bit target. The translator emits symbolic assembly; the assembler and linker resolve symbols and relocations. The translator does not establish that a complete linked program fits its chosen DOS memory layout.
- The resulting NASM file is assembled by this project's own `TASM.EXE` into a RDOFF2 `.RDF`, then linked with `TLINK.EXE` into a `.COM`/`.EXE`  -- not a generic `nasm -f bin`/`nasm -f obj` invocation.
- Global type declarations produce `struc` definitions usable after their declaration; field offsets are accessed using the `RecordType.fieldName` notation in NASM expressions.

### 14.1 Optimization Levels (`-O0`/`-O1`/`-O2`)

`spho.exe [-O0|-O1|-O2] file.smd`  -- the one argument that isn't a recognized `-O0`/`-O1`/`-O2` flag is taken as `file.smd`; a second `-O` flag, or more than one non-flag argument, is a translator error (`Usage` printed, non-zero exit), the same path a missing argument already used. **`-O1` is the default when no `-O` flag is given at all.**

The translator applies a per-PROCEDURE peephole optimizer (`SRC/PHOPT.PAS`) after parsing each body, before serialization -- register/flag/memory-visible behavior is always preserved; only which instructions actually get emitted changes.

| Rule | What it does | `-O0` | `-O1` (default) | `-O2` |
|---|---|:---:|:---:|:---:|
| `ConstCond` | Folds a literal/literal `CMP`+`Jcc` (e.g. `WHILE TRUE DO`/`WHILE FALSE DO`) to an unconditional jump or nothing | no | yes | yes |
| `ConstOrCond` | Folds a bare-BOOLEAN condition's `MOV`+`OR`+`Jcc` branch the same way | no | yes | yes |
| `FoldSavedOperand` (C1) | Collapses a compiler-generated `PUSH AX`/`MOV AX,src`/`ADD`or`SUB dst,AX`/`POP AX` scratch save into `ADD`or`SUB dst,src` (immediate or proven frame-local source only) | no | no | yes |
| `CollapseByteConstScaffolding` (C2) | Same idea at byte width, `CL`/`BL` scratch (`PUSH AX`/`MOV AX,K`/`MOV scratch,AL`/`POP AX`/`ADD`or`SUB AL,scratch`) -- fully collapses when the scratch register is provably dead afterward, otherwise keeps `MOV scratch,low8(K)` | no | no | yes |
| `RemoveUnnecessarySaveRestore` (C3) | Deletes a compiler-generated `PUSH reg`/`POP reg` pair outright when nothing in the (bounded, at most 8 instructions) interior could need the saved value restored | no | no | yes |
| `RemoveMovRR` (C4) | Deletes `MOV r,r` (identical register both sides) | no | no | yes |
| `RemoveMovSwapBack` (C4) | Deletes the second of an adjacent `MOV a,b`/`MOV b,a` pair | no | no | yes |
| `RemoveDeadConstMov` (C4) | Deletes the first of an adjacent `MOV r,K1`/`MOV r,K2` pair | no | no | yes |
| `CheapReturn` | Deletes a jump whose target is the very next label | no | yes | yes |
| `RemoveDeadBranch` (C4) | Deletes a jump reached by pure fallthrough through any number of labels | no | no | yes |
| `JumpChain` | Retargets a jump-to-a-jump past the redundant hop (one hop per pass) | no | yes | yes |
| `ThreadJumpChain` (C4) | Follows a multi-hop `JMP`-to-`JMP` chain to its real final target in one visit, with cycle detection | no | no | yes |
| `RemoveRepeatedFlagOp` (C4) | Deletes a redundant adjacent identical `OR`/`CMP`/`TEST` | no | no | yes |
| `RemoveIdentityLogicOp` (C4) | Deletes `OR`/`XOR reg,0` and `AND reg,all_ones` when provably flag-dead | no | no | yes |
| `DeadCode` | Deletes structured code between an unconditional transfer and the next label | no | yes | yes |
| `NoOpArith` | Deletes `ADD reg,0`/`SUB reg,0` when provably flag-dead | no | yes | yes |
| `StoreForwarding` (E1) | Rewrites `MOV dstReg,mem` to `MOV dstReg,srcReg` when `mem` was stored from `srcReg` earlier in the same block, with nothing overwriting `srcReg` or touching memory in between; the store itself is retained | no | no | yes |
| `FoldTempOperand` (E2) | Rewrites adjacent `MOV tmp,src`/`ADD`or`SUB`or`CMP dst,tmp` into `ADD`or`SUB`or`CMP dst,src` when `tmp` is provably dead afterward | no | no | yes |
| `LoadModifyStore` (E3) | Collapses `MOV AX,mem`/`ADD`or`SUB AX,K`/`MOV mem,AX` into `ADD`or`SUB word mem,K` when `AX` is provably dead afterward and `mem` is a proven-safe (non-indexed) location | no | no | yes |
| `ByteCompareNoWiden` (E4) | Collapses `MOV AL,byte mem`/`XOR AH,AH`/`CMP AX,K`/`Jcc L` into `CMP byte mem,K`/`Jcc L` when `K` is `0..255`, `Jcc` is an unsigned/equality condition, and `AX`/flags are provably dead on both successors (via Stage D's own CFG-based liveness) | no | no | yes |
| `StoreReload` | Elides an immediate memory reload of a just-stored value | no | no | no |

`-O1` runs only the Stage A rules above (`ConstCond`/`ConstOrCond`/`CheapReturn`/`JumpChain`/`DeadCode`/`NoOpArith`) -- every C1-C4/E1-E4 rule requires `-O2`. This was NOT always true: an implementation bug (OPT.TXT's own "R1" finding, fixed retroactively) meant every Stage C/E rule silently ran at the `-O1` default too, for the whole time each one was implemented, contradicting this project's own stated `-O1`/`-O2` contract from the start. Confirmed fixed directly: `-O1` output no longer contains any Stage C/E fold at all, and the level-less default is byte-for-byte identical to explicit `-O1`. See `DOCS/TRBUG.MD` for the full writeup.

`StoreReload` is implemented but disabled at every level (including `-O2`): its own match cannot yet prove the elided memory operand never escapes (e.g. via `ADR()`) or aliases another write, so eliding the reload would risk observing a write made through that escaped address instead of the value just stored -- it stays off until a later stage supplies the metadata needed to prove that safely.

The `(C1)`/`(C2)`/`(C3)`/`(C4)` rules require an additional "generated-save-pair" proof beyond ordinary text/mnemonic matching: a `PUSH`/`POP` pair is only ever eligible for C1/C2/C3 when the translator's own emitter tagged it, at the exact call site that produced it, as a genuine compiler-owned scratch save -- never a user-written `PUSH()`/`POP()` statement or a `USES` register-preservation pair. C1/C2 are tagged at `INC`/`DEC(reg, expr)`'s own codegen; C3 has no tagged call site yet (implemented and verified, but not yet wired to a specific emission point).

`(E1)`-`(E4)` are the first rules that reason about data flow rather than purely local text/mnemonic patterns. `StoreForwarding` (E1) is implemented within one block only -- forwarding a value across a branch merge point is deferred, as is a separate, smaller E1 sub-case (removing a redundant `XOR AH,AH` zero-extension). `FoldTempOperand` (E2, the "temporary operands" sub-case of that item) is the register-only analog of C1; E2's other two sub-cases (repeated `CMP`/`TEST` across merged paths, dead `MOV AH,0`) are deferred, both needing real cross-block reasoning; no naturally-occurring trigger site exists for it in current codegen. `LoadModifyStore` (E3)'s own dead-register proof can reach a bare `RETN`/`RETF` at a procedure's own tail without being able to prove the register dead there (a `PROCEDURE` with no declared return value, ending in a bare `RETN` with nothing overwriting `AX` afterward, is a known, documented case that does not fold today). `ByteCompareNoWiden` (E4) is the first rule to consult Stage D's own CFG-based liveness rather than a simple local scan; it cannot currently fire on any comparison whose own result flows to a bare `RETN` (flags stay conservatively "live" through an unproven return, the same category of gap as E3's own), though it does fire on comparisons that stay within a loop body or other non-returning control flow -- confirmed via a real `EXAMPLES/TETRIS` code-size reduction. See `DOCS/SPHO.MD`'s own "Data-flow-dependent rewrites" section for the full explanation of all four, and `OPT.TXT`'s own section 12 "KNOWN LIMITATIONS AND GAPS: REVIEW AND RESOLUTION PLAN" for the authoritative, actively-maintained tracker of every remaining gap across all stages.

`-O0` disables the optimizer's own call entirely for every PROCEDURE; the generated code is otherwise identical in observable behavior, just less compact (every comparison/branch/redundant instruction the rules above would otherwise remove is still present). See `DOCS/SPHO.MD`'s own "Peephole optimization" section for the full per-rule design notes and safety reasoning.

### Implementation Limits

These are limits of the current translator, not bounds checked by a
runtime system. Do not depend on invalid input receiving a clean error.

| Item | Limit |
|---|---|
| Identifier/token spelling | 63 characters; longer is a translator error |
| Ordinary string literal | 255 decoded bytes; longer is a translator error |
| BASE64/FILE decoded array | 65535 bytes |
| Array `[N]` bound | 1 to 32767; zero/negative/oversized is a translator error |
| Array/array-field total byte count | 65535 bytes; larger is a translator error |
| Constant array index | must be non-negative and within the array's own declared length; violation is a translator error (array-typed parameters exempt -- no declared length to check against) |
| Parameters per procedure | 32 |
| Fields per record | 112 |
| Entries in USES | 32 (only legal hardware registers/FLAGS are meaningful) |
| Names in one VAR group | 64 |
| Nested WHILE loops | 64 |
| Factors in one condition AND-term | 16 |
| Simultaneously open source/import files | 8, including the top-level file |
| Stored symbol/type/procedure rows | 4096 per detail-table kind |

IMPORT cycles are diagnosed. A repeated dependency and namespace/name
collision should not be treated as C header-guard semantics; use distinct
exported names and inspect generated headers. There is no module-qualified
name lookup. Runtime array lengths, overflow checks, and stack/segment
capacity checks are not implicitly supplied.

The complete section 13 example is also stored as `TESTS/RECDOC.SMD`.
It checks the low word, high word, and scalar field and exits through DOS
with status 0 on success or 1 on failure. It is standalone and does not
use the print-output smoke-test convention or require imported libraries.
To verify it after building the translator, run from `TESTS/`:

```sh
emu2 ../SRC/spho.exe RECDOC.SMD
emu2 ../BIN/TASM.EXE RECDOC.ASM
emu2 ../BIN/TLINK.EXE /T=com RECDOC.RDF RECDOC.COM
emu2 RECDOC.COM
```
