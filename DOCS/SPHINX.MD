# SPHINX Oberon Language Specification

## A Low‑Level Oberon Dialect Compiling to NASM

SPHINX Oberon is a strict 16‑bit systems programming language that combines the structured syntax of Oberon‑2 with direct access to the x86 CPU. This document defines the complete language semantics and, crucially, shows how each construct translates into human‑readable NASM assembly. The target is real‑mode DOS .COM or .EXE programs; segment registers are 16‑bit and memory is addressed with `segment:offset` pairs.

Few notes:
- This dialect allow _ into identifiers.
- Comments come in two forms: `(* ... *)` (block, can span multiple lines) and `// ...` (single-line, runs to end of line, same convention as C/C++/Oberon-2). `(* *)` does **not** nest: the first `*)` closes the comment regardless of any `(*` seen since, so `(* outer (* inner *) still code *)` is a comment ending after `inner`, leaving `still code *)` to be parsed as ordinary source (and very likely a syntax error) — unlike Oberon-07 proper (`DOCS/OBERON07.EBN`), which does nest. `//` has no such hazard (nothing after it on the same line is ever parsed, block or not).
- Exported procedures (marked with * ) is GLOBAL (nasm) and can be NEAR/FAR (default - far).
- If module initialization part exists (same as main() in C) - need generate label "start" and this block begin.
- IMPORT keyword is the same as #include (in c) - just includes other source file (in Sphinx Oberon). This file must start with `MODULE modulename;` and ends with `END modulename.`. All others - exactly as in C (just include SPHINX Oberon text).
- **IMPORT resolves to `.SHD`, not `.SMD`** (Sphinx Oberon HeaDer — like a C `.h`): `IMPORT Files;` opens `Files.SHD`, never `Files.SMD` directly, regardless of what the importing file's own extension is. `.SHD` is not hand-maintained — the translator generates it automatically as a side effect of translating a `.SMD` file (see below), the same way `.ASM` is; only the top-level file passed on the command line is ever opened as `.SMD`. Resolution tries the current directory first (`Files.SHD`), then a hardcoded `LIB\Files.SHD` fallback if that doesn't exist (`SRC/SCAN.PAS`'s own `OpenInclude`) — `IMPORT` itself has no path syntax to name a directory, so this lets many project directories share one real copy of a common module's own `.SHD` via a single `LIB` directory symlink per project (`ln -s /path/to/LIB LIB`) instead of a separate `.SMD`/`.SHD`/`.RDF` symlink per shared module. `TASM.EXE`/`TLINK.EXE` have no such search path — a project's own `Makefile` still lists every `LIB/<Name>.RDF` it links against explicitly.
- **Every top-level `.SMD` translation also writes a matching `.SHD` sibling** (`FILE.SMD` -> `FILE.SHD`, alongside `FILE.SMD` -> `FILE.ASM`) — **unless** that file has its own `BEGIN...END` init part (a real `start` label/entry point, i.e. it's a standalone program, not a library other modules could usefully `IMPORT`). The generated `.SHD` contains, verbatim, only the **`*`-exported** declarations: each `CONST Name* = value;` (its own final folded value), each `TYPE Name* = RECORD ... END;`, and one `PROCEDURE Name(params): RetTy; NEAR; EXTERNAL;` line per `*`-exported `PROCEDURE` — bodies, comments, any non-`*` `CONST`/`TYPE`/`PROCEDURE`, `FORWARD`-only `PROCEDURE`s, and `VAR` globals are never included. A module's own `CONST`/`TYPE`/`PROCEDURE` therefore each need their own real `*` export marker to be usable by anything that `IMPORT`s it — this differs from the old textual-splicing behavior, where every declaration was visible to an importer regardless of `*`.
- STRONG: Allowed 8086 intruction set only. (no 286, 386 etc)

---

## 1. Module Structure

```
MODULE ModuleName;
  IMPORT OtherModule;   (* optional *)
  CONST ...
  TYPE  ...
  VAR   ...             (* global variables *)
  PROCEDURE ...;         (* definitions, and optionally FORWARD
                             declarations -- see §6.3.1 *)
  PROCEDURE ...;
  ...
BEGIN
  ...                   (* module initialisation *)
END ModuleName.
```

**NASM translation:**  
Globals are placed in the `.data` section (or `.bss` for uninitialised). Code goes in the `.text` section. The module body becomes the entry point. Example:

```
MODULE Hello;
BEGIN
  AX := 0x4C00;
  INT(21H)
END Hello.
```

↓

```nasm
section .data
section .text
global start
start:
    mov  ax, 0x4C00
    int  0x21
```

`CONST`/`TYPE`/`VAR` sections and `PROCEDURE` definitions may repeat and appear in any order, mixed freely (e.g. `VAR ... CONST ... PROCEDURE ... VAR ... PROCEDURE ...`) — each keyword still applies its own usual rules to the declarations that follow it. A `VAR` section (global or local, inside a `PROCEDURE`) may also group several names under one shared type with a comma: `a, b, c : WORD;` is equivalent to three separate one-name declarations, `a : WORD; b : WORD; c : WORD;` — this does not extend to a shared initializer (`a, b : WORD = 5;` is a translator error; give each name its own `= value` on its own line instead).

Caveat: piling up more than one global `VAR`/`CONST` section separated by `PROCEDURE`s in the same file can trip a `TASM.EXE` assembler limitation (not a SPHO bug) — three or more `.text`/`.bss` section alternations in one `.ASM` file can make TASM misreport an ordinary short jump as `branch target is not in the code segment`. If you hit this, merge your extra `VAR`/`CONST` sections back into the module's first one.

---

## 2. Registers

The CPU registers are predefined variables. They are typed as follows:

| Register | Type     |
|----------|----------|
| AX, BX, CX, DX, SI, DI, BP, SP | WORD (16‑bit unsigned/signed) |
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

↓

```nasm
mov  ax, 0x1234
mov  al, ah
mov  bx, cx
add  bx, 4          ; because + is left‑to‑right, but BX := CX + 4 becomes mov bx,cx then add bx,4
push cs             ; mov ds, cs does not exists for 8086
pop  ds
```

The compiler must never preserve a register unless explicitly instructed by `USES` (see §7). In expressions, reading a register yields its current value; writing it updates the hardware.

---

## 3. Types and Type Declarations

### 3.1 Basic Types

| Type    | Size (bytes) | Description                           |
|---------|--------------|---------------------------------------|
| BYTE    | 1            | unsigned 8‑bit                        |
| CHAR    | 1            | synonym for BYTE (Pascal port extension) |
| BOOLEAN | 1            | like BYTE, 0 = FALSE, ≠0 = TRUE       |
| WORD    | 2            | unsigned 16‑bit (same size as INTEGER, but unsigned — see §7.1) |
| INTEGER | 2            | signed 16‑bit                         |
| LONGINT | 4            | signed 32‑bit, stored little‑endian   |
| POINTER | 4            | synonym for LONGINT (Pascal port extension) |
| Array   | element_size × count | packed sequentially           |
| RECORD  | sum of field sizes   | fields aligned to natural boundaries |

`TRUE` and `FALSE` are predeclared BOOLEAN constants (`TRUE` = 1, `FALSE` = 0), usable anywhere a literal is:

```ob2
RETURN TRUE
```

↓

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

**Passing an array to a procedure:** there is no array-typed formal
parameter syntax (`ParseParams` only ever resolves a scalar or RECORD
type per parameter group, §6.6 — `x: BYTE[10]` in a parameter list does
not parse). The working pattern is the same address-passing model
string literals already use (§3.3): declare the parameter as a plain
`WORD`/`INTEGER` holding the array's address, pass `ADR(arr)` at the call
site, and index through it with direct memory access (§10) inside the
callee.

```ob2
VAR buf: BYTE[16];
PROCEDURE FillIt(bufAddr: INTEGER); NEAR;
BEGIN
  BX := bufAddr;
  [DS:BX] := 65
END FillIt;
...
FillIt(ADR(buf));
```

↓

```nasm
FillIt:
    push bp
    mov  bp, sp
    mov  bx, [bp+4]     ; bufAddr
    mov  ax, 65
    mov  [ds:bx], ax    ; a bare "[DS:BX] := 65" stores a WORD -- see §10
                         ; for how to size a store to a specific field/byte
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

```
TYPE
  RecordName = RECORD
    field1 : type;
    field2 : type;
    ...
  END;
```

**NASM translation:**  
A NASM `struc` is emitted. The structure name is `RecordName` and its fields are accessible as `RecordName.fieldName` inside the assembler.

```
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

↓

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

**Array fields:** a field may itself be an array (`name : type[N];`, the same `[N]` bound as an ordinary array VAR, §3.1) — packed sequentially with no padding *inside* the array, same as a standalone array VAR:

```
TYPE
  FileBuf = RECORD
    handle : INTEGER;
    ofs    : WORD;
    fill   : WORD;
    data   : BYTE[1024];
  END;
```

↓

```nasm
struc FileBuf
    .handle: resw 1
    .ofs:    resw 1
    .fill:   resw 1
    .data:   resb 1024
endstruc
```

`SIZE(FileBuf)` is 1030 (2+2+2+1024), and `handle`/`ofs`/`fill` still work as ordinary scalar fields (`[seg:base].FileBuf.ofs := ...`). An array field has no standalone name of its own to `ADR()` the way a global/local array does, so it's addressed through the same `[seg:base].RecordType.field` structured-access syntax, given to `ADR()` instead of a bare name: `ADR([DS:BX].FileBuf.data)`. Using an array field directly as a scalar operand (`AX := [DS:BX].FileBuf.data;`) is a translator error — only `ADR()` of it is valid.

Once a record type is defined, it can be used in variable declarations and direct memory access (see §10).

### 3.3 Character and String Literals

Two distinct quoting styles, matching NASM's own distinction between a character-literal immediate and a quoted string operand:

- **`'x'`** (single-quoted, exactly one character) is a plain numeric immediate — its `ORD` value. No storage is allocated; it behaves exactly like a numeric literal.
- **`"..."`** (double-quoted, any length including empty) is a genuine string literal. It is stored once in a `.data` table (deduplicated: two occurrences of the identical text share one label) and evaluates everywhere to its own **offset** — SPHINX has no string-*value* operations, only pass-by-offset, the same model arrays and records already use. A string literal can be passed as a call argument, assigned to a register, or assigned to a 16-bit variable.

```ob2
AL := 'A';
PrintMsg("Hello, world!$");
msgPtr := "Another one$";
```

↓

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

Every literal used anywhere in a module is collected and emitted once, as a NUL-terminated `db` line, in a `.data` block appended at the very end of the translated output — the label may be referenced (as a forward reference) from anywhere earlier in the file. A byte in the literal's own text that would corrupt a plain NASM `'...'` operand if placed there directly (the `'` quote character itself, or any control byte such as tab/CR/LF/ESC — most commonly reached via an escape sequence, below) is emitted as a bare `NNh` hex immediate instead, comma-separated with any surrounding quoted run of ordinary printable characters — `_literal0: db 01Bh,'[95mHello',01Bh,'[0m',0`, for example. Plain printable text with none of these bytes still emits as a single quoted `db 'text', 0` line, unchanged.

**Escape sequences**: inside either quoting style, a `\` introduces a C-like escape, decoded to a single raw byte at translate time:

| Escape | Byte | Meaning |
|--------|------|---------|
| `\t`   | `09h` | tab |
| `\n`   | `0Ah` | line feed |
| `\r`   | `0Dh` | carriage return |
| `\\`   | `5Ch` | literal backslash |
| `\'`   | `27h` | literal single quote |
| `\"`   | `22h` | literal double quote |
| `\ooo` | —    | 1 to 3 **octal** digits, e.g. `\033` = `1Bh` (ESC) |
| `\xHH` | —    | 1 to 2 **hex** digits, e.g. `\x1b` = `1Bh` (ESC, same byte as `\033`) |

This is what makes a literal delimiter, or a genuinely unprintable byte such as an ANSI escape, representable at all: `"\033[95mRed\033[0m"` and `"\x1b[95mRed\x1b[0m"` both encode the same five-byte-prefixed/four-byte-suffixed ANSI color sequence. `'\t'` is a one-character `'...'` literal whose `ORD` value is 9, exactly as if it had been written `9` or `09H` directly. An escape not matching this table (e.g. `\q`), or a `\` at the very end of a literal with nothing after it, is a translator error — an unrecognized escape is far more likely a typo than an intentional literal backslash, so it is caught rather than silently passed through as two separate characters.

### 3.4 Array Literals (`BASE64` / `FILE` / `"..."`)

A global array declared with an **empty** bound (`T[]`, no size) can be given a real initial value instead of being uninitialized `.bss` space — the array's length comes from the decoded data itself, not from a written-out `N`:

```
VAR
  v : BYTE[]    = BASE64("TWFu");
  w : CHAR[]    = FILE("sprites.bin");
  s : BYTE[]    = "Hello!";
```

- `BASE64("...")`'s own `"..."` text is exempt from the ordinary 255-character string-literal limit (§3.3) — it may hold up to 65535 characters of base64 text (enough to decode a full 65535-byte blob, the largest a `BASE64()`/`FILE()` array can ever be). Every other `"..."` string literal in SPHINX stays capped at 255 characters.
- `BASE64("...")` decodes a standard base64 string into raw bytes at translate time. Whitespace (space, tab, CR, LF) anywhere in the text is ignored, so a long blob may be broken across multiple source lines for readability:
  ```
  VAR v : BYTE[] = BASE64("TWFu
     IGlzIHRoZSBjb25kaXRpb24=");
  ```
  decodes identically to the same characters written on one line.
- `FILE("...")` reads a file's raw bytes at translate time. The path is resolved **relative to the `.SMD` file the declaration appears in** (not the process's current directory, and not `IMPORT`'s own convention, which is CWD-relative) — the same file, correctly, even across an `IMPORT`ed file's own `FILE()` calls.
- `"..."` (a plain string literal directly as the initializer, not wrapped in `BASE64()`/`FILE()`) encodes the literal's own raw bytes, plus one trailing zero byte (an ASCIIZ C-style string) — same 255-character limit as any other `"..."` string literal (§3.3). Unlike `BASE64()`/`FILE()`, no decoding happens; the bytes are exactly the literal's own text, in source order.
- `T` may be any element type SPHINX already accepts in an array declaration (`BYTE`/`CHAR`/`BOOLEAN`/`WORD`/`INTEGER`/`LONGINT`, or a declared `RECORD` type). The declared type is descriptive only — the decoded data is always emitted as a flat sequence of bytes, one `db` per byte (as a hex-byte immediate, e.g. `048h`, never a quoted NASM string — so an initializer text containing a `'` needs no special escaping), regardless of `T`.
- The array always goes in `.data` (it holds a real stored value), never `.bss`, unlike every other array form.
- `SIZE(v)` (§9) returns the decoded byte count for an array declared this way (for `"..."`, that's the text length plus 1 for the trailing zero byte).
- `T[]` **requires** a `BASE64()`/`FILE()`/`"..."` initializer — an empty bound with no initializer, or one of these initializers on an explicit `T[N]` bound, are both translator errors.
- Only supported for a **global** `VAR` — SPHINX has no local-`.data` concept (a local array is always `.bss`/frame space), so `T[] = BASE64(...)`/`FILE(...)`/`"..."` inside a `PROCEDURE`'s own `VAR` section is a translator error.

```ob2
VAR sprite : BYTE[] = BASE64("/wD/AA==");
```

↓

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
Defined at module level, they reside in either the `.bss` or `.data` segment depending on whether an initializer is given: an **uninitialized** global (the common case — a plain scalar, an array, or a RECORD instance) is zero-filled reserved space and belongs in `.bss`; only a global with an explicit `= value` initializer holds a real stored value and belongs in `.data`. There is no default/assumed section anywhere in the output — each declaration switches to whichever section it needs.

```ob2
VAR
  counter: INTEGER;
  flag: BYTE;
  bigValue: LONGINT;
```

↓

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

↓

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

↓

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

↓

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
If a formal parameter name matches a register, the value is passed **directly in that register** – no stack operation.

```ob2
PROCEDURE CB_API(AX); NEAR;
BEGIN
  INT(2FH)
END CB_API;
```

Call: `CB_API(0x1700);`

↓

```nasm
; call site
mov  ax, 0x1700
call CB_API

; procedure (near, no stack frame needed)
CB_API:
    int  0x2F
    retn
```

No stack frame is generated if the procedure doesn't have local variables, non-register parameters, or `USES`.

The call site shown above is the minimal-case ideal, not `SPHO.MOD`'s own literal current output: the real translator always pushes every argument first (any argument's own evaluation might otherwise clobber an already-computed register-bound one, `DOCS/SPHO.MD`'s own "Call sites now load a register-named formal's argument directly" entry has the full reasoning), then extracts each register-bound one back off the stack via a small self-contained `push bp`/`[bp+N]`/`pop bp` sequence — a few bytes larger than the ideal `mov ax, 0x1700; call CB_API` shown here for this trivial single-argument case, but correct for any number/mix of register- and stack-bound arguments in any order, which the minimal form cannot express in general.

The keyword `REG` is optional for clarity: `PROCEDURE CB_API(REG AX);` is equivalent.

### 6.3 Procedure Attributes

| Attribute   | Call instruction | Return instruction | Description |
|-------------|------------------|--------------------|-------------|
| `NEAR` (default) | `call`      | `ret` / `ret n`    | 16‑bit near call |
| `FAR`       | `call far`       | `retf` / `retf n`  | 16‑bit far call, stack includes segment |
| `INTERRUPT` | (none)           | `iret`             | Interrupt handler, no parameters allowed |

**INTERRUPT** procedures cannot be `NEAR`/`FAR`. They must end with `iret`. `USES` and local `VAR`s are allowed (an `INTERRUPT` procedure has its own stack frame for those, same `push bp`/`mov bp,sp` prologue as any other), but **parameters are not** — an interrupt has no caller-pushed argument list to clean up. If `USES` is present, the compiler automatically saves/restores the listed registers and flags. Without `USES`, the programmer must do it manually in `ASM` blocks.

A parameter list on an `INTERRUPT` procedure is a translator error
("INTERRUPT procedures may not have parameters") — the `iret` return
would not clean up a caller-pushed argument list the way `retn n`/
`retf n` would for `NEAR`/`FAR`.

### 6.3.1 `FORWARD` Declarations

`PROCEDURE Name(params): RetTy; NEAR|FAR; FORWARD;` declares a procedure's
full signature without a body — the real definition (identical signature,
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

**Why this matters:** a call site can only ever know `Helper`'s
`NEAR`/`FAR`-ness (`call` vs. `call far`, §6.3 — getting this wrong
corrupts the stack on return, in either direction) from a PROCEDURE
declaration/definition of that name — a `FORWARD` declaration lets the
call site know it immediately, at translation time. `FORWARD` is
**optional**, not required, for a same-file forward call: a call to a
procedure not yet declared earlier in the file is recorded and
re-resolved once the whole file (and everything it `IMPORT`s) has been
parsed, and the correct `call`/`call far` form is used either way. Only
a call to a name that is *never* declared anywhere in the file is a
translator error ("call to undefined procedure '...'"). There is no
equivalent concern for the reverse situation (defined before use) —
that case never needs `FORWARD` at all, since the definition has
already been seen by the time the call site is translated.

Writing `FORWARD` still has one real effect: it makes the callee's
`NEAR`/`FAR`-ness known immediately at the call site, rather than only
after the whole file is parsed — useful mainly as documentation, since
the eventual generated code is identical either way.

A `FORWARD` declaration is not itself a callable definition: a second,
real `PROCEDURE Name...` with the same name is required later in the
file, or the name is still unresolved at end-of-file (same error as
never declaring it). That real definition's own signature must match
the `FORWARD` declaration's — parameter count, each parameter's
register-vs-stack placement (and register, if register-bound) and
`LONGINT`-vs-not type, and whether/what return type was declared. A
mismatch is a translator error (e.g. "parameter count differs from
FORWARD declaration", "return type differs from FORWARD declaration").
Two full `PROCEDURE` definitions sharing a name (not a `FORWARD`
followed by its real body) is a translator error ("duplicate PROCEDURE
definition"). `FORWARD` is not supported on an `INTERRUPT` procedure.

### 6.3.2 `EXTERNAL` Declarations

`PROCEDURE Name(params): RetTy; NEAR|FAR; EXTERNAL ["realname"];`
declares a procedure with **no body at all** — it is defined elsewhere
(another object file/library, linked in separately) and only its
signature is known here. `EXTERNAL` takes the same position `FORWARD`
does (right after `NEAR`/`FAR`/`INTERRUPT`) and, like `FORWARD`, ends the
declaration with no `BEGIN...END` body — the two are mutually exclusive,
never both on the same declaration.

Two forms:

```ob2
PROCEDURE ddd(p: INTEGER): BOOLEAN; FAR; EXTERNAL "ddd1";
PROCEDURE eee(); NEAR; EXTERNAL;
```

- **Named** (`EXTERNAL "realname"`) — `ddd` is only a local SPHINX-side
  synonym; every call to `ddd(...)` compiles to a call against
  `realname` (`ddd1` above) instead, and `extern ddd1` is emitted, not
  `extern ddd`. Use this when the real symbol's name isn't a legal (or
  desired) SPHINX identifier, or simply to give it a more convenient
  local name.
- **Unnamed** (bare `EXTERNAL;`) — the SPHINX name **is** the real
  linker symbol: `eee()` calls `eee`, and `extern eee` is emitted.

Either form emits a NASM `extern` directive (once, at the declaration
site) and makes the name callable exactly like any other declared
procedure — `NEAR`/`FAR`-ness, parameter passing, and return-register
convention (§6.4) all apply normally; the only difference is that no
code is generated for a body, and linking must supply the real symbol
from elsewhere. Not supported on an `INTERRUPT` procedure.

### 6.4 Return Values
Functions return via registers:

| Return type | Register |
|-------------|----------|
| BYTE, BOOLEAN | AL     |
| INTEGER, WORD | AX     |
| LONGINT       | DX:AX (DX=high, AX=low) |

**`CHAR` is a synonym for `BYTE`** (Pascal port extension; `SRC/TASM/SPHO.MOD` has no `CHAR` type anywhere — `ParseBaseType`'s original scalar-keyword list was `BYTE`/`BOOLEAN`/`WORD`/`INTEGER`/`LONGINT` only, matching §3.1's own table). A single character is represented as a `BYTE` holding its ASCII value (or a `'x'` character literal, §3.3, which is itself just a numeric immediate); `CHAR` is accepted everywhere `BYTE` is and produces identical code.

The compiler generates a move to the appropriate register(s) before `RET`.

```ob2
PROCEDURE GetMax(): INTEGER; NEAR;
BEGIN
  RETURN 0xFFFF
END;
```

↓

```nasm
GetMax:
    mov  ax, 0xFFFF
    retn
```

A procedure call taking no arguments may omit the parentheses entirely — `Foo;` is equivalent to `Foo();`:

```ob2
XMS_CLEAR_REC;
```

↓

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

↓

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

Procedures can have parameters with different types. A comma-separated run of names shares one trailing type (`a, b: INTEGER` — both `a` and `b` are INTEGER); `;` starts a new group with its own type, so a single parameter list can mix types freely:

```ob2
PROCEDURE Mixed(x: BYTE; y: INTEGER): INTEGER;
BEGIN
  AX := x;
  BX := y;
  RETURN AX + BX
END Mixed;
```

Call: `result := Mixed(1, 20);`

↓

```nasm
; Call site
mov  ax, 1
push ax
mov  ax, 20
push ax
call far Mixed

; Procedure definition
Mixed:
    push bp
    mov  bp, sp
    mov  AX, [bp+8]   ; x (first param, higher address)
    mov  BX, [bp+6]   ; y (second param)
    add  ax, BX
    mov  sp, bp
    pop  bp
    retf  4           ; clean 4 bytes of parameters (default FAR, unmarked NEAR/FAR)
```

A register-named formal (§6.2) never takes a type at all and never shares a following group's type — it may sit alongside ordinary names in the same comma-separated run.

**By-value RECORD parameters are not supported.** A parameter's type may
be `BYTE`/`BOOLEAN`/`WORD`/`INTEGER`/`LONGINT` (or the Pascal-port
synonyms `CHAR`/`POINTER`, §6.4) or a declared RECORD type,
but a RECORD-typed one is rejected as a translator error ("by-value
RECORD parameter not supported") — the Pascal calling convention above
pushes/reads exactly one word (or byte) per parameter, which cannot
represent a multi-byte struct's full value: an earlier version of
`SPHO.MOD` accepted this silently and truncated the record to its own
first field at both the call site and the callee's own stack-cleanup
size, a correctness bug, not merely an unsupported feature. Pass a
record the same way an array is passed (§3.1): `ADR(rec)` into a plain
`WORD`/`INTEGER` parameter, and access fields inside the callee via
direct memory access (§10, `[seg:paramReg].RecordType.field`).

**Array parameters (Pascal port).** A formal parameter's type may be
followed by `[N]` or an empty `[]`, e.g. `buf: WORD[3]` or
`buf: WORD[]` — address-only sugar over the manual `ADR()` convention
above, not a new calling convention: the parameter is still exactly one
`WORD`/address parameter underneath (`N`, if given, is descriptive
only — parsed but not enforced). The only difference from writing
`buf: WORD` by hand is at the CALL SITE: passing a plain array-typed
`VAR` name where an array-typed parameter is expected automatically
takes its address, the same as if the caller had written `ADR(arr)`
explicitly — a global array's own bare label already IS its address
(no code emitted for that half); a local array gets a real
`lea ax, [bp-N]`. This exemption also applies to an array of a declared
`RECORD` type (`buf: SomeRecord[N]`) — by-value RECORD parameters are
still rejected (just above), but an array-of-RECORD parameter is
address-only, same as a scalar array. Inside the callee, the parameter
is an ordinary address (`WORD`) — see "Array element indexing" below
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
`name` is any array-typed identifier — a plain global/local array `VAR`
or an array-typed formal parameter (just above) — reads or writes one
element directly, e.g. `arr[2]`, `arr[i] := 5`, `total := total +
buf[i]`. `indexExpr` is a single operand: a numeric literal, a `CONST`
name, a `VAR`, or a register — not a general nested expression (SPHINX
has no expression grouping/parens anywhere, matching every other
position in the language). Scalar element types only (`BYTE`/
`BOOLEAN`/`WORD`/`INTEGER`/`LONGINT`, or the Pascal-port synonyms
`CHAR`/`POINTER`) — indexing an array-of-`RECORD` element is a
translator error (structured field access on one element still works
the existing way, `[seg:base].RecordType.field`, after computing that
element's own address by hand). A literal or `CONST` index is folded
into the generated address directly at translate time (no runtime
arithmetic at all); any other index computes the address at runtime
(base + index × element size).

```ob2
VAR arr: WORD[3];
...
arr[0] := 10; arr[1] := 20; arr[2] := 30;
x := arr[1];        (* constant index -> no runtime arithmetic *)
y := arr[i];         (* i a VAR -> real address computation *)
```

↓

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

Expressions are evaluated **strictly left to right**, ignoring traditional operator precedence. Parentheses override the default order.

### 7.1 Arithmetic Operators

| Operator | Meaning          | x86 instruction |
|----------|------------------|-----------------|
| `+`      | addition         | `add`           |
| `-`      | subtraction      | `sub`           |
| `*`      | multiply (16‑bit, truncated to AX) | `mul` (WORD) / `imul` (INTEGER) |
| `DIV`    | division (quotient) | `div` (WORD) / `idiv` (INTEGER) |
| `MOD`    | remainder        | same `div`/`idiv`, result taken from DX |

`+`/`-` chain left-to-right with `&`/`OR`/`SHL`/`SHR`/`XOR` (§7.2) in one
expression as usual. **`*`/`DIV`/`MOD` are terminal-only**: `a * b`,
`a DIV b`, `a MOD b` is a single binary operation — it may not be chained
with `+`/`-`/etc. either before or after (`a + b * c` is a translator
error; introduce a temporary VAR instead: `t := b * c; x := a + t;`).
This is the same restriction relational operators (§7.3) already have,
and for the same reason: `mul`/`imul`/`div`/`idiv` hard-clobber `DX:AX`,
which would otherwise corrupt a chain's own running total mid-expression.

**Signedness (WORD vs INTEGER)**: `*`/`DIV`/`MOD` use the unsigned
(`mul`/`div`) or signed (`imul`/`idiv`) instruction form depending on the
left operand's type — a `WORD` VAR or a bare register (registers default
to `WORD`, §3.1) uses the unsigned form; an `INTEGER` VAR, or a register
explicitly cast with `.INTEGER` (see the new subsection below), uses the
signed form. Mixing an INTEGER-cast operand with a WORD/uncast one on the
other side is a translator error (both operands must agree in
signedness). `*`'s result is truncated to `AX` (the `DX` high word is
discarded — SPHINX has no LONGINT-widening multiply). `DIV`'s result is
the quotient (`AX`); `MOD`'s result is the remainder (`DX`, moved into
`AX` for the caller). Dividing by a literal `0` is a translator-time
error; a runtime-computed zero divisor is not checked (8086 `INT 0`
applies, same as any other unchecked runtime condition in SPHINX).

```ob2
AX := 3 + 4;        (* left-to-right chain, fine *)
t := 4 * 5;         (* '*' alone -- fine *)
AX := 3 + t;         (* combine via a temp instead of "3 + 4 * 5" *)
```

↓

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

↓

```nasm
mov  ax, bx
cwd                   ; sign-extend AX to DX:AX (INTEGER)
idiv cx               ; AX=quotient, DX=remainder
; result (quotient) in AX
```

**Unary `-`**: `-5` (immediately followed by a numeric literal) folds into a compile-time-constant immediate — no runtime cost. `-x` for any other operand (a VAR, register, `[mem]`, or call result — e.g. `n := -n;`) computes a real two's-complement negation via the 8086 `neg` instruction:

```ob2
n := -n;
```

↓

```nasm
mov ax, n
neg ax
mov [n], ax
```

### 7.1.1 Signedness cast: `REG.INTEGER` / `REG.WORD`

A bare 16-bit register operand (`AX`, `BX`, `CX`, `DX`, `SI`, `DI`, `BP`,
`SP`) defaults to `WORD` (unsigned) — matching §3.1's own type table.
Immediately following a bare register token (nowhere else — not after a
VAR name, not inside a `[...]` memory operand) with `.INTEGER` casts that
one operand to signed for this use; `.WORD` is also accepted, explicit
but equivalent to the default. This only affects comparisons (§7.3) and
`*`/`DIV`/`MOD` (§7.1) — it does not change the register's own bits, and
has no effect on a plain move (`x := AX.INTEGER;` emits the same `mov` as
`x := AX;`).

```ob2
IF AX.INTEGER < BX.INTEGER THEN ... END
IF SI.INTEGER >= 0 THEN ... END
IF AX < 0 THEN ... END        (* unsigned "AX < 0" -- always FALSE *)
```

↓ (first line)

```nasm
cmp  ax, bx
jge  .else            ; signed: "not less than" skips the THEN branch
```

### 7.2 Bitwise Operators

| Operator | Meaning   | x86 instruction |
|----------|-----------|-----------------|
| `&`      | AND       | `and`           |
| `OR`     | OR        | `or`            |
| `~`      | BOOLEAN NOT (unary)| `xor ax, 1` (not 8086 `not`) |
| `SHL`    | left shift | `shl` (clamping count) |
| `SHR`    | right shift| `shr`          |

`OR` is a keyword — bitwise OR has no symbolic spelling. This is unrelated
to §7.4's own "no `&`/`OR` **condition** composition" limitation below —
that note is about joining two separate `a REL b` conditions in `IF`/
`WHILE` position (still not implemented), not about this ordinary binary
expression operator.

**`~` has two distinct forms.** In **condition position** (directly in
front of `CFLAG`/`ZFLAG`, §7.5, or a bare BOOLEAN condition, §8.1) it
negates by picking the opposite `Jcc` (`onTrue # negated`) — no value is
computed at all. As a **general expression operand** (`x := ~y;`), it
computes a value: `y` is expected to already be a clean 0/1 BOOLEAN
(`TRUE`=1, `FALSE`=0, §3.1), so negation is `xor ax, 1` (flip bit 0),
**not** the 8086 `not` instruction (which would flip every bit — wrong
for a 0/1 value; `not 1` = `0FFFEh`, not `0`). `&` and `OR` (this table's
other two rows) are real, general binary expression operators, wired
into the left-to-right emitter the same as `+`/`-` (§7.1); `~` as an
expression operand is terminal (like `ODD(x)`, §9) — it is not itself
chainable with a following `+`/`-`/etc., though its own operand can be
any ordinary operand form (register, VAR, `[mem]`).

```ob2
muted := ~muted;   (* toggle a BOOLEAN *)
```

↓

```nasm
mov  ax, [muted]
xor  ax, 1
mov  byte [muted], al
```

The shift count is either an immediate or taken from `CL` if the right operand is a register.

```ob2
AL := AL SHL 1;
BX := CX SHR CL;
```

↓

```nasm
shl  al, 1
mov  bx, cx
shr  bx, cl
```

### 7.3 Relational Operators
Relationals compare two values and set the destination to 0 or 1. Internally, they use `cmp` and a conditional jump — **never `SETcc`** (that's a 386+ instruction; this dialect targets 8086 only, see the notes at the top of this document).

`=`/`#` are sign-independent (`je`/`jne` either way). `<`/`>`/`<=`/`>=`
use the LEFT operand's own signedness (§7.1's "Signedness" subsection —
`WORD`/bare register default = unsigned `jb`/`ja`/`jbe`/`jae`;
`INTEGER`/`.INTEGER`-cast register = signed `jl`/`jg`/`jle`/`jge`). This
is a single-sided design: only the left operand's type decides the jump
form, matching how a byte-sized VAR's own zero-extension is likewise only
ever checked on the left operand.

```ob2
IF AX > BX THEN ...          (* unsigned: bare registers default WORD *)
IF AX.INTEGER > BX.INTEGER THEN ...   (* signed *)
```

↓

```nasm
cmp  ax, bx
ja   .L1                     ; unsigned "greater than"
...
```

In an `IF`/`WHILE` **condition**, an `INTEGER`-typed VAR (not just a
register) also gets the signed form automatically, from its own declared
type — no cast needed there:

```ob2
VAR i : INTEGER;
...
IF i < 0 THEN ...            (* signed -- i's own declared type *)
```

**Known gap**: when a relational appears as a *value* (`AL := AX > BX;`,
below) rather than an `IF`/`WHILE` condition, the signedness split only
applies when the left operand is directly a register (with or without a
`.INTEGER`/`.WORD` cast) — a plain VAR name reaching this form still uses
the signed default regardless of its own declared WORD/INTEGER type. Use
an `IF`/`WHILE` condition (which peeks the VAR's real type) instead of a
relational-as-value expression when a `WORD` VAR's unsigned comparison
matters.

When used as a value, an 8086-legal `cmp`/`Jcc`/`mov 0`/`jmp`/`mov 1` sequence is emitted instead of `xor`/`setCC`:

```ob2
AL := AX > BX;   (* AL = 1 if AX>BX else 0 *)
```

↓

```nasm
cmp  ax, bx
jg   .L1
mov  al, 0
jmp  .L2
.L1:
mov  al, 1
.L2:
```

This is terminal — no example chains a relational result into a further operator.

### 7.4 Logical Operators
`~`, `&`, `OR` operate on boolean (byte) values as ORDINARY binary
expression operators (§7.2) — no short-circuit there, both operands are
computed, e.g. `flag := a & b;`.

**Condition composition (Pascal port, SPHO.PAS).** An `IF`/`WHILE`
condition accepts two or more `a REL b`/bare-BOOLEAN factors joined by
`&`/`OR`, `&` binding tighter than `OR` (no parentheses needed or
accepted — SPHINX has no expression-grouping parens anywhere else
either). Unlike §7.2's own ordinary `&`/`OR`, condition-position `&`/
`OR` DOES short-circuit: an `OR`'s later disjuncts are never evaluated
once an earlier one is true, and an `&`'s later conjuncts are never
evaluated once an earlier one is false — matching Oberon/Pascal
convention, and meaningful here because each factor can itself have a
side effect (a function call) or be expensive.

```ob2
IF a < 10 OR b > 20 THEN ...
IF a < 10 & b < 10 OR c < 10 THEN ...   (* (a<10 & b<10) OR c<10 *)
```

↓ (first line)

```nasm
cmp ax, 10
jl  .Ltrue      ; a<10 true -> skip straight to the body
cmp bx, 20
jle .Lfalse     ; b>20 false too -> whole condition false
.Ltrue:
  ...THEN body...
.Lfalse:
```

A single-factor condition (no `&`/`OR` at all — the common case) emits
exactly the same code as before this existed: one comparison, one
conditional jump, no extra label. The original DOS `SPHO.MOD` never
implemented this (the `OR` keyword didn't exist there at all); this is
a Pascal-port extension beyond what the original DOS tool accepted, not
a fidelity bug — see `CLAUDE.md`'s own "Fidelity notes."

### 7.5 Conditional Flags
In a condition, `CFLAG` and `ZFLAG` can be tested directly, avoiding a `cmp`.

```ob2
WHILE ~ZFLAG DO ... END;
```

↓

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

```
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

↓

```nasm
    cmp  ax, 0
    jne  .Lelse
    mov  bx, 1
    jmp  .Lend
.Lelse:
    mov  bx, 2
.Lend:
```

`condition` (here and in `WHILE` below) is either a full `a REL b` relational (§7.3) or a bare BOOLEAN value used directly — a variable, register, or a BOOLEAN-returning call — tested against zero (TRUE=1/FALSE=0, §3.1) instead of a `cmp`:

```ob2
IF sss THEN ... END;          (* same as IF sss = TRUE THEN ... END *)
IF ~sss THEN ... END;         (* same as IF sss = FALSE THEN ... END *)
WHILE HasMore() DO ... END;   (* same as WHILE HasMore() = TRUE DO ... END *)
```

`~` in front of a bare condition negates it via jump selection (same as it does for `CFLAG`/`ZFLAG`, §7.5) — no `xor`/value is computed here, unlike `~` as a general expression operand (§7.2), which does compute one. §7.4's own "no `&`/`OR` composition in a condition" limit still applies in condition position — only a single bare condition, optionally `~`-negated, is accepted, not `~(a & b)` or similar.

### 8.2 WHILE Loop

```
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

↓

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

Evaluates expression into `AX`, then jumps to the procedure's own single epilogue label. `RETURN` is legal anywhere inside a procedure body, not only as its textually last statement — a `RETURN` inside a conditional branch, a loop, or any nested statement correctly skips the rest of the body:

```ob2
PROCEDURE Cond(x: INTEGER): BOOLEAN;
BEGIN
  IF x < 5 THEN RETURN TRUE
  ELSE RETURN FALSE END;
  AX := 999   (* unreachable *)
END Cond;
```

↓

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

**`RETURN` of a `LONGINT`** is more restricted than the general case above: only a bare `LONGINT` VAR name, or a register pair (`SEGREG:REG` / `REG:REG`, §11's own syntax), may be returned — never a general expression, since nothing in this dialect's `LONGINT` model produces a real 32-bit result from an arithmetic chain or a nested call. `RETURN` of a register pair moves the pair into `DX:AX` (§6.4's own `LONGINT`-return-register convention) if it isn't already there — `RETURN DX:AX` itself is a no-op, since the value is already in place:

```ob2
PROCEDURE GetPtr() : LONGINT; NEAR;
BEGIN
  PUSH(CS); POP(ES);
  DI := 654;
  RETURN ES:DI
END GetPtr;
```

↓

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

## 9. Built‑in Procedures and Functions

These are part of the language and generate inline code.

| Built‑in          | NASM translation                    |
|-------------------|-------------------------------------|
| `INC(var)`        | `inc word [var]` (or byte)          |
| `DEC(var)`        | `dec word [var]`                    |
| `INC(var, expr)`  | `add [var], expr` (or a register destination directly) |
| `DEC(var, expr)`  | `sub [var], expr` |
| `PUSH(r1,r2,...)` | `push r1` etc.                      |
| `POP(r1,r2,...)`  | `pop rN` in reverse order           |
| `INT(n)`          | `int n`                             |
| `ADR(v)`          | `offset v`                          |
| `SEG(v)`          | `seg v`                             |
| `SIZE(T)`         | `sizeof(T)` (constant)              |
| `ODD(x)`          | `test ax,1` / `jz`/`mov 0`/`jmp`/`mov 1` (no `SETcc`; 8086 only) |

`ADR(v)` returns the offset of `v` within its segment. `v` may name a global VAR, a local VAR, a (non-register) parameter, or a PROCEDURE: a global or a PROCEDURE both yield a constant offset (`offset v`, a PROCEDURE's own bare label is already its own offset as a NASM immediate — useful for installing an interrupt vector or any other function-pointer-style use), while a local/parameter yields its stack-frame address computed at runtime (`lea ax, [bp±N]`). A register-named parameter has no address and is rejected.
For far pointers, the segment can be obtained via `CS`, `DS`, etc.
For example, `ADR(xmsRec)` yields a constant offset.

`ADR` also accepts a `[seg:base].RecordType.field` structured-access operand (§10, §3.2) instead of a bare name — the only way to get an array field's own address, since it has no standalone name of its own: `ADR([DS:BX].FileBuf.data)` yields `lea ax, [bx + FileBuf.data]` (segment-override-adjusted). This is the array-field case in practice, but a scalar field works here too, same as `ADR()` of a plain scalar VAR.

`SEG(v)` returns the segment of `v` (also global-VAR only).

`SIZE(v)` also accepts a VAR name, not only a type name, when `v` is a global array declared with a `BASE64()`/`FILE()`/`"..."` initializer (§3.4) — it returns that array's own decoded byte count. An ordinary scalar VAR or a plain `T[N]` array still requires `SIZE(T)`'s type-name form.

`ADR`/`SEG`/`SIZE`/`ODD` are value built-ins — usable as an expression's RHS, but not directly as an `IF`/`WHILE` condition. `CFLAG`/`ZFLAG` (§7.5), by contrast, are condition-position-only. The two built-in families are not interchangeable.

`INC`/`DEC` take an optional second argument — `INC(v, expr)`/`DEC(v, expr)` is `v := v + expr`/`v := v - expr`, `expr` any expression (including a call), evaluated the same way an ordinary right-hand side is. `v` may be a variable or a bare register name.

```ob2
INC(counter, 5);
DEC(BX, delta);
```

↓

```nasm
mov  ax, 5
add  word [counter], ax
mov  ax, [delta]
sub  bx, ax
```

When `v` is the register `AX` itself, its old value must survive evaluating `expr` (which may itself use `AX`, e.g. any call result) — `AX` is saved and restored around `expr`'s evaluation instead of being combined directly:

```ob2
INC(AX, delta);
```

↓

```nasm
push ax
mov  ax, [delta]
mov  cx, ax
pop  ax
add  ax, cx
```

---

## 10. Direct Memory Access

Square‑bracket notation accesses memory at a given segment:offset. The general forms are:

```
[segment:offset]                     ; simple byte/word access
[segment:base] RecordType.field      ; structured field access
```

The segment override is optional; if omitted, `DS` is assumed (except when `BP` is the base, where `SS` applies). The base register can be any 16‑bit register that can be used in an effective address (`BX`, `BP`, `SI`, `DI`). For structured access, the record type and field name are appended with a dot, allowing the compiler to compute the correct offset.

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

↓

```nasm
mov  al, [0x0484]
```

The compiler resolves the field offset using the NASM structure definition. For example, `StructXmsRec` defined as a `struc` with `.len` at offset 0, `.src_hnd` at offset 4, etc. `[SI].StructXmsRec.src_hnd` becomes `[si + StructXmsRec.src_hnd]`.

When the target is a `LONGINT`, the compiler generates two moves if necessary, but the built‑in `LONGINT` register‑pair moves (see §11) provide more efficient bulk transfer.

---

## 11. LONGINT Register‑Pair Moves

Basic syntax — `variable` is a declared `LONGINT` VAR (global or local) referenced by its bare name, `SEGREG:REG` is `ES`/`DS` paired with any general 16‑bit register, and `REG:REG` is any other register pair (`DX:AX`, `ES:DI`, ...):

```ob2
SEGREG:REG := variable;
REG:REG    := variable;
variable   := SEGREG:REG;
variable   := REG:REG;
SEGREG:REG := REG:REG;
SEGREG:REG := myfunction();
```

These allow efficient loading/storing of 32‑bit values using `LES`/`LDS` instructions where possible. A register-pair operand may not currently be a `[seg:base]` memory-access expression — only a plain named `LONGINT` variable.

| Syntax | NASM |
|--------|------|
| `ES:BX := longvar;` | `les bx, [longvar]` |
| `DS:BX := longvar;` | `lds bx, [longvar]` |
| `DS:SI := longvar;` | `lds si, [longvar]` |
| `ES:DI := longvar;` | `les di, [longvar]` |
| `DX:AX := longvar;` | `mov ax, [longvar]` / `mov dx, [longvar+2]` |
| `ES:DI := DX:AX;` | `MOV DI,AX`/`MOV ES,DX` |
| `longvar := ES:BX;` | `mov [longvar], bx` / `mov [longvar+2], es` |
| etc. | … |

The compiler uses `les`/`lds` when possible, which are more efficient.

```ob2
xmsApiEntry := ES:BX;
```

↓

```nasm
mov  [xmsApiEntry], bx
mov  [xmsApiEntry+2], es
```

```ob2
ES:BX := xmsApiEntry;
```

↓

```nasm
les  bx, [xmsApiEntry]
```

```ob2
ES:BX := myfunction()
```

↓

```nasm
call myfunction
mov  bx, ax
mov  es, dx
```

... and vice versa!

---

## 12. Inline Assembly

A block `ASM ... END` is copied verbatim into the output. It must respect NASM syntax. Labels inside are local to the procedure.

```ob2
ASM
  cld
  rep stosb
END
```

↓

```nasm
cld
rep stosb
```

---

## 13. Complete Example with Record Types

The following excerpt shows the declaration of a record type and its use with structured memory access.

### Type declaration (module level)

```ob2
TYPE
  StructXmsRec = RECORD
    len      : LONGINT;
    src_hnd  : INTEGER;
    src_ofs  : LONGINT;
    dst_hnd  : INTEGER;
    dst_ofs  : LONGINT;
    src_high : BYTE;
    dst_high : BYTE
  END;
```

↓

```nasm
struc StructXmsRec
    .len:      resd 1
    .src_hnd:  resw 1
    .src_ofs:  resd 1
    .dst_hnd:  resw 1
    .dst_ofs:  resd 1
    .src_high: resb 1
    .dst_high: resb 1
endstruc
```

### Access in code

```ob2
PROCEDURE xmsCopy(lenl, lenh, srcHnd, srcl, srch, dstHnd, dstl, dsth: INTEGER); NEAR;
USES DS, SI, CX;
VAR
  tmpLen, tmpSrc, tmpDst: LONGINT;
BEGIN
  XMS_CLEAR_REC;
  DS := CS;
  SI := ADR(xmsRec);
  tmpLen := lenl + (lenh * 65536);
  tmpSrc := srcl + (srch * 65536);
  tmpDst := dstl + (dsth * 65536);
  DX:AX := tmpLen;   [DS:SI].StructXmsRec.len     := DX:AX;
  DX:AX := tmpSrc;   [DS:SI].StructXmsRec.src_ofs := DX:AX;
  DX:AX := tmpDst;   [DS:SI].StructXmsRec.dst_ofs := DX:AX;
  [DS:SI].StructXmsRec.src_hnd := srcHnd;
  [DS:SI].StructXmsRec.dst_hnd := dstHnd;
  XMS(XMS_API_COPY)
END xmsCopy;
```

↓

```nasm
xmsCopy:
    push bp
    mov  bp, sp
    push ds
    push si
    push cx
    sub  sp, 12       ; local LONGINT variables (3*4 bytes)
    ; ... (XMS_CLEAR_REC call, etc.)
    mov  ds, cs
    mov  si, xmsRec   ; ADR(xmsRec) = offset xmsRec
    ; tmpLen ...
    ; DX:AX := tmpLen
    mov  ax, [bp-4]
    mov  dx, [bp-2]
    mov  [ds:si + StructXmsRec.len], ax
    mov  [ds:si + StructXmsRec.len + 2], dx
    ; etc.
    ...
    call XMS
    ; epilogue
    add  sp, 12
    pop  cx
    pop  si
    pop  ds
    mov  sp, bp
    pop  bp
    ret  16           ; 8 params * 2 bytes
```

The structured access `[DS:SI].StructXmsRec.len` elegantly maps to a NASM expression using the structure field offset.

---

## 14. Compiler Notes

- All numeric literals are evaluated as 16‑bit unless cast by context. **Not implemented:** an `L` suffix marking a literal LONGINT (`SRC/TASM/SPHO.MOD` has no such suffix anywhere) — a LONGINT value is only ever produced by a LONGINT-typed VAR/expression, never a literal written directly as one.
- The compiler should infer the type of expressions from the target register or variable.
- `WORD` and `INTEGER` are the same size (16-bit) and interchangeable everywhere a type is merely checked for compatibility, but are **not** identical: `WORD` is unsigned, `INTEGER` is signed, and this affects codegen for comparisons (`<`,`>`,`<=`,`>=`) and `*`/`DIV`/`MOD` — see §7's own "Signedness: WORD vs INTEGER" subsection.
- Code generation must respect the 64‑KB segment limits; no relocation is performed.
- The resulting NASM file is assembled by this project's own `TASM.EXE` (`DOCS/TASM.MD`) into a RDOFF2 `.RDF`, then linked (`toc.exe`'s embedded linker, or `TLINK.EXE`'s `/T=com`/`/T=exe`/etc., `DOCS/BUILD.MD`) into a `.COM`/`.EXE` — not a generic `nasm -f bin`/`nasm -f obj` invocation.
- Global type declarations produce `struc` definitions that are visible throughout the module; field offsets are accessed using the `RecordType.fieldName` notation in NASM expressions.

