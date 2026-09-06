{$I FLAGS.INC}
{ TYPES: the recorded-operation data layer split out of SPHO.PAS --
  the mnemonic constants (Mn*), the operation-kind constants (TOpLabel/
  TOpInstr/TOpAsm), and TOperation/TOpChunk/POpChunk themselves. Pure
  data + one text-lookup function (MnemonicText); no parsing, no
  chunk-list append/walk logic -- SPHO.PAS still owns NewOpSlot/
  AppendLabelOp/AppendInstr0/1/2/SerializeOne/SerializeOps and every
  Mn*-producing helper (RelJumps, AddSubMnemonic, etc), all of which
  stay in SPHO.PAS since they're translator LOGIC, not the data shape
  itself. Split out specifically so the mnemonic-constant/TOperation
  data shape (SPHO.PAS's own "mnemonic:WORD... allow do peephole
  optimizations" redesign) has one place to live independent of the
  parser/emitter that currently produces it -- a future standalone
  peephole pass over the finished operation list can `uses Types`
  without pulling in all of SPHO.PAS's own parsing machinery. }
unit Types;

interface

uses StrTab;

const
  Chunk = 64;   { same chunk-array size SPHO.PAS's own other chunked
                    lists (LitChunk/PendingChunk/etc) use -- duplicated
                    here rather than shared bidirectionally with
                    SPHO.PAS's own Chunk constant, since a unit lower
                    in the dependency chain (this one) can't reference
                    a constant defined in a unit that uses it. }

  { TOperation.kind -- SOPLAN.MD's own Phase 3, a typed translation-
    operation layer decoupling parsing from irreversible assembly-text
    emission. Every real Emits.* call site in SPHO.PAS reduces to
    exactly one of these three structural shapes (verified against
    every call site, not assumed): TOpLabel/TOpInstr/TOpAsm below
    collapse SOPLAN's own 6 named kinds (label, instruction, jump,
    call, inline-assembly line, declaration) into the 3 shapes that
    actually differ in TEXT FORM -- a jump/call is just a TOpInstr
    whose mnemonic happens to be jCC/jmp/call/call-far, not a
    structurally different record shape; inline-ASM-block text and a
    struc/global/extern declaration are both "write this line
    verbatim," the same TOpAsm shape. }
  TOpLabel = 0;  { a jump-target definition: "name:" or ".L<N>:" }
  TOpInstr = 1;  { any instruction line, 0-2 operands, incl. jumps/calls }
  TOpAsm   = 2;  { one raw, verbatim line }

  { Mnemonic constants: TOpInstr's own mnemonic field is a WORD constant
    from this table, not interned text -- every distinct mnemonic
    SPHO.PAS ever emits (found by enumerating every AppendInstr0/1/2/
    Ref call site, including every computed one: RelJumps/
    RelJumpsUnsigned/FlagJumps' own jt/jf out-params, AddSubMnemonic's
    inc->add/dec->sub mapping, LesLdsInstr's own seg->les/lds mapping,
    EmitMulDiv's own mul/imul/div/idiv choice, ParseProcedure's own
    retn/retf epilogue choice). A real, comparable constant (instead of
    StrTab-interned mnemonic TEXT) is what makes a later peephole pass
    possible at all -- comparing "is this a MOV" by integer instead of
    by string content/StrTab id equality, and (MnNop below) being able
    to delete an already-appended operation in place by overwriting its
    own mnemonic, without needing to splice/shift the chunked opHead
    list itself. MnemonicText (below) is the only place that maps a
    constant back to its own NASM text, once, at final serialization --
    every other reader compares the WORD directly. }
  MnNop     = 0;   { a deleted/no-op operation -- SerializeOne skips a
                       TOpInstr entirely when its mnemonic is MnNop, so
                       a future peephole pass can "remove" an operation
                       already appended to the list by overwriting its
                       mnemonic to MnNop in place, with no list-splice
                       needed. Never itself passed to AppendInstr0/1/2
                       by any parser code today -- only ever written by
                       a later optimization pass patching an existing
                       operation, the same "patch in place" mechanism
                       CheckPendingCalls/PatchCondRef already use. }
  MnMov     = 1;  MnAdd     = 2;  MnSub    = 3;  MnCmp   = 4;
  MnTest    = 5;  MnXor     = 6;  MnOr     = 7;  MnAnd   = 8;
  MnShl     = 9;  MnShr     = 10; MnNeg    = 11; MnLea   = 12;
  MnPush    = 13; MnPop     = 14; MnPushf  = 15; MnPopf  = 16;
  MnCwd     = 17; MnInt     = 18; MnIret   = 19;
  MnInc     = 20; MnDec     = 21;
  MnMul     = 22; MnImul    = 23; MnDiv    = 24; MnIdiv  = 25;
  MnLes     = 26; MnLds     = 27;
  MnRetn    = 28; MnRetf    = 29; MnCall   = 30; MnCallFar = 31;
  MnJmp     = 32;
  { Jcc: conditional jumps, RelJumps/RelJumpsUnsigned/FlagJumps' own
    jt/jf out-params (mnemonic TEXT before this redesign: 'je'/'jne'/
    ...) are one of these constants instead. }
  MnJe = 33; MnJne = 34; MnJl  = 35; MnJge = 36; MnJg  = 37; MnJle = 38;
  MnJb = 39; MnJae = 40; MnJa  = 41; MnJbe = 42; MnJc  = 43; MnJnc = 44;
  MnJz = 45; MnJnz = 46;

type
  { TOperation: one recorded emission, appended in the exact order
    Spho.pas used to WRITE it directly (Phase 3 item 5: "preserve the
    existing source-order section behavior... decoupling, not output
    reorganization"). Not a variant/tagged-union record -- a flat
    layout was chosen over a TP7 `case` variant record (which would save
    bytes, kind-specific fields sharing storage) because this project's
    own file-wide range-checking-disabled directive means a wrong-
    variant field access would be a silent bug, not a caught one, which
    a flat record with merely-sometimes-empty fields avoids entirely.

    **Heap-exhaustion fix (post-Phase-8)**: the operand fields were
    originally `string[80]` (81 bytes each) and this record also
    carried a write-only `fname: string[128]`/`line: integer` pair
    (SOPLAN's own "keep source file/line information... for a LATER
    phase's own diagnostics" -- never actually consulted by anything;
    confirmed via a direct grep, zero readers, before removing them) --
    together ~377 bytes per operation, and a large real-world program
    (not just the small TESTS/ fixtures) can accumulate thousands of
    operations across one translation, exhausting TP7's own 655KB max
    heap (Runtime error 203, reproduced directly translating
    EXAMPLES/LZSS/LZP.SMD and EXAMPLES/CRK/APPLYCRK.SMD -- DOCS/SPHO.MD's
    own "Known issues" entry has the full investigation). Fixed by (1)
    deleting fname/line entirely (pure dead-weight removal, zero
    behavior risk) and (2) interning every operand through StrTab
    (already used for literal/identifier dedup elsewhere) instead of
    storing each string inline -- mnemonics/register names/short
    operand text repeat constantly across a real translation (`mov`/
    `ax`/`push`/... appear thousands of times each), so StrTab's own
    content-dedup collapses the effective per-operation cost from 243
    bytes to 6 (three `TStrTabId` = word). SPHO.PAS's own AppendOp (now
    NewOpSlot plus the Append* wrappers) still takes plain `string`
    operand parameters -- interning happens inside it, via
    `StrTab.Put`, invisible to all ~130 `Append*` call sites; only
    SerializeOne (the one reader) resolves each id back via
    `StrTab.Get` immediately before calling `Emits.*`.

    mnemonic:WORD redesign (post-heap-fix): TOpInstr's own mnemonic is
    a WORD (one of the Mn* constants above), not StrTab-interned text
    -- a real, directly-comparable value instead of interned text/
    StrTab-id equality, which is what makes a later peephole
    optimization pass over the finished operation list possible in the
    first place (find "is this a MnPush immediately followed by a
    MnPop of the same register" by comparing WORDs, not re-resolving/
    re-comparing text). op1/op2 are StrTab-interned operand text,
    unchanged in meaning from before this redesign. labelId is a
    dedicated field for TOpLabel's own label text -- not overloaded
    onto the same slot mnemonic occupies, since a TOpLabel operation
    was never really "a mnemonic" at all. TOpAsm's own raw verbatim
    line text lives in op1 (mnemonic is meaningless for TOpAsm; op2
    stays unused/0 for it, same "harmlessly unused for this kind"
    shape sect/etc already have elsewhere in this record). }
  TOperation = record
    kind: byte;          { TOpLabel/TOpInstr/TOpAsm }
    needTab: boolean;    { TOpAsm only: Emits.Emit's own needtab param }
    mnemonic: word;       { TOpInstr only: one of the Mn* constants
                            above (MnNop is a deleted/no-op operation,
                            skipped entirely by SerializeOne -- see
                            MnNop's own comment). Meaningless (left 0/
                            MnNop, harmlessly) for TOpLabel/TOpAsm. }
    labelId: StrTab.TStrTabId;  { TOpLabel only: BARE label name (no
                            trailing ':'), StrTab-interned -- SPHO.PAS's
                            own SerializeOne appends ':' once, only at
                            final emission, so a peephole pass can
                            compare a TOpLabel's own labelId directly
                            against a jump operation's own op1 text
                            (also always the bare LabelName(n) form,
                            never ':'-terminated) without either side
                            needing to strip/append a colon first.
                            Meaningless (left 0) for TOpInstr/TOpAsm. }
    op1, op2: StrTab.TStrTabId;  { StrTab-interned text, not inline
                            (see this record's own header comment for
                            the heap-exhaustion fix this replaced).
                            TOpInstr: operand 1/2 (op1=0 if 0-operand,
                            op2=0 if <=1-operand -- SerializeOne infers
                            shape from which of op1/op2 is a real id vs.
                            0/"no string" (StrTab's own id-0
                            convention), matching every current call
                            site, none of which ever passes a genuinely
                            empty operand string).
                            TOpAsm: op1 = the raw line text verbatim,
                            op2 unused. TOpLabel: both unused. }
    sect: byte;          { SectData/SectBss/SectCode/SectStruc (SPHO.PAS's
                            own Sect* constants -- still defined there,
                            not here, since section handling is
                            SPHO.PAS's own concern, not this record's):
                            the section this operation belongs in, per
                            comp.curSect at append time (SOPLAN.MD's own
                            Phase 4 -- SerializeOps groups by this field
                            into one consolidated block per section,
                            instead of walking the list in plain append
                            order). Meaningless (but harmlessly set) for
                            an operation appended before EnsureSection
                            ever ran -- none exist in practice, since
                            ParseModule's own top-level EnsureSection
                            (SectCode) call runs before any declaration
                            is parsed. }
  end;

  POpChunk = ^TOpChunk;
  TOpChunk = record
    ops:   array[1..Chunk] of TOperation;
    count: integer;
    next:  POpChunk
  end;

{ MnemonicText: the one place a Mn* constant is ever turned back into
  its own NASM text -- everywhere else (comparisons, patching) works on
  the WORD constant directly (this unit's own header comment on why:
  this is what a peephole pass needs). Called exactly once per
  TOpInstr, by SPHO.PAS's own SerializeOne, at final serialization.
  MnNop is never passed here in practice -- SerializeOne skips a MnNop
  operation before this could ever run. }
function MnemonicText(mn: word): string;

implementation

function MnemonicText(mn: word): string;
begin
  case mn of
    MnMov:  MnemonicText := 'MOV';  MnAdd:  MnemonicText := 'ADD';
    MnSub:  MnemonicText := 'SUB';  MnCmp:  MnemonicText := 'CMP';
    MnTest: MnemonicText := 'TEST'; MnXor:  MnemonicText := 'XOR';
    MnOr:   MnemonicText := 'OR';   MnAnd:  MnemonicText := 'AND';
    MnShl:  MnemonicText := 'SHL';  MnShr:  MnemonicText := 'SHR';
    MnNeg:  MnemonicText := 'NEG';  MnLea:  MnemonicText := 'LEA';
    MnPush: MnemonicText := 'PUSH'; MnPop:  MnemonicText := 'POP';
    MnPushf: MnemonicText := 'PUSHF'; MnPopf: MnemonicText := 'POPF';
    MnCwd:  MnemonicText := 'CWD';  MnInt:  MnemonicText := 'INT';
    MnIret: MnemonicText := 'IRET';
    MnInc:  MnemonicText := 'INC';  MnDec:  MnemonicText := 'DEC';
    MnMul:  MnemonicText := 'MUL';  MnImul: MnemonicText := 'IMUL';
    MnDiv:  MnemonicText := 'DIV';  MnIdiv: MnemonicText := 'IDIV';
    MnLes:  MnemonicText := 'LES';  MnLds:  MnemonicText := 'LDS';
    MnRetn: MnemonicText := 'RETN'; MnRetf: MnemonicText := 'RETF';
    MnCall: MnemonicText := 'CALL'; MnCallFar: MnemonicText := 'CALL FAR';
    MnJmp:  MnemonicText := 'JMP';
    MnJe:  MnemonicText := 'JE';  MnJne: MnemonicText := 'JNE';
    MnJl:  MnemonicText := 'JL';  MnJge: MnemonicText := 'JGE';
    MnJg:  MnemonicText := 'JG';  MnJle: MnemonicText := 'JLE';
    MnJb:  MnemonicText := 'JB';  MnJae: MnemonicText := 'JAE';
    MnJa:  MnemonicText := 'JA';  MnJbe: MnemonicText := 'JBE';
    MnJc:  MnemonicText := 'JC';  MnJnc: MnemonicText := 'JNC';
    MnJz:  MnemonicText := 'JZ';  MnJnz: MnemonicText := 'JNZ';
    else MnemonicText := ''   { MnNop, or an out-of-range value --
                                  SerializeOne's own MnNop skip means
                                  this branch is never actually reached
                                  by MnNop in practice either way. }
  end
end;

end.
