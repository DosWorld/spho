{$I FLAGS.INC}
{$M 32000,256000,655000}
{
  spho -- SPHINX Oberon dialect translator: SRCFILE.SMD -> SRCFILE.ASM
  (NASM-subset, feed into TASM.EXE). Single recursive-descent pass, no
  AST: each Parse* procedure both parses its construct and emits its
  NASM text before returning. Full design notes: DOCS/SPHO.MD.

  The lexical layer is split across two units: character-level scanning,
  the raw token buffer, and the sticky `ok` failure flag live in unit
  Scan, and are called directly from here (Scan.CurTok*(),
  Scan.Ok/SetOk, Scan.ReportError, ...), never as a bare field.
  The unified lexeme table and TYPE/PROCEDURE/CONST/VAR detail tables
  (plus Next, the token-fetch entry point, and OpenInclude/CloseInclude,
  which need Next to prime the included file's first token) live in unit
  SymTab, layered on top of Scan.
}
program Spho;

uses
  SymTab, Regs86, Scan, LogErr, StrTab, LexTab, Util, Emits, Types, PHOpt, RecTypes, ShdWrt, GlobVar;

const
  ExitOk = 0; ExitUsage = 2; ExitIo = 3; ExitAsm = 4;

  MaxLine = Scan.MaxStrLit;
  MaxName = Scan.MaxName;

  TEof = Scan.TEof; TIdent = Scan.TIdent; TNum = Scan.TNum;
  TStr = Scan.TStr; TSym = Scan.TSym; TChar = Scan.TChar;

  TyByte = SymTab.TyByte; TyBool = SymTab.TyBool; TyWord = SymTab.TyWord;
  TyInt = SymTab.TyInt; TyLong = SymTab.TyLong; TyRec = SymTab.TyRec;

  SymVar = SymTab.SymVar; SymConst = SymTab.SymConst;

  MaxFields = SymTab.MaxFields; MaxParams = SymTab.MaxParams; MaxUses = SymTab.MaxUses;
  { MaxVarNames: cap on a single comma-separated 'VAR a,b,c : T;' name
    group, matching MaxParams/MaxUses' own bounds-checked-array pattern. }
  MaxVarNames = 64;

  Chunk = 64;

  { MaxArrayLit: the largest BASE64()/FILE() decoded byte count this
    translator will accept. Not a full 64K real-mode segment, since a
    FULL 65536-byte .data blob has no representable length at all in a
    16-bit WORD (DOCS/SPHINX.MD S3.1) -- Util.B64Init/StreamFileBytes
    both take their own maxLen as a WORD (0..65535), matching this
    project's own real-mode-target byte-count convention, so 65535 is
    the true largest value either can accept. Both BASE64() and FILE()
    now stream their "db" output straight to outF as bytes are
    decoded/read (Util.B64Feed/B64Flush, Util.StreamFileBytes) rather
    than buffering the whole decoded blob first -- MaxArrayLit is still
    the ceiling enforced against outLen while streaming. }
  MaxArrayLit = 65535;

  { global VAR section: an initialized declaration ("= value") belongs in
    .data; every uninitialized global -- a plain scalar, an array, or a
    RECORD instance -- is zero-filled reserved space and must be in .bss.
    SectCode is .text, where every PROCEDURE body belongs. SectStruc is
    not a real NASM section at all -- struc/endstruc (RECORD type
    layouts, ParseRecordType) are section-agnostic TASM directives, but
    still tagged with their own pseudo-section here (SOPLAN.MD's own
    Phase 4: "emit struc definitions, .data, .bss, and .text ... one
    consolidated block per section") so SerializeOps can group every
    struc/endstruc block together, ahead of every real section, instead
    of interleaved wherever a TYPE ... = RECORD happened to appear in
    the source. SectNone (-1) is not a real section id either, only
    EnsureSection's "nothing emitted yet" sentinel. }
  SectNone = -1; SectData = 0; SectBss = 1; SectCode = 2; SectStruc = 3;

  { TOpLabel/TOpInstr/TOpAsm (operation kind) and every Mn* mnemonic
    constant now live in unit Types (SRC/TYPES.PAS), alongside
    TOperation/TOpChunk/POpChunk themselves -- see that unit's own
    header comment for why they were split out. Used here unqualified
    via the `uses ... Types` clause above. }

type
  RegList = SymTab.RegList;

  { LitChunk: every distinct string literal seen so far, in first-
    occurrence order. StrTab.Put/Find already dedups by exact content,
    so EmitStringLiteral only appends an id here the first time it's
    seen. }
  PLitChunk = ^TLitChunk;
  TLitChunk = record
    id:    array[1..Chunk] of StrTab.TStrTabId;
    count: integer;
    next:  PLitChunk
  end;

  { TOperation/TOpChunk/POpChunk now live in unit Types (SRC/TYPES.PAS)
    -- see that unit's own header comment for why. Used here
    unqualified via the `uses ... Types` clause above. }

  { PendingChunk: every call site emitted against a procedure name not
    yet resolvable at the time of the call, in first-occurrence order.
    CheckPendingCalls re-resolves each recorded name once the whole
    module (and every file it IMPORTs) has been fully parsed -- opChunk/
    opSlot locate the TOpInstr operation EmitCall/EmitCallNoArgs already
    appended with a guessed 'call far' mnemonic, so CheckPendingCalls can
    patch that operation's mnemonic in place (SOPLAN.MD's own Phase 5:
    a same-module forward call no longer requires FORWARD). }
  PPendingChunk = ^TPendingChunk;
  TPendingChunk = record
    id:      array[1..Chunk] of StrTab.TStrTabId;
    line:    array[1..Chunk] of integer;
    fname:   array[1..Chunk] of StrTab.TStrTabId; { Scan.SrcPath's own value at append
                                                     time (a source/include filesystem
                                                     path), StrTab-interned rather than
                                                     stored inline as string[128] -- same
                                                     heap-saving fix TOperation's own a/b/c
                                                     fields got (see that record's own
                                                     header comment); PendingAppend fires
                                                     rarely (only for a genuinely
                                                     unresolved same-module forward call,
                                                     not per emitted operation), so this one
                                                     was never itself the heap-exhaustion
                                                     culprit, but the same waste is the same
                                                     waste -- StrTab.Put is never empty here
                                                     (Scan.SrcPath always names a real file),
                                                     so no InternOrZero guard is needed the
                                                     way TOperation's own operand text did. }
    opChunk: array[1..Chunk] of POpChunk;
    opSlot:  array[1..Chunk] of integer;
    count:   integer;
    next:    PPendingChunk
  end;

  { POptRangeChunk/TOptRangeChunk: OPT.TXT's own R6 finding ("this needs
    a post-parse optimization phase... because the current immediate
    per-procedure pass cannot see later callers") -- one entry per
    PROCEDURE body, recorded by ParseProcedure INSTEAD OF calling
    PHOpt.Optimize immediately the way every earlier version of this
    file did. Same chunked-list shape/convention as TPendingChunk just
    above (one append per PROCEDURE parsed, never per operation, so
    this list stays small regardless of how large any one procedure's
    own body is). OptimizeAllDeferred (below) walks this list exactly
    once, after CheckPendingCalls has resolved every pending call site
    (RunBody's own call order) -- only then does every TOperation's own
    callProcId (Types.TOperation, set by EmitCall/EmitCallNoArgs) refer
    to a stable, fully-resolved callee, letting PHOpt.PAS's own
    deferred call-graph analysis build a sound per-procedure output-
    demand fact before any individual procedure's own Optimize call
    actually runs. }
  POptRangeChunk = ^TOptRangeChunk;
  TOptRangeChunk = record
    procId:     array[1..Chunk] of integer;    { SymTab's own `pi` --
                                                   PHOpt.PAS's own call-
                                                   graph analysis keys its
                                                   per-procedure demand
                                                   facts by this same id,
                                                   the one callProcId
                                                   stamps at each call
                                                   site (see that field's
                                                   own comment, Types.
                                                   TOperation). }
    startChunk: array[1..Chunk] of POpChunk;
    startSlot:  array[1..Chunk] of integer;
    endChunk:   array[1..Chunk] of POpChunk;
    endSlot:    array[1..Chunk] of integer;
    level:      array[1..Chunk] of integer;
    count:      integer;
    next:       POptRangeChunk
  end;

  { TCompilation: state that lives for the whole run (SOPLAN.MD's own
    Phase 2 -- an explicit compilation-state record instead of bare
    globals). One instance ever exists (comp, below) -- Spho.pas runs a
    single compile per process, so this is grouped as a record for
    discoverability, not var-parameter-threaded through every Parse*/
    Emit*/Try* call: with ~130 such routines calling each other in a
    deep, mutually-recursive web (many forward-declared specifically
    for that reason), threading a var parameter through every one of
    those signatures would be a large, high-risk mechanical rewrite for
    no behavior change and no real reentrancy this process ever needs
    -- see SRC/PHASE2_DESIGN.md for the full reasoning, kept here only
    as a pointer since that file is scratch/deletable once Phase 2
    lands.
    loopExitStack/loopContStack/loopDepth live here, not in
    TProcedureContext below, despite looking like "this procedure's own
    loops" -- loopDepth is set to -1 exactly once, at the very start of
    RunBody, and ParseWhile only ever Inc/Dec's it in a matched pair
    around ParseStmtList, so it's naturally correct across procedure
    boundaries without ever needing a per-procedure reset -- genuinely
    compilation-scoped, not state that gets thrown away and rebuilt per
    procedure the way TProcedureContext's own fields do.
    opHead/opTail/nOps (Phase 3): the whole run's own recorded
    operation list, in append order -- same chunked-list shape as
    litHead/pendingHead above, grouped here rather than a separate
    record since there's no per-procedure scope to it either (an
    operation appended inside one procedure's own body is exactly as
    "whole-run" as one appended at top level -- SerializeOps walks the
    combined list once, at the very end, uninterested in which
    procedure any given operation came from). }
  TCompilation = record
    litHead, litTail: PLitChunk;
    nLits: integer;
    pendingHead, pendingTail: PPendingChunk;
    curSect: integer;
    loopExitStack: array[0..63] of word;
    loopContStack: array[0..63] of word;
    loopDepth: integer;
    opHead, opTail: POpChunk;
    nOps: integer;
    optRangeHead, optRangeTail: POptRangeChunk;   { OPT.TXT's own R6
                                                      finding -- see
                                                      TOptRangeChunk's
                                                      own comment above. }
  end;

  { TProcedureContext: the CURRENT procedure's own parse state, reset at
    the top of ParseProcedure (mirroring today's own labelCnt := 0/
    frameOfs := 0/procRetTy := TyWord reset lines, unchanged by this
    move) and meaningless outside one procedure's own parse -- see
    TCompilation's own comment above for why this is a record grouping,
    not a var-threaded parameter. }
  TProcedureContext = record
    procRetTy: integer;
    hasRetTy: boolean;
    frameOfs: integer;
    labelCnt: word;
  end;

var
  es: Emits.TEmitState;
  comp: TCompilation;
  ctx: TProcedureContext;

  { optRanges/optConservative: OPT.TXT's own R6 finding -- unit-level
    (not a local inside OptimizeAllDeferred) purely to avoid a large
    automatic array on the stack, same caution OPT.TXT's own R4
    resolution text already named ("not additional large automatic
    arrays") applied here to a NEW large array rather than the Stage D
    ones that finding was originally about. Sized to PHOpt.MaxProcs
    (512 -- see that constant's own header comment, PHOPT.PAS, for why
    this is a real MEASURED bound against this translator's own largest
    example, not SymTab's own much larger theoretical structural cap;
    TProcRange/TProcDemand/a plain boolean array all sized to SymTab's
    own real 4096 cap overflowed TP7's own 64KB data segment outright,
    confirmed directly, "Error 49: Data segment too large") --
    optRanges holds strictly fewer entries in practice (one per
    recorded OptRangeAppend call, i.e. one per PROCEDURE actually
    optimized at -O1/-O2, never more than SymTab.ProcCount itself),
    optConservative is genuinely indexed 1:1 by procId up to
    SymTab.ProcCount. }
  optRanges: array[0..PHOpt.MaxProcs-1] of PHOpt.TProcRange;
  optConservative: array[0..PHOpt.MaxProcs-1] of boolean;

  { optLevel: OPT.TXT's own "FIRST PREREQUISITE: COMMAND-LINE
    OPTIMIZATION LEVELS" -- 0/1/2 for -O0/-O1/-O2, parsed once by
    ParseOptLevel (RunBody's own first real step) from the raw
    ParamStr(1..ParamCount) list, defaulting to 1 when no -O flag is
    given at all ("by default (if parameter missed) use -O1"). Read
    by ParseProcedure's own PHOpt.Optimize call site: 0 skips the call
    entirely; 1/2 both call it (Stage A's own correctness repairs live
    inside PHOpt.Optimize itself, unconditionally -- they are bug
    fixes to existing rules, not new rewrites, so both levels get them
    for free per OPT.TXT's own "-O1 ... with the Stage A correctness
    repairs"); -O2 is accepted but currently behaves identically to -O1
    (Stages B onward, which would give -O2 real additional rewrites,
    are not implemented yet -- OPT.TXT's own explicit stage-by-stage
    order, "Finish and verify each stage before enabling its
    dependents"). }
  optLevel: integer;

  { nextGenSaveId: OPT.TXT's own Stage C "generated-save-pair identity"
    metadata (Stage B's own intro: "Add emitter metadata only where
    needed... generated save-pair identity... Capture it while symbols
    exist"). A plain, never-reset, monotonically increasing counter --
    0 means "not a compiler-generated scratch save" (TOperation's own
    genSaveId field default, set by NewOpSlot), any nonzero value is
    unique across the WHOLE translation (not just one procedure), so
    two independent save/restore pairs can never be mistaken for the
    same one even if PHOpt.PAS's own C1/C2/C3 matchers someday need to
    compare ids across chunk boundaries. Incremented once per NEW
    save/restore pair claimed (EmitGenSave below), never per operation
    -- both the PUSH and its matching POP share the SAME id. }
  nextGenSaveId: word;

  { topModName: the top-level file's own 'MODULE Name;' spelling --
    captured by ParseModule(isTop=TRUE) only (an IMPORTed file's own
    module name is irrelevant here), read back by RunBody after
    parsing to title EmitSHD's own 'MODULE Name;'/'END Name.' lines.
    Not validated against anything (ParseModule never checks it
    against the source filename or the trailing 'END Name.', a pre-
    existing simplification, not something this addition changes). }
  topModName: string;

  { topHasBegin: TRUE iff the top-level file has its own BEGIN...END
    init part (a real 'start' entry point, DOCS/SPHINX.MD's own "only
    the top-level file may hold the program's entry point") -- such a
    file is a standalone program, not an importable library, so
    RunBody skips EmitSHD for it entirely. }
  topHasBegin: boolean;

  { lastOperandWasIntReg: side-channel set ONLY by OperandText's own
    bare-register branch, TRUE iff that register operand was just
    followed by an explicit ".INTEGER" cast (DOCS/SPHINX.MD's new
    REG.INTEGER/REG.WORD section) -- FALSE for ".WORD", no cast at all,
    or any non-register operand. OperandText's own signature (a single
    `var dst: string` result) is unchanged everywhere else in this file
    to avoid touching its many call sites; a caller that cares about
    signedness (EmitCondJump, EmitMulDiv) reads this flag immediately
    after its own OperandText call for a register operand, mirroring
    how TryEmitOdd/TryBuiltinOperand already hand results back through
    `dst` rather than widening OperandText's own signature. Single-pass
    translator, no reentrancy into OperandText mid-resolution, so one
    shared flag is always safe. }
  lastOperandWasIntReg: boolean;

{ ---------- forward declarations (mirrors the Oberon FORWARD chain) ---------- }

procedure ParseStmtList; forward;
procedure EmitCall(const name: string); forward;
function TryParseRegPair(var seg, offReg, consumedReg: string): boolean; forward;
procedure LoadIfMem(const opnd, scratchReg: string; isByteVar, needWord: boolean; var dst: string); forward;
{ far: passed as a procedural value to RecTypes.ParseTypeSection/
  ParseRecordType, see Emit/Emit2/EnsureSection's own far comment above
  for why. }
function ParseArrayBound: integer; far; forward;
procedure EmitAdrOperand(const arg: string; si: integer; var dst: string); forward;
procedure OperandText(var dst: string); forward;
function PeekOperandIsByte(const nm: string): boolean; forward;
function PeekVarIsInt(const nm: string): boolean; forward;

{ CheckPendingCalls: called once, after the whole top-level file (and
  every file it IMPORTs) has been fully parsed. Every entry PendingAppend
  ever recorded is a call site where EmitCall/EmitCallNoArgs could not
  resolve the target's real NEAR/FAR-ness at the time and appended a
  guessed 'call far' operation -- by now the whole module has been
  parsed, so SymTab.ProcFindIsFar can resolve a genuine same-module
  forward call (SOPLAN.MD's own Phase 5: FORWARD is no longer required
  for this case) and this patches that operation's mnemonic in place if
  the guess was wrong. A name that STILL doesn't resolve (truly
  undefined, never declared anywhere in the module) is a hard translator
  error, same diagnostic text as before. }
procedure CheckPendingCalls;
  var pc: PPendingChunk; k: integer; nm, msg, fn: string; isFar: boolean; op: POpChunk; slot: integer;
begin
  pc := comp.pendingHead;
  while pc <> nil do begin
    k := 1;
    while k <= pc^.count do begin
      StrTab.Get(pc^.id[k], nm);
      if SymTab.ProcFindIsFar(nm, isFar) then begin
        op := pc^.opChunk[k]; slot := pc^.opSlot[k];
        if isFar then op^.ops[slot].mnemonic := MnCallFar else op^.ops[slot].mnemonic := MnCall
      end else begin
        msg := 'call to undefined procedure ''' + nm + '''';
        StrTab.Get(pc^.fname[k], fn);
        LogErr.ErrorInFile(fn, longint(pc^.line[k]), msg); Scan.SetOk(false)
      end;
      Inc(k)
    end;
    pc := pc^.next
  end
end;

{ LitLabelName: NASM label text for the n-th distinct string literal
  (0-based, in first-occurrence order). }
function LitLabelName(n: integer): string;
begin LitLabelName := '_literal' + IntStr(n) end;

{ LitIndexOf: 0-based slot index of id within litHead's own list, or -1
  if id was never appended. }
function LitIndexOf(id: StrTab.TStrTabId): integer;
  var c: PLitChunk; i, k: integer;
begin
  c := comp.litHead; i := 0;
  while c <> nil do begin
    k := 1;
    while k <= c^.count do begin
      if c^.id[k] = id then begin LitIndexOf := i; exit end;
      Inc(k); Inc(i)
    end;
    c := c^.next
  end;
  LitIndexOf := -1
end;

{ LitAppend: record a newly-seen literal's StrTab id at the end of the
  list, returning its 0-based slot index (== its label's own number). }
function LitAppend(id: StrTab.TStrTabId): integer;
  var last: PLitChunk; k: integer;
begin
  if (comp.litTail = nil) or (comp.litTail^.count >= Chunk) then begin
    New(last);
    last^.count := 0; last^.next := nil;
    if comp.litHead = nil then comp.litHead := last else comp.litTail^.next := last;
    comp.litTail := last
  end;
  Inc(comp.nLits);
  last := comp.litTail;
  k := last^.count + 1;
  last^.id[k] := id;
  last^.count := k;
  LitAppend := comp.nLits - 1
end;

{ PendingAppend: record a call site's target name (as an already-
  interned StrTab id), source line, source filename, and a reference to
  the TOpInstr operation already appended for this call (guessed 'call
  far', per EmitCall/EmitCallNoArgs), for CheckPendingCalls to re-
  resolve and patch once the whole file has been parsed. }
procedure PendingAppend(id: StrTab.TStrTabId; ln: integer; opChunk: POpChunk; opSlot: integer);
  var last: PPendingChunk; k: integer; sp: string;
begin
  if (comp.pendingTail = nil) or (comp.pendingTail^.count >= Chunk) then begin
    New(last);
    last^.count := 0; last^.next := nil;
    if comp.pendingHead = nil then comp.pendingHead := last else comp.pendingTail^.next := last;
    comp.pendingTail := last
  end;
  last := comp.pendingTail;
  k := last^.count + 1;
  Scan.SrcPath(sp);
  last^.id[k] := id; last^.line[k] := ln; last^.fname[k] := StrTab.Put(sp);
  last^.opChunk[k] := opChunk; last^.opSlot[k] := opSlot;
  last^.count := k
end;

{ OptRangeAppend: OPT.TXT's own R6 finding -- record ONE procedure
  body's own [startChunk,startSlot..endChunk,endSlot] range plus its
  own -O level and SymTab procId, instead of calling PHOpt.Optimize
  immediately the way ParseProcedure used to. OptimizeAllDeferred
  (below) walks this whole list exactly once, after every call site in
  the module has been fully resolved (RunBody's own call order:
  ParseModule, then CheckPendingCalls, then OptimizeAllDeferred, then
  SerializeOps). }
procedure OptRangeAppend(procId: integer; startChunk: POpChunk; startSlot: integer;
                          endChunk: POpChunk; endSlot: integer; level: integer);
  var last: POptRangeChunk; k: integer;
begin
  if (comp.optRangeTail = nil) or (comp.optRangeTail^.count >= Chunk) then begin
    New(last);
    last^.count := 0; last^.next := nil;
    if comp.optRangeHead = nil then comp.optRangeHead := last else comp.optRangeTail^.next := last;
    comp.optRangeTail := last
  end;
  last := comp.optRangeTail;
  k := last^.count + 1;
  last^.procId[k] := procId;
  last^.startChunk[k] := startChunk; last^.startSlot[k] := startSlot;
  last^.endChunk[k] := endChunk; last^.endSlot[k] := endSlot;
  last^.level[k] := level;
  last^.count := k
end;

{ OptimizeAllDeferred: OPT.TXT's own R6 finding -- calls PHOpt.Optimize
  once per recorded range, in the SAME order ParseProcedure would have
  called it immediately before this change (append order == source
  order, unaffected by deferring the call itself); the only actual
  behavior change is WHEN each call happens (after CheckPendingCalls,
  not immediately per-procedure), giving PHOpt.PAS's own call-graph
  analysis (built once, lazily, the first time PHOpt.Optimize itself
  needs it -- see PHOPT.PAS's own header comment) full visibility into
  every call site in the module, including a forward reference to a
  procedure whose own body was parsed LATER than some of its callers. }
procedure OptimizeAllDeferred;
  var rc: POptRangeChunk; k, nRanges, nProcs, i: integer;
begin
  { Flatten comp.optRangeHead's own chunked list into optRanges (PHOpt.
    BuildCallGraph needs a plain array -- a TP7 open-array parameter
    can't walk a linked chunk list on its own) -- OPT.TXT's own R6
    finding. }
  nRanges := 0;
  rc := comp.optRangeHead;
  while rc <> nil do begin
    for k := 1 to rc^.count do begin
      if nRanges < PHOpt.MaxProcs then begin
        optRanges[nRanges].procId := rc^.procId[k];
        optRanges[nRanges].startChunk := rc^.startChunk[k];
        optRanges[nRanges].startSlot := rc^.startSlot[k];
        optRanges[nRanges].endChunk := rc^.endChunk[k];
        optRanges[nRanges].endSlot := rc^.endSlot[k];
        nRanges := nRanges + 1
      end
    end;
    rc := rc^.next
  end;
  { optConservative: OPT.TXT's own R6 finding -- "Keep... external/
    indirect calls and address-taken entry points conservative", plus
    exported (a `*`-marked PROCEDURE may be called from some OTHER
    module entirely outside this pass's own visibility, via IMPORT/the
    generated .SHD header -- DOCS/SPHINX.MD's own EXTERNAL-declaration
    convention on the IMPORTING side). One entry per SymTab row,
    covering every procedure this module KNOWS about, not just the
    ones with a recorded optimize range (an EXTERNAL/FORWARD-only row
    has no body/range at all, but can still be a real callee some
    other procedure's own call site targets, and must still be
    correctly forced conservative here). }
  nProcs := SymTab.ProcCount;
  for i := 0 to nProcs - 1 do begin
    if i < PHOpt.MaxProcs then
      optConservative[i] := SymTab.ProcIsExternal(i) or SymTab.ProcIsExported(i)
                             or SymTab.ProcIsAddressTaken(i)
  end;
  PHOpt.BuildCallGraph(nProcs, nRanges, optRanges, optConservative);
  rc := comp.optRangeHead;
  while rc <> nil do begin
    for k := 1 to rc^.count do
      PHOpt.Optimize(rc^.startChunk[k], rc^.startSlot[k],
                      rc^.endChunk[k], rc^.endSlot[k], rc^.level[k], rc^.procId[k]);
    rc := rc^.next
  end
end;

{ InternOrZero: StrTab.Put(s), EXCEPT an empty string interns as id 0
  ("no string") instead of a real StrTab entry -- StrTab.Put('') would
  otherwise allocate a genuine id for the empty string like any other
  (StrTab has no built-in "empty means none" convention of its own), which
  would break SerializeOne's own "id=0 means this operand slot is unused"
  test (TOpInstr's own b/c fields: 0 if <=1-operand, matching every call
  site, none of which ever passes a genuinely empty operand string in
  practice -- but AppendLabelOp/AppendAsmLine's b/c ARE always empty by
  construction, so this guard is load-bearing, not defensive-only). }
function InternOrZero(const s: string): StrTab.TStrTabId;
begin
  if s = '' then InternOrZero := 0 else InternOrZero := StrTab.Put(s)
end;

{ NewOpSlot: the one real chunk-append primitive for the operation list
  (SOPLAN.MD's own Phase 3) -- every Append* helper below calls this to
  claim the next slot (zeroed/defaulted: mnemonic=MnNop, labelId/op1/
  op2=0), then fills in whichever fields its own kind actually needs
  directly through the returned chunk/index. Same chunk-growth shape as
  LitAppend/PendingAppend above. Returns the chunk pointer and 1-based
  slot index rather than a copy of the record itself (this project's
  own history has a real TP7 stack-corruption bug traced to an
  oversized stack parameter, SerializeOne's own header comment on why
  it takes a chunk/slot pair rather than a TOperation by value --  same
  reasoning applies here, on the write side). }
procedure NewOpSlot(kind: byte; needTab: boolean; var oc: POpChunk; var oi: integer);
  var last: POpChunk; idx, k: integer;
begin
  if (comp.opTail = nil) or (comp.opTail^.count >= Chunk) then begin
    New(last);
    last^.count := 0; last^.next := nil;
    if comp.opHead = nil then comp.opHead := last else comp.opTail^.next := last;
    comp.opTail := last
  end;
  idx := comp.nOps; Inc(comp.nOps);
  last := comp.opHead;
  while idx >= Chunk do begin last := last^.next; Dec(idx, Chunk) end;
  k := idx + 1;
  last^.ops[k].kind := kind;
  last^.ops[k].needTab := needTab;
  last^.ops[k].mnemonic := MnNop;
  last^.ops[k].labelId := 0;
  last^.ops[k].op1 := 0;
  last^.ops[k].op2 := 0;
  last^.ops[k].sect := comp.curSect;
  last^.ops[k].genSaveId := 0;
  last^.ops[k].callProcId := 0;
  last^.count := k;
  oc := last; oi := k
end;

{ AppendLabelOp: labelName is the BARE label name, no trailing ':' --
  callers (EmitLabel/the procedure-entry-label call site) must NOT
  append ':' themselves; SerializeOne appends it, once, only at final
  emission. Keeping labelId ':'-free lets a later peephole pass compare
  a TOpLabel's own labelId directly against a TOpInstr jump operation's
  own op1 (a jump target, e.g. from PatchCondRef -- also always the
  bare LabelName(n) text, no ':') without either side needing to
  strip/append a colon first to make the comparison meaningful. }
procedure AppendLabelOp(const labelName: string);
  var oc: POpChunk; oi: integer;
begin
  NewOpSlot(TOpLabel, false, oc, oi);
  oc^.ops[oi].labelId := InternOrZero(labelName)
end;

{ AppendInstr0/1/2: direct replacements for Emits.EmitOp0/EmitOp1/
  EmitOp2 -- an instruction line, 0/1/2 operands. mnemonic is one of
  the Mn* constants above now, not text (see TOperation's own header
  comment on this redesign). }
procedure AppendInstr0(mnemonic: word);
  var oc: POpChunk; oi: integer;
begin
  NewOpSlot(TOpInstr, false, oc, oi);
  oc^.ops[oi].mnemonic := mnemonic
end;

procedure AppendInstr1(mnemonic: word; const opnd: string);
  var oc: POpChunk; oi: integer;
begin
  NewOpSlot(TOpInstr, false, oc, oi);
  oc^.ops[oi].mnemonic := mnemonic;
  oc^.ops[oi].op1 := InternOrZero(opnd)
end;

{ AppendInstr1Ref: same as AppendInstr1, but also hands back a
  chunk/slot reference to the just-appended operation, for
  PendingAppend/CheckPendingCalls below to patch its mnemonic in place
  once the real callee NEAR/FAR-ness is known. }
procedure AppendInstr1Ref(mnemonic: word; const opnd: string; var opChunk: POpChunk; var opSlot: integer);
begin
  AppendInstr1(mnemonic, opnd);
  opChunk := comp.opTail; opSlot := comp.opTail^.count
end;

procedure AppendInstr2(mnemonic: word; const opnd1, opnd2: string);
  var oc: POpChunk; oi: integer;
begin
  NewOpSlot(TOpInstr, false, oc, oi);
  oc^.ops[oi].mnemonic := mnemonic;
  oc^.ops[oi].op1 := InternOrZero(opnd1);
  oc^.ops[oi].op2 := InternOrZero(opnd2)
end;

{ EmitGenSavePush/EmitGenSavePop: OPT.TXT Stage C's own "generated-
  save-pair identity" metadata -- a PUSH/POP pair this call site itself
  knows is a compiler-owned scratch-register save/restore (never a
  user-written PUSH()/POP() statement or a USES register-preservation
  pair -- neither of those call sites uses these two, only
  AppendInstr1(MnPush/MnPop,...) directly, same as before this pair
  existed) is tagged with a freshly claimed, globally unique id shared
  by both operations. EmitGenSavePush returns the id so its own caller
  can pass the SAME value to EmitGenSavePop once the matching POP is
  emitted -- deliberately explicit (not an implicit "most recent
  push" stack this unit tracks internally) since some call sites push
  more than one register before popping any of them back, and getting
  that pairing wrong would silently mislabel two UNRELATED PUSH/POP
  operations as a matched pair, a real correctness risk for whatever
  Stage C rule later trusts this id. }
function EmitGenSavePush(const opnd: string): word;
  var oc: POpChunk; oi: integer;
begin
  AppendInstr1Ref(MnPush, opnd, oc, oi);
  Inc(nextGenSaveId);
  oc^.ops[oi].genSaveId := nextGenSaveId;
  EmitGenSavePush := nextGenSaveId
end;

procedure EmitGenSavePop(const opnd: string; id: word);
  var oc: POpChunk; oi: integer;
begin
  AppendInstr1Ref(MnPop, opnd, oc, oi);
  oc^.ops[oi].genSaveId := id
end;

{ AppendAsmLine: direct replacement for Spho.pas's own Emit/Emit2 (and
  so, transitively, ParseAsm's own inline-ASM-block text and every
  struc/endstruc/global/extern declaration line) -- text is written
  out exactly as given, verbatim, needTab matching Emits.Emit's own
  needtab parameter. Raw text lives in op1 now (TOperation's own header
  comment on the mnemonic:WORD redesign -- the old shared "a" slot this
  used to occupy is mnemonic now, meaningless for TOpAsm). }
procedure AppendAsmLine(const text: string; needTab: boolean);
  var oc: POpChunk; oi: integer;
begin
  NewOpSlot(TOpAsm, needTab, oc, oi);
  oc^.ops[oi].op1 := InternOrZero(text)
end;

{ SerializeOps: the one backend routine (SOPLAN.MD's own Phase 3 item
  4) that walks the whole recorded operation list and writes it out
  through Emits.pas -- called once, from RunBody, after every Parse*/
  Emit* call this run will ever make has already appended its own
  operations (EmitLiterals included), right before the existing
  Emits.close(es) on the success path.
  Known sharp edge: 0-vs-1-vs-2-operand shape is inferred from op.b/
  op.c being empty, not from a stored operand count -- true for every
  current call site (none ever passes a genuinely empty operand
  string), but a future caller passing '' as a real operand would
  silently emit one operand short. Not fixed here (a 4th field,
  nOperands: byte, purely defensive against a case that doesn't exist
  yet) -- flagged so it isn't rediscovered the hard way later.
  SOPLAN.MD's own Phase 4 ("Emit struc definitions, .data, .bss, and
  .text in a deterministic backend order... one consolidated block per
  section"): four passes over the SAME list, one per op.sect value
  (SectStruc, SectData, SectBss, SectCode, that fixed order), instead of
  one single front-to-back walk -- WITHIN each group, operations still
  come out in their original append (source) order, since each pass
  itself walks the list front-to-back; only the GROUPING is
  reorganized, not each group's own internal order (item 5: "Keep
  procedure bodies in source order inside .text"). A group's own
  "section ..." header (skipped for SectStruc -- struc/endstruc are
  section-agnostic TASM directives, DOCS/SPHO.MD) is emitted at most
  once, only if that group turns out non-empty (an EnsureSection(X)
  call with nothing appended after it before the next EnsureSection --
  e.g. a MODULE with no globals at all -- must not emit a stray empty
  "section .bss"). }
{ MnemonicText (Types.MnemonicText): the one place a Mn* constant is
  ever turned back into its own NASM text -- everywhere else
  (comparisons, patching) works on the WORD constant directly (see
  TYPES.PAS's own header comment on why: this is what a peephole pass
  needs). Called exactly once per TOpInstr, by SerializeOne below, at
  final serialization. MnNop is never passed here -- SerializeOne skips
  a MnNop operation before this could ever run (see SerializeOne's own
  case below). Moved into unit Types alongside TOperation/the Mn*
  constants themselves; used here unqualified via `uses ... Types`. }

{ SerializeOne: op is a POpChunk/slot pair, not a TOperation passed by
  value -- this project's own history has one real TP7 stack-corruption
  bug traced to an oversized stack parameter (EmitCall's own TRegName-
  vs-string array, see that procedure's own header comment); addressed
  in place via c^.ops[k] here rather than copied onto the stack for
  every single serialized operation (moot for TOperation's own size
  post-heap-fix, now just three TStrTabId words plus a few bytes, but
  kept as the established pattern regardless). labelId/op1/op2 are
  StrTab ids, not inline text (see TOperation's own header comment) --
  resolved back via StrTab.Get into plain locals immediately before the
  one Emits.* call each branch makes; id 0 ("no string", InternOrZero's
  own convention) resolves to '' via StrTab.Get already (id out of
  range -> empty string, StrTab.Get's own documented behavior), so the
  op1/op2-empty checks below are unchanged in spirit from the pre-fix
  inline-string version.
  MnNop (TOpInstr only): a deleted operation, from a peephole pass
  overwriting an existing operation's own mnemonic in place -- skipped
  here entirely, emitting nothing at all, rather than falling through
  to MnemonicText's own '' case (which would otherwise still call
  Emits.EmitOp0/1/2 with an empty mnemonic string, a real bug: a blank
  line with just the operand(s), not actually "nothing"). }
procedure SerializeOne(c: POpChunk; k: integer);
  var lbl, op1, op2, mn: string;
begin
  case c^.ops[k].kind of
    TOpLabel: begin
      { labelId holds the BARE label name, no trailing ':' -- appended
        here, once, only at final emission (AppendLabelOp's own header
        comment on why: a later peephole pass comparing a label name
        against a jump target's own op1 text needs both sides in the
        same, colon-free form). }
      StrTab.Get(c^.ops[k].labelId, lbl);
      Emits.Emit(es, false, lbl + ':')
    end;
    TOpInstr: begin
      if c^.ops[k].mnemonic = MnNop then exit;
      mn := MnemonicText(c^.ops[k].mnemonic);
      StrTab.Get(c^.ops[k].op1, op1);
      if c^.ops[k].op2 <> 0 then begin
        StrTab.Get(c^.ops[k].op2, op2);
        Emits.EmitOp2(es, mn, op1, op2)
      end else if c^.ops[k].op1 <> 0 then Emits.EmitOp1(es, mn, op1)
      else Emits.EmitOp0(es, mn)
    end;
    TOpAsm: begin
      StrTab.Get(c^.ops[k].op1, op1);
      Emits.Emit(es, c^.ops[k].needTab, op1)
    end
  end
end;

procedure SerializeSection(wantSect: integer; const header: string);
  var c: POpChunk; k: integer; started: boolean;
begin
  started := false;
  c := comp.opHead;
  while c <> nil do begin
    k := 1;
    while k <= c^.count do begin
      if c^.ops[k].sect = wantSect then begin
        if (not started) and (header <> '') then Emits.Emit(es, false, header);
        started := true;
        SerializeOne(c, k)
      end;
      Inc(k)
    end;
    c := c^.next
  end
end;

procedure SerializeOps;
begin
  SerializeSection(SectStruc, '');
  SerializeSection(SectData, 'section .data');
  SerializeSection(SectBss, 'section .bss');
  SerializeSection(SectCode, 'section .text')
end;

{ InternStringLiteral: text is a double-quoted string literal's already-
  scanned content. Interns it via StrTab (exact byte content, dedup for
  free) and returns its NASM label text. }
procedure InternStringLiteral(const text: string; var dst: string);
  var id: StrTab.TStrTabId; li: integer;
begin
  id := StrTab.Put(text);
  li := LitIndexOf(id);
  if li < 0 then li := LitAppend(id);
  dst := LitLabelName(li)
end;

{ ---------------- output ---------------- }

{ Emit/Emit2/EnsureSection are `far`, against this file's own project-
  wide near-call default (FLAGS.INC's own F-minus state) -- RecTypes.
  ParseTypeSection/ParseRecordType take them as procedural-value
  parameters (RecTypes can't call back into this file, circular uses),
  and TP7 requires a routine assigned to a procedural value to be far. }
procedure Emit(const s: string); far;
begin AppendAsmLine(s, false) end;

procedure Emit2(const a, b: string); far;
begin AppendAsmLine(a + b, false) end;

{ EnsureSection: record sect (SectData/SectBss/SectCode/SectStruc) as
  the section every subsequent AppendOp call should tag its operations
  with, until the next EnsureSection call. Does NOT itself emit a
  "section ..." line (SOPLAN.MD's own Phase 4: SerializeOps now groups
  every operation by its own recorded sect into one consolidated block
  per section, synthesizing exactly one "section ..." header per
  non-empty group there, rather than one appended inline wherever the
  source happened to switch sections). }
procedure EnsureSection(sect: integer); far;
begin
  comp.curSect := sect
end;

function NewLabel: word;
begin Inc(ctx.labelCnt); NewLabel := ctx.labelCnt end;

function LabelName(id: word): string;
begin LabelName := '.L' + IntStr(id) end;

procedure EmitLabel(id: word);
begin AppendLabelOp(LabelName(id)) end;

{ ---------------- symbol table ---------------- }

{ IsZeroLiteral: TRUE if s is a numeric-literal spelling of zero via the
  decimal ("0", "00", ...) or trailing-H/B-suffix shapes -- NOT the
  C-style "0x..." prefix hex form. }
function IsZeroLiteral(const s: string): boolean;
  var i: integer;
begin
  IsZeroLiteral := false;
  if s = '' then exit;
  if not (s[1] in ['0'..'9']) then exit;
  i := 1;
  while (i <= Length(s)) and (s[i] in ['0'..'9']) do begin
    if s[i] <> '0' then exit;
    Inc(i)
  end;
  { every digit seen so far was '0' -- what follows must be nothing
    (plain "0"/"00") or a single trailing H/X/B literal-kind suffix. }
  if i > Length(s) then begin IsZeroLiteral := true; exit end;
  if i + 1 <= Length(s) then exit;   { more than one char follows }
  IsZeroLiteral := (s[i] = 'H') or (s[i] = 'h') or (s[i] = 'X') or (s[i] = 'x')
                or (s[i] = 'B') or (s[i] = 'b')
end;

{ ---------------- type parsing (TYPE section: RECORD) ----------------
  TySize/SizeHintFor/ScalarKwTy/ParseBaseType/ParseBaseTypeName/
  ResSuffix/DeclMnemonic/ParseRecordType/ParseTypeSection now live in
  unit RecTypes (SRC/RECTYPES.PAS) -- see that unit's own header
  comment for why this section, and only this section, could split out
  cleanly. Called here as RecTypes.X; ParseRecordType/ParseTypeSection
  take Emit/Emit2/EnsureSection/ParseArrayBound as explicit parameters
  since RecTypes can't call back into this file (circular uses). }

{ ParseConstDecl: 'name = numericLiteral;' -- named INTEGER/WORD/BYTE/
  LONGINT values, no storage allocated. }
procedure ParseConstDecl;
  var nm, msg: string; val: longint; neg, exported: boolean; si: integer;
begin
  Scan.CurTokText(nm); SymTab.Next;
  exported := false;
  if SymTab.IsLexSym(SymTab.SyStar) then exported := true;
  SymTab.Expect(SymTab.SyEq);
  neg := SymTab.IsLexSym(SymTab.SyMinus);
  if Scan.CurTokKind = TNum then begin
    val := Scan.CurTokVal; SymTab.Next
  end else begin
    msg := 'expected numeric literal in CONST';
    Scan.ReportError(msg); val := 0
  end;
  if neg then val := -val;
  si := SymTab.SymAppend(nm, SymConst);
  SymTab.SymSetVal(si, val);
  SymTab.SymSetExported(si, exported);
  SymTab.Expect(SymTab.SySemi)
end;

{ ---------------- VAR section (global) ----------------
  EmitVarDecl/ParseArrayLitInit/ParseArrayStrLitInit/ParseVarSection
  now live in unit GlobVar (SRC/GLOBVAR.PAS) -- see that unit's own
  header comment for why. Called here as GlobVar.ParseVarSection.
  ParseArrayBound stays here (not moved into GlobVar): RecTypes.
  ParseRecordType also calls it directly for a RECORD field's own
  '[N]' bound, so it's passed as a procedural-value parameter to BOTH
  RecTypes and GlobVar rather than living in either. }

{ ParseArrayBound: 'N' in 'NAME: T[N]' -- a numeric literal, or a CONST
  identifier. PLAN.TXT S1.4: N <= 0 (negative or zero) is rejected here
  -- the one place every declared bound passes through, whether it's a
  RECORD field's own '[N]' (RecTypes.ParseRecordType), an array VAR's
  own 'T[N]' (GlobVar.ParseVarSection), or the same syntax's address-
  only sugar on a formal PARAMETER -- so fixing it here covers all
  three without duplicating the check at each call site. Before this,
  'VAR buf: WORD[N];' with a negative CONST N silently emitted a NASM
  'resw <negative>' -- caught only much later, and only as a confusing
  TASM.EXE assembly error, not a clean translator diagnostic naming
  the real problem. A zero bound is rejected too: 'T[0]' has no
  legitimate real use ('T[]', a DIFFERENT, already-existing empty-
  bound syntax, is how an array whose OWN size comes from a BASE64()/
  FILE()/"..." initializer is actually spelled, DOCS/SPHINX.MD S3.4).
  vL (a genuine longint, not the final integer function result) holds
  the raw parsed value BEFORE it's narrowed to this function's own
  16-bit integer return type -- PLAN.TXT's own "perform size
  calculations without silently wrapping at 16 bits": Scan.CurTokVal
  and SymTab.SymVal are already both longint, so the truncation this
  function used to do by simply writing "integer(...)" straight into
  its own result happened silently, one full step before this
  function's own >0 check could ever see the real value -- 'WORD[40000]'
  used to silently become integer(40000) = -25536 (40000 mod 65536,
  reinterpreted signed) BEFORE the old check ran, so it was rejected
  as "-25536" (confusing, and technically the wrong reason) rather
  than the real problem: 40000 itself is simply too large a bound for
  this translator's own 16-bit element-count representation, whatever
  T's own size is. }
function ParseArrayBound: integer;
  var si: integer; vL: longint; nm, msg: string;
begin
  if Scan.CurTokKind = TNum then begin
    vL := Scan.CurTokVal; SymTab.Next
  end else if Scan.CurTokKind = TIdent then begin
    Scan.CurTokText(nm); SymTab.Next;
    si := SymTab.FindSym(nm);
    if (si >= 0) and (SymTab.SymKind(si) = SymConst) then
      vL := SymTab.SymVal(si)
    else begin
      msg := 'array bound is not a numeric literal or CONST: ' + nm;
      Scan.ReportError(msg); ParseArrayBound := 1; exit
    end
  end else begin
    Scan.ReportError('expected array bound'); ParseArrayBound := 1; exit
  end;
  if (vL <= 0) or (vL > 32767) then begin
    msg := 'array bound must be a positive count, no larger than 32767, got '
      + IntStr(vL);
    Scan.ReportError(msg); vL := 1
  end;
  ParseArrayBound := integer(vL)
end;

{ ---------------- expression translation ---------------- }
{ SPHINX has no operator precedence -- left to right. }

{ SymOperandText: resolve a (non-register) identifier already read into
  `nm`, with its already-resolved si, to its NASM operand text -- the
  literal value for a CONST, a local/param's [bp+-N] frame slot for a
  local VAR, or a bare [name] for a global VAR. }
procedure SymOperandText(si: integer; const nm: string; var dst: string);
  var ofs: integer;
begin
  if (si >= 0) and (SymTab.SymKind(si) = SymConst) then begin
    dst := IntStr(SymTab.SymVal(si)); exit
  end;
  if (si >= 0) and SymTab.SymIsReg(si) then begin
    { register-named param: the actual formal-parameter identifier IS the
      register name -- reuse it verbatim, no [bp+N] frame slot at all. }
    dst := nm; exit
  end;
  if (si >= 0) and SymTab.SymIsLocal(si) then begin
    ofs := SymTab.SymOfs(si);
    dst := '[bp';
    if ofs >= 0 then dst := dst + '-' else dst := dst + '+';
    dst := dst + IntStr(longint(Abs(ofs))) + ']'
  end else
    dst := '[' + nm + ']'
end;

{ IdentOperandText: resolve a (non-register) identifier already read into
  `nm` to its NASM operand text. }
procedure IdentOperandText(const nm: string; var dst: string);
begin SymOperandText(SymTab.FindSym(nm), nm, dst) end;

{ SpliceOffset: memOperand is an already-bracketed memory operand text
  ('[name]' or '[bp-N]'); returns the operand with '+off' inserted just
  before the closing ']' (off=0 leaves it unchanged) -- same splice
  technique HighWordOperand already uses for a LONGINT's own high word. }
procedure SpliceOffset(const memOperand: string; off: integer; var dst: string);
begin
  if off = 0 then dst := memOperand
  else dst := Copy(memOperand, 1, Length(memOperand) - 1) + '+' + IntStr(longint(off)) + ']'
end;

{ EmitIndexedOperand: 'name[' already consumed (si/nm already resolved,
  SymIsArr(si) already confirmed by the caller) -- parses 'indexExpr]'
  and returns dst/sizeHint for the resulting element operand, exactly
  like ParseMemOperand's own (dst, sizeHint) pair. A follow-on to
  SOPLAN.MD's own Phase 7 item 3 (array-parameter syntax): that item
  made 'buf: T[N]' a valid PARAMETER declaration (address-only sugar);
  this adds the matching ELEMENT-ACCESS syntax 'name[indexExpr]' for any
  array-typed name (VAR or param), scalar element types only -- an
  array-of-RECORD element (TyRec) is rejected here with a translator
  error, since its own size needs recIdx, not externally readable from
  SymTab (SymTy alone, which is all SymIsArr's own callers have ever
  needed until now). SPHINX has no general arr[i]-style indexing
  anywhere else in the language (DOCS/SPHINX.MD S10's own memory-operand
  syntax is 'base' only, no inline '+N' -- this is the one place that
  changes).

  Base-address computation depends on WHETHER si is an array-typed VAR
  or an array-typed PARAMETER (SymIsParam, added alongside this feature
  specifically for this distinction -- see TSymChunk's own isParam
  comment): a VAR's storage location IS the array itself, so its
  ADDRESS must be computed (a bare label for a global, 'lea' for a
  local -- EmitAdrOperand's own logic, reused here); a PARAMETER's own
  stack slot instead holds an address VALUE already (the array's base,
  passed in by the caller, Phase 7 item 3's own auto-ADR() at the call
  site) -- reading it directly, an ordinary 'mov', is enough.

  A compile-time-constant index (a numeric literal or CONST name, same
  grammar ParseArrayBound already accepts for a declared bound) folds
  into the operand text directly -- no runtime arithmetic at all: for a
  VAR, SpliceOffset onto its own already-computed address text (global:
  '[name+off]', local: '[bp-N+off]'); for a param, the base is loaded
  into BX once (a param's own value is only ever known at runtime, even
  for a literal index) and the constant offset is still folded into the
  NASM operand text as a literal, not a separate 'add'. A non-constant
  index (a VAR/register) needs real runtime arithmetic: base into BX,
  index into a scratch register, scaled by the element's own byte size
  (a 'shl' by 0/1/2 bits -- every scalar element size here is a power of
  two: BYTE/BOOLEAN=1, WORD/INTEGER=2, LONGINT=4), added into BX, then
  dereferenced as '[bx]'. }
procedure EmitIndexedOperand(si: integer; const nm: string; var dst: string; var sizeHint: string);
  var elemTy: integer; elemSz: integer; typ: SymTab.TTypeInfo;
      base, idxNm, idxOpnd, msg: string; idxSi: integer;
      isConstIdx: boolean; constOff: integer; shiftAmt: integer;
      idxPeekNm: string; idxIsByte: boolean; bxIsSS: boolean; bxBase: string;
      rawIdx: integer; arrLen: longint;
begin
  elemTy := SymTab.SymTy(si);
  if elemTy = TyRec then begin
    msg := 'array-of-RECORD element indexing not supported: ' + nm;
    Scan.ReportError(msg); dst := '0'; sizeHint := '';
    { still consume 'indexExpr]' so the caller's own parse can continue
      past this error instead of desyncing on the very next token. }
    if not SymTab.IsSym(SymTab.SyRBrack) then OperandText(idxOpnd);
    SymTab.Expect(SymTab.SyRBrack); exit
  end;
  typ.ty := elemTy; typ.recIdx := -1;
  elemSz := RecTypes.TySize(typ);
  RecTypes.SizeHintFor(elemTy, sizeHint);

  { Peek: a numeric literal or a CONST name is a compile-time-constant
    index, same grammar ParseArrayBound already accepts for a declared
    array bound -- checked here (not via ParseArrayBound itself) since
    the non-constant case below needs the general OperandText path
    instead, not ParseArrayBound's own narrower one. }
  isConstIdx := false; constOff := 0; rawIdx := 0;
  if Scan.CurTokKind = TNum then begin
    isConstIdx := true; rawIdx := integer(Scan.CurTokVal); SymTab.Next
  end else if Scan.CurTokKind = TIdent then begin
    Scan.CurTokText(idxNm);
    idxSi := SymTab.FindSym(idxNm);
    if (idxSi >= 0) and (SymTab.SymKind(idxSi) = SymConst) and not SymTab.IsRegName(idxNm) then begin
      isConstIdx := true; rawIdx := integer(SymTab.SymVal(idxSi)); SymTab.Next
    end
  end;
  if isConstIdx then begin
    { PLAN.TXT S1.4: reject a constant index that's provably out of
      range at translate time -- negative outright, or (when the
      array's own element count is actually knowable) >= that count.
      An array-typed formal PARAMETER is skipped entirely, not silently
      "checked and found fine": its own declared bound never proves the
      caller's real allocation size (PLAN.TXT S1.3's own scope note,
      TryBuiltinOperand's matching SIZE()/LEN() rejection for the exact
      same reason), so there's no reliable bound here to check against
      at all. }
    if rawIdx < 0 then begin
      msg := 'array index is negative: ' + nm + '[' + IntStr(longint(rawIdx)) + ']';
      Scan.ReportError(msg); rawIdx := 0
    end else if not SymTab.SymIsParam(si) then begin
      arrLen := SymTab.SymVal(si);
      if SymTab.SymIsLitInit(si) and (elemSz > 0) then arrLen := arrLen div elemSz;
      if (arrLen > 0) and (rawIdx >= arrLen) then begin
        msg := 'array index ' + IntStr(longint(rawIdx)) + ' is out of range for ' + nm
          + ' (length ' + IntStr(longint(arrLen)) + ')';
        Scan.ReportError(msg); rawIdx := 0
      end
    end;
    constOff := rawIdx * elemSz
  end;

  bxIsSS := false;
  if SymTab.SymIsParam(si) then begin
    { Param: its own stack slot holds the array's base ADDRESS as a
      value -- load it into BX (needed even for a constant index, since
      a parameter's own value is never known at translate time). An
      array formal passes an offset only, with no hidden segment (this
      file's own DOCS/SPHINX.MD S6.6/S10) -- bxIsSS stays FALSE here
      deliberately: the callee genuinely has no way to know whether the
      caller's own array lived in SS or DS, PLAN.TXT S1.8's own "a
      separate issue" scope note (passing a local array to an offset-
      only formal still requires DS=SS at the call site, unfixed by
      this same PLAN.TXT item -- see this procedure's own SS-override
      comment below for the part that IS in scope). }
    SymOperandText(si, nm, base);
    AppendInstr2(MnMov, 'bx', base)
  end else if isConstIdx then begin
    { Real array VAR, constant index: SymOperandText gives its own
      STORAGE location ('[name]' global, '[bp-N]' local) -- that IS the
      array's base, and SpliceOffset folds the constant index directly
      onto it, no register needed at all. }
    SymOperandText(si, nm, base);
    SpliceOffset(base, constOff, dst);
    SymTab.Expect(SymTab.SyRBrack); exit
  end else if SymTab.SymIsLocal(si) then begin
    { Real array VAR, non-constant index, LOCAL array: its own base
      address needs a real 'lea' (no compile-time-known label the way
      a global has) -- emitted directly into BX here, NOT via
      EmitAdrOperand (which always targets AX). This is a real, found
      bug fix, not a style choice: EmitIndexedOperand can be reached
      mid-chain-expression (e.g. "total := total + arr[i];"), where AX
      already holds the chain's own running accumulator by the time
      this runs (EmitExprTail's own destReg convention, see this
      procedure's later comment on the index-scaling arithmetic
      already being routed through CX for exactly the same reason) --
      routing through EmitAdrOperand's own hardcoded 'lea ax, [mem]'
      clobbered that live accumulator before the caller's own combining
      instruction ever read it, silently computing "&arr + arr[i]"
      instead of "total + arr[i]" (confirmed via a Sum3()-style repro:
      arr:=[10,20,30], summing arr[i] over i=0..2 in a WHILE loop
      returned 18 instead of the correct 60). A global array's own
      base (the `if not SymIsLocal` case, unaffected by this fix) was
      never at risk -- EmitAdrOperand returns a bare label for it, no
      register write at all.

      bxIsSS := TRUE (PLAN.TXT S1.8, "correctness priority"): a local
      array lives in SS, but 'lea bx, [bp-N]' only computes the OFFSET
      -- BX itself carries no segment information, and a bare '[bx]'
      memory operand implicitly means DS:BX, not SS:BX (NASM's own
      default segment for BX same as for any other non-BP base
      register). Before this fix, runtime-indexed local-array access
      silently read/wrote through DS instead of SS, correct only by
      accident whenever DS happens to equal SS (this project's own
      tiny-model .COM convention keeps them equal at program start, but
      nothing enforces that for the rest of a running program -- see
      DOCS/SPHINX.MD's own "Constant local indexing uses BP-relative
      storage... require DS = SS" limitation note, now narrower: only
      the constant-index case ever legitimately relied on that, since
      it goes through '[bp-N]' directly, itself always SS-relative
      regardless of DS; the non-constant case fixed here needs no such
      assumption anymore). Fixed by emitting an explicit 'SS:' segment
      override on the final memory operand below instead. }
    SymOperandText(si, nm, base);
    AppendInstr2(MnLea, 'bx', base);
    bxIsSS := true
  end else begin
    { Real array VAR, non-constant index, GLOBAL array: EmitAdrOperand
      returns a bare compile-time label (no register write), safe to
      route through unchanged regardless of what's live in AX. }
    EmitAdrOperand(nm, si, base);
    AppendInstr2(MnMov, 'bx', base)
  end;
  if bxIsSS then bxBase := '[SS:BX]' else bxBase := '[bx]';
  if isConstIdx then
    SpliceOffset(bxBase, constOff, dst)
  else begin
    { Index arithmetic scaled by the element's own byte size (a 'shl' by
      0/1/2 bits -- every scalar element size here is a power of two:
      BYTE/BOOLEAN=1, WORD/INTEGER=2, LONGINT=4) via CX, deliberately
      NOT ax -- EmitExprTail's own destReg convention is always 'ax'
      (every real call site passes it literally), so an earlier operand
      in the same chain expression ('total + buf[i]') may already have
      a live value sitting in AX that this indexing computation must
      not clobber before the caller's own combining instruction reads
      it. CX has no such conflict anywhere buf[i]/arr[i] can be reached
      from.
      idxIsByte: peeked BEFORE OperandText consumes/flattens the token
      (PeekOperandIsByte's own header comment, same pattern TryEmitNot/
      EmitCondJump already use) -- a BYTE/BOOLEAN-typed index VAR (or a
      bare byte register, AL/BL/...) must load via CL + a separate
      zero-extend, never a blind 'mov cx, idxOpnd': that would read a
      full WORD starting at a one-byte VAR's own storage, pulling
      whatever memory happens to follow it into CH as live garbage that
      then corrupts the scaled index (confirmed the hard way via
      EXAMPLES/MIME/MIME.SMD's own 'EncodeTable[idx]' with idx: BYTE --
      every lookup read CH's own garbage into the array address). }
    Scan.CurTokText(idxPeekNm);
    idxIsByte := (Scan.CurTokKind = TIdent) and PeekOperandIsByte(idxPeekNm);
    OperandText(idxOpnd);
    if idxIsByte then begin
      if EqualICase(idxOpnd, 'AX') then AppendInstr2(MnMov, 'cl', 'al')
      else AppendInstr2(MnMov, 'cl', idxOpnd);
      AppendInstr2(MnMov, 'ch', '0')
    end else
      AppendInstr2(MnMov, 'cx', idxOpnd);
    if elemSz > 1 then begin
      if elemSz = 2 then shiftAmt := 1 else shiftAmt := 2;
      AppendInstr2(MnShl, 'cx', IntStr(longint(shiftAmt)))
    end;
    AppendInstr2(MnAdd, 'bx', 'cx');
    dst := bxBase
  end;
  SymTab.Expect(SymTab.SyRBrack)
end;

{ ParseMemOperand: '[' already consumed. '[seg:base]' or '[offset]' (DS
  implied), optionally followed by '.RecordType.field' for structured
  access. forAddress is TRUE only when the caller wants this operand's
  own ADDRESS (ADR(), via lea) rather than its VALUE (an ordinary
  read/write memory operand) -- an array field is only valid in the
  former position (its address, to hand to e.g. BlockRead), never the
  latter (reading/writing it as if it were one scalar would silently
  read/write the wrong size), so the array-field check below is skipped
  when forAddress is TRUE. }
{ IsEffAddrBaseReg: TRUE iff regUp (already upper-cased) is a legal
  8086 base register for an effective address -- BX/BP/SI/DI only
  (PLAN.TXT S2.1's own "Accept 8086 address forms only" list). Used to
  both recognize the new base+index+disp grammar (TryParseEffAddr,
  below) and its own AX-based-address rejection ("Reject AX-based
  addresses... and other unsupported forms"). }
function IsEffAddrBaseReg(const regUp: string): boolean;
begin
  IsEffAddrBaseReg := EqualICase(regUp, 'BX') or EqualICase(regUp, 'BP')
                    or EqualICase(regUp, 'SI') or EqualICase(regUp, 'DI')
end;

{ TryParseEffAddr: attempts PLAN.TXT S2.1's own new effective-address
  grammar -- a base register (BX/BP/SI/DI) optionally followed by '+'
  and an index register (only BX+SI/BX+DI/BP+SI/BP+DI are legal
  8086 base+index pairs -- BX+BP and any other combination, including
  a repeated base, is rejected outright, "Reject... BX+BP, scaled
  indices, and other unsupported forms"), optionally followed by a
  constant displacement ('+'/'-' then a numeric literal -- SI+CONST
  reads as one signed 16-bit immediate either way, matching ordinary
  8086 encoding, not two separate additions). Returns FALSE (consuming
  nothing) if the current token isn't a register at all, or isn't one
  of BX/BP/SI/DI specifically -- the caller falls back to
  ParseMemOperand's own pre-existing single-token base parse for every
  other case (a plain VAR name, a bare numeric address, AX/CX/DX/other
  registers -- all handled exactly as before this addition, unchanged).
  isSS is set TRUE iff the base register is BP (PLAN.TXT S2.1's own
  "Without an explicit segment, BP-based addresses use SS; the
  remaining forms use DS" -- the caller applies this default only when
  no explicit SEG: was written, same as ParseMemOperand's own existing
  seg-default logic elsewhere). }
{ ParseEffAddrTail: appends an optional '+index' (SI/DI only, and only
  when legal alongside baseNm -- BX+SI/BX+DI/BP+SI/BP+DI, "Reject...
  BX+BP, scaled indices, and other unsupported forms") and an optional
  constant displacement onto addrText, given the base register's own
  name baseNm (already consumed by the caller -- either the plain
  single-register path or the TRegPair-fused 'SEG:BASE' path, both of
  which reach here identically once their own base register is known,
  so 'DS:BX + SI + 4' and a loosely-spelled 'BX + SI + 4' with no
  segment are parsed by the exact same tail logic either way). }
procedure ParseEffAddrTail(const baseNm: string; var addrText: string);
  var idxNm, msg: string; neg: boolean; disp: longint; consumedPlus: boolean;
begin
  { A leading '+' could introduce an index register ('[BX+SI]') OR a
    plain positive displacement ('[BX+4]') -- no lookahead buffer
    exists in this scanner (Scan.CurTok* only ever exposes the token
    already consumed), so '+' is consumed first (IsLexSym, self-
    advancing) and the token that becomes current right after decides
    which of the two this actually is: a register -> index, anything
    else (expected: a numeric literal) -> falls through to the
    displacement check below unchanged, exactly as if this '+' had
    been the displacement's own sign token all along. }
  consumedPlus := false;
  if SymTab.IsLexSym(SymTab.SyPlus) then begin
    consumedPlus := true;
    if (Scan.CurTokKind = TIdent) and SymTab.CurTokIsReg then begin
      Scan.CurTokText(idxNm);
      if not (EqualICase(idxNm, 'SI') or EqualICase(idxNm, 'DI')) then begin
        msg := 'unsupported effective-address index register: ' + idxNm;
        Scan.ReportError(msg); SymTab.Next
      end else if EqualICase(baseNm, 'SI') or EqualICase(baseNm, 'DI') then begin
        msg := 'unsupported effective-address base+index combination: ' + baseNm + '+' + idxNm;
        Scan.ReportError(msg); SymTab.Next
      end else begin
        addrText := addrText + '+' + UpStr(idxNm); SymTab.Next
      end;
      consumedPlus := false   { the index register (or the malformed
                                  token reported above) is now fully
                                  consumed -- any further '+'/'-'
                                  belongs to a genuinely NEW
                                  displacement clause, parsed by the
                                  ordinary check below, not treated as
                                  still "pending" from this one. }
    end
  end;
  disp := 0; neg := false;
  if consumedPlus or SymTab.IsSym(SymTab.SyPlus) or SymTab.IsSym(SymTab.SyMinus) then begin
    if not consumedPlus then begin
      neg := SymTab.IsSym(SymTab.SyMinus);
      SymTab.Next
    end;
    if Scan.CurTokKind = TNum then begin
      disp := Scan.CurTokVal; SymTab.Next
    end else
      Scan.ReportError('expected a constant displacement in effective address');
    if neg then addrText := addrText + '-' + IntStr(disp)
    else addrText := addrText + '+' + IntStr(disp)
  end
end;

{ TryParseEffAddr: entry point for a LOOSELY-spelled (no TRegPair fast
  path involved) effective address, e.g. a bare 'BX+SI+4' with no
  segment override written at all. Returns FALSE (consuming nothing)
  when the current token isn't one of BX/BP/SI/DI -- the caller falls
  back to ParseMemOperand's own pre-existing single-token base parse
  for every other case (a plain VAR name, a bare numeric address, AX/
  CX/DX/other registers -- all unchanged by this addition). The
  TRegPair-fused 'SEG:BASE' case (e.g. '[DS:BX + SI + 4]') never
  reaches this function at all -- ParseMemOperand's own TRegPair
  branch already consumed 'DS:BX' as one token by the time '+SI+4'
  is seen, so it calls ParseEffAddrTail directly instead, see that
  branch's own comment. }
function TryParseEffAddr(var addrText: string; var isSS: boolean; var baseOut: string): boolean;
  var baseNm: string;
begin
  TryParseEffAddr := false;
  if (Scan.CurTokKind <> TIdent) or not SymTab.CurTokIsReg then exit;
  Scan.CurTokText(baseNm);
  if not IsEffAddrBaseReg(baseNm) then exit;
  TryParseEffAddr := true;
  SymTab.Next;
  baseOut := baseNm;
  isSS := EqualICase(baseNm, 'BP');
  addrText := UpStr(baseNm);
  ParseEffAddrTail(baseNm, addrText)
end;

procedure ParseMemOperand(var dst: string; var sizeHint: string; forAddress: boolean;
                           var isTypedWidth: boolean);
  var seg, base, baseNm: string; fieldName, recTyName, msg: string;
      ti: integer; ftyp: SymTab.TTypeInfo; fcnt: word; haveSeg, isSS: boolean;
begin
  sizeHint := '';
  seg := ''; haveSeg := false; isSS := false;
  if Scan.CurTokKind = TRegPair then begin
    { '[SEG:BASE]' with a tightly-spelled pair, e.g. '[DS:BX]' -- the
      scanner's own TRegPair fast path (see Scan.RawNext's comment)
      cannot tell this apart from a genuine LONGINT register-pair VALUE
      at the character level, since both are spelled identically; only
      this parser, which knows it's inside '[...]', can. Recovered here
      by reading both names straight off the fused token instead of
      re-deriving them from ':' (already consumed into the token, so
      SymTab.IsLexSym(SyColon) below would never see it -- this was a
      real regression before this branch existed: '[DS:BX].Rec.field'
      silently lost its own segment override, TESTS/RECORDS.SMD's own
      "[DS:BX].Point.x := AX" case). PLAN.TXT S2.1's own '+index+disp'
      tail (e.g. '[DS:BX + SI + 4]') DOES reach here too, unlike this
      comment's own earlier draft assumed -- the scanner's TRegPair
      fast path only ever fuses the FIRST two tokens ('DS:BX'), fully
      independent of whatever follows, so '+SI+4' is still sitting
      unconsumed right after SymTab.Next below; ParseEffAddrTail
      parses it the exact same way the loosely-spelled 'BX+SI+4' case
      (no segment override, TryParseEffAddr below) already does --
      found the hard way, confirmed by TESTS/EFFADDR.SMD's own
      '[DS:BX + SI + 4].WORD' case failing to parse at all before this
      fix, cascading into several follow-on "unexpected" errors. }
    haveSeg := true;
    Scan.CurTokRegPair(seg, base);
    SymTab.Next;
    baseNm := base;
    ParseEffAddrTail(baseNm, base)
  end else if TryParseEffAddr(base, isSS, baseNm) then begin
    { PLAN.TXT S2.1: 'BX+SI+4' etc -- TryParseEffAddr already validated
      and consumed the whole base+index+disp grammar; only a leading
      'SEG:' can still precede it (it was already ruled out above by
      TRegPair's own fast path catching the tightly-spelled case, so
      only a loosely-spelled 'DS : BX+SI' -- with real whitespace
      around ':' -- could reach here, and SPHINX's own scanner never
      produces that shape in practice; this branch exists for
      completeness, not a real gap). No explicit SEG here means isSS
      decides the default (BP-based -> SS, everything else -> DS),
      applied by the .BYTE/.WORD handling below -- ParseMemOperand's
      own EXISTING single-token base path (the two branches above/
      below this one) never had a register-conditional default at all
      (always DS unless literally written), so this default is new,
      scoped to ONLY the new grammar, per this session's own design
      decision (arithmetic addressing is reserved for .BYTE/.WORD). }
  end else begin
    Scan.CurTokText(base); SymTab.Next;
    if SymTab.IsLexSym(SymTab.SyColon) then begin
      haveSeg := true; seg := base; Scan.CurTokText(base); SymTab.Next
    end;
    baseNm := base
  end;
  SymTab.Expect(SymTab.SyRBrack);
  dst := '[';
  if haveSeg then dst := dst + seg + ':' + base
  else if isSS then dst := dst + 'SS:' + base
  else dst := dst + base;
  isTypedWidth := false;
  if SymTab.IsLexSym(SymTab.SyDot) then begin
    { '.' already consumed (IsLexSym) -- what follows decides which of
      two grammar forms this is: PLAN.TXT S2.1's own '.BYTE'/'.WORD'
      explicit width selector (KwByte/KwWord are reserved keywords,
      never a real RECORD type's own name, so there is no ambiguity),
      or the pre-existing '.RecordType.field' structured-access form
      (any other identifier). }
    if SymTab.IsKw(SymTab.KwByte) or SymTab.IsKw(SymTab.KwWord) then begin
      if SymTab.IsKw(SymTab.KwByte) then sizeHint := 'byte' else sizeHint := 'word';
      SymTab.Next;
      isTypedWidth := true;
      { PLAN.TXT S2.1's own base-register restriction ("Accept 8086
        address forms only"... BX/BP/SI/DI, "Reject AX-based
        addresses... and other unsupported forms") only applies to
        THIS typed-width path, never to the pre-existing '.RecordType.
        field'/bare-memory forms (which have always accepted any
        register as base, unchanged, a pre-existing simplification out
        of PLAN.TXT's own scope) -- checked here, retroactively against
        the already-parsed baseNm, rather than earlier at parse time,
        since whether '.BYTE'/'.WORD' even follows isn't knowable until
        this exact point (TryParseEffAddr's own callers already reject
        an illegal base up front, but the OTHER two branches above --
        TRegPair's fused 'SEG:BASE', and the plain single-token
        fallback -- never restricted their own base register at all,
        so '[DS:AX].BYTE' silently reached here with no rejection
        before this check existed, confirmed the hard way via
        TESTS/EFFADDR.SMD's own negative case). A base that's already
        a full effective address (base+index, from TryParseEffAddr) is
        never re-checked here -- IsEffAddrBaseReg was already the
        gating condition for reaching that branch at all, so baseNm
        there is always already legal. }
      if not IsEffAddrBaseReg(baseNm) then begin
        msg := 'unsupported effective-address base register for .BYTE/.WORD: ' + baseNm;
        Scan.ReportError(msg)
      end;
      dst := dst + ']'; exit
    end;
    Scan.CurTokText(fieldName); SymTab.Next;   { RecordType name }
    ti := SymTab.FindType(fieldName);
    SymTab.Expect(SymTab.SyDot);
    Scan.CurTokText(fieldName); SymTab.Next;   { field name }
    dst := dst + ' + ';
    if ti >= 0 then begin
      SymTab.TypeName(ti, recTyName);
      dst := dst + recTyName + '.' + fieldName;
      if SymTab.TypeFindFieldTy(ti, fieldName, ftyp, fcnt) then begin
        RecTypes.SizeHintFor(ftyp.ty, sizeHint);
        if (fcnt <> 1) and not forAddress then begin
          msg := 'array field used as a scalar operand (only ADR() can address it): ' + recTyName + '.' + fieldName;
          Scan.ReportError(msg)
        end
      end
    end else
      dst := dst + fieldName
  end;
  dst := dst + ']'
end;

{ IsBuiltinName: TRUE for a value built-in (ADR/SEG/SIZE/LEN/ODD) name.
  LEN is checked differently from the other four (EqualICase alone,
  unconditionally winning over any same-named declared identifier,
  matching this function's own pre-existing behavior for ADR/SEG/SIZE/
  ODD, left unchanged here): LEN is new (PLAN.TXT S1.3) and collides
  with a real, already-widely-used parameter name in this project's
  own LIB/FILES.SMD (ClampToEnd/BlockRead/BlockWrite's own 'len: WORD'
  formal, used throughout their own bodies as a plain identifier, e.g.
  "IF remLo > len THEN") -- confirmed the hard way: TESTS/run_tests.py
  regressed CLAMPEOF/LZPBIG (both exercise FILES.SMD) the moment LEN
  was added here unconditionally, since EmitAssignRhs's own IsBuiltinName
  check runs BEFORE checking whether the identifier is separately
  declared. Rather than risk the same fix for ADR/SEG/SIZE/ODD (no
  known collision for any of those in this codebase, and changing
  their 34-years-established priority is a bigger, unrelated risk),
  LEN alone defers to an already-declared symbol of the same name --
  SymTab.FindSym(nm) < 0 means nm names nothing else, so it's safe to
  treat as the LEN() builtin; if the program already has its own VAR/
  param/CONST/PROC called len (any case), that declaration wins,
  exactly matching pre-LEN behavior for that program. }
function IsBuiltinName(const nm: string): boolean;
begin
  IsBuiltinName := EqualICase(nm, 'ADR') or EqualICase(nm, 'SEG')
                or EqualICase(nm, 'SIZE') or EqualICase(nm, 'ODD')
                or (EqualICase(nm, 'LEN') and (SymTab.FindSym(nm) < 0))
end;

{ IsGlobalVarName: TRUE if arg names a declared, non-local, non-register
  VAR -- SEG()'s own validity check. }
function IsGlobalVarName(const arg: string): boolean;
  var si: integer;
begin
  if SymTab.IsRegName(arg) then begin IsGlobalVarName := false; exit end;
  si := SymTab.FindSym(arg);
  IsGlobalVarName := (si >= 0) and not SymTab.SymIsLocal(si)
end;

{ EmitAdrOperand: resolves arg (already known to be a declared,
  non-register VAR/param -- global or local) to an ADR() operand text. }
procedure EmitAdrOperand(const arg: string; si: integer; var dst: string);
  var mem: string; msg: string;
begin
  if not SymTab.SymIsLocal(si) then begin
    dst := arg; exit
  end;
  if SymTab.SymIsReg(si) then begin
    msg := 'ADR() of a register-named param has no address: ' + arg;
    Scan.ReportError(msg); dst := '0'; exit
  end;
  SymOperandText(si, arg, mem);
  AppendInstr2(MnLea, 'ax', mem);
  dst := 'ax'
end;

function TryBuiltinOperand(var dst: string): boolean;
  var nm, arg, msg, mem, discardSize, nmPeek: string; ti, si, elemSzLen: integer;
      typ: SymTab.TTypeInfo; wasValid: boolean; discardTW: boolean;
begin
  TryBuiltinOperand := true;
  { nmPeek: the CURRENT token's own raw text, fetched once here before
    the whole ADR/SEG/SIZE/LEN/ODD dispatch chain below -- only LEN's
    own branch actually needs it (see that branch's own comment on
    why), but fetching it unconditionally, before Scan.CurTokKind is
    even checked, avoids re-deriving it differently inside that one
    branch depending on control flow. Scan.CurTokText itself is a
    cheap read of the already-scanned current token, never a re-scan. }
  Scan.CurTokText(nmPeek);
  if Scan.TokTextEqICase('ADR') then begin
    SymTab.Next; SymTab.Expect(SymTab.SyLParen);
    if Scan.CurTokKind = TIdent then begin
      Scan.CurTokText(arg); SymTab.Next;
      si := SymTab.FindSym(arg);
      if (si >= 0) and not SymTab.IsRegName(arg) then
        EmitAdrOperand(arg, si, dst)
      else if (not SymTab.IsRegName(arg)) and (SymTab.ProcFindAny(arg, wasValid) >= 0) then begin
        { ADR(ProcName): a PROCEDURE's own bare label name already IS its
          offset as a NASM immediate. OPT.TXT's own R6 finding: this
          procedure's own address is now escaping this call site's own
          visibility (installed as an interrupt vector, stored for a
          later indirect call, or handed to raw ASM) -- mark it so
          PHOpt.PAS's own deferred call-graph analysis conservatively
          treats this row's own output demand as fully unknown, never
          narrowed from only the direct, by-name call sites it can
          actually see. }
        SymTab.ProcSetAddressTaken(SymTab.ProcFindAny(arg, wasValid));
        dst := arg
      end
      else begin
        msg := 'ADR() requires a declared VAR, param, or PROCEDURE name: ' + arg;
        Scan.ReportError(msg); dst := '0'
      end
    end else if SymTab.IsSym(SymTab.SyLBrack) then begin
      { ADR([SEG:BASE].RecordType.field): the only way to get an array
        field's own address (SIZE(v)-BUF, arrays inside a RECORD have no
        standalone name of their own to ADR() the way a global/local
        array does) -- forAddress=true so ParseMemOperand doesn't reject
        an array field here the way it would as an ordinary value
        operand. A scalar field works here too (its address, same as
        ADR() of a plain scalar VAR), just less commonly useful. }
      SymTab.Next; ParseMemOperand(mem, discardSize, true, discardTW);
      AppendInstr2(MnLea, 'ax', mem);
      dst := 'ax'
    end else begin
      Scan.ReportError('expected variable or procedure name in ADR()'); SymTab.Next; dst := '0'
    end;
    SymTab.Expect(SymTab.SyRParen); exit
  end else if Scan.TokTextEqICase('SEG') then begin
    SymTab.Next; SymTab.Expect(SymTab.SyLParen);
    if Scan.CurTokKind = TIdent then begin
      Scan.CurTokText(arg); SymTab.Next;
      if not IsGlobalVarName(arg) then begin
        msg := 'SEG() requires a global VAR name: ' + arg;
        Scan.ReportError(msg); dst := '0'
      end else
        dst := 'seg ' + arg
    end else begin
      Scan.ReportError('expected variable name in SEG()'); SymTab.Next; dst := '0'
    end;
    SymTab.Expect(SymTab.SyRParen); exit
  end else if Scan.TokTextEqICase('SIZE') then begin
    { SIZE(type) keeps its original meaning (a scalar keyword or a
      declared RECORD TYPE name -- ti >= 0 wins first, unconditionally,
      exactly as before this PLAN.TXT S1.3 rework). SIZE(variable) is
      the new case: the complete storage size in bytes of ANY declared
      VAR (scalar, RECORD instance, plain 'T[N]' array, or a BASE64()/
      FILE()/"..." literal-initialized array), resolved via SymIsArr/
      SymIsLitInit rather than the old single "SymVal(si) > 0" test
      (which could no longer tell a literal-init's own BYTE COUNT
      apart from a plain array's own newly-added ELEMENT COUNT, both
      sharing the same SymVal field -- see GlobVar's own header comment
      on why reusing it is safe, and SymIsLitInit's own TSymChunk
      comment on why this flag exists at all). Array PARAMETERS are
      deliberately rejected (PLAN.TXT's own S1.3 scope note: "reject
      SIZE on array parameters to avoid confusing pointed-to data size
      with the two-byte address slot") -- a formal parameter's own
      stack slot never holds the array itself, only a 2-byte address
      into it, so SIZE() there would silently answer the wrong
      question no matter which of those two numbers it picked. }
    SymTab.Next; SymTab.Expect(SymTab.SyLParen);
    if Scan.CurTokKind = TIdent then begin
      Scan.CurTokText(nm); SymTab.Next;
      ti := SymTab.FindType(nm);
      si := SymTab.FindSym(nm);
      if ti >= 0 then begin typ.ty := TyRec; typ.recIdx := ti; dst := IntStr(longint(RecTypes.TySize(typ))) end
      else if (si >= 0) and (SymTab.SymKind(si) = SymVar) and SymTab.SymIsArr(si) and SymTab.SymIsParam(si) then begin
        msg := 'SIZE() of an array parameter is not supported (holds a 2-byte address, not the array): ' + nm;
        Scan.ReportError(msg); dst := '0'
      end else if (si >= 0) and (SymTab.SymKind(si) = SymVar) and SymTab.SymIsLitInit(si) then
        { BASE64()/FILE()/"..." literal-initialized array: SymVal is
          already the real decoded byte count, no further scaling. }
        dst := IntStr(SymTab.SymVal(si))
      else if (si >= 0) and (SymTab.SymKind(si) = SymVar) and SymTab.SymIsArr(si) then begin
        { plain 'T[N]' array VAR (not literal-init, not a parameter):
          SymVal now holds N, the declared element count -- total size
          is TySize(elementType) * N. }
        typ.ty := SymTab.SymTy(si); typ.recIdx := SymTab.SymRecIdx(si);
        dst := IntStr(longint(RecTypes.TySize(typ)) * SymTab.SymVal(si))
      end else if (si >= 0) and (SymTab.SymKind(si) = SymVar) then begin
        { an ordinary scalar VAR or a single RECORD instance -- total
          size is just TySize of its own declared type. }
        typ.ty := SymTab.SymTy(si); typ.recIdx := SymTab.SymRecIdx(si);
        dst := IntStr(longint(RecTypes.TySize(typ)))
      end else begin
        { not a declared VAR at all -- SIZE(type), the original path,
          unchanged: a scalar keyword (BYTE/WORD/INTEGER/LONGINT/
          BOOLEAN, or the CHAR/POINTER synonyms). }
        RecTypes.ParseBaseTypeName(nm, typ);
        dst := IntStr(longint(RecTypes.TySize(typ)))
      end
    end else begin
      Scan.ReportError('expected a type or variable name in SIZE()'); SymTab.Next; dst := '0'
    end;
    SymTab.Expect(SymTab.SyRParen); exit
  end else if Scan.TokTextEqICase('LEN') and (SymTab.FindSym(nmPeek) < 0) then begin
    { LEN(array) (PLAN.TXT S1.3, new): the element count of a declared
      array VAR, known at compile time. Guarded by SymTab.FindSym(nmPeek)
      < 0 (nmPeek is the CURRENT token's own real spelling, e.g. 'len'
      lowercase, fetched into a var ABOVE this whole if/else-if chain
      specifically for this check -- FindSym('LEN') the literal
      uppercase string would never match a lowercase declared 'len' at
      all, silently defeating this exact guard) -- an already-declared
      identifier of this exact spelling wins
      instead, same reasoning as IsBuiltinName's own matching guard,
      see that function's own comment) -- LIB/FILES.SMD has a real
      parameter literally named 'len' used as a plain identifier
      throughout ClampToEnd/BlockRead/BlockWrite's own bodies, which
      this check reaches too (OperandText -> TryBuiltinOperand, a
      different, more pervasive call path than IsBuiltinName's own
      EmitAssignRhs call site -- both needed the same guard). A plain
      'T[N]' array VAR returns N directly (SymVal, per ParseVarSection's
      own new SymSetVal(si, cnt) -- see GlobVar's own header comment). A
      BASE64()/FILE()/"..." literal-initialized array returns its own
      decoded byte count DIVIDED by its element size, rejecting a
      malformed payload whose byte count isn't evenly divisible by
      that size (PLAN.TXT's own wording: "LEN requires that this count
      be divisible by the element size; reject malformed typed
      payloads" -- a byte/CHAR-element array's own element size is
      always 1, so that specific combination can never actually
      trigger this rejection, only a WORD/INTEGER/LONGINT-element
      array's own literal init could). Array PARAMETERS and any non-
      array VAR/type are rejected outright: PLAN.TXT's own S1.3 scope
      note ("Initially reject LEN on array parameters: they carry an
      offset, not an actual length... A written formal bound does not
      prove the allocation size") -- there's no real element count to
      report for either case. }
    SymTab.Next; SymTab.Expect(SymTab.SyLParen);
    if Scan.CurTokKind = TIdent then begin
      Scan.CurTokText(nm); SymTab.Next;
      si := SymTab.FindSym(nm);
      if (si < 0) or (SymTab.SymKind(si) <> SymVar) or not SymTab.SymIsArr(si) then begin
        msg := 'LEN() requires a declared array VAR: ' + nm;
        Scan.ReportError(msg); dst := '0'
      end else if SymTab.SymIsParam(si) then begin
        msg := 'LEN() of an array parameter is not supported: ' + nm;
        Scan.ReportError(msg); dst := '0'
      end else if SymTab.SymIsLitInit(si) then begin
        typ.ty := SymTab.SymTy(si); typ.recIdx := SymTab.SymRecIdx(si);
        elemSzLen := RecTypes.TySize(typ);
        if (elemSzLen > 0) and (SymTab.SymVal(si) mod elemSzLen = 0) then
          dst := IntStr(SymTab.SymVal(si) div elemSzLen)
        else begin
          msg := 'LEN(): literal-initialized array''s own byte count is not divisible by its element size: ' + nm;
          Scan.ReportError(msg); dst := '0'
        end
      end else
        { plain 'T[N]' array VAR: SymVal is already N. }
        dst := IntStr(SymTab.SymVal(si))
    end else begin
      Scan.ReportError('expected a declared array VAR name in LEN()'); SymTab.Next; dst := '0'
    end;
    SymTab.Expect(SymTab.SyRParen); exit
  end;
  TryBuiltinOperand := false
end;

{ OperandText: one primary operand (register/ident/number/[mem]) as NASM
  text; does not consume a following operator. A plain identifier
  immediately followed by '(' is a call (result lands in AX). }
procedure OperandText(var dst: string);
  var discardSize, nm, castNm, discardOpnd: string; idxSi: integer; discardTW: boolean;
begin
  lastOperandWasIntReg := false;
  if Scan.CurTokKind = TNum then begin
    Scan.CurTokText(dst); SymTab.Next
  end else if Scan.CurTokKind = TChar then begin
    dst := IntStr(Scan.CurTokVal); SymTab.Next
  end else if Scan.CurTokKind = TStr then begin
    Scan.CurTokText(nm); InternStringLiteral(nm, dst); SymTab.Next
  end else if (Scan.CurTokKind = TIdent) and TryBuiltinOperand(dst) then begin
    { handled }
  end else if Scan.CurTokKind = TIdent then begin
    if SymTab.CurTokIsReg then begin
      Scan.CurTokText(dst); SymTab.Next;
      { REG.INTEGER / REG.WORD (DOCS/SPHINX.MD's new cast syntax) --
        only legal right here, immediately after a bare register token;
        a VAR name never reaches this branch at all. Consuming the
        suffix does not change dst (the register's own NASM text) --
        only the lastOperandWasIntReg side-channel, read by a caller
        that pre-peeked this same token stream (EmitCondJump/
        EmitMulDiv) for signedness. }
      if SymTab.IsLexSym(SymTab.SyDot) then begin
        if SymTab.IsKw(SymTab.KwInteger) then begin
          lastOperandWasIntReg := true; SymTab.Next
        end else if SymTab.IsKw(SymTab.KwWord) then begin
          SymTab.Next
        end else begin
          Scan.CurTokText(castNm);
          Scan.ReportError('expected INTEGER or WORD after ''.'': ' + castNm);
          SymTab.Next
        end
      end
    end
    else begin
      Scan.CurTokText(nm); SymTab.Next;
      if SymTab.IsLexSym(SymTab.SyLParen) then begin
        EmitCall(nm); dst := 'ax'
      end else if SymTab.IsLexSym(SymTab.SyLBrack) then begin
        { 'name[indexExpr]' -- array element indexing, only meaningful
          when name is itself array-typed (SymIsArr); anything else
          reaching here with a '[' following it is a translator error
          (SPHINX has no other use for '[' right after a bare
          identifier). }
        idxSi := SymTab.FindSym(nm);
        if (idxSi >= 0) and SymTab.SymIsArr(idxSi) then
          EmitIndexedOperand(idxSi, nm, dst, discardSize)
        else begin
          Scan.ReportError('''['' after a non-array name: ' + nm);
          dst := '0'; OperandText(discardOpnd); SymTab.Expect(SymTab.SyRBrack)
        end
      end else
        IdentOperandText(nm, dst)
    end
  end else if SymTab.IsSym(SymTab.SyLBrack) then begin
    SymTab.Next; ParseMemOperand(dst, discardSize, false, discardTW)
  end else if SymTab.IsSym(SymTab.SyMinus) then begin
    SymTab.Next;
    if Scan.CurTokKind = TNum then begin
      Scan.CurTokText(nm); dst := '-' + nm; SymTab.Next
    end else begin
      Scan.ReportError('expected numeric literal after unary ''-''');
      dst := '0'
    end
  end else if Scan.CurTokKind = TRegPair then begin
    { A tightly-spelled register pair (e.g. "DX:AX") reaching general
      operand parsing means it wasn't one of the 3 forms a register
      pair is actually valid in (DOCS/SPHINX.MD S11: 'var := pair;',
      'pair := var/call;', a LONGINT call argument) -- each of those is
      recognized by its OWN dedicated caller (ParseAssignOrCall,
      EmitAssignRhs, EmitCall's own argIdx loop) before ever reaching
      here. Reaching this branch means something like
      'x := DX:AX + 1;' or 'TakesWord(DX:AX)' (a non-LONGINT parameter)
      -- a real error, not silently accepted. Before this branch
      existed, Scan.CurTokText still returned the FIRST register's own
      raw text (RawNext populates tokText from the ordinary TIdent scan
      before ever deciding this is a TRegPair, and never clears it), so
      this fell into the final plain-token fallback below and silently
      used ONLY the first register as an ordinary operand -- the second
      register was dropped with no error at all (reproduced directly:
      'TakesWord(DX:AX)' against a WORD parameter pushed only DX, AX
      vanished). }
    Scan.ReportError('register pair not valid here (only as a LONGINT VAR''s value, target, or call argument)');
    dst := '0'; SymTab.Next
  end else begin
    Scan.CurTokText(dst); SymTab.Next
  end
end;

function OpInstr(const sym: string; var instr: word): boolean;
begin
  OpInstr := true;
  if sym = '+' then instr := MnAdd
  else if sym = '-' then instr := MnSub
  else if sym = '&' then instr := MnAnd
  else if EqualICase(sym, 'XOR') then instr := MnXor
  else OpInstr := false
end;

{ IsCallOperand: TRUE if the CURRENT (not yet consumed) token is going to
  be read by OperandText as a call rather than a register/const/VAR/
  builtin -- without consuming anything. }
function IsCallOperand: boolean;
  var nm: string;
begin
  if Scan.CurTokKind <> TIdent then begin IsCallOperand := false; exit end;
  Scan.CurTokText(nm);
  if SymTab.IsRegName(nm) then begin IsCallOperand := false; exit end;
  if IsBuiltinName(nm) then begin IsCallOperand := false; exit end;
  IsCallOperand := SymTab.FindSym(nm) < 0
end;

{ EmitTailOperand: reads the next chain operand into opnd, exactly like a
  bare OperandText call -- EXCEPT when IsCallOperand says the operand
  about to be read is itself a call: evaluating it would otherwise
  silently clobber destReg before the instruction combining destReg's
  OWN prior value with the call's result ever runs. }
procedure EmitTailOperand(const destReg: string; var opnd: string);
  var isCall: boolean;
begin
  isCall := IsCallOperand;
  if isCall then begin
    AppendInstr1(MnPush, destReg)
  end;
  OperandText(opnd);
  if isCall then begin
    AppendInstr2(MnMov, 'cx', destReg);
    AppendInstr1(MnPop, destReg);
    opnd := 'cx'
  end
end;

{ EmitExprTail: destReg already holds the first operand's value; consume
  left-to-right +,-,&,|,XOR,SHL,SHR chains. }
procedure EmitExprTail(const destReg: string);
  var opnd, sym: string; instr: word; matched: boolean;
begin
  repeat
    matched := false;
    if Scan.CurTokKind = TSym then begin
      Scan.CurTokText(sym);
      if (sym = '+') or (sym = '-') or (sym = '&') then begin
        SymTab.Next; matched := OpInstr(sym, instr);
        EmitTailOperand(destReg, opnd);
        AppendInstr2(instr, destReg, opnd)
      end
    end else if SymTab.IsKw(SymTab.KwShl) then begin
      SymTab.Next; EmitTailOperand(destReg, opnd);
      AppendInstr2(MnShl, destReg, opnd); matched := true
    end else if SymTab.IsKw(SymTab.KwShr) then begin
      SymTab.Next; EmitTailOperand(destReg, opnd);
      AppendInstr2(MnShr, destReg, opnd); matched := true
    end else if SymTab.IsKw(SymTab.KwXor) then begin
      SymTab.Next; EmitTailOperand(destReg, opnd);
      AppendInstr2(MnXor, destReg, opnd); matched := true
    end else if SymTab.IsKw(SymTab.KwOr) then begin
      SymTab.Next; EmitTailOperand(destReg, opnd);
      AppendInstr2(MnOr, destReg, opnd); matched := true
    end
  until not matched
end;

function IsRelSym(const s: string): boolean;
begin
  IsRelSym := (s = '=') or (s = '#') or (s = '<') or (s = '>') or (s = '<=') or (s = '>=')
end;

{ RelJumps: single source of truth for the relational-symbol-to-
  condition-code mapping (=,#,<,>,<=,>=). }
procedure RelJumps(const rel: string; var jt, jf: word);
begin
  if rel = '=' then begin jt := MnJe; jf := MnJne end
  else if rel = '#' then begin jt := MnJne; jf := MnJe end
  else if rel = '<' then begin jt := MnJl; jf := MnJge end
  else if rel = '>' then begin jt := MnJg; jf := MnJle end
  else if rel = '<=' then begin jt := MnJle; jf := MnJg end
  else if rel = '>=' then begin jt := MnJge; jf := MnJl end
  else begin jt := MnJe; jf := MnJne end
end;

{ RelJumpsUnsigned: RelJumps' own sibling for a WORD (unsigned) operand --
  '='/'#' are sign-independent (je/jne either way), so only <,>,<=,>= get
  a different mnemonic here. }
procedure RelJumpsUnsigned(const rel: string; var jt, jf: word);
begin
  if rel = '<' then begin jt := MnJb; jf := MnJae end
  else if rel = '>' then begin jt := MnJa; jf := MnJbe end
  else if rel = '<=' then begin jt := MnJbe; jf := MnJa end
  else if rel = '>=' then begin jt := MnJae; jf := MnJb end
  else RelJumps(rel, jt, jf)
end;

{ EmitRelational: 'a REL' already scanned into firstOpnd/rel; destReg is
  the boolean-result destination. Emits xor/cmp/Jcc -- terminal. 8086 has
  no SETcc (that's 386+), so the boolean result is built with a
  conditional jump instead.
  firstOpndIsInt: firstOpnd's own WORD/INTEGER-ness, resolved by the
  caller (EmitExprFrom) BEFORE this runs -- firstOpnd arrives already
  flattened to text here (same pre-existing limitation EmitCondJump's
  own isByteVar treatment used to have before it started peeking the
  raw identifier first), so only a bare register operand's own
  lastOperandWasIntReg state, captured by EmitExprFrom immediately
  after its own OperandText call, is knowable here -- a plain VAR name
  reaching this path keeps today's signed default (documented gap,
  DOCS/SPHO.MD). }
procedure EmitRelational(const firstOpnd, rel, destReg: string; firstOpndIsInt: boolean);
  var opnd, a: string; jt, jf: word;
      trueLbl, endLbl: integer;
begin
  OperandText(opnd);
  LoadIfMem(firstOpnd, 'ax', false, true, a);
  if SymTab.IsRegName(a) and IsZeroLiteral(opnd) then begin
    { 'a REL 0' -- "or a,a" sets the same flags as "cmp a,0", same
      optimization EmitCondJump's own condition-position check has. }
    AppendInstr2(MnOr, a, a)
  end else begin
    AppendInstr2(MnCmp, a, opnd)
  end;
  if firstOpndIsInt then RelJumps(rel, jt, jf) else RelJumpsUnsigned(rel, jt, jf);
  trueLbl := NewLabel; endLbl := NewLabel;
  AppendInstr1(jt, LabelName(trueLbl));
  if SymTab.IsRegName(destReg) and not Regs86.IsSegReg(Regs86.LookupReg(UpStr(destReg))) then begin
    { destReg := 0 -- xor destReg,destReg is the standard 8086 idiom,
      same optimization EmitExprFrom's own 'reg := 0;' case already
      gets (works for a byte register too, e.g. "xor al,al"). }
    AppendInstr2(MnXor, destReg, destReg)
  end else begin
    AppendInstr2(MnMov, destReg, '0')
  end;
  AppendInstr1(MnJmp, LabelName(endLbl));
  EmitLabel(trueLbl);
  AppendInstr2(MnMov, destReg, '1');
  EmitLabel(endLbl)
end;

{ EmitWidenByteToWord: destReg := ZeroExtend(srcByteReg) -- 8086 has no
  move-with-zero-extend, so this is the plain-8086 idiom. }
procedure EmitWidenByteToWord(const srcByteReg, destReg: string);
  var lo, hi: string;
begin
  if WordHalves(destReg, lo, hi) then begin
    if not EqualICase(srcByteReg, lo) then begin
      AppendInstr2(MnMov, lo, srcByteReg)
    end;
    AppendInstr2(MnXor, hi, hi)
  end else begin
    { destReg has no byte halves -- widen through AX, then move the full
      word across. }
    if not EqualICase(srcByteReg, 'AL') then begin
      AppendInstr2(MnMov, 'al', srcByteReg)
    end;
    AppendInstr2(MnXor, 'ah', 'ah');
    AppendInstr2(MnMov, destReg, 'ax')
  end
end;

{ LoadIfMem: cmp's two operands can't both be bare memory, and a bare
  memory operand compared against an immediate is ambiguous in size -- if
  opnd is a raw "[...]" memory operand, load it into scratchReg first and
  return that register's name instead.
  needWord: when isByteVar is TRUE, whether the CALLER actually needs a
  full word-sized result (comparing against a possibly-wide value) or
  only a byte-sized one is enough (a zero/nonzero test via "or"/"cmp
  al,0", or a comparison against another byte-range value) -- when
  FALSE, this skips EmitWidenByteToWord's own "mov ah,0" entirely and
  returns the byte half itself (e.g. "AL") as dst, since zero-extending
  into a register nothing downstream reads the top half of is pure
  waste (found via inspection: "IF someBoolVar THEN" was emitting
  "mov al,[x] / mov ah,0 / or ax,ax" when "mov al,[x] / or al,al" means
  the exact same thing, one instruction shorter). Ignored when isByteVar
  is FALSE (nothing to widen in the first place). }
procedure LoadIfMem(const opnd, scratchReg: string; isByteVar, needWord: boolean; var dst: string);
  var byteLo, byteHi: string;
begin
  if (opnd <> '') and (opnd[1] = '[') then begin
    if isByteVar then begin
      if not WordHalves(scratchReg, byteLo, byteHi) then byteLo := 'AL';
      AppendInstr2(MnMov, byteLo, 'byte ' + opnd);
      if needWord then begin
        EmitWidenByteToWord(byteLo, scratchReg);
        dst := scratchReg
      end else
        dst := byteLo
    end else begin
      AppendInstr2(MnMov, scratchReg, opnd);
      dst := scratchReg
    end
  end else if isByteVar and not needWord and EqualICase(opnd, scratchReg) then begin
    { opnd is ALREADY a register (not memory) -- the call-result case:
      a BYTE/BOOLEAN-returning procedure's own body only ever writes the
      low half (e.g. "AL := TRUE;"), the value is already sitting in
      scratchReg (AX) after EmitCall, nothing to load -- but the caller
      only needs a byte-sized test (needWord=FALSE, same reasoning as
      the memory case above), so hand back the LOW HALF's own name
      instead of the full register: testing the untouched high half
      (garbage from whatever the callee's own body clobbered it with,
      e.g. HasKey's raw "INT(16H)" leaving a pending key's scan code in
      AH) would silently corrupt an "or ax,ax"/"cmp ax,0" test. }
    if WordHalves(scratchReg, byteLo, byteHi) then dst := byteLo else dst := opnd
  end else
    dst := opnd
end;

{ MulDivOp: which of the three terminal-only operators EmitMulDiv is
  emitting for. }
const
  MulDivStar = 0; MulDivDiv = 1; MulDivMod = 2;

{ LoadMulDivOperand: mul/imul/div/idiv's own single explicit operand must
  be a register, never a bare immediate (8086 has no "mul imm16" form at
  all) NOR a bare "[...]" memory operand (legal on real 8086, but NASM/
  TASM reject it as size-ambiguous with no further annotation -- same
  ambiguity LoadIfMem already sidesteps for `cmp` by always loading
  through a register first, DOCS/SPHO.MD). So unless opnd is ALREADY a
  register name, this loads it into scratchReg, same shape as LoadIfMem.
  isByteVar: opnd names a BYTE/BOOLEAN-sized source (a byte MEMORY var,
  per PeekOperandIsByte -- a bare byte REGISTER already returns early via
  the IsRegName branch above, opndIsByte only matters for the memory
  case) -- mul/div's own explicit operand register (CX here) must then
  be loaded through its own byte half (CL) with the top half zeroed,
  never a bare word-sized mov, which would read one byte past a
  byte-sized var's own storage (same bug class LoadIfMem's own isByteVar
  guards against for cmp; found via "w := w2 DIV b;", b a BYTE local --
  "mov cx, [b]" read cx's high byte from whatever memory follows b). }
procedure LoadMulDivOperand(const opnd, scratchReg: string; isByteVar: boolean; var dst: string);
  var lo, hi: string;
begin
  if SymTab.IsRegName(opnd) then
    dst := opnd
  else if isByteVar and WordHalves(scratchReg, lo, hi) then begin
    AppendInstr2(MnMov, lo, 'byte ' + opnd);
    AppendInstr2(MnXor, hi, hi);
    dst := scratchReg
  end else begin
    AppendInstr2(MnMov, scratchReg, opnd);
    dst := scratchReg
  end
end;

{ EmitMulDiv: 'a (* | DIV | MOD)' already scanned into firstOpnd/op;
  destReg is the result destination. Terminal only (like EmitRelational)
  -- 8086 mul/imul (1-operand form) and div/idiv hard-clobber DX:AX, which
  would otherwise corrupt a left-to-right +/-/&/| chain's own running
  total mid-expression, so this is never invoked from EmitExprTail's own
  chain loop, only from EmitExprFrom's pre-chain dispatch (same as
  EmitRelational). firstOpndIsInt: same meaning/limitation as
  EmitRelational's own parameter -- WORD (unsigned mul/div) unless
  firstOpnd is a register carrying an explicit ".INTEGER" cast.
  srcIsByte: firstOpnd names a byte-sized MEMORY var (peeked by the
  caller, EmitExprFromEx, same as EmitExpr's own srcIsByte for the
  ordinary mov/chain path) -- widen through AL instead of a bare word
  mov, same reasoning as LoadMulDivOperand's own isByteVar above (found
  via "w := b * 2;", b a BYTE local -- "mov ax, [b]" read ax's high byte
  from whatever memory follows b, corrupting the multiplicand whenever
  that neighbor byte was nonzero). }
procedure EmitMulDiv(const firstOpnd: string; op: integer; const destReg: string; firstOpndIsInt: boolean; srcIsByte: boolean);
  var opnd, nm, opndLoaded: string; mulInstr, divInstr: word;
      bIsIntReg, opndIsByte: boolean;
begin
  Scan.CurTokText(nm);
  opndIsByte := (Scan.CurTokKind = TIdent) and not SymTab.IsRegName(nm)
    and PeekOperandIsByte(nm);
  OperandText(opnd);
  { the SECOND operand's own signedness only matters for a bare register
    cast (".INTEGER"/".WORD"); for MUL/DIV/MOD the two operands must agree
    in signedness to mean anything, so this trusts firstOpndIsInt (the
    plan's own single-sided design, matching EmitCondJump/EmitRelational
    -- 'a's type decides) and does not re-derive a second, independent
    signedness from opnd. Only a REGISTER opnd can carry an explicit,
    independently-conflicting ".WORD"/".INTEGER" cast of its own -- a
    plain literal or VAR/CONST name has no signedness annotation to
    disagree with, so it must never trip this check regardless of
    firstOpndIsInt (PLAN.TXT S1.2: fixing EmitExpr's own srcIsInt peek
    made firstOpndIsInt correctly TRUE for a plain INTEGER VAR far more
    often than before, which would otherwise have turned this
    "SymTab.IsRegName(opnd) and lastOperandWasIntReg" check's own
    non-register FALSE default into a constant false-positive mismatch
    against any such VAR combined with a bare literal/CONST divisor,
    e.g. "w DIV 4;" -- confirmed the hard way immediately after that
    fix landed). }
  if SymTab.IsRegName(opnd) then begin
    bIsIntReg := lastOperandWasIntReg;
    if bIsIntReg <> firstOpndIsInt then begin
      { Mismatched casts on the two sides is almost certainly a mistake --
        report it, but keep going with firstOpnd's own signedness so
        translation can still surface any further errors. }
      Scan.ReportError('mismatched WORD/INTEGER operands in */DIV/MOD (left is '
        + 'INTEGER=' + IntStr(ord(firstOpndIsInt)) + ', right is INTEGER='
        + IntStr(ord(bIsIntReg)) + ')')
    end
  end;
  { firstOpnd -> AX first (mul/div's own implicit operand). A byte-sized
    firstOpnd (srcIsByte) must widen through AL/AH instead of a bare
    word mov -- see this procedure's own header comment. }
  if srcIsByte then begin
    if not EqualICase(firstOpnd, 'AL') then AppendInstr2(MnMov, 'al', firstOpnd);
    AppendInstr2(MnXor, 'ah', 'ah')
  end else if not EqualICase(firstOpnd, 'AX') then begin
    AppendInstr2(MnMov, 'ax', firstOpnd)
  end;
  if op = MulDivStar then begin
    LoadMulDivOperand(opnd, 'cx', opndIsByte, opndLoaded);
    if firstOpndIsInt then mulInstr := MnImul else mulInstr := MnMul;
    AppendInstr1(mulInstr, opndLoaded)
    { result in AX; DX (high word) is unused -- SPHINX has no LONGINT-
      from-multiply widening in this pass, TySize's own 16-bit-only
      scope for */DIV/MOD. }
  end else begin
    { DIV/MOD: a literal 0 divisor is a translator-time error (the plan's
      own confirmed scope -- a runtime-computed zero divisor is left to
      the programmer/8086 INT 0 trap, same as today's total absence of
      any div-by-zero handling). }
    if IsZeroLiteral(opnd) then begin
      Scan.ReportError('DIV/MOD by literal 0');
      opnd := '1'   { fallback: keep translation going with a harmless divisor }
    end;
    LoadMulDivOperand(opnd, 'cx', opndIsByte, opndLoaded);
    if firstOpndIsInt then begin
      AppendInstr0(MnCwd);   { sign-extend AX into DX:AX }
      divInstr := MnIdiv
    end else begin
      AppendInstr2(MnXor, 'dx', 'dx');   { zero-extend AX into DX:AX }
      divInstr := MnDiv
    end;
    AppendInstr1(divInstr, opndLoaded);
    if op = MulDivMod then AppendInstr2(MnMov, 'ax', 'dx')   { remainder -> AX }
    { else: DIV's own quotient is already in AX }
  end;
  if not EqualICase(destReg, 'AX') then begin
    AppendInstr2(MnMov, destReg, 'ax')
  end
end;

{ EmitExprFrom: like EmitExpr, but the first operand's text was already
  scanned by the caller. A relational operator diverts to EmitRelational
  instead of the ordinary arithmetic mov+chain. }
{ callIsByte: TRUE when firstOpnd is a BYTE/BOOLEAN-returning call's own
  result ('ax', per EmitCall's convention), which EmitCall never narrows
  itself (only AL is promised there -- AH is genuinely whatever it was
  before the call). Zeroing AH happens right after the base value lands
  in destReg but BEFORE EmitExprTail's own chain loop runs below (found
  via TESTS/NOTCALL.SMD: zeroing only after the whole call -- as a first
  attempt at this fix did, in EmitExpr's own caller -- would leave stale
  AH corrupting a chained "SomeBoolCall() + 1" add before the fix ever
  ran). Scoped the same as srcIsByte's own widen path below: neither one
  protects EmitRelational's or EmitMulDiv's early-exit branches, matching
  how EmitExpr's own srcIsByte peek was already scoped before this fix --
  widening that scope is a separate concern, not part of this one. }
procedure EmitExprFromEx(const firstOpnd, destReg: string; srcIsByte: boolean; callIsByte: boolean; callerSrcIsInt: boolean);
  var rel: string; firstOpndIsInt: boolean;
begin
  { firstOpnd's own WORD/INTEGER-ness: for a bare register operand, only
    knowable here via lastOperandWasIntReg (a trailing ".INTEGER" cast,
    detected by OperandText itself); for a plain VAR name, firstOpnd
    arrives already flattened to NASM memory text ('[w]'/'[bp-2]') with
    no INTEGER-ness of its own left in it, so the caller (EmitExpr) must
    peek it BEFORE that flattening and pass the result through as
    callerSrcIsInt (PLAN.TXT S1.2 -- see EmitExpr's own comment on the
    "flag := w > x" bug this fixes). The two sources are mutually
    exclusive (firstOpnd is either a register or a flattened VAR/other
    operand, never both), so a plain OR combines them safely. Captured
    BEFORE any further OperandText call (inside EmitRelational/
    EmitMulDiv/EmitExprTail below) has a chance to overwrite
    lastOperandWasIntReg for a DIFFERENT operand. }
  firstOpndIsInt := (SymTab.IsRegName(firstOpnd) and lastOperandWasIntReg) or callerSrcIsInt;
  Scan.CurTokText(rel);
  if (Scan.CurTokKind = TSym) and IsRelSym(rel) then begin
    SymTab.Next;
    EmitRelational(firstOpnd, rel, destReg, firstOpndIsInt); exit
  end;
  { '*'/DIV/MOD: terminal-only, same restriction as the relational check
    just above -- diverts BEFORE EmitExprTail's own chain loop ever
    starts, so these can never appear mid-chain with +/-/&/| (IsChainOp
    deliberately has no entries for them). }
  if SymTab.IsSym(SymTab.SyStar) then begin
    SymTab.Next; EmitMulDiv(firstOpnd, MulDivStar, destReg, firstOpndIsInt, srcIsByte); exit
  end else if SymTab.IsKw(SymTab.KwDiv) then begin
    SymTab.Next; EmitMulDiv(firstOpnd, MulDivDiv, destReg, firstOpndIsInt, srcIsByte); exit
  end else if SymTab.IsKw(SymTab.KwMod) then begin
    SymTab.Next; EmitMulDiv(firstOpnd, MulDivMod, destReg, firstOpndIsInt, srcIsByte); exit
  end;
  { firstOpnd a byte register -- OR a byte-sized MEMORY var, per srcIsByte,
    a peek EmitExpr already did BEFORE OperandText flattened the
    identifier into this plain NASM text with no size marker of its own
    (e.g. '[bp-3]') -- landing in a word-sized destReg is a size mismatch:
    widen instead of a bare mov. Found via LZP.SMD's own "DX := b;", b a
    BYTE local: without srcIsByte this emitted 'mov DX, [bp-3]', a full
    word read from one byte of real storage. }
  if (SymTab.IsRegName(firstOpnd) and Regs86.IsByteReg(Regs86.LookupReg(UpStr(firstOpnd)))
      and (not SymTab.IsRegName(destReg) or not Regs86.IsByteReg(Regs86.LookupReg(UpStr(destReg)))))
     or (srcIsByte and (not SymTab.IsRegName(destReg) or not Regs86.IsByteReg(Regs86.LookupReg(UpStr(destReg))))) then
    EmitWidenByteToWord(firstOpnd, destReg)
  else if EqualICase(firstOpnd, destReg) then begin
    { firstOpnd already names the same register as destReg -- skip the
      no-op self-move entirely. }
  end else if SymTab.IsRegName(firstOpnd) and SymTab.IsRegName(destReg)
        and Regs86.IsSegReg(Regs86.LookupReg(UpStr(firstOpnd)))
        and Regs86.IsSegReg(Regs86.LookupReg(UpStr(destReg))) then begin
    { 'DS := CS;' -- 8086 has no segreg-to-segreg mov. The documented
      idiom is push/pop through the stack instead. }
    AppendInstr1(MnPush, firstOpnd);
    AppendInstr1(MnPop, destReg)
  end else if IsZeroLiteral(firstOpnd) and SymTab.IsRegName(destReg)
        and not Regs86.IsSegReg(Regs86.LookupReg(UpStr(destReg))) then begin
    { 'reg := 0;' -- xor reg,reg is the standard 8086 idiom. }
    AppendInstr2(MnXor, destReg, destReg)
  end else begin
    AppendInstr2(MnMov, destReg, firstOpnd)
  end;
  if callIsByte and SymTab.IsRegName(destReg)
     and not Regs86.IsByteReg(Regs86.LookupReg(UpStr(destReg))) then
    AppendInstr2(MnMov, 'ah', '0');
  EmitExprTail(destReg)
end;

procedure EmitExprFrom(const firstOpnd, destReg: string);
begin
  { callerSrcIsInt=false: every EmitExprFrom call site (unlike EmitExpr's
    own EmitExprFromEx call) already passes firstOpnd as either a bare
    register (its own lastOperandWasIntReg check inside EmitExprFromEx
    still applies) or a BYTE-typed VAR (never INTEGER) -- see EmitExpr's
    own header comment on why only ITS call site needed the new
    parameter. }
  EmitExprFromEx(firstOpnd, destReg, false, false, false)
end;

{ TryEmitOdd: 'ODD(x)' -- a terminal boolean expression like a
  relational, so handled where EmitExpr already knows the final destReg. }
function TryEmitOdd(const destReg: string): boolean;
  var arg: string; zeroLbl, endLbl: integer;
begin
  if not ((Scan.CurTokKind = TIdent) and Scan.TokTextEqICase('ODD')) then begin TryEmitOdd := false; exit end;
  SymTab.Next; SymTab.Expect(SymTab.SyLParen);
  OperandText(arg);
  SymTab.Expect(SymTab.SyRParen);
  zeroLbl := NewLabel; endLbl := NewLabel;
  AppendInstr2(MnMov, 'ax', arg);
  AppendInstr2(MnTest, 'ax', '1');
  AppendInstr1(MnJz, LabelName(zeroLbl));
  AppendInstr2(MnMov, destReg, '1');
  AppendInstr1(MnJmp, LabelName(endLbl));
  EmitLabel(zeroLbl);
  AppendInstr2(MnMov, destReg, '0');
  EmitLabel(endLbl);
  TryEmitOdd := true
end;

{ TryEmitLoad: 'LOADB()'/'LOADW()' (PLAN.TXT S2.3) -- reads DS:SI into
  AL/AX and advances SI by 1/2 per the current direction flag (lodsb/
  lodsw themselves; this translator never emits CLD/STD on its own,
  see SetDFlag, so the caller's own last SetDFlag call, if any, is
  what decides direction here, unchanged by this function). "Initially
  LOADB must be assigned directly to AL and LOADW to AX as shown, not
  embedded in a larger expression" -- enforced here by requiring
  destReg be EXACTLY 'al'/'ax' respectively; reaching this function
  with any other destReg (e.g. chained into a larger expression, or
  assigned to a plain WORD/BYTE VAR instead of the literal register)
  is a translator error, not a silent narrowing/widening. }
function TryEmitLoad(const destReg: string): boolean;
  var msg: string; isB: boolean;
begin
  TryEmitLoad := false;
  isB := SymTab.IsKw(SymTab.KwLoadB);
  if not (isB or SymTab.IsKw(SymTab.KwLoadW)) then exit;
  SymTab.Next; SymTab.Expect(SymTab.SyLParen); SymTab.Expect(SymTab.SyRParen);
  if isB and not EqualICase(destReg, 'al') then begin
    msg := 'LOADB() must be assigned directly to AL, not ''' + destReg + '''';
    Scan.ReportError(msg)
  end else if (not isB) and not EqualICase(destReg, 'ax') then begin
    msg := 'LOADW() must be assigned directly to AX, not ''' + destReg + '''';
    Scan.ReportError(msg)
  end else if isB then AppendInstr0(MnLodsb)
  else AppendInstr0(MnLodsw);
  TryEmitLoad := true
end;

{ ParsePortOperand: 'INPORTB('/'INPORTW('/'OUTPORTB('/'OUTPORTW(' 's own
  port argument -- PLAN.TXT S2.2's own "Initially allow only... DX or
  an immediate port number in 0..255. Larger port numbers must be
  loaded into DX first." A bare DX register is passed through as-is; a
  numeric literal outside 0..255 is a translator error (still emitted
  as written, same "report, then still emit the value as it was
  written" recovery this file's own CheckTypedWidthStore already
  established for an out-of-range .BYTE/.WORD immediate -- there is
  nothing further to protect here once the diagnostic is reported, and
  leaving the token/parse otherwise undisturbed avoids a cascade).
  Anything else (a different register, a VAR, an expression) is
  likewise a translator error -- PLAN.TXT's own "Initially allow
  only" scope note names exactly these two forms and nothing wider. }
function ParsePortOperand: string;
  var nm, msg: string; v: longint;
begin
  ParsePortOperand := '0';
  if (Scan.CurTokKind = TIdent) and SymTab.CurTokIsReg then begin
    Scan.CurTokText(nm); SymTab.Next;
    if EqualICase(nm, 'DX') then ParsePortOperand := 'dx'
    else begin
      msg := 'port operand must be DX or an immediate 0..255, not ''' + nm + '''';
      Scan.ReportError(msg)
    end
  end else if Scan.CurTokKind = TNum then begin
    v := Scan.CurTokVal;
    Scan.CurTokText(nm); SymTab.Next;
    if (v < 0) or (v > 255) then begin
      msg := 'port number out of range (0..255): ' + IntStr(v);
      Scan.ReportError(msg)
    end;
    ParsePortOperand := nm
  end else begin
    Scan.ReportError('port operand must be DX or an immediate 0..255');
    SymTab.Next
  end
end;

{ TryEmitInPort: 'INPORTB(port)'/'INPORTW(port)' -- like TryEmitLoad
  above, a terminal expression form that must be assigned directly to
  AL/AX respectively ("Initially allow only the exact accumulator
  destinations/values shown"). }
function TryEmitInPort(const destReg: string): boolean;
  var msg, portOpnd: string; isB: boolean;
begin
  TryEmitInPort := false;
  isB := SymTab.IsKw(SymTab.KwInPortB);
  if not (isB or SymTab.IsKw(SymTab.KwInPortW)) then exit;
  SymTab.Next; SymTab.Expect(SymTab.SyLParen);
  portOpnd := ParsePortOperand;
  SymTab.Expect(SymTab.SyRParen);
  if isB and not EqualICase(destReg, 'al') then begin
    msg := 'INPORTB() must be assigned directly to AL, not ''' + destReg + '''';
    Scan.ReportError(msg)
  end else if (not isB) and not EqualICase(destReg, 'ax') then begin
    msg := 'INPORTW() must be assigned directly to AX, not ''' + destReg + '''';
    Scan.ReportError(msg)
  end else if isB then AppendInstr2(MnInB, 'al', portOpnd)
  else AppendInstr2(MnInW, 'ax', portOpnd);
  TryEmitInPort := true
end;

{ PeekOperandIsByte: TRUE iff nm names a byte-sized operand -- a BYTE/
  BOOLEAN VAR, a BYTE/BOOLEAN-returning PROCEDURE call, or a bare byte
  register (AL/BL/...) -- called BEFORE OperandText consumes/flattens the
  identifier, same "peek the raw identifier first" pattern EmitCondJump's
  own aIsByteVar/PeekVarIsInt already use. A byte-sized value must only
  ever be loaded/stored via its own byte register (AL), never widened
  into AX -- loading two bytes from a one-byte VAR reads past its own
  storage into whatever memory follows it. }
function PeekOperandIsByte(const nm: string): boolean;
  var si, ty: integer;
begin
  PeekOperandIsByte := false;
  if SymTab.IsRegName(nm) then begin
    PeekOperandIsByte := Regs86.IsByteReg(Regs86.LookupReg(UpStr(nm))); exit
  end;
  si := SymTab.FindSym(nm);
  if (si >= 0) and (SymTab.SymKind(si) = SymVar) then begin
    ty := SymTab.SymTy(si);
    PeekOperandIsByte := (ty = TyByte) or (ty = TyBool)
  end else if SymTab.ProcFindRetTy(nm, ty) then
    PeekOperandIsByte := (ty = TyByte) or (ty = TyBool)
end;

{ TryEmitNot: '~x' as a general expression operand (SPHINX.MD §7.2) --
  x is expected to already be a clean 0/1 BOOLEAN (TRUE=1, FALSE=0,
  SPHINX.MD §3.1), so negation is a plain "xor ax,1", not a bitwise
  8086 `not` (which would flip every bit, not just bit 0). This is
  DISTINCT from `~` in condition position (IF/WHILE, EmitCondJump),
  which negates by picking the opposite Jcc instead of computing a
  value at all -- that path is unaffected by this one. Before this,
  `~` reaching OperandText's own final fallback branch (which just
  treats an unrecognized token as literal text) silently produced
  garbage operand text AND left the real operand token completely
  unconsumed, corrupting the parse of whatever statement followed
  (SPHINX.MD's own long-standing "not implemented" note for this). }
function TryEmitNot(const destReg: string): boolean;
  var opnd, nm: string; srcIsByte: boolean;
begin
  if not SymTab.IsSym(SymTab.SyTilde) then begin TryEmitNot := false; exit end;
  SymTab.Next;
  Scan.CurTokText(nm);
  srcIsByte := (Scan.CurTokKind = TIdent) and PeekOperandIsByte(nm);
  OperandText(opnd);
  { A call's own result -- PeekOperandIsByte(nm) correctly says TRUE for
    a BYTE/BOOLEAN-returning call (DOCS/SPHINX.MD S6.4: that return
    value logically lives in AL), but OperandText's own call branch
    always hands back the full 'ax' text (EmitCall's result register,
    never 'al' specifically -- there is no separate byte-sized call
    convention), so "mov al, opnd" here would be "mov al, ax", an
    invalid NASM register-size mismatch. 'AX' is the one 'srcIsByte'
    operand text that's never itself byte-sized: read AL (the same
    register's own low half, already holding the right value) instead
    of moving the whole word into it. }
  if srcIsByte then begin
    if EqualICase(opnd, 'AX') then begin end
    else if not EqualICase(opnd, 'AL') then AppendInstr2(MnMov, 'al', opnd);
    AppendInstr2(MnXor, 'al', '1')
  end else begin
    if not EqualICase(opnd, 'AX') then AppendInstr2(MnMov, 'ax', opnd);
    AppendInstr2(MnXor, 'ax', '1')
  end;
  if Regs86.IsByteReg(Regs86.LookupReg(UpStr(destReg))) then begin
    if not EqualICase(destReg, 'AL') then
      AppendInstr2(MnMov, destReg, 'al')
  end else if not EqualICase(destReg, 'AX') then begin
    AppendInstr2(MnMov, destReg, 'ax')
  end else if srcIsByte then begin
    { destReg IS 'AX' (the one case the branch above skips, since AX
      already looks like "no mov needed") -- but the srcIsByte path
      above only ever computed into AL ("xor al,1"), never touching AH,
      so a WORD destReg='ax' would otherwise silently inherit whatever
      garbage AH held before this call (found via NOT.SMD's own AH=5AH
      probe convention -- 'r := ~ReturnTrue()' printed 23041 (0x5A01)
      instead of 1, the exact AH=5AH leaking into the high byte of an
      INTEGER destination). Zero-extend explicitly. }
    AppendInstr2(MnMov, 'ah', '0')
  end;
  TryEmitNot := true
end;

{ TryEmitNeg: '-x' as a general expression operand (SPHINX.MD S7.1),
  e.g. "n := -n;" -- x is any ordinary operand (VAR, register, [mem],
  call result), computed via a genuine 8086 `neg` (two's-complement
  negation), unlike OperandText's own much narrower unary-'-' handling
  (SyMinus branch), which only ever accepted a following NUMERIC
  LITERAL and folded it into a compile-time-constant immediate text
  (e.g. "-5" -> the NASM text "-5", zero runtime cost) -- that literal
  fast path is intentionally left untouched here (still the cheaper
  option whenever it applies), so this function ONLY fires when the
  token right after '-' is NOT itself a numeric literal: peeked before
  consuming '-' at all, so OperandText's own literal path is undisturbed
  for "-5"/"-1"/etc, and this one handles everything else "-n"/"-AX"/
  "-Foo()"/"-[mem]" was reaching OperandText's own catch-all fallback
  before (mis-parsed as a bare '-' token) — the same class of "silently
  eats one token as garbage AND desyncs everything after it" bug
  TryEmitNot's own header comment already documents for '~'. }
function TryEmitNeg(const destReg: string): boolean;
  var opnd, nm: string; srcIsByte: boolean;
begin
  TryEmitNeg := false;
  if not SymTab.IsSym(SymTab.SyMinus) then exit;
  { The scanner has no lookahead past the current token (this file's
    own single-pass design, no exceptions elsewhere either) -- '-' must
    be consumed before the token AFTER it is even knowable, so a
    numeric literal there is handled right here instead of leaving it
    for OperandText's own SyMinus branch to fold (which can never be
    reached now that this check runs first in EmitExpr) -- same
    "-5" -> compile-time-constant-immediate-text behavior, just
    relocated, not changed. }
  SymTab.Next;
  if Scan.CurTokKind = TNum then begin
    Scan.CurTokText(opnd); opnd := '-' + opnd; SymTab.Next;
    AppendInstr2(MnMov, destReg, opnd);
    TryEmitNeg := true; exit
  end;
  Scan.CurTokText(nm);
  srcIsByte := (Scan.CurTokKind = TIdent) and PeekOperandIsByte(nm);
  OperandText(opnd);
  { Same 'AX' exception as TryEmitNot's own identical check above: a
    BYTE/BOOLEAN-returning call's result is still the full 'ax' text
    (never 'al'), so "mov al, ax" here would be an invalid NASM
    register-size mismatch -- read AL (the same register's own low
    half) directly instead. }
  if srcIsByte then begin
    if EqualICase(opnd, 'AX') then begin end
    else if not EqualICase(opnd, 'AL') then AppendInstr2(MnMov, 'al', opnd);
    AppendInstr1(MnNeg, 'al')
  end else begin
    if not EqualICase(opnd, 'AX') then AppendInstr2(MnMov, 'ax', opnd);
    AppendInstr1(MnNeg, 'ax')
  end;
  if Regs86.IsByteReg(Regs86.LookupReg(UpStr(destReg))) then begin
    if not EqualICase(destReg, 'AL') then
      AppendInstr2(MnMov, destReg, 'al')
  end else if not EqualICase(destReg, 'AX') then begin
    AppendInstr2(MnMov, destReg, 'ax')
  end else if srcIsByte then begin
    { Same AH-zero-extend fix as TryEmitNot's own identical case above:
      the srcIsByte path only ever computed into AL ("neg al"), never
      touching AH, so a WORD destReg='ax' would otherwise silently
      inherit whatever garbage AH held before this call. }
    AppendInstr2(MnMov, 'ah', '0')
  end;
  TryEmitNeg := true
end;

{ EmitExpr: parse an expression (via OperandText for its first operand)
  and leave its value in destReg (a valid instruction operand, e.g. "ax"). }
procedure EmitExpr(const destReg: string);
  var opnd, nm: string; srcIsByte, callIsByte, srcIsInt: boolean; si, ty: integer;
begin
  if TryEmitOdd(destReg) then exit;
  if TryEmitLoad(destReg) then exit;
  if TryEmitInPort(destReg) then exit;
  if TryEmitNot(destReg) then exit;
  if TryEmitNeg(destReg) then exit;
  { srcIsByte: only a genuine byte-sized MEMORY VAR needs this peek --
    NOT a call (SymTab.ProcFindRetTy case PeekOperandIsByte also covers,
    right for TryEmitNot/TryEmitNeg's own '~x'/'-x' operand, wrong here):
    OperandText already flattens a call's result to a register name
    ('ax') via EmitCall, so treating THAT text as a byte source here
    would feed EmitWidenByteToWord('ax','ax') -- a nonsense self-widen
    that emitted 'mov AL, ax', a real size mismatch, not a fix.

    callIsByte is the separate, correct way to handle a BYTE/BOOLEAN-
    returning call reaching here with no '~'/'-' at all (a plain "r :=
    SomeBoolCall();"): EmitCall's own result convention only promises
    AL, but nothing narrows AX before it lands in destReg -- firstOpnd
    and destReg are both literally 'ax' in EmitExprFromEx, so its own
    "already the same register" fast path skips the move as a no-op,
    silently carrying whatever garbage sat in AH straight into a WORD
    destination (found via TESTS/NOTCALL.SMD's own "r := ReturnThree()"
    probe, same AH=5AH-poisoning technique CALLBOOL.SMD's own DirtyFalse
    already established). Passed through to EmitExprFromEx itself
    (rather than zeroing AH here, after it returns) so the zero happens
    BEFORE EmitExprTail's own chain loop runs there -- zeroing only
    after the whole call, as a first attempt at this fix did here, left
    stale AH corrupting a chained "SomeBoolCall() + 1" add. }
  Scan.CurTokText(nm);
  srcIsByte := false; callIsByte := false; srcIsInt := false;
  if (Scan.CurTokKind = TIdent) and not SymTab.IsRegName(nm) then begin
    si := SymTab.FindSym(nm);
    if (si >= 0) and (SymTab.SymKind(si) = SymVar) then begin
      srcIsByte := (SymTab.SymTy(si) = TyByte) or (SymTab.SymTy(si) = TyBool);
      { srcIsInt: PLAN.TXT S1.2 -- a plain INTEGER VAR reaching a value-
        position relational ('flag := w > x;') used to always compare
        UNSIGNED regardless of its own declared signedness (only a bare
        register operand's own trailing ".INTEGER" cast was ever
        detected here), silently disagreeing with the SAME expression's
        own condition-position form ('IF w > x THEN'), which already
        correctly peeks the VAR's real type via EmitCondJump's own
        aIsInt (confirmed the hard way: w,x: INTEGER; w:=-1; x:=1 --
        "IF w>x" correctly says FALSE via a signed JLE, but "flag := w>x"
        used to say TRUE via an unsigned JA, since -1 as UNSIGNED WORD
        is 65535 > 1). PeekVarIsInt is this same peek-before-OperandText-
        flattens-it pattern EmitCondJump's own aIsInt already
        established, now finally wired up here too. }
      srcIsInt := PeekVarIsInt(nm)
    end else if (si < 0) and SymTab.ProcFindRetTy(nm, ty) then begin
      callIsByte := (ty = TyByte) or (ty = TyBool)
    end
  end;
  OperandText(opnd);
  EmitExprFromEx(opnd, destReg, srcIsByte, callIsByte, srcIsInt)
end;

{ PeekVarIsInt: TRUE iff nm names an already-declared global/local INTEGER
  VAR (SymTab.SymTy(si) = TyInt) -- called BEFORE OperandText consumes/
  flattens the identifier, same "peek the raw identifier first" pattern
  EmitCondJump's own aIsByteVar already uses. Registers are handled
  separately (via lastOperandWasIntReg, set by OperandText itself when a
  ".INTEGER" cast follows a bare register token) -- this helper only
  ever needs to run for a plain (non-register) identifier. Anything else
  (CONST, unresolved name, non-INTEGER VAR) defaults to FALSE (WORD/
  unsigned), matching the plan's documented default. }
function PeekVarIsInt(const nm: string): boolean;
  var si: integer;
begin
  PeekVarIsInt := false;
  si := SymTab.FindSym(nm);
  if (si >= 0) and (SymTab.SymKind(si) = SymVar) then
    PeekVarIsInt := (SymTab.SymTy(si) = TyInt)
end;

{ FlagJumps: CFLAG/ZFLAG tested directly, no `cmp` needed. }
function FlagJumps(const flagName: string; var jt, jf: word): boolean;
begin
  FlagJumps := true;
  if EqualICase(flagName, 'CFLAG') then begin jt := MnJc; jf := MnJnc; exit end
  else if EqualICase(flagName, 'ZFLAG') then begin jt := MnJz; jf := MnJnz; exit end;
  FlagJumps := false
end;

{ EmitCondJump: parses either a full relational condition ('a REL b') or
  a bare BOOLEAN condition -- a plain variable/register/call used
  directly, optionally preceded by '~'. opChunk/opSlot report back the
  chunk/slot of the ONE jump operation this call emits (there is always
  exactly one, whichever of the three branches below runs) -- ParseCondition
  (below) uses this to retarget the jump's own label text later via
  backpatching, if a condition composed with 'OR' turns out to need a
  different label than the one guessed here (SOPLAN.MD's own Phase 7:
  "Boolean condition composition with short-circuit lowering"). Every
  existing call site that doesn't care simply passes throwaway locals. }
procedure EmitCondJump(toLabel: integer; onTrue: boolean; var opChunk: POpChunk; var opSlot: integer);
  var a, aLoaded, b, rel, nm: string; jt, jf, buf: word; negated: boolean;
      si, ty: integer; aIsByteVar, aIsInt, aIsReg, bIsByteVar: boolean;
begin
  { '~CFLAG'/'~ZFLAG'/'CFLAG'/'ZFLAG': tested directly via the matching
    Jcc, skipping `cmp` entirely. }
  negated := SymTab.IsSym(SymTab.SyTilde);
  if negated then SymTab.Next;
  Scan.CurTokText(nm);
  if (Scan.CurTokKind = TIdent) and FlagJumps(nm, jt, jf) then begin
    SymTab.Next;
    nm := LabelName(toLabel);
    if onTrue then begin
      if negated then buf := jf else buf := jt
    end else begin
      if negated then buf := jt else buf := jf
    end;
    AppendInstr1Ref(buf, nm, opChunk, opSlot); exit
  end;
  { PLAN.TXT S1.5: 'ODD(x)' (a VALUE built-in, not a real procedure call)
    reaching here as condition operand 'a' -- e.g. "IF ODD(x) THEN" --
    used to fall through to the raw-identifier peek/OperandText path
    below, which only knows how to flatten a VAR/register/genuine CALL
    into memory/register text; ODD is neither (TryBuiltinOperand, the
    ADR/SEG/SIZE/LEN memory-operand-text path OperandText already
    delegates to, doesn't cover ODD either -- ODD needs real codegen, a
    TEST+Jcc pair, not just substitute text), so it fell all the way
    through to EmitCall's own "undefined procedure" error. Handled here
    directly, BEFORE the peek: evaluate 'ODD(x)' the same way any other
    value expression would (TryEmitOdd, into a scratch register), then
    test that register's own bit 0 result against zero exactly like any
    other bare BOOLEAN condition operand below -- CFLAG/ZFLAG's own
    direct-flag-test branch above, and every other relational form,
    are untouched. }
  if (Scan.CurTokKind = TIdent) and Scan.TokTextEqICase('ODD') and TryEmitOdd('ax') then begin
    a := 'ax'
  end else begin
  { Peek a's own identifier BEFORE OperandText flattens it to memory text. }
  aIsByteVar := false; aIsInt := false;
  Scan.CurTokText(nm);
  aIsReg := (Scan.CurTokKind = TIdent) and SymTab.IsRegName(nm);
  if (Scan.CurTokKind = TIdent) and not aIsReg then begin
    si := SymTab.FindSym(nm);
    if (si >= 0) and (SymTab.SymKind(si) = SymVar) then begin
      ty := SymTab.SymTy(si);
      aIsByteVar := (ty = TyByte) or (ty = TyBool);
      aIsInt := (ty = TyInt)
    end else if SymTab.ProcFindRetTy(nm, ty) then begin
      { 'a' is a call, e.g. "HasKey()" -- its result lands in AX via
        EmitCall/IsCallOperand's own convention, but a BYTE/BOOLEAN-
        returning procedure only ever guarantees AL is meaningful (its
        own body only ever writes AL, e.g. "AL := TRUE;"); AH is
        whatever it happened to be beforehand (real garbage for a
        procedure whose body runs a raw ASM/INT block that clobbers AH
        without the procedure's own SPHINX-level code ever touching
        it again -- HasKey's own "INT(16H)" is exactly this case: BIOS
        INT 16h/AH=01 leaves a pending key's scan code in AH). Testing
        the FULL AX (a bare "cmp ax,0"/"or ax,ax") against that garbage
        silently corrupts the condition. Same aIsByteVar treatment as a
        byte-sized VAR fixes it: LoadIfMem loads/tests only AL below. }
      aIsByteVar := (ty = TyByte) or (ty = TyBool)
    end
  end;
  OperandText(a);
  { a bare register operand's own signedness (default WORD/unsigned,
    unless OperandText just consumed a ".INTEGER" cast right after it)
    is only knowable AFTER OperandText has run -- see
    lastOperandWasIntReg's own comment. }
  if aIsReg then aIsInt := lastOperandWasIntReg
  end;
  Scan.CurTokText(rel);
  bIsByteVar := false;
  if (Scan.CurTokKind = TSym) and IsRelSym(rel) then begin
    SymTab.Next;
    { Peek b's own identifier BEFORE OperandText flattens it to memory
      text -- same pre-peek pattern as a's own, above, and only knowable
      now that SymTab.Next has consumed the relational operator itself
      (the current token right after OperandText(a) is still 'rel', not
      b's identifier yet). }
    Scan.CurTokText(nm);
    if (Scan.CurTokKind = TIdent) and not SymTab.IsRegName(nm) then begin
      si := SymTab.FindSym(nm);
      if (si >= 0) and (SymTab.SymKind(si) = SymVar) then begin
        ty := SymTab.SymTy(si);
        bIsByteVar := (ty = TyByte) or (ty = TyBool)
      end
    end;
    OperandText(b);
    { b already known here -- if it's a zero literal, the 'or reg,reg'
      path below never touches AH, so a byte-sized 'a' never needs
      widening to AX at all (see LoadIfMem's own needWord comment).
      Likewise if a AND b are BOTH byte-sized VARs/params (aIsByteVar/
      bIsByteVar, the latter pre-peeked above the same way a's own
      byte-ness was): widening 'a' alone to AX and comparing against a
      bare "[mem]" operand text for b would emit an unsized
      "cmp ax, [b]", which NASM/TASM then defaults to a WORD-sized read
      of a 1-byte stack/data slot -- picking up whatever adjacent byte
      happens to sit past b's own storage as high-byte garbage instead
      of zero-extending it, a real silent-corruption bug (found via
      FindMatch's own byte-vs-byte equality test in
      EXAMPLES/LZSS/LZSS.SMD). Keeping the comparison byte-sized on
      both sides (needWord=FALSE for a, "byte" prefix on b's own memory
      operand if it's memory-based) avoids ever forming that
      mismatched-width cmp -- only done when BOTH sides are byte-sized,
      since aLoaded itself is only byte-sized (AL) in that case; a
      WORD/INTEGER 'a' compared against a byte 'b' is a separate,
      still-unaddressed mixed-size case, out of scope for this fix. }
    LoadIfMem(a, 'ax', aIsByteVar, (not IsZeroLiteral(b)) and not (aIsByteVar and bIsByteVar), aLoaded);
    if SymTab.IsRegName(aLoaded) and IsZeroLiteral(b) then begin
      { 'reg REL 0' for ANY relational symbol -- "or reg,reg" sets
        CF=0, OF=0, SF/ZF/PF from the value, identically to "cmp reg,0"
        (a "sub" against 0 can never actually borrow or overflow), so
        every Jcc this file ever emits (signed or unsigned, RelJumps or
        RelJumpsUnsigned) reads the exact same flag outcome either way
        -- shorter encoding, not just for '='/'#'. }
      AppendInstr2(MnOr, aLoaded, aLoaded)
    end else if aIsByteVar and bIsByteVar and (b <> '') and (b[1] = '[') then begin
      AppendInstr2(MnCmp, aLoaded, 'byte ' + b)
    end else begin
      AppendInstr2(MnCmp, aLoaded, b)
    end;
    if aIsInt then RelJumps(rel, jt, jf) else RelJumpsUnsigned(rel, jt, jf);
    nm := LabelName(toLabel);
    if onTrue then begin
      if negated then buf := jf else buf := jt
    end else begin
      if negated then buf := jt else buf := jf
    end;
    AppendInstr1Ref(buf, nm, opChunk, opSlot)
  end else begin
    { Bare BOOLEAN condition -- 'a' alone, no REL operator followed it,
      always an implicit "compare against 0" -- a byte-sized 'a' never
      needs widening to AX for this (see LoadIfMem's own needWord
      comment). }
    LoadIfMem(a, 'ax', aIsByteVar, false, aLoaded);
    if not SymTab.IsRegName(aLoaded) and ((aLoaded = '') or (aLoaded[1] <> '[')) then begin
      { aLoaded is neither a register nor a '[...]' memory operand --
        a bare LITERAL (e.g. "WHILE TRUE DO", TRUE/FALSE resolving to
        the plain text '1'/'0' via SymTab's own builtin constants):
        LoadIfMem only routes a memory operand or an already-register
        call result through scratchReg (its own header comment), so a
        literal falls straight through unchanged -- the AppendInstr2
        call below would otherwise emit "cmp 1, 0"/"or 1, 1" DIRECTLY
        on the literal text, neither of which is valid 8086 (TASM
        rejects "cmp 1, 0" outright: "register or memory operand
        required", confirmed the hard way -- CMP/OR both need at least
        one register/memory operand, never two bare immediates). Load
        it into AX first, same as the memory case just above. }
      AppendInstr2(MnMov, 'ax', aLoaded);
      aLoaded := 'ax'
    end;
    if SymTab.IsRegName(aLoaded) then begin
      { 'IF a THEN'/'WHILE a DO' with a bare register -- "or reg,reg"
        sets ZF identically to "cmp reg,0" with a shorter encoding, same
        optimization the explicit '= 0'/'# 0' relational form above
        already gets. }
      AppendInstr2(MnOr, aLoaded, aLoaded)
    end else begin
      AppendInstr2(MnCmp, aLoaded, '0')
    end;
    nm := LabelName(toLabel);
    if onTrue then begin
      if negated then buf := MnJe else buf := MnJne
    end else begin
      if negated then buf := MnJne else buf := MnJe
    end;
    AppendInstr1Ref(buf, nm, opChunk, opSlot)
  end
end;

const
  MaxCondFactors = 16;  { generous bound on '&'-joined factors in one
                          AND-term -- no real condition in this codebase
                          comes close; matches the project's own small-
                          fixed-limit style (MaxParams/MaxUses = 32). }

type
  { TCondRefs: every jump operation ParseCondAndTerm emitted for ONE
    AND-term's own factors, each initially targeting falseLabel (the
    only choice knowable before parsing -- see ParseCondition's own
    header comment for why). ParseCondition backpatches every ref's
    own jump-target text in place via PatchCondRef, once the real
    target is known (SOPLAN.MD's own Phase 7 short-circuit lowering). }
  TCondRefs = record
    opChunk: array[0..MaxCondFactors-1] of POpChunk;
    opSlot:  array[0..MaxCondFactors-1] of integer;
    n:       integer
  end;

{ PatchCondRef: overwrite one already-emitted jump operation's own
  target-label text in place (mirrors CheckPendingCalls' own mnemonic
  patch for a forward call, SOPLAN.MD Phase 5) -- the operation's own
  mnemonic (MnJe/MnJne/MnJl/etc, decided by EmitCondJump from the real
  relational symbol) is untouched, only its operand (op1 field of a
  TOpInstr -- these are always single-operand "jCC label" jumps, so op1
  is the jump target; renamed from the pre-mnemonic:WORD-redesign "b")
  changes. }
procedure PatchCondRef(c: POpChunk; slot: integer; newLabel: integer);
begin
  c^.ops[slot].op1 := StrTab.Put(LabelName(newLabel))
end;

{ ParseCondAndTerm: one or more '&'-joined factors (DOCS/SPHINX.MD S7.4:
  "&" binds tighter than "OR"). Every factor's own jump is emitted
  against falseLabel (the only target knowable without lookahead -- see
  ParseCondition below), and its op ref recorded into refs so the
  caller can retarget every one of them in bulk later if needed. A
  single-factor AND-term with NO surrounding "OR" (the overwhelmingly
  common case) is never retargeted at all (ParseCondition below leaves
  refs pointed at falseLabel unchanged when no "OR" ever follows),
  so it costs nothing extra over today's direct EmitCondJump(falseLabel,
  false) call -- identical one Jcc, byte for byte. }
procedure ParseCondAndTerm(falseLabel: integer; var refs: TCondRefs);
  var opChunk: POpChunk; opSlot: integer;
begin
  refs.n := 0;
  EmitCondJump(falseLabel, false, opChunk, opSlot);
  refs.opChunk[refs.n] := opChunk; refs.opSlot[refs.n] := opSlot; Inc(refs.n);
  while SymTab.IsLexSym(SymTab.SyAmp) do begin
    EmitCondJump(falseLabel, false, opChunk, opSlot);
    if refs.n < MaxCondFactors then begin
      refs.opChunk[refs.n] := opChunk; refs.opSlot[refs.n] := opSlot; Inc(refs.n)
    end else
      Scan.ReportError('too many ''&''-joined conditions')
  end
end;

{ ParseCondition: the real IF/WHILE condition entry point -- one or more
  'OR'-joined AND-terms (DOCS/SPHINX.MD S7.4). Falls through to whatever
  code follows this call if the WHOLE condition is true; jumps to
  falseLabel if it's false -- exactly ParseIf/ParseWhile's own existing
  calling convention (today: EmitCondJump(elseLbl/exitLbl, false)
  directly), so both callers only need their one call site's target
  renamed, no control-flow change on their part.

  Short-circuit lowering via BACKPATCHING, standard technique (Aho/
  Sethi/Ullman): a term's own FAILURE must fall through to try the NEXT
  OR-term, not jump straight to falseLabel (which would wrongly reject
  the whole condition on the FIRST failed disjunct) -- but whether a
  term is the LAST one (and so genuinely SHOULD target falseLabel) is
  only knowable AFTER it's fully parsed (peeking for "OR" needs the
  term's own tokens already consumed; this scanner has no lookahead
  buffer to check before committing). So every term is optimistically
  parsed against falseLabel first (ParseCondAndTerm, above) -- correct
  by construction for the true last term, and for the overwhelmingly
  common case of no "OR" at all, this needs no further work. If "OR"
  turns out to follow, that guess was wrong: PatchCondRef retargets
  every one of the term's own recorded jump refs from falseLabel to a
  freshly allocated nextTermLabel instead (their mnemonics, decided by
  the real relational symbol, are untouched -- only the jump-target
  operand text changes), whose definition is placed right where the
  next OR-term's own condition code starts (so "term failed, try the
  next one" is simple fallthrough, no jump needed). A term's own
  SUCCESS must skip every remaining OR-term and reach the body directly
  -- trueLabel, allocated lazily (only once a 2nd OR-term is actually
  found) and emitted once, right after the whole OR-chain, immediately
  before whatever code was already going to run next (the body) -- so a
  condition with NO "OR" at all never allocates or emits it either,
  again matching today's output exactly. }
procedure ParseCondition(falseLabel: integer);
  var trueLabel, nextTermLabel, i: integer; haveTrueLabel: boolean;
      refs: TCondRefs;
begin
  haveTrueLabel := false;
  ParseCondAndTerm(falseLabel, refs);
  while SymTab.IsLexKw(SymTab.KwOr) do begin
    if not haveTrueLabel then begin trueLabel := NewLabel; haveTrueLabel := true end;
    nextTermLabel := NewLabel;
    for i := 0 to refs.n - 1 do
      PatchCondRef(refs.opChunk[i], refs.opSlot[i], nextTermLabel);
    AppendInstr1(MnJmp, LabelName(trueLabel));
    EmitLabel(nextTermLabel);
    ParseCondAndTerm(falseLabel, refs)
  end;
  if haveTrueLabel then EmitLabel(trueLabel)
end;

{ ---------------- statement translation ---------------- }

{ MoveAxToDest: after an AX-valued result, move it into destReg -- unless
  destReg already IS ax and isn't a memory operand. }
procedure MoveAxToDest(const destReg: string; destIsMem: boolean; const destSize: string);
begin
  if destIsMem and EqualICase(destSize, 'byte') then begin
    AppendInstr2(MnMov, 'byte ' + destReg, 'al')
  end else if destIsMem or not EqualICase(destReg, 'AX') then begin
    AppendInstr2(MnMov, destReg, 'ax')
  end
end;

{ IsChainOp: TRUE if tok is an operator EmitExprTail would consume. }
function IsChainOp: boolean;
begin
  IsChainOp := ((Scan.CurTokKind = TSym) and (SymTab.IsSym(SymTab.SyPlus)
       or SymTab.IsSym(SymTab.SyMinus) or SymTab.IsSym(SymTab.SyAmp)))
       or SymTab.IsKw(SymTab.KwShl)
       or SymTab.IsKw(SymTab.KwShr)
       or SymTab.IsKw(SymTab.KwXor)
       or SymTab.IsKw(SymTab.KwOr)
end;

{ Extract one staged word without clobbering already loaded registers.
  Keep the selected value below BP while AX compacts the remaining words. }
procedure ExtractRegArg(const regName: string; depthBytes: integer);
  var d: integer;
begin
  AppendInstr1(MnPush, 'bp');
  AppendInstr2(MnMov, 'bp', 'sp');
  d := depthBytes + 2;
  AppendInstr1(MnPush, 'word [bp+' + IntStr(longint(d)) + ']');
  AppendInstr1(MnPush, 'ax');
  while d > 2 do begin
    AppendInstr2(MnMov, 'ax', '[bp+' + IntStr(longint(d - 2)) + ']');
    AppendInstr2(MnMov, '[bp+' + IntStr(longint(d)) + ']', 'ax');
    Dec(d, 2)
  end;
  AppendInstr1(MnPop, 'ax');
  if EqualICase(regName, 'BP') then
    AppendInstr1(MnPop, 'word [bp]')
  else begin
    AppendInstr2(MnMov, regName, '[bp-2]');
    AppendInstr2(MnAdd, 'sp', '2')
  end;
  AppendInstr1(MnPop, 'bp');
  AppendInstr2(MnAdd, 'sp', '2')
end;

{ EmitCall: 'Name(' already consumed. Pushes actual params left to right
  (Pascal convention) -- EVERY argument, even one destined for a
  register-named formal parameter. Then `call`/`call far Name` depending
  on the callee's own FAR-ness. }
procedure EmitCall(const name: string);
  var opnd, nm, regNameTmp, callTarget: string; buf: word; isFar, isExternCallee: boolean;
      si, ty, pi, argIdx, nArgs, depthBytes, j: integer;
      isByteVar, wasValid, isLongArg, isRegPairArg, isLongVar, isLongCall: boolean;
      pairSeg, pairOff, pairConsumed, hiWord: string;
      argBytes: array[0..MaxParams-1] of integer;
      opRef: POpChunk; slotRef: integer;
      argIsReg: array[0..MaxParams-1] of boolean;
      argRegName: array[0..MaxParams-1] of SymTab.TRegName;
begin
  pi := SymTab.ProcFindAny(name, wasValid);
  argIdx := 0;
  { PLAN.TXT S1.6: a call with at least one argument, reached before
    'name' has ANY recorded signature at all (pi < 0 -- no real
    definition, FORWARD, or EXTERNAL declaration has been parsed yet
    for this name anywhere earlier in the module) cannot be emitted
    correctly here, full stop -- every decision the argument-parsing
    loop below makes (register-vs-stack placement, argBytes/LONGINT
    width, register-pair legality) depends on the callee's own real
    signature, which simply does not exist yet to consult. Unlike a
    NEAR/FAR mnemonic guess (EmitCall's own trailing PendingAppend/
    CheckPendingCalls, SOPLAN.MD Phase 5), there is no default that is
    merely "possibly wrong until re-checked later" -- literally nothing
    is known about argument count or placement, so guessing here can
    only silently corrupt the call (confirmed the hard way: a 2-arg
    call to a same-module procedure whose real 1-parameter definition
    comes later translated with NO argument-count error at all, one
    stack word never popped by the callee's own real "retn 2"; and a
    call passing a plain stack argument for what turns out to be a
    register-named parameter left the callee's own body reading
    whatever garbage already sat in that register, the pushed word
    never consumed by anything). A same-module forward call with NO
    arguments at all (EmitCallNoArgs, a separate procedure, never
    routes through here) is unaffected -- that path never had this
    problem, since a 0-argument call has no placement decision to get
    wrong, which is exactly why Phase 5 could safely drop FORWARD for
    it in the first place. }
  if (pi < 0) and not SymTab.IsSym(SymTab.SyRParen) then begin
    Scan.ReportError('call to ''' + name + ''' with arguments requires a prior'
      + ' declaration or FORWARD declaration in this module');
    exit
  end;
  { A register-pair argument (e.g. 'DX:AX') passed for a LONGINT
    parameter, when it isn't argument 0, pushes whatever DX:AX (or
    whichever pair) LIVE hold at its own position in the left-to-right
    evaluation order -- no snapshot/protection against an earlier
    argument's own evaluation clobbering them first. This is
    deliberately consistent with how a plain bare-register argument
    (e.g. 'Foo(Earlier(), AX)') already behaves: caller-sequencing
    hazard, not something this translator guards against. An earlier
    version of this procedure DID special-case register pairs with a
    PreScanRegPairArg lookahead + a dedicated __spho_regpair_snap
    memory cell to protect them from exactly this hazard -- removed as
    inconsistent special-casing once TRegPair (the scanner-level
    tightly-spelled "DX:AX" token) made register-pair ARGUMENTS common
    enough to notice the asymmetry with plain-register arguments, which
    never had this protection. }
  if not SymTab.IsLexSym(SymTab.SyRParen) then begin
    repeat
      if argIdx >= MaxParams then begin
        Scan.ReportError('too many call arguments'); exit
      end;
      argBytes[argIdx] := 2;
      isByteVar := false; isLongVar := false; isLongCall := false;
      si := -1;
      Scan.CurTokText(nm);
      if (Scan.CurTokKind = TIdent) and not SymTab.IsRegName(nm) then begin
        si := SymTab.FindSym(nm);
        if (si >= 0) and (SymTab.SymKind(si) = SymVar) then begin
          ty := SymTab.SymTy(si);
          isByteVar := (ty = TyByte) or (ty = TyBool);
          isLongVar := (ty = TyLong) and not SymTab.SymIsArr(si)
        end else if SymTab.ProcFindRetTy(nm, ty) then
          isLongCall := ty = TyLong
      end;
      argIsReg[argIdx] := SymTab.ProcParamIsReg(pi, argIdx, regNameTmp);
      argRegName[argIdx] := regNameTmp;
      isLongArg := SymTab.ProcParamIsLong(pi, argIdx);
      isRegPairArg := false;
      if isLongArg and ((Scan.CurTokKind = TRegPair) or
         ((Scan.CurTokKind = TIdent) and SymTab.IsRegName(nm))) then begin
        if TryParseRegPair(pairSeg, pairOff, pairConsumed) then begin
          { High word first, low word last, from live argument registers. }
          AppendInstr1(MnPush, pairSeg);
          AppendInstr1(MnPush, pairOff);
          isRegPairArg := true
        end else begin
          { A lone register is consumed here, then rejected as a partial
          LONGINT argument below. Consume its optional cast as well. }
          opnd := pairConsumed;
          lastOperandWasIntReg := false;
          if SymTab.IsLexSym(SymTab.SyDot) then begin
            if SymTab.IsKw(SymTab.KwInteger) then begin
              lastOperandWasIntReg := true; SymTab.Next
            end else if SymTab.IsKw(SymTab.KwWord) then
              SymTab.Next
            else begin
              Scan.ReportError('expected INTEGER or WORD after ''.''');
              SymTab.Next
            end
          end
        end
      end else if SymTab.ProcParamIsArray(pi, argIdx) and (si >= 0) and SymTab.SymIsArr(si) then begin
        { Array storage needs its address; a formal already stores one. }
        SymTab.Next;
        if SymTab.SymIsParam(si) then SymOperandText(si, nm, opnd)
        else EmitAdrOperand(nm, si, opnd)
      end else
        OperandText(opnd);
      if isLongArg and not isRegPairArg then begin
        if IsChainOp or isByteVar or
           (SymTab.IsRegName(opnd) and not isLongCall) then begin
          Scan.ReportError('LONGINT argument requires a full-width value or literal'); exit
        end
      end;
      if isRegPairArg then begin
        argBytes[argIdx] := 4
      end else if isLongArg and (isLongVar or isLongCall) then begin
        if isLongCall then begin
          AppendInstr1(MnPush, 'dx'); AppendInstr1(MnPush, 'ax')
        end else begin
          SpliceOffset(opnd, 2, hiWord);
          AppendInstr1(MnPush, 'word ' + hiWord);
          AppendInstr1(MnPush, 'word ' + opnd)
        end;
        argBytes[argIdx] := 4
      end else if IsChainOp then begin
        EmitExprFrom(opnd, 'ax');
        AppendInstr1(MnPush, 'ax')
      end else if SymTab.IsRegName(opnd) and Regs86.IsByteReg(Regs86.LookupReg(UpStr(opnd))) then begin
        { 8086 has no `push` for a byte register -- zero-extend into AX first. }
        EmitWidenByteToWord(opnd, 'ax');
        AppendInstr1(MnPush, 'ax')
      end else if SymTab.IsRegName(opnd) then begin
        AppendInstr1(MnPush, opnd)
      end else if isByteVar then begin
        AppendInstr2(MnMov, 'al', 'byte ' + opnd);
        AppendInstr2(MnMov, 'ah', '0');
        AppendInstr1(MnPush, 'ax')
      end else if isLongArg then begin
        { Literal/address arguments are zero-extended to two stack words. }
        argBytes[argIdx] := 4;
        AppendInstr2(MnXor, 'ax', 'ax');
        AppendInstr1(MnPush, 'ax');
        AppendInstr2(MnMov, 'ax', opnd);
        AppendInstr1(MnPush, 'ax')
      end else if IsZeroLiteral(opnd) then begin
        { 'Foo(0)' -- xor ax,ax is the standard 8086 idiom, same
          optimization EmitExprFrom's own 'reg := 0;' case already gets. }
        AppendInstr2(MnXor, 'ax', 'ax');
        AppendInstr1(MnPush, 'ax')
      end else if (Length(opnd) > 0) and (opnd[1] = '[') then begin
        { A plain memory operand (a global '[name]' or local '[bp+-N]')
          needs no AX at all -- 'push word [mem]' pushes it directly,
          both simpler than routing it through AX first AND avoiding a
          real clobbering bug that path caused: a call argument evaluated
          AFTER this one but earlier in program order could have already
          loaded a register-pair argument's own AX half (e.g.
          'DX := hi; AX := lo; Seek(targetH, DX:AX);' -- targetH is
          arg 0, evaluated as part of THIS call, after AX was already
          set up by the two statements before it), and 'mov ax, opnd'
          here would silently stomp that live AX, corrupting the
          register-pair argument's own low half before it was ever
          pushed (reproduced directly via EXAMPLES/CRK/APPLYCRK.SMD's
          own Seek(targetH, DX:AX) call: every diff line in a real
          MKCRK-generated .CRK patch wrote to the wrong file offset). }
        AppendInstr1(MnPush, 'word ' + opnd)
      end else begin
        AppendInstr2(MnMov, 'ax', opnd);
        AppendInstr1(MnPush, 'ax')
      end;
      Inc(argIdx)
    until not SymTab.IsLexSym(SymTab.SyComma);
    SymTab.Expect(SymTab.SyRParen)
  end;
  nArgs := argIdx;
  if (pi >= 0) and (nArgs <> SymTab.ProcNParams(pi)) then begin
    Scan.ReportError('call argument count differs from declaration'); exit
  end;
  argIdx := 0;
  while argIdx < nArgs do begin
    if argIsReg[argIdx] then begin
      depthBytes := 0;
      j := argIdx + 1;
      while j < nArgs do begin Inc(depthBytes, argBytes[j]); Inc(j) end;
      ExtractRegArg(argRegName[argIdx], depthBytes)
    end;
    Inc(argIdx)
  end;
  if not SymTab.ProcFindIsFar(name, isFar) then isFar := true;
  if isFar then buf := MnCallFar else buf := MnCall;
  isExternCallee := SymTab.ProcFindExternal(name, callTarget);
  if not isExternCallee then callTarget := name;
  AppendInstr1Ref(buf, callTarget, opRef, slotRef);
  { OPT.TXT's own R6 finding: stamp this call site with the resolved
    callee's own SymTab row (Types.TOperation's own callProcId field),
    but ONLY for a proven same-module, direct, by-name call with a REAL
    body in this module (pi>=0 and not external) -- PHOpt.PAS's own
    deferred call-graph analysis (built after CheckPendingCalls, once
    every pending call site is fully resolved) needs this to attribute
    a call site's own "what does the code right after this CALL read"
    proof back to the correct callee row; an EXTERNAL procedure's own
    pi is real (one row per name, same as any other), but its body
    lives outside this translation unit entirely, so it must stay
    unattributed (0, the default) rather than silently misidentifying
    opaque external code as something this analysis could reason about. }
  if (pi >= 0) and not isExternCallee then
    opRef^.ops[slotRef].callProcId := pi;
  if not SymTab.ProcFindIsFar(name, isFar) then
    PendingAppend(StrTab.Put(name), Scan.CurLine, opRef, slotRef)
end;

{ EmitCallNoArgs: 'Name' already consumed, no '(' at all. }
procedure EmitCallNoArgs(const name: string);
  var callTarget: string; buf: word; isFar, wasValid, isExternCallee: boolean; pi: integer;
      opRef: POpChunk; slotRef: integer;
begin
  pi := SymTab.ProcFindAny(name, wasValid);
  if (pi >= 0) and (SymTab.ProcNParams(pi) <> 0) then begin
    Scan.ReportError('call argument count differs from declaration'); exit
  end;
  if not SymTab.ProcFindIsFar(name, isFar) then isFar := true;
  if isFar then buf := MnCallFar else buf := MnCall;
  isExternCallee := SymTab.ProcFindExternal(name, callTarget);
  if not isExternCallee then callTarget := name;
  AppendInstr1Ref(buf, callTarget, opRef, slotRef);
  { OPT.TXT's own R6 finding -- see EmitCall's own identical comment
    above for why. }
  if (pi >= 0) and not isExternCallee then
    opRef^.ops[slotRef].callProcId := pi;
  if not SymTab.ProcFindIsFar(name, isFar) then
    PendingAppend(StrTab.Put(name), Scan.CurLine, opRef, slotRef)
end;

{ ---------------- LONGINT register-pair moves ---------------- }

{ LesLdsInstr: TRUE (with the right mnemonic) if seg:offReg is a valid
  LES/LDS target. }
function LesLdsInstr(const seg: string; var instr: word): boolean;
begin
  LesLdsInstr := true;
  if EqualICase(seg, 'ES') then begin instr := MnLes; exit end
  else if EqualICase(seg, 'DS') then begin instr := MnLds; exit end;
  LesLdsInstr := false
end;

{ IsPlainLongVar: TRUE if nm names a declared, non-CONST LONGINT variable,
  global or local. }
function IsPlainLongVar(const nm: string): boolean;
  var si: integer;
begin
  si := SymTab.FindSym(nm);
  IsPlainLongVar := (si >= 0) and (SymTab.SymKind(si) = SymVar) and (SymTab.SymTy(si) = TyLong)
end;

{ EmitRegPairStore: destSeg:destOff := srcSeg:srcOff (both already-read
  register-pair halves) -- always two plain word movs. }
procedure EmitRegPairStore(const destSeg, destOff, srcSeg, srcOff: string);
begin
  AppendInstr2(MnMov, destOff, srcOff);
  AppendInstr2(MnMov, destSeg, srcSeg)
end;

{ HighWordOperand: longVarMem is an already-bracketed memory operand;
  returns the operand for the dword's high 16 bits, by inserting "+2"
  just before the closing ']'. }
procedure HighWordOperand(const longVarMem: string; var dst: string);
begin
  dst := Copy(longVarMem, 1, Length(longVarMem) - 1) + '+2]'
end;

{ EmitRegPairFromLongVar: destSeg:destOff := longVarMem. LES/LDS in one
  instruction when destSeg is ES or DS, else the general two-mov
  fallback. }
procedure EmitRegPairFromLongVar(const destSeg, destOff, longVarMem: string);
  var hi: string; instr: word;
begin
  if LesLdsInstr(destSeg, instr) then begin
    AppendInstr2(instr, destOff, longVarMem)
  end else begin
    HighWordOperand(longVarMem, hi);
    AppendInstr2(MnMov, destOff, longVarMem);
    AppendInstr2(MnMov, destSeg, hi)
  end
end;

{ EmitLongVarFromRegPair: longVarMem := srcSeg:srcOff -- always the
  two-mov form. }
procedure EmitLongVarFromRegPair(const longVarMem, srcSeg, srcOff: string);
  var hi: string;
begin
  HighWordOperand(longVarMem, hi);
  AppendInstr2(MnMov, longVarMem, srcOff);
  AppendInstr2(MnMov, hi, srcSeg)
end;

{ TryParseRegPair: if the current token names a register immediately
  followed by ':' (a bare ':', never ':='), consume 'REG:REG' and return
  its two halves. }
function TryParseRegPair(var seg, offReg, consumedReg: string): boolean;
begin
  consumedReg := '';
  { Fast path: the scanner already recognized a tightly-spelled
    "REG:REG"/"SEGREG:REG" (no whitespace/comment inside it, e.g.
    "DX:AX") as one TRegPair token -- both names are already resolved,
    upper-cased, and known to be valid registers (Scan.IsPairReg), so
    there's nothing left to check here. This is the ONLY place
    TRegPair is consumed; every other caller of Scan.Next/SymTab.Next
    that doesn't go through TryParseRegPair never sees this token kind
    (ParseAssignOrCall's own top-level statement dispatcher is the one
    exception -- it checks for TRegPair directly, since a register
    pair as an assignment TARGET, not an RHS, never reaches this
    function at all). A loosely-spelled pair ("DX : AX", or a comment
    between the pieces) was never turned into a TRegPair by the
    scanner in the first place, so it still falls through to the
    original TIdent/':'/TIdent handling below exactly as before this
    token kind existed. }
  if Scan.CurTokKind = TRegPair then begin
    Scan.CurTokRegPair(seg, offReg);
    SymTab.Next;
    TryParseRegPair := true; exit
  end;
  Scan.CurTokText(seg);
  if (Scan.CurTokKind <> TIdent) or not SymTab.IsRegName(seg) then begin TryParseRegPair := false; exit end;
  SymTab.Next;
  if not SymTab.IsLexSym(SymTab.SyColon) then begin consumedReg := seg; TryParseRegPair := false; exit end;
  Scan.CurTokText(offReg);
  if (Scan.CurTokKind <> TIdent) or not SymTab.IsRegName(offReg) then begin
    Scan.ReportError('expected register after '':'' in register pair');
    offReg := 'AX'; TryParseRegPair := true; exit
  end;
  SymTab.Next;
  TryParseRegPair := true
end;

{ ParseRegPairAssignFromPair: destSeg/destOff already fully known
  (either read the old TIdent/':'/TIdent way by ParseRegPairAssign
  below, or straight from a scanner-recognized TRegPair token by
  ParseAssignOrCall) -- parses ':= RHS' and dispatches on the RHS's
  own shape. Split out from ParseRegPairAssign so a TRegPair-shaped
  assignment TARGET (never routed through TryParseRegPair -- that
  function only ever reads an RHS) can reach this same RHS-dispatch
  logic without re-deriving destOff from a token stream that, in the
  TRegPair case, has already moved past both register names. }
procedure ParseRegPairAssignFromPair(const destSeg, destOff: string);
  var srcSeg, srcOff, consumedReg, nm, longText, msg: string;
begin
  SymTab.Expect(SymTab.SyAssign);
  if TryParseRegPair(srcSeg, srcOff, consumedReg) then
    EmitRegPairStore(destSeg, destOff, srcSeg, srcOff)
  else if consumedReg <> '' then begin
    msg := 'register-pair RHS must be a LONGINT VAR, a register pair, or a call, not a single register: ' + consumedReg;
    Scan.ReportError(msg)
  end else if Scan.CurTokKind = TIdent then begin
    Scan.CurTokText(nm); SymTab.Next;
    if SymTab.IsLexSym(SymTab.SyLParen) then begin
      EmitCall(nm);
      EmitRegPairStore(destSeg, destOff, 'DX', 'AX')
    end else begin
      IdentOperandText(nm, longText);
      if not IsPlainLongVar(nm) then begin
        msg := 'register-pair RHS must be a LONGINT VAR or a call: ' + nm;
        Scan.ReportError(msg)
      end;
      EmitRegPairFromLongVar(destSeg, destOff, longText)
    end
  end else
    Scan.ReportError('expected LONGINT VAR, register pair, or call after '':='' in register-pair assignment')
end;

{ ParseRegPairAssign: 'destSeg:' already read; parses 'destOff := RHS'
  the old TIdent way, then delegates to ParseRegPairAssignFromPair. }
procedure ParseRegPairAssign(const destSeg: string);
  var destOff: string;
begin
  Scan.CurTokText(destOff);
  if (Scan.CurTokKind <> TIdent) or not SymTab.IsRegName(destOff) then begin
    Scan.ReportError('expected register after '':'' in register pair');
    destOff := 'AX'
  end else
    SymTab.Next;
  ParseRegPairAssignFromPair(destSeg, destOff)
end;

{ EmitAssignRhs: destSize is "byte"/"word"/"" -- the destination's own
  declared storage size when known. Also handles the reverse LONGINT
  register-pair direction: the RHS -- checked first -- may itself be a
  bare 'SEG:REG' register pair. }
procedure EmitAssignRhs(const destReg: string; destIsMem: boolean; const destSize: string; saveBase: boolean);
  var nm, opnd, sfx, srcSeg, srcOff, consumedReg: string;
      regId, si, ty: integer; gotReg, freshIsReg: boolean;
  procedure RestoreBase;
  begin
    if saveBase then AppendInstr1(MnPop, 'bx')
  end;
begin
  if saveBase then AppendInstr1(MnPush, 'bx');
  gotReg := false;
  if destIsMem then begin
    if TryParseRegPair(srcSeg, srcOff, consumedReg) then begin
      RestoreBase; EmitLongVarFromRegPair(destReg, srcSeg, srcOff); exit
    end else if consumedReg <> '' then begin
      nm := consumedReg; gotReg := true
    end
  end;
  { Fast path: '[mem] := SingleReg;' with no further chained operator. }
  freshIsReg := false;
  if (not gotReg) and destIsMem and (Scan.CurTokKind = TIdent) then begin
    Scan.CurTokText(nm); freshIsReg := SymTab.IsRegName(nm)
  end;
  if gotReg or freshIsReg then begin
    if not gotReg then SymTab.Next;
    { A trailing ".INTEGER"/".WORD" cast (DOCS/SPHINX.MD's new REG cast
      syntax) must be consumed here too -- OperandText's own cast-peek
      never runs on this fast path (it bypasses OperandText entirely for
      a bare register), so lastOperandWasIntReg is set by hand instead,
      exactly what OperandText would have left it as. }
    lastOperandWasIntReg := false;
    if SymTab.IsLexSym(SymTab.SyDot) then begin
      if SymTab.IsKw(SymTab.KwInteger) then begin lastOperandWasIntReg := true; SymTab.Next end
      else if SymTab.IsKw(SymTab.KwWord) then SymTab.Next
      else Scan.ReportError('expected INTEGER or WORD after ''.''')
    end;
    { '*'/DIV/MOD following the cast (if any) must NOT take the plain-mov
      fast path below -- EmitExprFrom's own dispatch, not IsChainOp, is
      what recognizes them (they're deliberately terminal-only, not
      chain operators). }
    if (not IsChainOp) and not SymTab.IsSym(SymTab.SyStar)
       and not SymTab.IsKw(SymTab.KwDiv) and not SymTab.IsKw(SymTab.KwMod) then begin
      opnd := UpStr(nm);
      regId := Regs86.LookupReg(opnd);
      if Regs86.IsByteReg(regId) then sfx := 'byte ' else sfx := 'word ';
      if destIsMem and EqualICase(destSize, 'byte') and not Regs86.IsByteReg(regId) then begin
        { 'byteVar := AX;' (or any other WORD-only register source into a
          BYTE-typed destination) -- sfx computed above ('word ', from
          the SOURCE register's own size) would silently ignore the
          destination's own declared BYTE size and store a full WORD,
          corrupting whatever 1 byte of memory sits immediately after
          the destination (found via EXAMPLES/LZSS/LZSS.SMD's own
          "b := AX; b := b & 1" pattern, b a BYTE local, AX a WORD
          register -- this clobbered the very next stack slot). Fall
          through to the general EmitExprFrom/MoveAxToDest path instead,
          which already correctly narrows via AL when destSize='byte'. }
      end else if destIsMem and EqualICase(destSize, 'word') and Regs86.IsByteReg(regId) then begin
        { 'wordVar := AL;' (a byte-register source into a KNOWN WORD/
          INTEGER-typed destination -- destSize='word' specifically,
          NOT '' -- see below) -- the mirror-image bug of the one just
          above: sfx computed above ('byte ', from the SOURCE
          register's own size) would silently ignore the destination's
          own declared WORD size and store only one byte, leaving the
          destination's own HIGH byte whatever value already happened
          to be sitting there (found via EXAMPLES/LZSS/LZP.SMD's own
          long-standing "cmdTailLen := AL;" idiom, cmdTailLen a WORD/
          INTEGER global -- silently correct only because a fresh
          .bss global happens to start zeroed; EXAMPLES/MIME/MIME.SMD's
          own byte-for-byte copy of the same CLI-parsing idiom is what
          surfaced this while auditing real generated output). Fall
          through to the general EmitExprFrom/MoveAxToDest path
          instead, which already correctly WIDENS via
          EmitWidenByteToWord when the source is a byte register and
          destReg is not (EmitExprFromEx's own header comment).
          destSize='' (unknown -- e.g. a raw '[DS:DI] := AL;' memory
          write with no declared VAR type at all, LIB/FILES.SMD's own
          BlockRead/BlockWrite byte-copy loops) must NOT take this
          branch: an untyped destination has no "own declared WORD
          size" to violate, so the SOURCE register's own size (byte,
          here) is exactly the right one to trust, same as it always
          was -- an earlier, broader version of this guard
          (destSize<>'byte' rather than destSize='word') wrongly
          widened these too, turning a correct single-byte buffer copy
          into a 2-byte write that corrupted the following byte
          (confirmed the hard way via TESTS/CLAMPEOF.SMD, which
          regressed from its own expected 40000 to 0 until this
          narrower condition replaced it). }
      end else begin
        RestoreBase; AppendInstr2(MnMov, sfx + destReg, nm);
        exit
      end
    end;
    EmitExprFrom(nm, 'ax');
    RestoreBase; MoveAxToDest(destReg, destIsMem, destSize);
    exit
  end;
  Scan.CurTokText(nm);
  if (Scan.CurTokKind = TIdent) and IsBuiltinName(nm) then begin
    if destIsMem then begin EmitExpr('ax'); RestoreBase; MoveAxToDest(destReg, destIsMem, destSize) end
    else EmitExpr(destReg);
    exit
  end;
  { Fast path: '[mem] := byteVar;' with no further chained operator and
    no RECORD-field size hint already known. }
  if destIsMem and (destSize = '') and (Scan.CurTokKind = TIdent) and not SymTab.IsRegName(nm) then begin
    si := SymTab.FindSym(nm);
    if (si >= 0) and (SymTab.SymKind(si) = SymVar) then begin
      ty := SymTab.SymTy(si);
      if (ty = TyByte) or (ty = TyBool) then begin
        Scan.CurTokText(nm); SymTab.Next;
        if not IsChainOp then begin
          IdentOperandText(nm, opnd);
          if (opnd <> '') and (opnd[1] = '[') then begin
            AppendInstr2(MnMov, 'al', 'byte ' + opnd);
            RestoreBase; AppendInstr2(MnMov, 'byte ' + destReg, 'al')
          end else begin
            RestoreBase; AppendInstr2(MnMov, 'byte ' + destReg, opnd)
          end;
          exit
        end;
        EmitExprFrom(nm, 'ax');
        RestoreBase; AppendInstr2(MnMov, 'byte ' + destReg, 'al');
        exit
      end
    end
  end;
  if destIsMem then begin
    EmitExpr('ax'); RestoreBase; MoveAxToDest(destReg, true, destSize)
  end else EmitExpr(destReg)
end;

{ EmitLongVarFromCallIfMatch: if the CURRENT token is 'name(' where name
  is a known PROCEDURE with declared return type LONGINT, consumes the
  whole call (via EmitCall, leaving its result in DX:AX per the
  documented LONGINT-return convention, DOCS/SPHINX.MD S6.4) and stores
  BOTH words into destMem (the caller's own already-resolved LHS
  operand text, e.g. "[sz]") -- returns TRUE. Otherwise consumes
  nothing and returns FALSE, so the caller falls through to the
  ordinary EmitAssignRhs/MoveAxToDest path unchanged.

  Exists because MoveAxToDest (used by every other assignment shape)
  only ever moves the LOW word AX into destMem -- correct for every
  scalar type this dialect has except LONGINT, where a bare call's
  result needs its DX half stored too (found via EXAMPLES/LZSS/LZSS.SMD's
  own "sz := FileSize(inH);": sz's own high word was silently left as
  stack garbage, corrupting a real program's own output whenever that
  garbage happened to be non-zero -- DOCS/SPHINX.MD S11 already
  documents 'SEGREG:REG := myfunction()' for the register-pair-LHS
  case, and this is the missing plain-LONGINT-variable-LHS twin of
  that same rule, not a new language feature). }
function EmitLongVarFromCallIfMatch(const destMem: string): boolean;
  var nm, hi: string; ty: integer;
begin
  EmitLongVarFromCallIfMatch := false;
  if Scan.CurTokKind <> TIdent then exit;
  Scan.CurTokText(nm);
  if SymTab.IsRegName(nm) then exit;
  if not SymTab.ProcFindRetTy(nm, ty) then exit;
  if ty <> TyLong then exit;
  SymTab.Next;
  if not SymTab.IsLexSym(SymTab.SyLParen) then begin
    { 'name' resolved to a LONGINT-returning PROCEDURE but wasn't
      actually followed by '(' -- not a call after all (e.g. some other
      construct that merely starts with this identifier); this shape
      doesn't arise in practice (a bare PROCEDURE name with no call
      parens isn't a valid RHS expression here), but bail out cleanly
      rather than silently mis-emitting if it ever does. }
    Scan.ReportError('expected ''('' after ''' + nm + '''');
    exit
  end;
  EmitCall(nm);
  HighWordOperand(destMem, hi);
  AppendInstr2(MnMov, destMem, 'ax');
  AppendInstr2(MnMov, hi, 'dx');
  EmitLongVarFromCallIfMatch := true
end;

{ CheckTypedWidthStore: PLAN.TXT S2.1's own strict store rules for a
  '.BYTE'/'.WORD'-typed memory destination -- STRICTER than the
  general EmitAssignRhs/MoveAxToDest machinery every OTHER memory
  destination here uses (that machinery silently narrows/widens a
  mismatched-width register source, a deliberate, already-established
  behavior for '.RecordType.field'/bare memory -- see EmitAssignRhs's
  own header comments on why). Peeks the CURRENT (not yet consumed)
  RHS token the same "peek before OperandText/EmitAssignRhs flattens
  it" pattern this file already uses throughout (PeekVarIsInt,
  EmitCondJump's own aIsByteVar, etc): a bare register source must
  match destSize's own width exactly ("initially require a matching-
  width register for register-to-memory stores"); a bare numeric
  literal must fit the destination's own width ("Diagnose out-of-range
  immediate stores rather than silently narrowing them" -- BYTE: 0..255,
  WORD: 0..65535). Anything else (a VAR name, a call, a chained
  expression) is unrestricted -- PLAN.TXT never asked for narrower
  rules THERE, only for a bare register or a bare immediate reaching
  this specific typed destination directly. }
{ CheckTypedWidthStore: PLAN.TXT S2.1's own strict store rules for a
  '.BYTE'/'.WORD'-typed memory destination -- STRICTER than the
  general EmitAssignRhs/MoveAxToDest machinery every OTHER memory
  destination here uses (that machinery silently narrows/widens a
  mismatched-width register source, a deliberate, already-established
  behavior for '.RecordType.field'/bare memory, left unchanged --
  scoped to ONLY '.BYTE'/'.WORD', this session's own explicit design
  decision). Peeks the CURRENT (not yet consumed) RHS token the same
  "peek before OperandText/EmitAssignRhs flattens it" pattern this
  file already uses throughout (PeekVarIsInt, EmitCondJump's own
  aIsByteVar, etc): a bare register source must match destSize's own
  width exactly ("initially require a matching-width register for
  register-to-memory stores"); a bare numeric literal must fit the
  destination's own width ("Diagnose out-of-range immediate stores
  rather than silently narrowing them" -- BYTE: 0..255, WORD:
  0..65535). Anything else (a VAR name, a call, a chained expression)
  is unrestricted -- PLAN.TXT never asked for narrower rules THERE,
  only for a bare register or a bare immediate reaching this specific
  typed destination directly. Never consumes any token itself -- purely
  a diagnostic pass; TryDirectImmStore (below) does the real parsing/
  consuming for the literal case, called separately by the caller. }
procedure CheckTypedWidthStore(const destSize: string);
  var nm, msg: string; regId: integer; v: longint;
begin
  if Scan.CurTokKind = TIdent then begin
    Scan.CurTokText(nm);
    if SymTab.IsRegName(nm) then begin
      regId := Regs86.LookupReg(UpStr(nm));
      if EqualICase(destSize, 'byte') and not Regs86.IsByteReg(regId) then begin
        msg := 'register-to-memory store to a .BYTE destination requires a byte register, not ''' + nm + '''';
        Scan.ReportError(msg)
      end else if EqualICase(destSize, 'word') and Regs86.IsByteReg(regId) then begin
        msg := 'register-to-memory store to a .WORD destination requires a word register, not ''' + nm + '''';
        Scan.ReportError(msg)
      end
    end
  end else if Scan.CurTokKind = TNum then begin
    v := Scan.CurTokVal;
    if EqualICase(destSize, 'byte') and ((v < 0) or (v > 255)) then begin
      msg := 'immediate store to a .BYTE destination out of range (0..255): ' + IntStr(v);
      Scan.ReportError(msg)
    end else if EqualICase(destSize, 'word') and ((v < 0) or (v > 65535)) then begin
      msg := 'immediate store to a .WORD destination out of range (0..65535): ' + IntStr(v);
      Scan.ReportError(msg)
    end
  end
end;

{ TryDirectImmStore: returns TRUE iff it fully handled the store itself
  (a bare numeric literal RHS with nothing chained after it -- the
  caller must skip EmitAssignRhs entirely in that case, the literal
  token already having been consumed here). Emits a direct 'mov word/
  byte [mem], imm' -- one instruction, no AX round-trip -- for ANY
  sized ('byte'/'word') memory destination, both the new '.BYTE'/
  '.WORD' typed form AND the pre-existing '.RecordType.field' one
  (unlike CheckTypedWidthStore's own strict rejection rules above,
  this codegen optimization is NOT scoped to '.BYTE'/'.WORD' only --
  there is no reason a genuinely simpler+shorter emission should be
  withheld from an ordinary RECORD field just because its own
  acceptance rules stay permissive). destSize='' (an untyped bare-
  memory destination, or a RECORD field of a type SizeHintFor has no
  byte/word mapping for, e.g. LONGINT) always returns FALSE --
  unchanged from before this function existed, since there is no known
  width to pick 'byte'/'word' from. FALSE for every other RHS shape (a
  register, a VAR, a call, a literal with something chained after it)
  -- the caller falls through to the ordinary EmitAssignRhs path
  unchanged in every one of those cases, exactly as before this
  function existed. }
function TryDirectImmStore(const destMem, destSize: string): boolean;
  var msg, sfx, litText: string; v: longint;
begin
  TryDirectImmStore := false;
  if (destSize = '') or (Scan.CurTokKind <> TNum) then exit;
  v := Scan.CurTokVal;
  if (EqualICase(destSize, 'byte') and ((v < 0) or (v > 255)))
     or (EqualICase(destSize, 'word') and ((v < 0) or (v > 65535))) then
    { Out of range for its own destination width -- CheckTypedWidthStore
      (the '.BYTE'/'.WORD'-only path) already reported this; a plain
      RECORD field never had this check at all (still doesn't -- this
      function only optimizes codegen, never adds a new rejection), so
      staying silent and falling through to the general EmitAssignRhs
      path here is correct for both callers: it either re-reports
      nothing new ('.BYTE'/'.WORD', already flagged) or emits the
      value exactly as it always did (a RECORD field, unchanged
      behavior). }
    exit;
  Scan.CurTokText(litText);
  SymTab.Next;
  if IsChainOp then begin
    { A literal WITH something chained after it (e.g. '[BX].WORD := 5 +
      1;') is not a bare immediate -- finish the computation via the
      general EmitExprFrom/MoveAxToDest path instead, same "already-
      consumed operand handed to EmitExprFrom as its own firstOpnd"
      shape EmitIncDecAmountToReg's own fast path uses for the
      identical reason (the literal token is already gone from the
      stream at this point, so the caller's own EmitAssignRhs can no
      longer re-parse it from scratch -- this function must finish the
      whole store itself once it reaches this branch). }
    EmitExprFrom(litText, 'ax');
    MoveAxToDest(destMem, true, destSize)
  end else begin
    if EqualICase(destSize, 'byte') then sfx := 'byte ' else sfx := 'word ';
    AppendInstr2(MnMov, sfx + destMem, litText)
  end;
  TryDirectImmStore := true
end;

{ ParseAssignOrCall: an assignment 'dst := expr' (dst is a register, a
  named var, or a '[seg:base]' direct memory operand) or a procedure
  call 'Name(args)'. }
procedure ParseAssignOrCall;
  var lhs, destSeg, destOff, buf, msg, destSize, hiWord: string; si: integer;
      isTypedWidth: boolean;
begin
  if SymTab.IsSym(SymTab.SyLBrack) then begin
    SymTab.Next; ParseMemOperand(buf, destSize, false, isTypedWidth);
    SymTab.Expect(SymTab.SyAssign);
    if isTypedWidth then CheckTypedWidthStore(destSize);
    if not TryDirectImmStore(buf, destSize) then
      EmitAssignRhs(buf, true, destSize, false)
  end else if Scan.CurTokKind = TRegPair then begin
    { A tightly-spelled register pair ("DX:AX", no whitespace inside
      it) as the assignment TARGET -- the scanner already recognized
      both register names as one token, so there's no ':' left in the
      token stream to look for the way the TIdent branch below does. }
    Scan.CurTokRegPair(destSeg, destOff);
    SymTab.Next;
    ParseRegPairAssignFromPair(destSeg, destOff)
  end else if Scan.CurTokKind = TIdent then begin
    Scan.CurTokText(lhs); SymTab.Next;
    si := SymTab.FindSym(lhs);
    if SymTab.IsLexSym(SymTab.SyLBrack) and (si >= 0) and SymTab.SymIsArr(si) then begin
      { 'name[indexExpr] := expr;' -- array element assignment, the
        write-side counterpart of OperandText's own 'name[indexExpr]'
        read (EmitIndexedOperand, above -- see its own header comment
        for the full design). }
      EmitIndexedOperand(si, lhs, buf, destSize);
      SymTab.Expect(SymTab.SyAssign);
      EmitAssignRhs(buf, true, destSize, Copy(buf, 1, 3) = '[bx')
    end
    else if SymTab.IsRegName(lhs) and SymTab.IsLexSym(SymTab.SyColon) then
      ParseRegPairAssign(lhs)
    else if SymTab.IsLexSym(SymTab.SyAssign) then begin
      if SymTab.IsRegName(lhs) then
        EmitAssignRhs(lhs, false, '', false)
      else begin
        si := SymTab.FindSym(lhs);
        if (si >= 0) and (SymTab.SymKind(si) = SymConst) then begin
          msg := 'cannot assign to a CONST: ' + lhs;
          Scan.ReportError(msg)
        end;
        SymOperandText(si, lhs, buf);
        if (si >= 0) and (SymTab.SymKind(si) = SymVar) then RecTypes.SizeHintFor(SymTab.SymTy(si), destSize)
        else destSize := '';
        if (si >= 0) and (SymTab.SymKind(si) = SymVar) and (SymTab.SymTy(si) = TyLong)
           and not SymTab.SymIsReg(si) and (Scan.CurTokKind = TNum) then begin
          { 'longVar := <plain numeric literal>;' -- DOCS/SPHINX.MD S14
            documents that a LONGINT value is never produced by a
            literal directly, but nothing stopped this assignment shape
            from parsing anyway, and the general EmitAssignRhs/
            MoveAxToDest path below only ever stores the LOW word
            (MoveAxToDest has no LONGINT-destination case at all,
            SizeHintFor's own 'else hint := ''''' branch for TyLong
            included) -- longVar's own high word was left holding
            whatever .bss garbage preceded it. Found via TESTS/
            LONGINT.SMD's own "v := 555;" followed by "lds BX, [v]"
            (a real 4-byte far-pointer read): the garbage high word
            landed in DS itself, corrupting every following memory
            access. Zero-extending here (the only sane reading of
            "assign a small positive literal to a 32-bit variable")
            turns this from silently-undefined into a real, safe
            32-bit store -- the low word still goes through the
            ordinary EmitAssignRhs path right after, unchanged. }
          HighWordOperand(buf, hiWord);
          AppendInstr2(MnMov, 'word ' + hiWord, '0')
        end;
        if (si >= 0) and (SymTab.SymKind(si) = SymVar) and (SymTab.SymTy(si) = TyLong)
           and not SymTab.SymIsReg(si) and EmitLongVarFromCallIfMatch(buf) then begin
          { handled -- 'longVar := SomeLongCall();': see
            EmitLongVarFromCallIfMatch's own comment for why this needs
            its own path (MoveAxToDest/EmitExprFrom, the general
            assignment machinery every other case here still uses, only
            ever move the LOW word AX -- a LONGINT-returning call's own
            DX half would otherwise be silently dropped). }
        end
        else if (si >= 0) and SymTab.SymIsReg(si) then EmitAssignRhs(buf, false, '', false)
        else EmitAssignRhs(buf, true, destSize, false)
      end
    end else if SymTab.IsLexSym(SymTab.SyLParen) then
      EmitCall(lhs)
    else if not SymTab.IsRegName(lhs) then
      EmitCallNoArgs(lhs)
    else begin
      msg := 'expected '':='' after register ''' + lhs + '''';
      Scan.ReportError(msg); SymTab.Next
    end
  end else if not SymTab.IsSym(SymTab.SySemi) then begin
    Scan.CurTokText(lhs);
    msg := 'unexpected ''' + lhs + '''';
    Scan.ReportError(msg); SymTab.Next
  end
end;

procedure ParseIf;
  var elseLbl, endLbl: integer;
begin
  elseLbl := NewLabel; endLbl := NewLabel;
  ParseCondition(elseLbl);
  SymTab.ExpectKw(SymTab.KwThen);
  ParseStmtList;
  while SymTab.IsLexKw(SymTab.KwElsif) do begin
    AppendInstr1(MnJmp, LabelName(endLbl));
    EmitLabel(elseLbl);
    elseLbl := NewLabel;
    ParseCondition(elseLbl);
    SymTab.ExpectKw(SymTab.KwThen);
    ParseStmtList
  end;
  if SymTab.IsLexKw(SymTab.KwElse) then begin
    AppendInstr1(MnJmp, LabelName(endLbl));
    EmitLabel(elseLbl);
    ParseStmtList
  end else
    EmitLabel(elseLbl);
  EmitLabel(endLbl);
  SymTab.ExpectKw(SymTab.KwEnd)
end;

procedure ParseWhile;
  var topLbl, exitLbl: integer;
begin
  topLbl := NewLabel; exitLbl := NewLabel;
  EmitLabel(topLbl);
  ParseCondition(exitLbl);
  SymTab.ExpectKw(SymTab.KwDo);
  Inc(comp.loopDepth); comp.loopExitStack[comp.loopDepth] := exitLbl; comp.loopContStack[comp.loopDepth] := topLbl;
  ParseStmtList;
  Dec(comp.loopDepth);
  AppendInstr1(MnJmp, LabelName(topLbl));
  EmitLabel(exitLbl);
  SymTab.ExpectKw(SymTab.KwEnd)
end;

{ ParseReturn: RETURN [expr] -- evaluates expr (if present) into AX (and
  DX too, if the enclosing procedure's own declared return type is
  LONGINT, DOCS/SPHINX.MD §6.4's DX:AX row), then jumps to procExitLbl,
  the current procedure's one epilogue label.

  A LONGINT return value is only ever a bare LONGINT VAR/CONST-free
  identifier -- the same "variable, not a general expression" limit
  DOCS/SPHINX.MD §11's own register-pair moves already have (see
  EmitRegPairFromLongVar/EmitLongVarFromRegPair, TryParseRegPair):
  nothing in this translator's LONGINT model ever produces a 32-bit
  result from an arithmetic chain or a nested call, so RETURN longExpr
  for anything but a bare variable is rejected rather than silently
  returning a truncated 16-bit value in AX with DX left stale (the bug
  this fixes -- DOCS/SPHINX.MD's own worked example, §11's
  "SEGREG:REG := myfunction()", depends on DX actually being loaded). }
procedure ParseReturn;
  var nm, msg, longMem, hi, seg, offReg, consumedReg: string;
begin
  if not SymTab.IsSym(SymTab.SySemi) and (Scan.CurTokKind <> TEof) and not SymTab.IsKw(SymTab.KwEnd)
     and not SymTab.IsKw(SymTab.KwElse) and not SymTab.IsKw(SymTab.KwElsif) then begin
    consumedReg := '';
    Scan.CurTokText(nm);
    if (ctx.procRetTy = TyLong)
       and ((Scan.CurTokKind = TRegPair)
            or ((Scan.CurTokKind = TIdent) and SymTab.IsRegName(nm)))
       and TryParseRegPair(seg, offReg, consumedReg) then begin
      { 'RETURN SEGREG:REG' / 'RETURN REG:REG' -- DOCS/SPHINX.MD §11's
        own register-pair syntax, reused here for a LONGINT RETURN: the
        value must end up in DX:AX regardless of which pair it started
        in (§6.4's own DX:AX return-register convention), so this is
        skipped entirely (a no-op move) when the pair IS already DX:AX,
        and a plain two-mov shuffle otherwise -- never LES/LDS (nothing
        here is a memory operand to load FROM, unlike
        EmitRegPairFromLongVar's own VAR-sourced case). }
      if not (EqualICase(seg, 'DX') and EqualICase(offReg, 'AX')) then begin
        if not EqualICase(offReg, 'AX') then AppendInstr2(MnMov, 'ax', offReg);
        if not EqualICase(seg, 'DX') then AppendInstr2(MnMov, 'dx', seg)
      end;
      AppendInstr1(MnJmp, '.return');
      exit
    end;
    { TryParseRegPair (above) consumes a lone register token (no ':'
      following) even when it returns FALSE, via its own consumedReg
      out-param -- nm must be resynced from that, not the original
      pre-call peek, before falling into the ordinary LONGINT-VAR/
      EmitExpr paths below, exactly like ParseRegPairAssign's own
      dispatch does. When TryParseRegPair was never even attempted
      (procRetTy <> TyLong, or the first token wasn't a register at
      all), nm already holds the right peeked text from above. }
    if consumedReg <> '' then nm := consumedReg;
    if (ctx.procRetTy = TyLong) and ((consumedReg <> '') or (Scan.CurTokKind = TIdent)) then begin
      if (not SymTab.IsRegName(nm)) and IsPlainLongVar(nm) then begin
        SymTab.Next;
        if IsChainOp or SymTab.IsSym(SymTab.SyLParen) then begin
          msg := 'RETURN of a LONGINT expression is only supported for a bare LONGINT variable, not '''
                  + nm + ''' combined with a further operator/call';
          Scan.ReportError(msg)
        end else begin
          IdentOperandText(nm, longMem);
          HighWordOperand(longMem, hi);
          AppendInstr2(MnMov, 'ax', longMem);
          AppendInstr2(MnMov, 'dx', hi)
        end;
        AppendInstr1(MnJmp, '.return');
        exit
      end;
      msg := 'RETURN of a LONGINT expression is only supported for a bare LONGINT variable, not ''' + nm + '''';
      Scan.ReportError(msg);
      { consumedReg <> '' means TryParseRegPair already consumed this
        token (a bare register with no ':' pair following it) -- must
        not consume a SECOND, unrelated token here. }
      if consumedReg = '' then SymTab.Next;
      AppendInstr1(MnJmp, '.return');
      exit
    end;
    EmitExpr('ax')
  end;
  AppendInstr1(MnJmp, '.return')
end;

{ ParseAsm: copies raw text verbatim until a line whose first word is
  END. }
procedure ParseAsm;
  var buf, word: string; atEnd: boolean;
begin
  SymTab.SkipAsmLead;
  atEnd := false;
  while not atEnd do begin
    SymTab.ReadAsmLine(buf, word, atEnd);
    if not atEnd then begin
      if EqualICase(word, 'END') then
        atEnd := true
      else begin
        buf := TrimStr(buf);
        if buf <> '' then Emit(buf)
      end
    end
  end;
  SymTab.Next
end;

{ AddSubMnemonic: the plain-inc/dec mnemonic's own two-operand
  equivalent -- "inc"->"add", "dec"->"sub". }
procedure AddSubMnemonic(mnemonic: word; var dst: word);
begin
  if mnemonic = MnInc then dst := MnAdd
  else dst := MnSub
end;

{ EmitIncDecAmountToReg: nm is the register being INC'd/DEC'd by a
  second-argument expr. }
procedure EmitIncDecAmountToReg(const nm: string; mnemonic: word);
  var opnd: string; addSub: word; nmIsAx, nmIsAl, protectAx: boolean;
      saveId: word;
begin
  nmIsAx := EqualICase(nm, 'ax');
  { AL is exactly as self-referential as AX (INC(AX,expr)'s own
    documented "AX must survive evaluating expr" case, DOCS/SPHINX.MD
    S9): EmitExpr('ax') below always computes expr into the FULL AX
    first (the only shape EmitExpr knows how to produce, even for a
    byte-sized nm) -- if nm were AL itself, that overwrites AL's own
    OLD value with expr's low byte before the add/sub ever runs, the
    same corruption AX's own dedicated push/pop path exists to avoid.
    Any OTHER byte register (BL/CL/DL/AH/BH/CH/DH) has no such hazard
    -- it isn't touched by EmitExpr('ax') at all. }
  nmIsAl := EqualICase(nm, 'al');
  { protectAx: INC/DEC(otherReg, expr) -- otherReg isn't AX/AL itself.
    Translated exactly the same shape 'otherReg := otherReg + expr'
    already uses (no separate carry register at all): push the
    CALLER's own incoming AX/AL (may still be live -- e.g.
    "AL := [DS:SI]; ...; DI := ADR(buf); INC(DI, i); [DS:DI] := AL",
    found via EXAMPLES/LZSS/LZSS.SMD's own Refill, where AL's freshly-
    read byte was silently zeroed/corrupted by this exact call before
    the final store used it), compute expr into AX via EmitExpr, apply
    it to destReg DIRECTLY from AX (add/sub destReg, ax -- no
    intermediate carry register at all, so no risk of colliding with
    some OTHER live register the way carrying the amount through CX
    used to whenever CX itself was independently in use by the caller
    at the call site -- found via EXAMPLES/LZSS/LZSS.SMD's own
    "INC(SI, srcIdx)" inside a CX-counted loop, where the old CX-carry
    path silently clobbered the loop's own live counter), then restore
    the caller's original AX from the stack. }
  protectAx := not (nmIsAx or nmIsAl);
  AddSubMnemonic(mnemonic, addSub);
  { Fast path: expr is a single bare register or plain numeric literal
    with nothing chained after it -- OperandText for either of those
    two forms never touches AX/CX/any register at all (it just returns
    NASM operand text), so the whole push-AX/EmitExpr/pop-AX dance the
    general path below needs is pure overhead here and can be skipped
    entirely: apply opnd to destReg directly, AX never disturbed at
    all (not even saved/restored -- there is nothing to protect it
    from). Only tried when protectAx (nmIsAx/nmIsAl are already
    self-referential regardless of what expr's own shape is, so they
    always need the general EmitExpr('ax') path below). A bare
    register operand here is used as-is (word or byte, matching
    whatever nm itself needs -- 8086 requires the two add/sub operands
    to already agree in size, which callers of INC/DEC(reg, expr)
    are responsible for, same as any other explicit-register op in
    this dialect). }
  if protectAx and ((Scan.CurTokKind = TNum)
     or ((Scan.CurTokKind = TIdent) and SymTab.CurTokIsReg)) then begin
    OperandText(opnd);
    if not IsChainOp then begin
      AppendInstr2(addSub, nm, opnd);
      exit
    end;
    { a chain followed after all -- fall through to the general path,
      evaluating the ALREADY-CONSUMED opnd as EmitExprFrom's own
      firstOpnd instead of re-parsing it from scratch. }
    saveId := EmitGenSavePush('ax');
    EmitExprFrom(opnd, 'ax')
  end else begin
    if nmIsAx or nmIsAl or protectAx then saveId := EmitGenSavePush('ax')
    else saveId := 0;
    EmitExpr('ax')
  end;
  if nmIsAx then begin
    { INC(AX, expr)/DEC(AX, expr): expr's own value is already in AX;
      the caller's OLD AX sits on the stack (pushed above). BX is used
      as the scratch to carry expr's value across the pop -- NOT CX,
      unlike this procedure's own previous version (this file's own
      header comment on this procedure claims no register but AX
      itself is ever disturbed here, "no risk of colliding with some
      OTHER live register the way carrying the amount through CX used
      to" -- true for every OTHER destination register (protectAx,
      below) but NOT for nmIsAx/nmIsAl themselves until this fix: both
      previously used 'mov cx,ax'/'mov cl,al' as their own scratch,
      silently clobbering the caller's own live CX exactly like the
      bug that comment describes -- found via LIB/OUT.SMD's own
      'INC(AL, 30H)' inside Out_Word, corrupting a caller's live CX
      across an ordinary Out_Int() call). BX is not risk-free either in
      the abstract, but this codebase already treats it as ordinary
      scratch at call boundaries with no dedicated preserved-register
      convention (EmitCall's own header comment; Out_Int/Out_Word's
      own bodies already use BX freely with no USES BX anywhere), so
      reusing it here is consistent with the rest of this file, not a
      new risk category. }
    AppendInstr2(MnMov, 'bx', 'ax');
    EmitGenSavePop('ax', saveId);
    AppendInstr2(addSub, 'ax', 'bx')
  end else if nmIsAl then begin
    { Same BX-instead-of-CX shape as nmIsAx above, at byte width. }
    AppendInstr2(MnMov, 'bl', 'al');
    EmitGenSavePop('ax', saveId);
    AppendInstr2(addSub, 'al', 'bl')
  end else if protectAx and Regs86.IsByteReg(Regs86.LookupReg(UpStr(nm))) then begin
    { nm is some OTHER byte register (not AL) -- apply AL to nm directly
      while AL still holds expr's own freshly-computed value (nm is
      provably not AL here, nmIsAl already handled that case above),
      THEN restore the caller's original AX -- no intermediate carry
      register at all, so nothing else nm's own caller might have live
      (CX included) is ever touched by this call. This exact shape --
      PUSH ax; <eval expr into ax>; add/sub nm,al; POP ax -- is OPT.TXT
      C1/C2's own target (genSaveId tags both ends of the pair, above/
      below, letting PHOpt.PAS's own Stage C matchers, once
      implemented, prove this is a compiler-owned scratch save rather
      than assuming it from context). }
    AppendInstr2(addSub, nm, 'al');
    EmitGenSavePop('ax', saveId)
  end else if protectAx then begin
    { nm is some OTHER word register (not AX) -- same direct-apply-
      then-restore shape, at word width -- OPT.TXT C1's own literal
      example shape ("PUSH AX; MOV AX,src; ADD SI,AX; POP AX"). }
    AppendInstr2(addSub, nm, 'ax');
    EmitGenSavePop('ax', saveId)
  end
end;

{ EmitIncDec: 'INC('/'DEC(' already parsed up to the argument identifier.
  Two forms: INC(var)/DEC(var) and INC(var, expr)/DEC(var, expr). }
procedure EmitIncDec(mnemonic: word);
  var nm, opnd, sfx, msg: string; addSub: word; si, ty: integer;
      hasAmount, discardTW: boolean;
begin
  if SymTab.IsSym(SymTab.SyLBrack) then begin
    { INC/DEC([seg:base].RecordType.field): a struct field used as the
      target, not just a plain named VAR -- e.g. bumping a BufferedFile's
      own .ofs field in place (LIB/READER.SMD's own ReadChar/WriteChar).
      ParseMemOperand already resolves the field's own byte/word size
      hint the same way a plain scalar VAR's ty would (SizeHintFor,
      called internally on a successful TypeFindFieldTy); forAddress is
      FALSE here since this is a value operand (read-modify-write via
      inc/dec or add/sub), not an address -- an array field is correctly
      rejected the same way "AX := [seg:base].Rec.field;" already is. }
    SymTab.Next; ParseMemOperand(opnd, sfx, false, discardTW); opnd := sfx + ' ' + opnd;
    hasAmount := SymTab.IsLexSym(SymTab.SyComma);
    if hasAmount then begin
      EmitExpr('ax');
      AddSubMnemonic(mnemonic, addSub);
      if EqualICase(sfx, 'byte') then AppendInstr2(addSub, opnd, 'al')
      else AppendInstr2(addSub, opnd, 'ax')
    end else
      AppendInstr1(mnemonic, opnd);
    exit
  end;
  Scan.CurTokText(nm); SymTab.Next;
  hasAmount := SymTab.IsLexSym(SymTab.SyComma);
  if SymTab.IsRegName(nm) then begin
    if hasAmount then EmitIncDecAmountToReg(nm, mnemonic)
    else begin
      AppendInstr1(mnemonic, nm)
    end;
    exit
  end;
  si := SymTab.FindSym(nm);
  if (si >= 0) and (SymTab.SymKind(si) = SymConst) then begin
    msg := 'cannot INC/DEC a CONST: ' + nm;
    Scan.ReportError(msg); exit
  end;
  if (si >= 0) and SymTab.SymIsReg(si) then begin
    if hasAmount then EmitIncDecAmountToReg(nm, mnemonic)
    else begin
      AppendInstr1(mnemonic, nm)
    end;
    exit
  end;
  SymOperandText(si, nm, opnd);
  if (si >= 0) and (SymTab.SymKind(si) = SymVar) then ty := SymTab.SymTy(si) else ty := TyWord;
  if (ty = TyByte) or (ty = TyBool) then sfx := 'byte' else sfx := 'word';
  if hasAmount then begin
    EmitExpr('ax');
    AddSubMnemonic(mnemonic, addSub);
    if EqualICase(sfx, 'byte') then AppendInstr2(addSub, sfx + ' ' + opnd, 'al')
    else AppendInstr2(addSub, sfx + ' ' + opnd, 'ax')
  end else begin
    AppendInstr1(mnemonic, sfx + ' ' + opnd)
  end
end;

{ ParsePushPop: 'PUSH(r1,r2,...)'/'POP(r1,r2,...)' -- PUSH pushes left to
  right; POP pops in reverse order. }
{ ParsePushPop: 'PUSH(r1,r2,...)'/'POP(r1,r2,...)' -- each ri is
  either an ordinary register name or the literal 'FLAGS' (mirroring
  USES's own EmitUsesPush/EmitUsesPop, which already special-case
  FLAGS to PUSHF/POPF rather than a real register operand -- PUSH/POP
  themselves never accept a bare "flags" pseudo-register on 8086 at
  all). Before this fix, 'FLAGS' fell through to the ordinary
  AppendInstr1(mnemonic, regs[i]) path unchanged, and regs[i]'s own
  storage (RegList's fixed string[3]) silently truncated the 5-letter
  name to 'FLA' -- neither a real register nor a real instruction,
  producing "PUSH FLA"/"POP FLA" in the generated .ASM (confirmed the
  hard way: TASM.EXE would reject it as an undefined symbol, with no
  translator-side diagnostic at all pointing at the real cause). }
procedure ParsePushPop(mnemonic: word; reverse: boolean);
  var regs: RegList; n, i: integer; regNameTmp: string;
      isFlags: array[0..MaxUses-1] of boolean;
  procedure EmitOne(idx: integer);
  begin
    if isFlags[idx] then begin
      if mnemonic = MnPush then AppendInstr0(MnPushf) else AppendInstr0(MnPopf)
    end else
      AppendInstr1(mnemonic, regs[idx])
  end;
begin
  SymTab.Expect(SymTab.SyLParen);
  n := 0;
  if not SymTab.IsSym(SymTab.SyRParen) then begin
    repeat
      if Scan.CurTokKind <> TIdent then
        Scan.ReportError('expected register name in PUSH/POP')
      else if n >= MaxUses then
        Scan.ReportError('too many registers in PUSH/POP')
      else begin
        { Scan.CurTokText's own `var dst: string` needs a plain-`string`
          actual argument (TP7's exact-type-match rule for `var`
          params) -- regs[n] is RegList's own TRegName (string[3]), so
          go through this plain-string temp first, same pattern
          EmitCall's own regNameTmp uses. }
        Scan.CurTokText(regNameTmp);
        isFlags[n] := EqualICase(regNameTmp, 'FLAGS');
        if not isFlags[n] then regs[n] := regNameTmp;
        Inc(n)
      end;
      SymTab.Next
    until not SymTab.IsLexSym(SymTab.SyComma)
  end;
  SymTab.Expect(SymTab.SyRParen);
  if reverse then i := n - 1 else i := 0;
  while (i >= 0) and (i < n) do begin
    EmitOne(i);
    if reverse then Dec(i) else Inc(i)
  end
end;

{ ParseCompileTimeBool: '(' already consumed by the caller. Reads one
  identifier that must resolve to a CONST whose value is exactly 0 or
  1 (in practice, TRUE/FALSE -- SymTab's own predeclared CONSTs,
  RegisterBuiltins -- but any CONST alias of them, e.g. 'CONST On =
  TRUE;', is accepted too, same as any other CONST use elsewhere in
  this translator). PLAN.TXT S2.5/S2.3's own explicit requirement for
  SetIFlag/SetCFlag/SetDFlag/STOREB/STOREW/COPYB/COPYW: "Initially
  require a compile-time Boolean constant, not a runtime value" --
  a plain VAR or register operand here is a translator error, not a
  runtime branch, since these operations exist specifically to emit
  one exact, statically-known instruction/prefix combination. }
function ParseCompileTimeBool: boolean;
  var nm, msg: string; si: integer;
begin
  ParseCompileTimeBool := false;
  if Scan.CurTokKind <> TIdent then begin
    Scan.ReportError('expected a compile-time Boolean constant (TRUE/FALSE)');
    exit
  end;
  Scan.CurTokText(nm); SymTab.Next;
  si := SymTab.FindSym(nm);
  if (si < 0) or (SymTab.SymKind(si) <> SymConst)
     or ((SymTab.SymVal(si) <> 0) and (SymTab.SymVal(si) <> 1)) then begin
    msg := 'expected a compile-time Boolean constant (TRUE/FALSE): ' + nm;
    Scan.ReportError(msg); exit
  end;
  ParseCompileTimeBool := SymTab.SymVal(si) <> 0
end;

{ ParseFlagStmt: 'SetIFlag(TRUE)'/'SetCFlag(FALSE)'/etc, already
  identified by the caller -- 'Name(' up to (not including) the
  Boolean argument already consumed. mnTrue/mnFalse are the two
  possible zero-operand mnemonics (PLAN.TXT S2.5: STI/CLI, STC/CLC,
  STD/CLD respectively). }
procedure ParseFlagStmt(mnTrue, mnFalse: word);
  var v: boolean;
begin
  SymTab.Expect(SymTab.SyLParen);
  v := ParseCompileTimeBool;
  SymTab.Expect(SymTab.SyRParen);
  if v then AppendInstr0(mnTrue) else AppendInstr0(mnFalse)
end;

{ ParseRepeatStmt: 'STOREB(TRUE)'/'COPYW(FALSE)'/etc, already
  identified by the caller. mn is the plain (no REP) mnemonic;
  mnRep is the REP-prefixed one (PLAN.TXT S2.3: TRUE emits REP,
  repeating CX times; FALSE omits REP, executing once regardless of
  CX). }
procedure ParseRepeatStmt(mn, mnRep: word);
  var v: boolean;
begin
  SymTab.Expect(SymTab.SyLParen);
  v := ParseCompileTimeBool;
  SymTab.Expect(SymTab.SyRParen);
  if v then AppendInstr0(mnRep) else AppendInstr0(mn)
end;

{ ParseOutPortStmt: 'OUTPORTB(port, AL)'/'OUTPORTW(port, AX)' --
  PLAN.TXT S2.2's own "Initially allow only the exact accumulator
  destinations/values shown" applies symmetrically to the value
  argument here, same as INPORTB/INPORTW's own destReg restriction:
  the second argument must be written as the literal register AL/AX,
  not a VAR/expression that merely happens to hold the right value. }
procedure ParseOutPortStmt(mn: word; wantAl: boolean);
  var portOpnd, nm, msg: string;
begin
  SymTab.Expect(SymTab.SyLParen);
  portOpnd := ParsePortOperand;
  SymTab.Expect(SymTab.SyComma);
  Scan.CurTokText(nm); SymTab.Next;
  if wantAl and not EqualICase(nm, 'AL') then begin
    msg := 'OUTPORTB() value must be the literal register AL, not ''' + nm + '''';
    Scan.ReportError(msg)
  end else if (not wantAl) and not EqualICase(nm, 'AX') then begin
    msg := 'OUTPORTW() value must be the literal register AX, not ''' + nm + '''';
    Scan.ReportError(msg)
  end else begin
    if wantAl then AppendInstr2(mn, portOpnd, 'al')
    else AppendInstr2(mn, portOpnd, 'ax')
  end;
  SymTab.Expect(SymTab.SyRParen)
end;

{ ParseGeneralReg: reads one bare register name, requiring it be a
  real GENERAL register (not a segment register) -- shared by
  ParseCarryArithStmt/ParseRotateStmt below, both of which need this
  exact restriction ("Initially accept matching-width general
  registers only; no segment registers" -- PLAN.TXT S2.4). Reports an
  error and returns '' for anything else (a non-register identifier, a
  segment register, a different token kind entirely) -- the caller
  decides how to recover; this function's own job is only to read and
  validate one register name. }
function ParseGeneralReg(const what: string): string;
  var nm, msg: string;
begin
  ParseGeneralReg := '';
  if (Scan.CurTokKind <> TIdent) or not SymTab.CurTokIsReg then begin
    Scan.ReportError(what + ' requires a general register operand');
    if Scan.CurTokKind <> TEof then SymTab.Next;
    exit
  end;
  Scan.CurTokText(nm); SymTab.Next;
  if Regs86.IsSegReg(Regs86.LookupReg(UpStr(nm))) then begin
    msg := what + ' does not accept a segment register: ' + nm;
    Scan.ReportError(msg); exit
  end;
  ParseGeneralReg := nm
end;

{ TCarryOpnd: one already-classified ADDCarry/SUBBorrow operand --
  ParseCarryOperand's own result, consumed by ParseCarryArithStmt
  right after both operands are fully read (never in between reading
  them: PLAN.TXT S2.4's own "Emit the instruction directly so operand
  evaluation cannot destroy the incoming carry flag" -- nothing here
  computes into a register or otherwise touches flags while parsing,
  it only ever produces operand TEXT, same discipline ParseGeneralReg
  already established for the register-only case this replaces). }
type
  TCarryOpnd = record
    text: string;
    isReg, isMem, isImm: boolean;
    isByte: boolean;   { meaningful only when isReg; a bare immediate/
                           memory operand's own width isn't separately
                           known here (memory carries no inherent width
                           tag of its own at this call site -- unlike
                           .BYTE/.WORD typed memory access, ADDCarry/
                           SUBBorrow's own memory operand is a plain
                           '[...]' with no such suffix), so width
                           checking below only ever fires when BOTH
                           sides are registers, same as before this
                           fix -- a register/memory or register/
                           immediate pair is accepted without a width
                           check, matching real 8086 (which infers the
                           memory operand's own width from whichever
                           register/explicit size prefix appears, not
                           validated here at the SPHINX level). }
  end;

{ ParseCarryOperand: reads one ADDCarry/SUBBorrow operand -- a bare
  register (ParseGeneralReg's own rules: general-purpose only, no
  segment register), a '[...]' memory operand (ParseMemOperand, the
  same parser '.BYTE'/'.WORD' typed memory access already uses,
  PLAN.TXT S2.1 -- forAddress=false, an ordinary value operand), or (source
  operand only, gated by the caller) a decimal/hex numeric literal.
  Real 8086 ADC/SBB accept reg/reg, reg/mem, mem/reg, reg/imm, and
  mem/imm -- never mem/mem -- so this function only classifies ONE
  operand; ParseCarryArithStmt itself is what rejects the mem/mem
  combination once both sides are known. }
procedure ParseCarryOperand(const what: string; allowImm: boolean; var r: TCarryOpnd);
  var sizeHint: string; isTypedWidth: boolean; nm: string;
begin
  r.text := ''; r.isReg := false; r.isMem := false; r.isImm := false; r.isByte := false;
  if Scan.CurTokKind = TSym then begin
    Scan.CurTokText(nm);
    if EqualICase(nm, '[') then begin
      SymTab.Next;
      ParseMemOperand(r.text, sizeHint, false, isTypedWidth);
      r.isMem := true; exit
    end
  end;
  if allowImm and (Scan.CurTokKind = TNum) then begin
    Scan.CurTokText(r.text); SymTab.Next;
    r.isImm := true; exit
  end;
  if (Scan.CurTokKind = TIdent) and SymTab.CurTokIsReg then begin
    r.text := ParseGeneralReg(what);
    if r.text <> '' then begin
      r.isReg := true;
      r.isByte := Regs86.IsByteReg(Regs86.LookupReg(UpStr(r.text)))
    end;
    exit
  end;
  if allowImm then
    Scan.ReportError(what + ' requires a register, memory, or immediate operand')
  else
    Scan.ReportError(what + ' requires a register or memory operand');
  if Scan.CurTokKind <> TEof then SymTab.Next
end;

{ ParseCarryArithStmt: 'ADDCarry(dest, src)'/'SUBBorrow(dest, src)' --
  dest is a register or a '[...]' memory operand; src is a register, a
  '[...]' memory operand, or an immediate -- matching real 8086 ADC/SBB
  encodings exactly (reg/reg, reg/mem, mem/reg, reg/imm, mem/imm); a
  mem/mem pair is rejected outright, since no such encoding exists at
  all. Width matching ("matching-width general registers only") is
  still checked when BOTH operands are registers -- a byte+word
  mismatch there is rejected the same way CheckTypedWidthStore's own
  register-width check already is (PLAN.TXT S2.1); memory's own width
  isn't independently known at this call site (see TCarryOpnd's own
  comment), so a register/memory or register/immediate pair is
  accepted without that check, matching real 8086 (which resolves the
  memory operand's own width from whichever register or explicit size
  prefix is present, not validated at the SPHINX level here). }
procedure ParseCarryArithStmt(mn: word; const name: string);
  var dest, src: TCarryOpnd; msg: string;
begin
  SymTab.Expect(SymTab.SyLParen);
  ParseCarryOperand(name, false, dest);
  SymTab.Expect(SymTab.SyComma);
  ParseCarryOperand(name, true, src);
  SymTab.Expect(SymTab.SyRParen);
  if (dest.text = '') or (src.text = '') then exit;
  if dest.isMem and src.isMem then begin
    msg := name + ' cannot have a memory operand on both sides';
    Scan.ReportError(msg); exit
  end;
  if dest.isReg and src.isReg and (dest.isByte <> src.isByte) then begin
    msg := name + ' requires matching-width registers, not ''' + dest.text + ''' and ''' + src.text + '''';
    Scan.ReportError(msg); exit
  end;
  AppendInstr2(mn, dest.text, src.text)
end;

{ ParseRotateStmt: 'ROL(reg, 1)'/'ROR(reg, CL)'/'RCL(reg, 1)'/
  'RCR(reg, CL)' -- a byte/word general register (ParseGeneralReg,
  above -- the same "no expression evaluation, no segment register"
  restriction as ParseCarryArithStmt) and a count that must be written
  as literally '1' or the register 'CL', matching the two 8086
  encodings that actually exist for a shift/rotate instruction (an
  arbitrary immediate count is not a real 8086 form at all). }
procedure ParseRotateStmt(mn: word; const name: string);
  var reg, cnt, msg: string;
begin
  SymTab.Expect(SymTab.SyLParen);
  reg := ParseGeneralReg(name);
  SymTab.Expect(SymTab.SyComma);
  cnt := '';
  if (Scan.CurTokKind = TNum) and (Scan.CurTokVal = 1) then begin
    cnt := '1'; SymTab.Next
  end else if (Scan.CurTokKind = TIdent) and SymTab.CurTokIsReg then begin
    Scan.CurTokText(cnt); SymTab.Next;
    if not EqualICase(cnt, 'CL') then begin
      msg := name + ' count must be 1 or CL, not ''' + cnt + '''';
      Scan.ReportError(msg); cnt := ''
    end else cnt := 'cl'
  end else begin
    msg := name + ' count must be 1 or CL';
    Scan.ReportError(msg);
    if Scan.CurTokKind <> TEof then SymTab.Next
  end;
  SymTab.Expect(SymTab.SyRParen);
  if (reg <> '') and (cnt <> '') then AppendInstr2(mn, reg, cnt)
end;

{ ParseStmt: one statement. Statement separator ';' consumed here. }
procedure ParseStmt;
  var buf: string;
begin
  if SymTab.IsLexKw(SymTab.KwIf) then ParseIf
  else if SymTab.IsLexKw(SymTab.KwWhile) then ParseWhile
  else if SymTab.IsLexKw(SymTab.KwBreak) then begin
    if comp.loopDepth >= 0 then AppendInstr1(MnJmp, LabelName(comp.loopExitStack[comp.loopDepth]))
  end else if SymTab.IsLexKw(SymTab.KwContinue) then begin
    if comp.loopDepth >= 0 then AppendInstr1(MnJmp, LabelName(comp.loopContStack[comp.loopDepth]))
  end else if SymTab.IsLexKw(SymTab.KwReturn) then ParseReturn
  else if SymTab.IsKw(SymTab.KwAsm) then ParseAsm
  else if SymTab.IsLexKw(SymTab.KwInc) then begin
    SymTab.Expect(SymTab.SyLParen); EmitIncDec(MnInc); SymTab.Expect(SymTab.SyRParen)
  end else if SymTab.IsLexKw(SymTab.KwDec) then begin
    SymTab.Expect(SymTab.SyLParen); EmitIncDec(MnDec); SymTab.Expect(SymTab.SyRParen)
  end else if SymTab.IsLexKw(SymTab.KwInt) then begin
    SymTab.Expect(SymTab.SyLParen); Scan.CurTokText(buf); SymTab.Next; SymTab.Expect(SymTab.SyRParen);
    AppendInstr1(MnInt, buf)
  end else if SymTab.IsLexKw(SymTab.KwPush) then ParsePushPop(MnPush, false)
  else if SymTab.IsLexKw(SymTab.KwPop) then ParsePushPop(MnPop, true)
  else if SymTab.IsLexKw(SymTab.KwSetIFlag) then ParseFlagStmt(MnSti, MnCli)
  else if SymTab.IsLexKw(SymTab.KwSetCFlag) then ParseFlagStmt(MnStc, MnClc)
  else if SymTab.IsLexKw(SymTab.KwSetDFlag) then ParseFlagStmt(MnStd, MnCld)
  else if SymTab.IsLexKw(SymTab.KwStoreB) then ParseRepeatStmt(MnStosb, MnRepStosb)
  else if SymTab.IsLexKw(SymTab.KwStoreW) then ParseRepeatStmt(MnStosw, MnRepStosw)
  else if SymTab.IsLexKw(SymTab.KwCopyB) then ParseRepeatStmt(MnMovsb, MnRepMovsb)
  else if SymTab.IsLexKw(SymTab.KwCopyW) then ParseRepeatStmt(MnMovsw, MnRepMovsw)
  else if SymTab.IsLexKw(SymTab.KwOutPortB) then ParseOutPortStmt(MnOutB, true)
  else if SymTab.IsLexKw(SymTab.KwOutPortW) then ParseOutPortStmt(MnOutW, false)
  else if SymTab.IsLexKw(SymTab.KwAddCarry) then ParseCarryArithStmt(MnAdc, 'ADDCarry')
  else if SymTab.IsLexKw(SymTab.KwSubBorrow) then ParseCarryArithStmt(MnSbb, 'SUBBorrow')
  else if SymTab.IsLexKw(SymTab.KwRol) then ParseRotateStmt(MnRol, 'ROL')
  else if SymTab.IsLexKw(SymTab.KwRor) then ParseRotateStmt(MnRor, 'ROR')
  else if SymTab.IsLexKw(SymTab.KwRcl) then ParseRotateStmt(MnRcl, 'RCL')
  else if SymTab.IsLexKw(SymTab.KwRcr) then ParseRotateStmt(MnRcr, 'RCR')
  else
    ParseAssignOrCall;
  while SymTab.IsLexSym(SymTab.SySemi) do begin end
end;

procedure ParseStmtList;
begin
  while (Scan.CurTokKind <> TEof)
         and not SymTab.IsKw(SymTab.KwEnd)
         and not SymTab.IsKw(SymTab.KwElse)
         and not SymTab.IsKw(SymTab.KwElsif) do ParseStmt
end;

{ ---------------- procedure translation ---------------- }

{ ParseParams: '(' already consumed. Register-named params get no stack
  slot; others get Pascal-order [bp+4],[bp+6],... }
procedure ParseParams(var regFlags: array of boolean; var sis: array of integer; var n: integer);
  var groupStart, i: integer; typ: SymTab.TTypeInfo; isArr: boolean;
      nm: string; moreGroups, moreNames: boolean;
begin
  n := 0;
  if SymTab.IsLexKw(SymTab.KwReg) then begin end;  { optional leading REG keyword }
  if not SymTab.IsSym(SymTab.SyRParen) then begin
    moreGroups := true;
    while moreGroups do begin
      groupStart := n;
      moreNames := true;
      while moreNames do begin
        if n >= MaxParams then begin
          Scan.ReportError('too many parameters'); moreNames := false; moreGroups := false
        end else begin
          Scan.CurTokText(nm);
          regFlags[n] := SymTab.IsRegName(nm);
          SymTab.Next;
          sis[n] := SymTab.SymAppend(nm, SymVar);
          SymTab.SymSetIsLocal(sis[n], true);
          SymTab.SymSetIsParam(sis[n], true);
          if regFlags[n] then
            SymTab.SymSetTy(sis[n], TyInt, -1);
          Inc(n);
          moreNames := SymTab.IsLexSym(SymTab.SyComma)
        end
      end;
      if not SymTab.IsLexSym(SymTab.SyColon) then begin typ.ty := TyInt; typ.recIdx := -1 end
      else RecTypes.ParseBaseType(typ);
      { Optional 'T[N]'/'T[]' array-parameter syntax (SOPLAN.MD's own
        Phase 7 item 3, "array parameter syntax... typed address/
        length convention") -- address-only sugar: N itself (if given)
        is parsed and discarded, not stored/enforced anywhere, same as
        DOCS/SPHO.MD's own "Simplicity First" scope decision to skip a
        real bundled address+length calling convention. Marks every
        name in this group SymSetIsArr so EmitCall's own call-site
        argument parser (ProcParamIsArray, consulted via the callee's
        pi once fully declared) can later auto-ADR() a bare array-typed
        VAR argument instead of reading it as an ordinary scalar. A
        register-named parameter (regFlags[i]) can't meaningfully be
        array-typed (a register holds one scalar value) -- '[N]'/'[]'
        after one is simply not looked for, same as this group's own
        register params never receive a real ParseBaseType call either
        (SymSetTy(sis[n], TyInt, -1) above, hardcoded, unconditional). }
      isArr := false;
      if SymTab.IsLexSym(SymTab.SyLBrack) then begin
        isArr := true;
        if not SymTab.IsSym(SymTab.SyRBrack) then ParseArrayBound;
        SymTab.Expect(SymTab.SyRBrack)
      end;
      i := groupStart;
      while i < n do begin
        if not regFlags[i] then begin
          SymTab.SymSetTy(sis[i], typ.ty, typ.recIdx);
          if isArr then SymTab.SymSetIsArr(sis[i], true)
        end;
        Inc(i)
      end;
      moreGroups := moreGroups and SymTab.IsLexSym(SymTab.SySemi)
    end
  end;
  SymTab.Expect(SymTab.SyRParen)
end;

{ RejectRecordParams: a by-value RECORD-typed formal parameter is not
  supported. }
procedure RejectRecordParams(var regFlags: array of boolean; var sis: array of integer; n: integer);
  var i: integer; msg: string;
begin
  i := 0;
  while i < n do begin
    { A T[N]/T[] array-typed parameter (SymIsArr) is exempt even when T
      is a RECORD type -- SOPLAN.MD's own Phase 7 item 3 array-parameter
      syntax is address-only sugar (still exactly one WORD/address
      parameter underneath, same as writing 'name: WORD' and passing
      ADR(recArr) manually), not a by-value RECORD parameter at all. }
    if (not regFlags[i]) and (SymTab.SymTy(sis[i]) = TyRec) and not SymTab.SymIsArr(sis[i]) then begin
      msg := 'by-value RECORD parameter not supported (pass ADR(rec) into a WORD/INTEGER parameter instead)';
      Scan.ReportError(msg)
    end;
    Inc(i)
  end
end;

{ AssignParamOffsets: called once isFar is finally known. Each stack
  parameter's own size (2 bytes for everything except LONGINT, 4 for
  LONGINT -- RejectRecordParams above has already turned a by-value
  RECORD parameter into a translator error, so TyLong is the only
  non-2-byte case that can still reach here) advances nStack by that
  many bytes, not a flat 2 -- a LONGINT stack parameter used to alias
  its own high word onto whichever parameter came after it, and every
  procedure's own retn N (EmitProcedureEpilogue) undercounted the real
  pushed byte total by 2 for each LONGINT stack parameter present. }
procedure AssignParamOffsets(var regFlags: array of boolean;
var sis: array of integer;
n: integer;
isFar: boolean;
var nStack: integer);
  var i, retOfs, sz: integer;
begin
  if isFar then retOfs := 6 else retOfs := 4;
  nStack := 0;
  i := n - 1;
  while i >= 0 do begin
    if regFlags[i] then
      SymTab.SymSetIsReg(sis[i], true)
    else begin
      { An array-typed parameter (SymIsArr) is always exactly one WORD
        (an address, SOPLAN.MD's own Phase 7 item 3 sugar) regardless of
        its own element type T -- 'arr: LONGINT[5]' is still a 2-byte
        address parameter, not a 4-byte LONGINT VALUE, so it must NOT
        take the TyLong=4 branch below just because its declared T
        happens to be LONGINT. }
      if (SymTab.SymTy(sis[i]) = TyLong) and not SymTab.SymIsArr(sis[i]) then sz := 4 else sz := 2;
      SymTab.SymSetOfs(sis[i], -(retOfs + nStack));
      Inc(nStack, sz)
    end;
    Dec(i)
  end
end;

{ ParseUses: 'USES r1, r2, ...;'. }
procedure ParseUses(var regs: RegList; var n: integer);
  var regNameTmp: string;
begin
  n := 0;
  if SymTab.IsLexKw(SymTab.KwUses) then begin
    repeat
      if n >= MaxUses then begin
        Scan.ReportError('too many registers in USES'); SymTab.Next
      end else begin
        { Scan.CurTokText's own `var dst: string` needs a plain-`string`
          actual argument (TP7's exact-type-match rule for `var`
          params) -- regs[n] is RegList's own TRegName (string[3]), so
          go through this plain-string temp first, same pattern
          EmitCall's own regNameTmp / ParsePushPop's own fix use. }
        Scan.CurTokText(regNameTmp); regs[n] := regNameTmp; SymTab.Next; Inc(n)
      end
    until not SymTab.IsLexSym(SymTab.SyComma);
    SymTab.Expect(SymTab.SySemi)
  end
end;

procedure EmitUsesPush(var regs: RegList; n: integer);
  var i: integer;
begin
  i := 0;
  while i < n do begin
    if EqualICase(regs[i], 'FLAGS') then AppendInstr0(MnPushf)
    else AppendInstr1(MnPush, regs[i]);
    Inc(i)
  end
end;

{ EmitUsesPop: pops the USES-saved registers back, in reverse push
  order. A register that's also part of THIS procedure's own declared
  return value (AX for any hasRetTy procedure, DX too when procRetTy =
  TyLong) is deliberately NOT popped into -- .return: (where this runs)
  is reached both by falling off the end of the body AND by a mid-body
  RETURN expr that has already loaded the real return value into AX/DX,
  and popping the caller's stale saved value on top of it here would
  silently discard that return value right before retn (found via
  FILES.SMD's own "FileSize(handle):LONGINT; USES BX,CX,DX,SI" --
  DX doubles as FileSize's own internal scratch AND half its LONGINT
  return, so the plain pop-everything-back version of this function
  clobbered DX with the caller's pre-call value on every return,
  corrupting the high word of every FileSize() result). The pushed
  bytes still need consuming either way, to keep retn N's own stack
  arithmetic correct -- "add sp, 2" instead of "pop reg" discards them
  without touching any register when a pop must be skipped. }
procedure EmitUsesPop(var regs: RegList; n: integer);
  var i: integer; skip: boolean;
begin
  i := n - 1;
  while i >= 0 do begin
    skip := ctx.hasRetTy and (EqualICase(regs[i], 'AX')
                           or (EqualICase(regs[i], 'DX') and (ctx.procRetTy = TyLong)));
    if skip then AppendInstr2(MnAdd, 'sp', '2')
    else if EqualICase(regs[i], 'FLAGS') then AppendInstr0(MnPopf)
    else AppendInstr1(MnPop, regs[i]);
    Dec(i)
  end
end;

{ ParseProcedure: 'PROCEDURE' already consumed.

  FORWARD: 'PROCEDURE Name(params): RetTy; NEAR|FAR; FORWARD;' parses
  the full signature and registers isFar via ProcSetIsFar immediately,
  but emits no label/prologue/body at all. A name already forward-
  declared reuses that row's pi. A name already FULLY defined is a
  genuine duplicate-definition translator error. }
procedure ParseProcedure;
  var nm: string; exported, isFar, isInterrupt, hasParams, isFwd, isExtern, wasValid, needsFrame: boolean;
      nStack, nParams, pi: integer;
      retTyp: SymTab.TTypeInfo;
      savedLex: LexTab.TLexMark;
      regFlags: array[0..MaxParams-1] of boolean;
      sis: array[0..MaxParams-1] of integer;
      usesRegs: RegList; nUses: integer;
      msg, externName: string; buf: word;
      bodyStartChunk: POpChunk; bodyStartSlot: integer;
      bodyEndChunk: POpChunk; bodyEndSlot: integer;
begin
  ctx.labelCnt := 0;
  Scan.CurTokText(nm); SymTab.Next;
  exported := false;
  if SymTab.IsLexSym(SymTab.SyStar) then exported := true;
  pi := SymTab.ProcFindAny(nm, wasValid);
  if pi >= 0 then begin
    if wasValid then begin
      msg := 'duplicate PROCEDURE definition: ' + nm;
      Scan.ReportError(msg)
    end
  end else
    pi := SymTab.ProcReserve(nm);
  { Persist the '*' export marker past parse time -- EmitSHD (below)
    needs it to know which PROCEDUREs belong in this module's own
    .SHD header; previously `exported` was only ever a local used
    inline for isFar/the 'global' NASM directive, then discarded. }
  SymTab.ProcSetExported(pi, exported);
  SymTab.CurLexMark(savedLex);
  hasParams := SymTab.IsLexSym(SymTab.SyLParen);
  if hasParams then ParseParams(regFlags, sis, nParams) else nParams := 0;
  RejectRecordParams(regFlags, sis, nParams);
  { procRetTy: DOCS/SPHINX.MD's own §6.4 return-register table (BYTE/
    BOOLEAN -> AL, WORD/INTEGER -> AX, LONGINT -> DX:AX) -- TyWord if no
    ': RetTy' was given at all (an untyped/procedure declaration).
    hasRetTy separately records whether ': RetTy' was actually WRITTEN
    (not just procRetTy's own TyWord default) -- EmitUsesPop needs this
    to know whether AX/DX genuinely hold this procedure's own return
    value at .return: (and so must not be clobbered by a USES pop),
    since an untyped PROCEDURE has no such contract even though
    procRetTy still defaults to TyWord for RETURN-parsing purposes. }
  ctx.procRetTy := TyWord; ctx.hasRetTy := false;
  if SymTab.IsLexSym(SymTab.SyColon) then begin
    { PLAN.TXT S1.7: 'RetTy' used to be resolved by its own narrower
      inline check (ScalarKwTy directly on the current token) instead
      of the general RecTypes.ParseBaseType every OTHER type position
      (VAR declarations, RECORD fields, PROCEDURE parameters) already
      goes through -- so a scalar TYPE alias (e.g. 'TYPE Handle =
      WORD;') used as a return type ('PROCEDURE P(): Handle; NEAR;')
      was never recognized as a scalar keyword at all, silently left
      the identifier token completely UNCONSUMED (kwTy stayed -1,
      SymTab.Next was only ever called inside "if kwTy >= 0"), and
      corrupted the rest of this procedure's own parse from there
      (confirmed the hard way: cascading "expected 'END'"/"expected
      '.'" errors, nowhere near the real problem). ParseBaseType
      itself already knows how to resolve a user TYPE alias (via
      SymTab.FindType) in addition to every scalar keyword, so reusing
      it here fixes the gap directly, consistently with every other
      type position. A RECORD type name (aliased or not) is rejected
      here explicitly -- SPHINX.MD's own §6.4 return-register
      convention (BYTE/BOOLEAN->AL, WORD/INTEGER->AX, LONGINT->DX:AX)
      has no slot for an arbitrary-sized RECORD value at all. }
    Scan.CurTokText(msg);
    RecTypes.ParseBaseType(retTyp);
    if retTyp.ty = TyRec then
      Scan.ReportError('RECORD type not supported as a return type: ' + msg)
    else begin
      ctx.procRetTy := retTyp.ty; ctx.hasRetTy := true
    end
  end;
  isFar := exported; isInterrupt := false;
  if SymTab.IsLexSym(SymTab.SySemi) then begin end;
  if SymTab.IsLexKw(SymTab.KwNear) then begin isFar := false; SymTab.IsLexSym(SymTab.SySemi) end
  else if SymTab.IsLexKw(SymTab.KwFar) then begin isFar := true; SymTab.IsLexSym(SymTab.SySemi) end
  else if SymTab.IsLexKw(SymTab.KwInterrupt) then begin isInterrupt := true; SymTab.IsLexSym(SymTab.SySemi) end;
  { DOCS/SPHINX.MD's own §6 table: "INTERRUPT | (none) | iret | Interrupt
    handler, no parameters allowed" -- an interrupt has no caller-pushed
    argument list to clean up, so a parameter list here (already parsed
    above, before isInterrupt was even known) is rejected the same way
    FORWARD/EXTERNAL are rejected just below, not silently accepted. }
  if isInterrupt and (nParams > 0) then
    Scan.ReportError('INTERRUPT procedures may not have parameters');
  isFwd := SymTab.IsLexKw(SymTab.KwForward);
  if isFwd then begin
    SymTab.IsLexSym(SymTab.SySemi);
    if isInterrupt then
      Scan.ReportError('FORWARD not supported for INTERRUPT procedures')
    else begin
      SymTab.ProcSetForward(pi, isFar);
      { Store the FORWARD declaration's own signature too (not just
        isFar), so the real definition below can be checked against it
        (SOPLAN.MD's own Phase 5 item 4) -- ProcSetParams/ProcSetRetTy
        write into SymTab's own row, unaffected by the LexTruncate just
        below (that only rewinds the LEXER, discarding these params as
        real locals for a body that doesn't exist here, same as before
        this change). }
      SymTab.ProcSetParams(pi, regFlags, sis, nParams);
      SymTab.ProcSetRetTy(pi, ctx.procRetTy, ctx.hasRetTy)
    end;
    SymTab.LexTruncate(savedLex);
    exit
  end;
  isExtern := SymTab.IsLexKw(SymTab.KwExternal);
  if isExtern then begin
    externName := '';
    if Scan.CurTokKind = TStr then begin
      Scan.CurTokText(externName); SymTab.Next
    end;
    SymTab.IsLexSym(SymTab.SySemi);
    if isInterrupt then
      Scan.ReportError('EXTERNAL not supported for INTERRUPT procedures')
    else begin
      SymTab.ProcSetExternal(pi, isFar, externName);
      { Without this, an EXTERNAL procedure's own parameter signature
        (which ones are LONGINT/array/register-named) is never
        recorded, since ProcSetExternal itself (unlike ProcSetForward
        just above) never called ProcSetParams -- every call site's
        own EmitCall then silently treats every argument as an
        ordinary WORD, including a LONGINT one, pushing only its low
        word and leaving the high word off the stack entirely (found
        via EXAMPLES/TARPAK's own Seek(fp, aLongintVar) calls reading
        back garbage for their own high word). }
      SymTab.ProcSetParams(pi, regFlags, sis, nParams);
      SymTab.ProcSetRetTy(pi, ctx.procRetTy, ctx.hasRetTy);
      if externName = '' then externName := nm;
      EnsureSection(SectCode);
      Emit2('extern ', externName)
    end;
    SymTab.LexTruncate(savedLex);
    exit
  end;
  AssignParamOffsets(regFlags, sis, nParams, isFar, nStack);
  if (not isInterrupt) and SymTab.ProcIsFwdOnly(pi) then begin
    if not SymTab.ProcCompareSig(pi, regFlags, sis, nParams, ctx.hasRetTy, ctx.procRetTy, msg) then
      Scan.ReportError('PROCEDURE ' + nm + ': ' + msg)
  end;
  if not isInterrupt then begin
    SymTab.ProcSetIsFar(pi, isFar); SymTab.ProcSetParams(pi, regFlags, sis, nParams);
    SymTab.ProcSetRetTy(pi, ctx.procRetTy, ctx.hasRetTy)
  end;
  ParseUses(usesRegs, nUses);

  EnsureSection(SectCode);
  if exported then Emit2('global ', nm);
  AppendLabelOp(nm);
  { bodyStartChunk/bodyStartSlot: this procedure's own first operation
    (the entry label just appended above) -- captured the same way
    AppendInstr1Ref hands back a chunk/slot reference to its own
    just-appended operation (comp.opTail/comp.opTail^.count are always
    "wherever the append just landed" right after any Append* call).
    Marks the start of the range PHOpt.Optimize walks once this
    procedure's body is fully parsed, below. }
  bodyStartChunk := comp.opTail; bodyStartSlot := comp.opTail^.count;
  ctx.frameOfs := 0;
  if SymTab.IsLexKw(SymTab.KwVar) then
    GlobVar.ParseVarSection(false, ctx.frameOfs, es, SectData, SectBss, Emit, EnsureSection, ParseArrayBound);
  needsFrame := (nStack > 0) or (ctx.frameOfs > 0);
  if needsFrame then begin
    AppendInstr1(MnPush, 'bp');
    AppendInstr2(MnMov, 'bp', 'sp')
  end;
  if ctx.frameOfs > 0 then begin
    AppendInstr2(MnSub, 'sp', IntStr(longint(ctx.frameOfs)))
  end;
  EmitUsesPush(usesRegs, nUses);

  if SymTab.IsLexKw(SymTab.KwBegin) then ParseStmtList;
  SymTab.ExpectKw(SymTab.KwEnd);
  if Scan.CurTokKind = TIdent then SymTab.Next;
  SymTab.Expect(SymTab.SySemi);

  { AppendLabelOp, not the old raw Emit('.return:') verbatim line --
    .return needs to be a real TOpLabel (not TOpAsm) so PHOpt's own
    CheapReturn peephole rule (jmp immediately followed by its own
    target label) can actually match RETURN's own "jmp .return"
    against it; a TOpAsm line's raw text is opaque to that comparison
    (found via CONTROL.SMD's own output still carrying a redundant
    "jmp .return" immediately before ".return:" after CheapReturn was
    added -- traced to this exact line still using Emit instead of
    AppendLabelOp). Bare name, no ':' -- same convention every other
    AppendLabelOp caller follows (SerializeOne appends ':' once, only
    at final emission). }
  AppendLabelOp('.return');

  EmitUsesPop(usesRegs, nUses);
  if isInterrupt then
    AppendInstr0(MnIret)
  else begin
    if needsFrame then begin
      AppendInstr2(MnMov, 'sp', 'bp');
      AppendInstr1(MnPop, 'bp')
    end;
    if isFar then buf := MnRetf else buf := MnRetn;
    if nStack > 0 then AppendInstr1(buf, IntStr(longint(nStack)))
    else AppendInstr0(buf);
  end;
  { bodyEndChunk/bodyEndSlot: snapshot the tail HERE, right after the
    real RETN/RETF/IRET (whichever branch above just ran) and BEFORE
    the blank Emit('') line right below -- OPT.TXT's own R6 finding
    surfaced a real, pre-existing bug here: Emit('') appends a genuine
    TOpAsm operation (AppendAsmLine, unconditionally, even for an EMPTY
    string -- there is no "blank line, so skip appending anything at
    all" special case), and PHOpt.PAS's own BuildCfg REJECTS any range
    containing a TOpAsm outright (cfg.ok := false, unconditionally, no
    exception for a blank/empty one) -- every PHOpt.Optimize call this
    procedure ever made (going all the way back to before R6 existed)
    included this trailing blank TOpAsm in its own range, which means
    ByteCompareNoWiden (E4, the ONLY existing PHOpt.PAS rule that calls
    BuildCfg) had ALWAYS silently failed its own internal CFG build on
    every REAL procedure's own full range, never once actually
    succeeding via this call path -- found via direct instrumentation
    while verifying R6's own BuildCallGraph (which also calls BuildCfg,
    once per procedure, and hit the exact same cfg.ok=FALSE on every
    single one of Tetris's own 47 procedures). Fixed by recording the
    range's own END at the real last instruction instead of the
    blank-line tail -- the blank line itself was never meaningful
    content anyway (Emit('') exists purely as visual spacing in the
    generated .ASM, SerializeOne's own TOpAsm case just writes its own
    text verbatim, an empty line in this case), so excluding it from
    the analyzed range loses nothing a peephole/CFG pass could ever
    want to see. }
  bodyEndChunk := comp.opTail; bodyEndSlot := comp.opTail^.count;
  Emit('');
  { This procedure's own operation list is now fully appended (nothing
    else appends more operations for THIS procedure past this point) --
    record the whole [bodyStartChunk,bodyStartSlot .. bodyEndChunk,
    bodyEndSlot] range (NOT comp.opTail's own current position, which
    would include the blank Emit('') line just above -- see this
    procedure's own bodyEndChunk/bodyEndSlot capture, right before that
    Emit('') call, for why) for OptimizeAllDeferred to hand to
    PHOpt.Optimize later, once the WHOLE module (every PROCEDURE, every
    call site) has been parsed.

    OPT.TXT's own R6 finding ("this needs a post-parse optimization
    phase... because the current immediate per-procedure pass cannot
    see later callers"): calling PHOpt.Optimize immediately, right
    here, the way every earlier version of this procedure did, means a
    procedure parsed EARLIER in the module can never see a call site in
    a procedure parsed LATER -- PHOpt.PAS's own deferred call-graph
    analysis (built lazily, the first time OptimizeAllDeferred's own
    PHOpt.Optimize calls actually need it) needs the WHOLE module's
    call graph before it can safely narrow what a RETN is considered to
    observe for any one procedure, not just the ones parsed so far. }
  { OPT.TXT's own -O0/-O1/-O2 prerequisite: -O0 skips this entirely (no
    peephole optimization at all -- no range is even recorded, so
    OptimizeAllDeferred has nothing to do for this procedure); -O1 (the
    default) and -O2 both record one, but PHOpt.Optimize's own "level"
    parameter (OPT.TXT R1's own fix -- see PHOPT.PAS's own Optimize/
    OptimizePass header comments) is what actually decides WHICH rules
    run once PHOpt.Optimize itself is called: Stage A's own correctness
    repairs run at level=1 unconditionally (bug fixes to existing
    rules, not new rewrites); every Stage C/E rule added since is
    gated to level>=2 inside PHOpt.Optimize itself, not here -- optLevel
    is passed straight through unchanged. }
  if optLevel > 0 then
    OptRangeAppend(pi, bodyStartChunk, bodyStartSlot, bodyEndChunk, bodyEndSlot, optLevel);
  SymTab.LexTruncate(savedLex)
end;

{ ---------------- module translation ---------------- }

{ ParseModule: isTop = top-level file (may have a BEGIN...END, becoming
  'start') vs. an IMPORTed file (spliced in, but may not have its own
  BEGIN...END -- only the top-level file may hold the program's entry
  point). Both may IMPORT further modules (SOPLAN.MD's own Phase 7:
  "natural multi-level imports with an include stack" -- ParseModule was
  already recursive for this, calling itself as ParseModule(false) for
  each IMPORT; the only thing that ever prevented a deeper chain was
  this function's own single-level check, removed here, PLUS
  Scan.pas/SymTab.pas's own file-state save/restore, previously capped
  at exactly one level -- see Scan.pas's own MaxImportDepth/srcStack
  comment for that half of the fix). Genuinely too-deep nesting
  (MaxImportDepth) and a genuine IMPORT cycle are both still caught,
  as translator errors from SymTab.OpenInclude/Scan.OpenInclude below,
  not silently accepted or left to exhaust real resources. }
function ParseModule(isTop: boolean): boolean;
  var incNm, sp, nm: string;
begin
  Scan.SetOk(true);
  SymTab.ExpectKw(SymTab.KwModule);
  { ExpectKw/IsLexKw already advanced past 'MODULE' on a match (IsLexKw
    calls Next internally), so the module's own NAME is already the
    current token here -- capture it before the Next below advances
    past it too. }
  if isTop then begin
    Scan.CurTokText(nm); topModName := nm
  end;
  SymTab.Next;
  SymTab.Expect(SymTab.SySemi);

  while SymTab.IsLexKw(SymTab.KwImport) do begin
    repeat
      Scan.CurTokText(incNm); SymTab.Next;
      if Scan.Ok then begin
        if not SymTab.OpenInclude(incNm) then Scan.SetOk(false)
        else begin
          if not ParseModule(false) then Scan.SetOk(false);
          SymTab.CloseInclude
        end
      end
    until not SymTab.IsLexSym(SymTab.SyComma);
    SymTab.Expect(SymTab.SySemi)
  end;
  { CONST/TYPE/VAR/PROCEDURE sections may repeat and appear in any order
    and mixed, each one applying its own keyword's rules; loop until none
    of the four section-starters matches. }
  EnsureSection(SectCode);
  while SymTab.IsKw(SymTab.KwConst) or SymTab.IsKw(SymTab.KwType)
        or SymTab.IsKw(SymTab.KwVar) or SymTab.IsKw(SymTab.KwProcedure) do begin
    if SymTab.IsLexKw(SymTab.KwConst) then begin
      while (Scan.CurTokKind = TIdent)
            and not SymTab.IsKw(SymTab.KwType)
            and not SymTab.IsKw(SymTab.KwVar)
            and not SymTab.IsKw(SymTab.KwConst)
            and not SymTab.IsKw(SymTab.KwProcedure)
            and not SymTab.IsKw(SymTab.KwBegin)
            and not SymTab.IsKw(SymTab.KwEnd) do ParseConstDecl
    end else if SymTab.IsLexKw(SymTab.KwType) then
      RecTypes.ParseTypeSection(SectStruc, Emit, Emit2, EnsureSection, ParseArrayBound)
    else if SymTab.IsLexKw(SymTab.KwVar) then
      { frameOfs (ctx.frameOfs here) is a required var parameter but
        never touched by ParseVarSection's own isGlobal=true path --
        no live procedure context exists at this call site anyway
        (module-level VAR section, not inside a PROCEDURE body). }
      GlobVar.ParseVarSection(true, ctx.frameOfs, es, SectData, SectBss, Emit, EnsureSection, ParseArrayBound)
    else if SymTab.IsLexKw(SymTab.KwProcedure) then
      ParseProcedure
  end;

  if SymTab.IsLexKw(SymTab.KwBegin) then begin
    EnsureSection(SectCode);
    if not isTop then begin
      Scan.SrcPath(sp);
      LogErr.ErrorInFile(sp, longint(Scan.CurLine), 'an IMPORTed file may not have its own BEGIN...END init part');
      Scan.SetOk(false)
    end else begin
      Emit('global start');
      Emit('start:');
      topHasBegin := true
    end;
    ParseStmtList
  end;
  SymTab.ExpectKw(SymTab.KwEnd);
  if Scan.CurTokKind = TIdent then SymTab.Next;
  SymTab.Expect(SymTab.SyDot);
  ParseModule := Scan.Ok
end;

{ ---------------- driver ---------------- }

procedure Usage;
begin
  WriteLn('SPHINX Oberon Translator, 2026 (c) DosWorld, Public domain (unlicense)');
  WriteLn;
  WriteLn('Usage: SPHO [-O0|-O1|-O2] file.smd');
  WriteLn;
  WriteLn('  Translates file.smd (SPHINX Oberon Module, see DOCS/SPHINX.MD) to');
  WriteLn('  file.asm (NASM-subset syntax).');
  WriteLn;
  WriteLn('  -O0  Do not run the peephole optimizer at all.');
  WriteLn('  -O1  Run the optimizer (default if no -O flag is given).');
  WriteLn('  -O2  Same as -O1 for now (reserved for additional rewrites).')
end;

{ ParseOptLevel: OPT.TXT's own -O0/-O1/-O2 command-line prerequisite --
  scans every ParamStr(1..ParamCount) for the one recognized -O flag
  (at most one; a second, contradicting -O flag is a translator error,
  not silently "last one wins" or "first one wins" -- ambiguous intent
  should not be guessed at). srcPath is set to whichever argument is
  NOT a -O flag (still required to be exactly one such argument --
  zero or more than one is Usage's own pre-existing "no argument"/
  argc-mismatch path, unchanged by this addition, just now computed
  from the non-flag argument count instead of assuming ParamStr(1) is
  always the file). Returns FALSE (leaving level/srcPath unspecified)
  on a malformed -O value or more than one non-flag argument -- the
  caller reports Usage and exits, same as the pre-existing "argc < 1"
  check already did for the zero-argument case. }
function ParseOptLevel(var level: integer; var srcPath: string): boolean;
  var i: integer; arg: string; haveLevel, haveSrc: boolean;
begin
  ParseOptLevel := false;
  level := 1; srcPath := ''; haveLevel := false; haveSrc := false;
  for i := 1 to ParamCount do begin
    arg := ParamStr(i);
    if (Length(arg) = 3) and (arg[1] = '-') and (UpCase(arg[2]) = 'O')
       and (arg[3] in ['0', '1', '2']) then begin
      if haveLevel then exit;   { a second -O flag -- ambiguous, reject }
      level := Ord(arg[3]) - Ord('0'); haveLevel := true
    end else begin
      if haveSrc then exit;   { a second non-flag argument -- ambiguous, reject }
      srcPath := arg; haveSrc := true
    end
  end;
  if not haveSrc then exit;
  ParseOptLevel := true
end;

{ EmitLiteralBytes: writes text's own bytes (plus a trailing 0) as a
  "db" operand list, alternating between a quoted 'run of consecutive
  safe characters' and a bare NNh hex-immediate for any byte that
  would corrupt a NASM '...' string if placed there literally -- the
  quote character itself (') and any control character (a raw
  newline/CR/tab/ESC/etc byte breaks the single-line db statement,
  same failure this fixes for \033/\x1b-style escapes, DOCS/SPHINX.MD
  S3.3). Printable text with no such bytes (the overwhelmingly common
  case) still emits as one plain quoted db line, unchanged from
  before. }
procedure EmitLiteralBytes(const lbl, text: string);
  var i: integer; b: byte; buf: string; inQuote: boolean;
begin
  buf := lbl + ': db ';
  inQuote := false;
  for i := 1 to Length(text) do begin
    b := byte(text[i]);
    if (b >= 32) and (b <= 126) and (chr(b) <> '''') then begin
      if not inQuote then begin
        if (i > 1) then buf := buf + ',';
        buf := buf + ''''; inQuote := true
      end;
      buf := buf + text[i]
    end else begin
      if inQuote then begin buf := buf + ''''; inQuote := false end;
      if i > 1 then buf := buf + ',';
      buf := buf + Util.HexByte(b)
    end
  end;
  if inQuote then buf := buf + '''';
  if Length(text) > 0 then buf := buf + ',';
  buf := buf + '0';
  Emit(buf)
end;

{ EmitLiterals: one ".data"-section "db ..." line per distinct string
  literal collected during translation (via EmitLiteralBytes, safe
  against quote/control-character bytes -- e.g. from a \033/\x1b
  escape, DOCS/SPHINX.MD S3.3), in first-occurrence order, emitted
  once at the very end of RunBody after everything else. }
procedure EmitLiterals;
  var c: PLitChunk; i, k: integer; text, lbl: string;
begin
  if comp.nLits = 0 then exit;
  EnsureSection(SectData);
  c := comp.litHead; i := 0;
  while c <> nil do begin
    k := 1;
    while k <= c^.count do begin
      StrTab.Get(c^.id[k], text);
      lbl := LitLabelName(i);
      EmitLiteralBytes(lbl, text);
      Inc(k); Inc(i)
    end;
    c := c^.next
  end
end;

{ FreeChunks: dispose every allocated node/block of THIS module's own
  Lit/Pending lists, then SymTab.FreeChunks for its own lex/type/proc/
  const/var tables. }
procedure FreeChunks;
  var lc, ln: PLitChunk; pc, pn: PPendingChunk; oc, onext: POpChunk;
      rc, rn: POptRangeChunk;
begin
  lc := comp.litHead;
  while lc <> nil do begin ln := lc^.next; Dispose(lc); lc := ln end;
  comp.litHead := nil; comp.litTail := nil;
  pc := comp.pendingHead;
  while pc <> nil do begin pn := pc^.next; Dispose(pc); pc := pn end;
  comp.pendingHead := nil; comp.pendingTail := nil;
  oc := comp.opHead;
  while oc <> nil do begin onext := oc^.next; Dispose(oc); oc := onext end;
  comp.opHead := nil; comp.opTail := nil;
  rc := comp.optRangeHead;
  while rc <> nil do begin rn := rc^.next; Dispose(rc); rc := rn end;
  comp.optRangeHead := nil; comp.optRangeTail := nil;
  SymTab.FreeChunks
end;

{ TySphinxName/EmitFieldType/EmitSHD now live in unit ShdWrt
  (SRC/SHDWRT.PAS) -- see that unit's own header comment for why
  this cluster split out even more cleanly than RecTypes did (no
  comp/ctx/es dependency at all, so no procedural-parameter hooks
  needed). Called here as ShdWrt.EmitSHD. }

function FileExistsLocal(const path: string): boolean;
  var f: file; i : integer;
begin
  Assign(f, path);
  {$I-}
  System.Reset(f);
  i := IOResult;
  {$I+}
  if i = 0 then begin FileExistsLocal := true; System.Close(f) end
  else FileExistsLocal := false
end;

function RunBody: integer;
  var srcPath, outPath: string;
begin
  if not ParseOptLevel(optLevel, srcPath) then begin
    Usage; RunBody := ExitUsage; exit
  end;
  if not FileExistsLocal(srcPath) then begin
    LogErr.Error2('no such file: ', srcPath); RunBody := ExitIo; exit
  end;
  comp.nLits := 0;
  comp.nOps := 0;
  ctx.labelCnt := 0; comp.loopDepth := -1;
  comp.curSect := SectNone;
  comp.litHead := nil; comp.litTail := nil;
  comp.pendingHead := nil; comp.pendingTail := nil;
  comp.opHead := nil; comp.opTail := nil;
  comp.optRangeHead := nil; comp.optRangeTail := nil;
  topModName := ''; topHasBegin := false;
  SymTab.Reset;
  Scan.SetSrcPath(srcPath);
  if not Scan.OpenSource(srcPath) then begin RunBody := ExitIo; exit end;
  SymTab.Next;

  outPath := ReplaceExt(srcPath, '.ASM');
  if not Emits.open(es, outPath) then begin
    Scan.CloseSource; RunBody := ExitIo; exit
  end;

  if (not ParseModule(true)) or LogErr.HaveErr then begin
    Scan.CloseSource;
    Emits.close(es);
    Erase(es.f);
    FreeChunks; RunBody := ExitAsm; exit
  end;

  CheckPendingCalls;
  if LogErr.HaveErr then begin
    Scan.CloseSource;
    Emits.close(es);
    Erase(es.f);
    FreeChunks; RunBody := ExitAsm; exit
  end;

  { OPT.TXT's own R6 finding -- every call site in the module is now
    fully resolved (CheckPendingCalls just ran), so every recorded
    procedure range's own PHOpt.Optimize call can safely build/consult
    a whole-module call-graph analysis, not just whatever procedures
    happened to be parsed before this one. See OptRangeAppend/
    OptimizeAllDeferred's own header comments above for the full
    reasoning, and ParseProcedure's own comment at its OptRangeAppend
    call site for why this replaced an immediate per-procedure
    PHOpt.Optimize call. }
  OptimizeAllDeferred;

  EmitLiterals;
  SerializeOps;
  Scan.CloseSource;
  Emits.close(es);
  LogErr.Info2('wrote ', outPath);
  if not topHasBegin then ShdWrt.EmitSHD(srcPath, topModName);
  FreeChunks;
  RunBody := ExitOk
end;

begin
  Halt(RunBody)
end.
