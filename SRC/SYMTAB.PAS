{$I FLAGS.INC}
{
  SPHINX Oberon translator's name tables: keyword/symbol/register/TYPE/
  PROCEDURE/CONST/VAR names, all interned in unit LexTab as (kind, id)
  pairs, plus the small per-kind detail tables (symbol/type/procedure
  tables) and Next, the token-fetch entry point every parse step in
  Spho calls.

  Every keyword and symbol SPHO recognizes is registered once, at
  RegisterBuiltins time, via LexTab.Add(spelling, LexKw/LexSym, id) --
  id is one of the Kw*/Sy* constants below. Every register is
  registered the same way (LexReg, Regs86.Reg*). Dynamically-declared
  names (TYPE/PROCEDURE/CONST/VAR) are added the same way as they're
  parsed (LexType/LexProc/LexConst/LexVar, id = that kind's own
  detail-table index) via TypeAppend/ProcReserve/SymAppend.

  Callers (Spho) never compare token spellings against string literals
  for a keyword/symbol/register/proc/var/const check: Next resolves the
  current token's (kind, id) pair once via LexTab.Find, and every
  IsKw/IsSym/-family check compares the cached (kind, id) against a
  named Kw*/Sy* constant -- no per-call string comparison, no literal
  at any Spho.pas call site.

  Split out of unit SphoLex so the identifier/symbol/type/procedure
  tables have their own module boundary, separate from unit Scan
  (character-level scanning, which this unit uses for NextCh/ReportError
  and the raw token buffer). Full design notes: DOCS/SPHO.MD.

  Token state (tokKind/tokText/tokVal) physically lives in unit Scan,
  and callers outside this unit (Spho) read it directly via Scan's own
  CurTok* accessors, never a bare field. The resolved (curKind, curId)
  pair -- this unit's replacement for the old tokLex lexeme-array index
  -- lives here, since only this unit knows about LexTab.

  okFlag (sticky translator-failed flag) lives in Scan, not here: the
  scanner itself (Scan.RawNext) can fail (an over-long or empty
  literal) and must be able to set it directly, alongside every
  SymTab/Spho-side parse error. ParseModule (Spho) reads it via
  Scan.Ok/SetOk directly.
}
unit SymTab;

interface

uses
  StrTab, Regs86, LexTab, Scan, LogErr, Util;

const
  { type kinds }
  TyByte = 0; TyBool = 1; TyWord = 2; TyInt = 3; TyLong = 4; TyRec = 5;

  { symbol-table entry kinds -- VAR and CONST share one identifier
    namespace (both are referenced as a bare operand name), so they
    share one table; TYPE is a separate namespace and stays its own
    table. }
  SymVar = 0; SymConst = 1;

  { LexTab `kind` values -- every keyword, symbol, register, TYPE,
    PROCEDURE, CONST, and VAR name in the whole file is interned in
    LexTab under one of these. `id`'s meaning depends on kind: for
    LexKw/LexSym it's a Kw*/Sy* constant (below); for LexReg it's a
    Regs86.Reg* constant; for LexType/LexProc it's an index into that
    kind's own detail-chunk table (typeDir/procDir); for LexConst/LexVar
    it's an si index into the ONE shared CONST+VAR detail table (symDir
    -- see TSymChunk), since SymKind/SymTy/etc. take a bare si with no
    separate kind parameter and need the row's own stored kind to know
    which fields apply. }
  LexKw = 0; LexSym = 1; LexReg = 2; LexType = 3; LexProc = 4;
  LexConst = 5; LexVar = 6;

  { Kw*: one id per keyword SPHO recognizes (LexKw rows' own `id`).
    Numbered in declaration order below -- the numbering itself is
    arbitrary (nothing depends on specific values, only on each being
    distinct; RegisterBuiltins passes each one by name to its own
    LexTab.Add call, not by array position), unlike the old alphabetical
    Kw* numbering this replaces. }
  KwModule = 0; KwImport = 1; KwConst = 2; KwType = 3; KwRecord = 4;
  KwEnd = 5; KwVar = 6; KwProcedure = 7; KwForward = 8; KwInterrupt = 9;
  KwFar = 10; KwNear = 11; KwReg = 12; KwBegin = 13; KwReturn = 14;
  KwIf = 15; KwThen = 16; KwElsif = 17; KwElse = 18; KwWhile = 19;
  KwDo = 20; KwBreak = 21; KwContinue = 22; KwAsm = 23; KwInc = 24;
  KwDec = 25; KwPush = 26; KwPop = 27; KwUses = 28; KwByte = 29;
  KwWord = 30; KwInteger = 31; KwLongint = 32; KwBoolean = 33;
  KwInt = 34; KwShl = 35; KwShr = 36; KwXor = 37; KwPointer = 38;
  KwChar = 39;
  KwDiv = 40; KwMod = 41; KwExternal = 42; KwOr = 43;

  { Sy*: one id per symbol (LexSym rows' own `id`), numbered in
    declaration order. Only the 15 symbols Spho ever checks via
    IsSym/IsLexSym/Expect get a Sy* constant used at a call site; the
    five relational symbols (#,<,>,<=,>=) are still registered (for
    completeness/IsRegName-style lookups) but Spho keeps reading them
    via tokText directly -- IsRelSym/RelJumps/OpInstr, unchanged, same
    as before this refactor. }
  SyLParen = 0; SyRParen = 1; SyLBrack = 2; SyRBrack = 3; SyComma = 4;
  SySemi = 5; SyColon = 6; SyAssign = 7; SyDot = 8; SyPlus = 9;
  SyMinus = 10; SyStar = 11; SyAmp = 12; SyTilde = 14;
  SyEq = 15;
  { registered but not Is*-checked by name -- see note above }
  SyNe = 16; SyLt = 17; SyGt = 18; SyLe = 19; SyGe = 20;

  { MaxFields: 128 didn't fit anymore once FieldDef grew an extra 'cnt'
    word for array-field support (TP7's Structure too large: TTypeChunk's
    fields array alone would be Chunk*MaxFields*sizeof(FieldDef) =
    64*128*8 = 65536 bytes, at/over the 64KB record-size limit) -- 112
    keeps the same generous headroom (no real RECORD in this codebase
    comes close to even 10 fields) while fitting comfortably under it. }
  MaxFields = 112; MaxParams = 32; MaxUses = 32;

  { symbols/types are unbounded: chunked linked lists of Chunk-sized
    parallel-array nodes, names StrTab-interned instead of a fixed-size
    flat array of char-array records. MaxFields/MaxParams/MaxUses stay
    fixed-size: each bounds a single declaration's own field/param/
    register list, not an accumulate-over-the-whole-file count. }
  Chunk = 64;

  { MaxDetailChunks: the four small detail tables (Type/Proc/Const/Var)
    are a fixed-size DIRECTORY of Chunk-sized blocks (array of
    pointer-to-block), not a linked list -- O(1) to reach (id div Chunk
    indexes straight into it). }
  MaxDetailChunks = 64;

type
  { TRegName: every register spelling this whole translator ever
    handles (AX, BX, ..., AL, AH, ..., CS, DS, ...) is at most 2
    characters -- a plain `string` (TP7 ShortString, 256 bytes) to hold
    one is 128x more storage than ever needed, and a real, measured
    contributor to a genuine TP7-only stack-corruption bug (an array of
    plain `string` sized for a whole parameter/USES list, on the stack,
    under this project's own stack-overflow-checking-disabled
    directive, silently corrupted adjacent memory instead of raising a
    clean runtime error -- DOCS/SPHO.MD has the full investigation). A
    single NAMED type here, not a repeated anonymous `string[3]` at
    each declaration site: TP7 (unlike some later Pascal dialects)
    treats two separately-written `string[3]` array-element types as
    DISTINCT types for `var`-parameter matching purposes, so every
    site that needs to pass a register-name string by `var` must share
    this exact same declared type or a "type mismatch" compile error
    results. }
  TRegName = string[3];

  { fixed-size (not open) array-of-strings: bounds a single declaration's
    own register list (USES/PUSH/POP). }
  RegList = array[0..MaxUses-1] of TRegName;

  { TTypeInfo: a scalar type (TyByte..TyRec) plus its RECORD detail-
    table index (meaningful, >= 0, only when ty = TyRec; -1 otherwise) --
    SOPLAN.MD's own Phase 6, bundling the (ty, recIdx) pair that
    ParseBaseType/ParseBaseTypeName produce and TypeAddField/TySize/
    TypeField/TypeFindFieldTy store/consume, all as one unit, instead of
    two parallel parameters that must always travel together. Deliberately
    NOT used for VAR/CONST scalar declarations (SymSetTy/SymTy) -- every
    external caller of SymTy only ever compares the returned ty (=TyRec,
    =TyLong, etc.), never reads recIdx back, so that pair is write-only
    from outside SymTab and bundling it there would add packaging with no
    read-side benefit (this project's own Simplicity First: no
    abstraction beyond what removes real duplication). }
  TTypeInfo = record
    ty:     integer;
    recIdx: integer
  end;

  FieldDef = record
    nameId: StrTab.TStrTabId;
    typ:    TTypeInfo;
    cnt:    word   { array element count; 1 for a scalar (non-array) field }
  end;

  { TypeChunk: LexType detail table -- one block of Chunk TYPE entries,
    addressed via typeDir[id div Chunk]. No nameId field: the type's own
    name is already interned in LexTab (Add'd under (LexType, ti) by
    TypeAppend), so TypeName reads it back via LexTab.FindText instead
    of keeping a second copy here. }
  PTypeChunk = ^TTypeChunk;
  TTypeChunk = record
    aliasTy: array[1..Chunk] of integer;   { TyRec for a real RECORD type;
                                              otherwise the scalar base type
                                              of a non-RECORD alias. }
    nFields: array[1..Chunk] of integer;
    fields:  array[1..Chunk] of array[0..MaxFields-1] of FieldDef;
    isExported: array[1..Chunk] of boolean { TRUE for a 'TYPE Name* = ...;'
                                              declaration (DOCS/SPHINX.MD's
                                              own '*' export marker, same
                                              convention PROCEDURE/CONST
                                              already have -- see
                                              TProcChunk/TSymChunk's own
                                              isExported). EmitSHD
                                              (Spho.pas) uses this to
                                              decide which TYPE rows
                                              belong in this module's own
                                              .SHD header. }
  end;

  { ProcChunk: LexProc detail table -- one block of Chunk PROCEDURE
    entries, addressed via procDir[id div Chunk]. paramRegId holds a
    Regs86.Reg* id, not the register's own spelling -- the name is
    already interned in LexTab (RegisterBuiltins' own LexReg rows), so
    storing a second string copy per parameter per procedure would be
    the exact redundancy TypeChunk/SymChunk's own nameId removal already
    avoided; ProcParamIsReg resolves the id back to text via
    LexTab.FindText only at the point a caller actually needs it. }
  PProcChunk = ^TProcChunk;
  TProcChunk = record
    isFar:      array[1..Chunk] of boolean;
    valid:      array[1..Chunk] of boolean;     { FALSE for INTERRUPT/FORWARD-pending }
    isFwdKnown: array[1..Chunk] of boolean;      { TRUE only for a FORWARD-declared row
                                                    whose isFar is already known/trustworthy }
    nParams:      array[1..Chunk] of integer;
    paramIsReg:   array[1..Chunk] of array[0..MaxParams-1] of boolean;
    paramRegId:   array[1..Chunk] of array[0..MaxParams-1] of integer;
    { paramNameId/paramTy: each formal parameter's own name (StrTab-
      interned, same reason externName below is: ParseProcedure's own
      SymTab.LexTruncate at the end of every procedure discards that
      procedure's own param names from LexTab, so a bare si captured
      here instead -- SymName(si, ...) -- would fail to resolve once
      EmitSHD (Spho.pas) runs much later, after every procedure in the
      module has already been parsed and truncated) and scalar type,
      captured eagerly in ProcSetParams while the names/types are
      still live, so EmitSHD can reconstruct a full
      'PROCEDURE Name(a: WORD; ...): RetTy; NEAR; EXTERNAL;' .SHD line
      long after parsing is done. paramTy mirrors SymTy(si)'s own
      result at ProcSetParams time (TyRec never occurs here -- by-value
      RECORD parameters are rejected elsewhere, RejectRecordParams). }
    paramNameId:  array[1..Chunk] of array[0..MaxParams-1] of StrTab.TStrTabId;
    paramTy:      array[1..Chunk] of array[0..MaxParams-1] of integer;
    { paramIsLong: TRUE for a non-register LONGINT-typed parameter --
      EmitCall's own call site needs this to know a plain numeric-
      literal argument must be widened to a real 4-byte push (DX:AX,
      zero/sign-extended) instead of the ordinary 2-byte push every
      other parameter type gets; a LONGINT VAR/expression argument
      already produces its own DX:AX pair some other way and doesn't
      consult this. }
    paramIsLong:  array[1..Chunk] of array[0..MaxParams-1] of boolean;
    { paramIsArr: TRUE for a formal parameter declared 'name: T[N]' or
      'name: T[]' (SOPLAN.MD's own Phase 7 item 3, "array parameter
      syntax... typed address/length convention") -- address-only sugar,
      not a real second parameter word: the formal is still exactly one
      WORD/address parameter underneath (same as writing 'name: WORD'
      and passing ADR(arr) manually, the pre-existing convention every
      real EXAMPLES/ file still uses). EmitCall's own argument parser
      consults this (ProcParamIsArray) to decide whether a bare array-
      typed VAR argument should be auto-ADR()'d instead of read as an
      ordinary scalar operand. }
    paramIsArr:   array[1..Chunk] of array[0..MaxParams-1] of boolean;
    retTy:      array[1..Chunk] of integer;      { declared return type (TyByte..TyRec/TyLong),
                                                    TyWord if the procedure has no ':' return
                                                    type at all -- ProcSetRetTy is called
                                                    unconditionally, same point ProcSetIsFar
                                                    already is, so this is always meaningful
                                                    once valid[k]/isFwdKnown[k] is TRUE. }
    retTyKnown: array[1..Chunk] of boolean;      { FALSE until ProcSetRetTy has actually run --
                                                    a FORWARD declaration's own row is
                                                    isFwdKnown=TRUE for isFar well before its
                                                    real body (and therefore its real retTy)
                                                    is parsed, so retTy must be tracked
                                                    separately, not folded into isFwdKnown. }
    sigHasRetTy: array[1..Chunk] of boolean;     { TRUE iff the declaration THIS row's params/
                                                    retTy were stored from actually wrote a
                                                    ': RetTy' clause -- retTy alone can't tell
                                                    "no return type at all" apart from "declared
                                                    WORD", since ParseProcedure always defaults
                                                    procRetTy to TyWord either way (SPHINX.MD
                                                    S6.4). Only meaningful once nParams/retTy
                                                    themselves are meaningful (ProcSetParams/
                                                    ProcSetRetTy called), i.e. for a FORWARD row
                                                    once ParseProcedure's own FORWARD branch
                                                    stores its signature too, not just isFar. }
    isExternal: array[1..Chunk] of boolean;      { TRUE for an EXTERNAL-declared row (DOCS/
                                                    SPHINX.MD's own EXTERNAL entry) -- no body,
                                                    same isFar/isFwdKnown/valid=false shape a
                                                    FORWARD-only row uses, so an ordinary call
                                                    site resolves it exactly the same way. }
    externName: array[1..Chunk] of StrTab.TStrTabId; { the real linker-visible symbol name
                                                    from EXTERNAL's own optional 'name'
                                                    string, e.g. EXTERNAL 'ddd1' -- StrTab-
                                                    interned rather than stored inline as
                                                    string[255] (same heap-saving fix
                                                    Spho.pas's own TOperation/TPendingChunk
                                                    got; far lower-impact here, one entry per
                                                    EXTERNAL-declared PROCEDURE, not per
                                                    emitted operation, so this was never a
                                                    real exhaustion risk on its own -- applied
                                                    anyway to keep SymTab.pas consistent with
                                                    the same fix elsewhere). id 0 ("no
                                                    string", InternOrZero's own convention,
                                                    re-declared locally here since Spho.pas's
                                                    own copy is a `program`, not a `unit`, and
                                                    units can't depend on it) means the
                                                    SPHINX-level name IS the real name (the
                                                    unnamed EXTERNAL form). Every call site
                                                    substitutes this in place of the SPHINX name
                                                    when non-empty; ParseProcedure also emits one
                                                    "extern <this-or-the-SPHINX-name>" line. }
    isExported: array[1..Chunk] of boolean       { TRUE for a 'PROCEDURE Name*(...)' declaration
                                                    (DOCS/SPHINX.MD's own '*' export marker) --
                                                    previously only a parse-time-local `exported`
                                                    boolean in ParseProcedure (Spho.pas), used
                                                    inline for isFar/'global' and then discarded;
                                                    persisted here so EmitSHD (Spho.pas) can later
                                                    enumerate which PROCEDUREs belong in this
                                                    module's own .SHD header. }
  end;

  { SymChunk: CONST/VAR detail table -- one block of Chunk entries,
    addressed via symDir[si div Chunk]. CONST and VAR share this ONE
    table/index space (si), unlike TYPE/PROCEDURE which each get their
    own: SymKind/SymTy/etc. all take a bare si with no separate kind
    parameter, and FindSym/SymAppend hand out si values from this same
    shared counter, so si alone must be enough to know which fields are
    meaningful (kind tags which). Mirrors the old lexeme-array design,
    where CONST and VAR rows lived in one chunked list and each row
    carried its own kind tag. }
  PSymChunk = ^TSymChunk;
  TSymChunk = record
    kind:    array[1..Chunk] of integer;        { SymConst or SymVar }
    val:     array[1..Chunk] of longint;        { SymConst rows only }
    ty:      array[1..Chunk] of integer;        { SymVar rows only: TyByte..TyRec }
    recIdx:  array[1..Chunk] of integer;        { SymVar rows only: index into types[], if ty = TyRec }
    isLocal: array[1..Chunk] of boolean;        { SymVar rows only }
    ofs:     array[1..Chunk] of integer;        { SymVar rows only: [bp-ofs] if local, meaningless if isReg }
    isReg:   array[1..Chunk] of boolean;        { SymVar rows only: a register-named param,
                                                    accessed by register name directly, no frame slot }
    isArr:   array[1..Chunk] of boolean;        { SymVar rows only: TRUE for a global/local VAR
                                                    declared with an array bound ('name: T[N]' or
                                                    'name: T[]') -- SOPLAN.MD's own Phase 7 item 3
                                                    ("array parameter syntax... typed address/
                                                    length convention"): EmitCall's own argument
                                                    parser checks this (SymIsArr) against the
                                                    callee's own formal parameter (ProcParamIsArray)
                                                    to decide whether a bare array-VAR argument
                                                    should be auto-ADR()'d instead of read as an
                                                    ordinary scalar operand. Not previously tracked
                                                    at all -- ParseVarSection's own isArr/cnt locals
                                                    were parse-time-only, never persisted per VAR. }
    isParam: array[1..Chunk] of boolean;         { SymVar rows only: TRUE iff this row was
                                                    declared by ParseParams (a formal PROCEDURE
                                                    parameter), FALSE for an ordinary VAR
                                                    (ParseVarSection never sets it). A re-addition
                                                    of a field with the same name/shape removed as
                                                    dead write-only code in an earlier cleanup pass
                                                    (DOCS/SPHO.MD's own "Implementation note: dead-
                                                    code cleanup") -- this time genuinely read: array
                                                    element indexing ('buf[i]', a Phase 7 follow-on)
                                                    needs to tell an array-typed PARAMETER (whose own
                                                    stack slot holds an ADDRESS value -- the array's
                                                    base -- read it directly) apart from a real array
                                                    VAR (whose own stack slot/label IS the array's
                                                    storage -- its ADDRESS must be computed via
                                                    lea/a bare label, EmitAdrOperand's own logic).
                                                    SymIsArr alone can't distinguish the two: both a
                                                    local array VAR and a local array-typed param
                                                    have isArr=TRUE, isLocal=TRUE. }
    isExported: array[1..Chunk] of boolean      { SymConst rows only: TRUE
                                                    for a 'CONST Name* = ...;' declaration
                                                    (DOCS/SPHINX.MD's own '*' export marker,
                                                    same convention PROCEDURE already has --
                                                    see TProcChunk's own isExported). EmitSHD
                                                    (Spho.pas) uses this to decide which CONST
                                                    rows belong in this module's own .SHD
                                                    header. Never set for a SymVar row (VAR
                                                    globals never appear in a .SHD at all,
                                                    regardless of any marker). }
  end;

{ ---------------- current-token (kind, id) ---------------- }

{ CurTokKind/CurTokId: the resolved LexTab (kind, id) pair naming the
  CURRENT token's own spelling, for TIdent/TSym tokens only (LexKw/
  LexSym/LexReg/LexType/LexProc/LexConst/LexVar as appropriate). -1/-1
  for TNum/TStr/TChar/TEof, or an identifier/symbol spelling LexTab has
  never seen (Next leaves both at -1 in that case). }
function CurTokKind: integer;
function CurTokId: integer;

{ ---------------- scope-exit rollback ---------------- }

{ CurLexMark/LexTruncate: re-export LexTab's Mark/Truncate under their
  old names -- ParseProc marks the lexeme table before parsing a
  PROCEDURE's params, then truncates back after the body, discarding
  that procedure's own param names so they don't leak into the next
  procedure's lookups (LexTab has no per-scope namespacing; this is the
  only mechanism that keeps params scoped to their own procedure).
  CurLexMark is a procedure with a var parameter, not a function
  returning TLexMark -- Turbo Pascal function results are limited to
  ordinal/real/pointer/string types, not an arbitrary record. }
procedure CurLexMark(var m: LexTab.TLexMark);
procedure LexTruncate(const m: LexTab.TLexMark);


{ ---- CONST/VAR detail table ---- }

procedure SymName(si: integer; var dst: string);
function SymKind(si: integer): integer;
function SymTy(si: integer): integer;
procedure SymSetTy(si, ty, recIdx: integer);
function SymIsLocal(si: integer): boolean;
procedure SymSetIsLocal(si: integer; v: boolean);
function SymOfs(si: integer): integer;
procedure SymSetOfs(si, ofs: integer);
function SymIsReg(si: integer): boolean;
procedure SymSetIsReg(si: integer; v: boolean);
function SymIsArr(si: integer): boolean;
procedure SymSetIsArr(si: integer; v: boolean);
function SymIsParam(si: integer): boolean;
procedure SymSetIsParam(si: integer; v: boolean);
function SymVal(si: integer): longint;
procedure SymSetVal(si: integer; val: longint);
function SymAppend(const nm: string; kind: integer): integer;
function FindSym(const nm: string): integer;
procedure SymSetExported(si: integer; v: boolean);
function SymIsExported(si: integer): boolean;

{ ---- TYPE detail table ---- }

function TypeAppend(const nm: string; aliasTy: integer): integer;
procedure TypeSetExported(ti: integer; v: boolean);
function TypeIsExported(ti: integer): boolean;
function FindType(const nm: string): integer;
procedure TypeName(ti: integer; var dst: string);
function TypeNFields(ti: integer): integer;
function TypeAliasTy(ti: integer): integer;
procedure TypeAddField(ti: integer; const nm: string; typ: TTypeInfo; cnt: word);
procedure TypeField(ti, fi: integer; var nm: string; var typ: TTypeInfo; var cnt: word);
function TypeFindFieldTy(ti: integer; const fieldName: string; var typ: TTypeInfo; var cnt: word): boolean;

{ ---- PROCEDURE detail table ---- }

function ProcReserve(const nm: string): integer;
procedure ProcSetIsFar(pi: integer; isFar: boolean);
procedure ProcSetForward(pi: integer; isFar: boolean);
procedure ProcSetExternal(pi: integer; isFar: boolean; const externName: string);
function ProcFindExternal(const nm: string; var externName: string): boolean;
procedure ProcSetExported(pi: integer; v: boolean);
function ProcIsExported(pi: integer): boolean;
procedure ProcSetParams(pi: integer; var regFlags: array of boolean; var sis: array of integer; n: integer);
function ProcParamIsReg(pi, i: integer; var regName: string): boolean;
function ProcParamIsLong(pi, i: integer): boolean;
function ProcParamIsArray(pi, i: integer): boolean;

{ ---- enumeration accessors for EmitSHD (Spho.pas) -- see their own
  implementation-side comment for why these exist. }
function ProcCount: integer;
procedure ProcName(pi: integer; var dst: string);
function ProcIsFar(pi: integer): boolean;
function ProcNParams(pi: integer): integer;
procedure ProcParamName(pi, i: integer; var dst: string);
function ProcParamTy(pi, i: integer): integer;
function ProcRetTy(pi: integer): integer;
function ProcSigHasRetTy(pi: integer): boolean;
function TypeCount: integer;
function SymCount: integer;
function BuiltinSymCount: integer;

function ProcFindIsFar(const nm: string; var isFar: boolean): boolean;
function ProcFindAny(const nm: string; var isValid: boolean): integer;
procedure ProcSetRetTy(pi: integer; ty: integer; hasRetTy: boolean);
function ProcFindRetTy(const nm: string; var ty: integer): boolean;
function ProcIsFwdOnly(pi: integer): boolean;
function ProcCompareSig(pi: integer; var regFlags: array of boolean;
  var sis: array of integer; n: integer; hasRetTy: boolean;
  retTy: integer; var why: string): boolean;

{ ---------------- token fetch ---------------- }

procedure SkipAsmLead;
procedure ReadAsmLine(var buf, firstWord: string; var atEnd: boolean);
procedure Next;

{ ---------------- driver-facing setup/reset ---------------- }

function OpenInclude(const nm: string): boolean;
procedure CloseInclude;
procedure RegisterBuiltins;
procedure Reset;
procedure FreeChunks;

function IsRegName(const s: string): boolean;
function CurTokIsReg: boolean;

{ IsKw/IsSym: TRUE if the CURRENT token is the keyword/symbol named by
  the given Kw*/Sy* id -- no string comparison, just a (kind, id)
  compare against Next's already-resolved CurTokKind/CurTokId. }
function IsKw(kwId: integer): boolean;
function IsSym(syId: integer): boolean;
function IsLexKw(kwId: integer): boolean;
function IsLexSym(syId: integer): boolean;
procedure Expect(syId: integer);
procedure ExpectKw(kwId: integer);

implementation

var
  { gCurKind/gCurId: this token's resolved LexTab pair, filled by Next.
    -1/-1 if the current token doesn't name a lexeme (TNum/TStr/TChar/
    TEof, or an identifier/symbol LexTab has never seen). Named gCur*,
    not curTok*, to avoid colliding with the CurTokKind/CurTokId
    function names below -- Pascal identifiers are case-insensitive, so
    a var and function can't share a spelling even in different case. }
  gCurKind, gCurId: integer;

  { stkCurKind/stkCurId: gCurKind/gCurId's own save STACK around nested
    IMPORTs, mirroring Scan's own stkTokKind/stkTokText (SOPLAN.MD's own
    Phase 7 "natural multi-level imports with an include stack" --
    a single outerCurKind/outerCurId slot, this project's own earlier
    design, only ever supported one level of nesting correctly; a second
    IMPORT opened while the first was still open would silently
    overwrite it, corrupting the first IMPORT's own saved state instead
    of the top-level file's). OpenInclude saves the includer's own
    already-resolved (kind,id) pair, indexed by Scan.CurImportDepth
    (the includer's OWN depth, before Scan.OpenInclude bumps it) --
    exactly the same indexing convention Scan.pas's own stack uses.
    CloseInclude restores it after, indexed by the SAME depth value
    (read again post-decrement, once Scan.CloseInclude has already
    popped back to it). Scan.CloseInclude only restores its OWN token-
    buffer fields (tokKind/tokText/tokLex); it knows nothing about
    LexTab or the (kind,id) classification layered on top here, so this
    half of the restore has to happen in this unit instead. }
  stkCurKind, stkCurId: array[0..Scan.MaxImportDepth-1] of integer;

  typeDir: array[0..MaxDetailChunks-1] of PTypeChunk;
  nTypes: integer;

  procDir: array[0..MaxDetailChunks-1] of PProcChunk;
  nProcs: integer;

  symDir: array[0..MaxDetailChunks-1] of PSymChunk;
  nSyms: integer;

  { gBuiltinSymCount: nSyms right after RegisterBuiltins seeded TRUE/
    FALSE/NIL (Reset's own call to it) -- every si below this index is
    a builtin CONST, not something the module itself declared; EmitSHD
    (Spho.pas) uses BuiltinSymCount below to skip them when enumerating
    this module's own CONST section (SymCount/SymKind/SymName/SymVal
    alone can't otherwise tell a builtin CONST apart from a real one --
    both are plain SymConst rows in the same shared si space). Named
    gBuiltinSymCount, not builtinSymCount, to avoid colliding with the
    BuiltinSymCount function below -- Pascal identifiers are case-
    insensitive, so a var and function can't share a spelling even in
    different case (same reason gCurKind/gCurId aren't named
    curKind/curId, see that var's own comment). }
  gBuiltinSymCount: integer;

{ ---------------- current-token (kind, id) ---------------- }

function CurTokKind: integer;
begin CurTokKind := gCurKind end;

function CurTokId: integer;
begin CurTokId := gCurId end;

{ ---------------- scope-exit rollback ---------------- }

procedure CurLexMark(var m: LexTab.TLexMark);
begin LexTab.Mark(m) end;

procedure LexTruncate(const m: LexTab.TLexMark);
begin LexTab.Truncate(m) end;

{ ---- CONST/VAR detail table (shared si index space, see TSymChunk) ---- }

procedure SymChunkFor(si: integer; var c: PSymChunk; var k: integer);
begin c := symDir[si div Chunk]; k := (si mod Chunk) + 1 end;

function SymAppend(const nm: string; kind: integer): integer;
  var si, bi, k: integer; last: PSymChunk;
begin
  si := nSyms; Inc(nSyms);
  bi := si div Chunk;
  if symDir[bi] = nil then New(symDir[bi]);
  { LexTab kind is LexConst/LexVar (its own namespace vs. TYPE/PROC), not
    the SymConst/SymVar tag stored per-row here -- both are needed:
    LexTab's kind lets FindSym reject a same-named TYPE/PROC row via one
    (kind,id) compare with no detail-table touch; the per-row kind here
    is what SymKind actually reports back to callers. The name itself is
    NOT duplicated into a second table here -- LexTab.Add already
    interned it under (LexConst/LexVar, si); SymName reads it back via
    LexTab.FindText using that same (kind, si) pair. }
  if kind = SymConst then LexTab.Add(nm, LexConst, si)
  else LexTab.Add(nm, LexVar, si);
  SymChunkFor(si, last, k);
  last^.kind[k] := kind;
  last^.isReg[k] := false;   { fresh entries default -- explicit init, VAR rows only }
  last^.isArr[k] := false;   { fresh entries default -- explicit init, VAR rows only }
  last^.isParam[k] := false; { fresh entries default -- explicit init, VAR rows only }
  last^.isExported[k] := false; { fresh entries default -- explicit init, SymConst rows only }
  SymAppend := si
end;

{ SymSetExported/SymIsExported: the '*' export marker on a CONST
  declaration (SymConst rows only -- see isExported's own declaration
  comment, TSymChunk). }
procedure SymSetExported(si: integer; v: boolean);
  var c: PSymChunk; k: integer;
begin SymChunkFor(si, c, k); c^.isExported[k] := v end;

function SymIsExported(si: integer): boolean;
  var c: PSymChunk; k: integer;
begin SymChunkFor(si, c, k); SymIsExported := c^.isExported[k] end;

procedure SymName(si: integer; var dst: string);
  var c: PSymChunk; k: integer; lexKind: integer;
begin
  SymChunkFor(si, c, k);
  if c^.kind[k] = SymConst then lexKind := LexConst else lexKind := LexVar;
  LexTab.FindText(lexKind, si, dst)
end;

function SymKind(si: integer): integer;
  var c: PSymChunk; k: integer;
begin SymChunkFor(si, c, k); SymKind := c^.kind[k] end;

function SymTy(si: integer): integer;
  var c: PSymChunk; k: integer;
begin SymChunkFor(si, c, k); SymTy := c^.ty[k] end;

procedure SymSetTy(si, ty, recIdx: integer);
  var c: PSymChunk; k: integer;
begin SymChunkFor(si, c, k); c^.ty[k] := ty; c^.recIdx[k] := recIdx end;

function SymIsLocal(si: integer): boolean;
  var c: PSymChunk; k: integer;
begin SymChunkFor(si, c, k); SymIsLocal := c^.isLocal[k] end;

procedure SymSetIsLocal(si: integer; v: boolean);
  var c: PSymChunk; k: integer;
begin SymChunkFor(si, c, k); c^.isLocal[k] := v end;

function SymOfs(si: integer): integer;
  var c: PSymChunk; k: integer;
begin SymChunkFor(si, c, k); SymOfs := c^.ofs[k] end;

procedure SymSetOfs(si, ofs: integer);
  var c: PSymChunk; k: integer;
begin SymChunkFor(si, c, k); c^.ofs[k] := ofs end;

function SymIsReg(si: integer): boolean;
  var c: PSymChunk; k: integer;
begin SymChunkFor(si, c, k); SymIsReg := c^.isReg[k] end;

procedure SymSetIsReg(si: integer; v: boolean);
  var c: PSymChunk; k: integer;
begin SymChunkFor(si, c, k); c^.isReg[k] := v end;

function SymIsArr(si: integer): boolean;
  var c: PSymChunk; k: integer;
begin SymChunkFor(si, c, k); SymIsArr := c^.isArr[k] end;

procedure SymSetIsArr(si: integer; v: boolean);
  var c: PSymChunk; k: integer;
begin SymChunkFor(si, c, k); c^.isArr[k] := v end;

function SymIsParam(si: integer): boolean;
  var c: PSymChunk; k: integer;
begin SymChunkFor(si, c, k); SymIsParam := c^.isParam[k] end;

procedure SymSetIsParam(si: integer; v: boolean);
  var c: PSymChunk; k: integer;
begin SymChunkFor(si, c, k); c^.isParam[k] := v end;

function SymVal(si: integer): longint;
  var c: PSymChunk; k: integer;
begin SymChunkFor(si, c, k); SymVal := c^.val[k] end;

procedure SymSetVal(si: integer; val: longint);
  var c: PSymChunk; k: integer;
begin SymChunkFor(si, c, k); c^.val[k] := val end;

function FindSym(const nm: string): integer;
  var kind, id: integer;
begin
  if not LexTab.Find(nm, kind, id) then begin FindSym := -1; exit end;
  if (kind = LexConst) or (kind = LexVar) then FindSym := id
  else FindSym := -1
end;

{ ---- TYPE detail table (LexType rows) ---- }

procedure TypeChunkFor(ti: integer; var c: PTypeChunk; var k: integer);
begin c := typeDir[ti div Chunk]; k := (ti mod Chunk) + 1 end;

function TypeAppend(const nm: string; aliasTy: integer): integer;
  var last: PTypeChunk; ti, bi, k: integer;
begin
  ti := nTypes; Inc(nTypes);
  bi := ti div Chunk;
  if typeDir[bi] = nil then New(typeDir[bi]);
  TypeChunkFor(ti, last, k);
  last^.aliasTy[k] := aliasTy;
  last^.nFields[k] := 0;
  last^.isExported[k] := false;
  { The type's own name is not duplicated into a second table here --
    LexTab.Add is the only place it's interned; TypeName reads it back
    via LexTab.FindText(LexType, ti, ...). }
  LexTab.Add(nm, LexType, ti);
  TypeAppend := ti
end;

{ TypeSetExported/TypeIsExported: the '*' export marker on a TYPE
  declaration (see isExported's own declaration comment, TTypeChunk). }
procedure TypeSetExported(ti: integer; v: boolean);
  var c: PTypeChunk; k: integer;
begin TypeChunkFor(ti, c, k); c^.isExported[k] := v end;

function TypeIsExported(ti: integer): boolean;
  var c: PTypeChunk; k: integer;
begin TypeChunkFor(ti, c, k); TypeIsExported := c^.isExported[k] end;

function FindType(const nm: string): integer;
  var kind, id: integer;
begin
  if LexTab.Find(nm, kind, id) and (kind = LexType) then FindType := id
  else FindType := -1
end;

procedure TypeName(ti: integer; var dst: string);
begin LexTab.FindText(LexType, ti, dst) end;

function TypeNFields(ti: integer): integer;
  var c: PTypeChunk; k: integer;
begin TypeChunkFor(ti, c, k); TypeNFields := c^.nFields[k] end;

function TypeAliasTy(ti: integer): integer;
  var c: PTypeChunk; k: integer;
begin TypeChunkFor(ti, c, k); TypeAliasTy := c^.aliasTy[k] end;

procedure TypeAddField(ti: integer; const nm: string; typ: TTypeInfo; cnt: word);
  var c: PTypeChunk; k, fi: integer;
begin
  TypeChunkFor(ti, c, k);
  fi := c^.nFields[k];
  if fi >= MaxFields then begin
    Scan.ReportError('too many fields in RECORD'); exit
  end;
  c^.fields[k][fi].nameId := StrTab.Put(nm);
  c^.fields[k][fi].typ := typ;
  c^.fields[k][fi].cnt := cnt;
  c^.nFields[k] := fi + 1
end;

procedure TypeField(ti, fi: integer; var nm: string; var typ: TTypeInfo; var cnt: word);
  var c: PTypeChunk; k: integer;
begin
  TypeChunkFor(ti, c, k);
  StrTab.Get(c^.fields[k][fi].nameId, nm);
  typ := c^.fields[k][fi].typ; cnt := c^.fields[k][fi].cnt
end;

function TypeFindFieldTy(ti: integer; const fieldName: string; var typ: TTypeInfo; var cnt: word): boolean;
  var i: integer; fnm: string; ftyp: TTypeInfo; fcnt: word;
begin
  typ.ty := TyWord; typ.recIdx := -1; cnt := 1;
  if ti < 0 then begin TypeFindFieldTy := false; exit end;
  i := 0;
  while i < TypeNFields(ti) do begin
    TypeField(ti, i, fnm, ftyp, fcnt);
    if fnm = fieldName then begin typ := ftyp; cnt := fcnt; TypeFindFieldTy := true; exit end;
    Inc(i)
  end;
  TypeFindFieldTy := false
end;

{ ---- PROCEDURE detail table (LexProc rows) ---- }

procedure ProcChunkFor(pi: integer; var c: PProcChunk; var k: integer);
begin c := procDir[pi div Chunk]; k := (pi mod Chunk) + 1 end;

function ProcReserve(const nm: string): integer;
  var last: PProcChunk; pi, bi, k: integer;
begin
  pi := nProcs; Inc(nProcs);
  bi := pi div Chunk;
  if procDir[bi] = nil then New(procDir[bi]);
  ProcChunkFor(pi, last, k);
  last^.valid[k] := false;
  last^.isFwdKnown[k] := false;
  last^.nParams[k] := 0;
  last^.retTyKnown[k] := false;
  last^.isExternal[k] := false;
  last^.isExported[k] := false;
  LexTab.Add(nm, LexProc, pi);
  ProcReserve := pi
end;

procedure ProcSetIsFar(pi: integer; isFar: boolean);
  var c: PProcChunk; k: integer;
begin ProcChunkFor(pi, c, k); c^.isFar[k] := isFar; c^.valid[k] := true end;

{ ProcSetExported: records the '*' export marker (DOCS/SPHINX.MD's own
  entry) persistently -- ParseProcedure's own local `exported` boolean
  used to be discarded right after parsing; EmitSHD needs it later to
  decide which PROCEDUREs belong in this module's own .SHD header. }
procedure ProcSetExported(pi: integer; v: boolean);
  var c: PProcChunk; k: integer;
begin ProcChunkFor(pi, c, k); c^.isExported[k] := v end;

function ProcIsExported(pi: integer): boolean;
  var c: PProcChunk; k: integer;
begin ProcChunkFor(pi, c, k); ProcIsExported := c^.isExported[k] end;

procedure ProcSetForward(pi: integer; isFar: boolean);
  var c: PProcChunk; k: integer;
begin ProcChunkFor(pi, c, k); c^.isFar[k] := isFar; c^.valid[k] := false; c^.isFwdKnown[k] := true end;

{ InternOrZero: StrTab.Put(s), except an empty string interns as id 0
  ("no string") instead of a real StrTab entry -- mirrors Spho.pas's own
  identically-named/-shaped helper exactly (re-declared locally here
  since Spho.pas is a `program`, not a `unit`, so SymTab.pas can't
  depend on it); StrTab.Put('') would otherwise intern the empty string
  as a genuine id like any other content, breaking externName's own
  "id 0 = unnamed EXTERNAL form" convention below. }
function InternOrZero(const s: string): StrTab.TStrTabId;
begin
  if s = '' then InternOrZero := 0 else InternOrZero := StrTab.Put(s)
end;

{ ProcSetExternal: EXTERNAL ['name'] -- same isFar/valid=false/isFwdKnown
  shape ProcSetForward already uses, so an ordinary call site resolves an
  EXTERNAL procedure exactly the same way a FORWARD-only one resolves.
  externName interns as id 0 for the unnamed form (the SPHINX name IS
  the real linker symbol); ProcFindExternal below then reports
  isExternal=TRUE with externName=nm unchanged in that case, so a caller
  doesn't need its own "is this empty" branch. }
procedure ProcSetExternal(pi: integer; isFar: boolean; const externName: string);
  var c: PProcChunk; k: integer;
begin
  ProcChunkFor(pi, c, k);
  c^.isFar[k] := isFar; c^.valid[k] := false; c^.isFwdKnown[k] := true;
  c^.isExternal[k] := true; c^.externName[k] := InternOrZero(externName)
end;

{ ProcFindExternal: TRUE iff nm names an EXTERNAL-declared procedure --
  externName is set to the real linker-visible symbol name (nm itself
  when EXTERNAL's own optional 'name' string was omitted -- externName
  id 0, StrTab.Get's own "id 0 -> ''" already gives the same empty-check
  result the old plain-string comparison did). }
function ProcFindExternal(const nm: string; var externName: string): boolean;
  var kind, id: integer; pc: PProcChunk; pk: integer; en: string;
begin
  ProcFindExternal := false;
  if not (LexTab.Find(nm, kind, id) and (kind = LexProc)) then exit;
  ProcChunkFor(id, pc, pk);
  if not pc^.isExternal[pk] then exit;
  StrTab.Get(pc^.externName[pk], en);
  if en = '' then externName := nm
  else externName := en;
  ProcFindExternal := true
end;

procedure ProcSetParams(pi: integer; var regFlags: array of boolean; var sis: array of integer; n: integer);
  var c: PProcChunk; k, i: integer; nm: string;
begin
  ProcChunkFor(pi, c, k);
  c^.nParams[k] := n;
  i := 0;
  while i < n do begin
    SymName(sis[i], nm);
    c^.paramNameId[k][i] := StrTab.Put(nm);
    c^.paramTy[k][i] := SymTy(sis[i]);
    c^.paramIsReg[k][i] := regFlags[i];
    if regFlags[i] then begin
      c^.paramRegId[k][i] := Regs86.LookupReg(Util.UpStr(nm))
    end else begin
      { An array-typed parameter (SymIsArr) is always a plain WORD
        address underneath (SOPLAN.MD's own Phase 7 item 3 sugar),
        never LONGINT-widened here even if its own element type T is
        LONGINT ('arr: LONGINT[5]' is a 2-byte address, not a 4-byte
        value) -- see AssignParamOffsets' own identical exemption. }
      c^.paramIsLong[k][i] := (SymTy(sis[i]) = TyLong) and not SymIsArr(sis[i]);
      c^.paramIsArr[k][i] := SymIsArr(sis[i])
    end;
    Inc(i)
  end
end;

function ProcParamIsReg(pi, i: integer; var regName: string): boolean;
  var c: PProcChunk; k: integer;
begin
  if (pi < 0) or (pi >= nProcs) then begin ProcParamIsReg := false; exit end;
  ProcChunkFor(pi, c, k);
  if (i < 0) or (i >= c^.nParams[k]) then begin ProcParamIsReg := false; exit end;
  if not c^.paramIsReg[k][i] then begin ProcParamIsReg := false; exit end;
  LexTab.FindText(LexReg, c^.paramRegId[k][i], regName);
  ProcParamIsReg := true
end;

{ ProcParamIsLong: TRUE iff parameter i of procedure pi is a non-
  register LONGINT-typed formal -- see paramIsLong's own declaration
  comment (TProcChunk, above) for why EmitCall needs this. }
function ProcParamIsLong(pi, i: integer): boolean;
  var c: PProcChunk; k: integer;
begin
  if (pi < 0) or (pi >= nProcs) then begin ProcParamIsLong := false; exit end;
  ProcChunkFor(pi, c, k);
  if (i < 0) or (i >= c^.nParams[k]) then begin ProcParamIsLong := false; exit end;
  ProcParamIsLong := c^.paramIsLong[k][i]
end;

{ ProcParamIsArray: TRUE iff parameter i of procedure pi is a non-
  register array-typed formal ('name: T[N]'/'name: T[]') -- see
  paramIsArr's own declaration comment (TProcChunk, above) for why
  EmitCall needs this. }
function ProcParamIsArray(pi, i: integer): boolean;
  var c: PProcChunk; k: integer;
begin
  if (pi < 0) or (pi >= nProcs) then begin ProcParamIsArray := false; exit end;
  ProcChunkFor(pi, c, k);
  if (i < 0) or (i >= c^.nParams[k]) then begin ProcParamIsArray := false; exit end;
  ProcParamIsArray := c^.paramIsArr[k][i]
end;

{ ---- enumeration accessors for EmitSHD (Spho.pas) -- walk every
  PROCEDURE/TYPE/CONST this module declared, in declaration order, to
  regenerate a .SHD header after a full top-level translation. Every
  other accessor above takes a name (FindSym/FindType/LexTab.Find) or
  an already-known index handed back by *Reserve/*Append at parse
  time; nothing before this needed to walk the whole table by plain
  0-based position, so these are the first such accessors. }

function ProcCount: integer;
begin ProcCount := nProcs end;

procedure ProcName(pi: integer; var dst: string);
begin LexTab.FindText(LexProc, pi, dst) end;

function ProcIsFar(pi: integer): boolean;
  var c: PProcChunk; k: integer;
begin ProcChunkFor(pi, c, k); ProcIsFar := c^.isFar[k] end;

function ProcNParams(pi: integer): integer;
  var c: PProcChunk; k: integer;
begin ProcChunkFor(pi, c, k); ProcNParams := c^.nParams[k] end;

{ ProcParamSi: the si (SymChunk index) parameter i of procedure pi was
  declared under -- SymName/SymTy/SymIsArr of this give the parameter's
  own name/type/array-ness, same as ProcSetParams itself derives from
  at parse time (see paramSi's own declaration comment). }
procedure ProcParamName(pi, i: integer; var dst: string);
  var c: PProcChunk; k: integer;
begin ProcChunkFor(pi, c, k); StrTab.Get(c^.paramNameId[k][i], dst) end;

function ProcParamTy(pi, i: integer): integer;
  var c: PProcChunk; k: integer;
begin ProcChunkFor(pi, c, k); ProcParamTy := c^.paramTy[k][i] end;

function ProcRetTy(pi: integer): integer;
  var c: PProcChunk; k: integer;
begin ProcChunkFor(pi, c, k); ProcRetTy := c^.retTy[k] end;

function ProcSigHasRetTy(pi: integer): boolean;
  var c: PProcChunk; k: integer;
begin ProcChunkFor(pi, c, k); ProcSigHasRetTy := c^.sigHasRetTy[k] end;

function TypeCount: integer;
begin TypeCount := nTypes end;

function SymCount: integer;
begin SymCount := nSyms end;

function BuiltinSymCount: integer;
begin BuiltinSymCount := gBuiltinSymCount end;

function ProcFindIsFar(const nm: string; var isFar: boolean): boolean;
  var kind, id: integer; pc: PProcChunk; pk: integer;
begin
  if not (LexTab.Find(nm, kind, id) and (kind = LexProc)) then begin
    ProcFindIsFar := false; exit
  end;
  ProcChunkFor(id, pc, pk);
  if pc^.valid[pk] or pc^.isFwdKnown[pk] then begin
    isFar := pc^.isFar[pk]; ProcFindIsFar := true; exit
  end;
  ProcFindIsFar := false
end;

procedure ProcSetRetTy(pi: integer; ty: integer; hasRetTy: boolean);
  var c: PProcChunk; k: integer;
begin
  ProcChunkFor(pi, c, k);
  c^.retTy[k] := ty; c^.retTyKnown[k] := true; c^.sigHasRetTy[k] := hasRetTy
end;

{ ProcFindRetTy: TRUE only once the NAMED procedure's own body has
  actually been parsed far enough to know its real return type
  (ProcSetRetTy called) -- unlike ProcFindIsFar, a FORWARD declaration's
  own isFwdKnown does NOT make this TRUE: a FORWARD decl's return type
  IS now checked against the real definition's own (ProcCompareSig,
  called from ParseProcedure right before the real definition's own
  ProcSetRetTy call overwrites this row), but only at that later point,
  not here -- ProcFindRetTy itself is a lookup, not a validity check,
  and ProcSetRetTy is only ever called once, at the real body. A caller
  reached before the real definition (FORWARD-only) simply gets FALSE
  and falls back to whatever it already assumed a call result's own
  type is. }
function ProcFindRetTy(const nm: string; var ty: integer): boolean;
  var kind, id: integer; pc: PProcChunk; pk: integer;
begin
  if not (LexTab.Find(nm, kind, id) and (kind = LexProc)) then begin
    ProcFindRetTy := false; exit
  end;
  ProcChunkFor(id, pc, pk);
  if pc^.retTyKnown[pk] then begin
    ty := pc^.retTy[pk]; ProcFindRetTy := true; exit
  end;
  ProcFindRetTy := false
end;

{ ProcIsFwdOnly: TRUE iff row pi is a FORWARD-declared row awaiting its
  real definition (isFwdKnown, not valid, not EXTERNAL) -- ParseProcedure
  uses this to decide whether a reused pi's own stored signature should
  be compared against the real definition now being parsed (SOPLAN.MD's
  own Phase 5 item 4); an EXTERNAL row reaching a real PROCEDURE body
  isn't a documented/supported pattern, so it's deliberately excluded
  here rather than silently compared too. }
function ProcIsFwdOnly(pi: integer): boolean;
  var c: PProcChunk; k: integer;
begin
  ProcChunkFor(pi, c, k);
  ProcIsFwdOnly := c^.isFwdKnown[k] and (not c^.valid[k]) and (not c^.isExternal[k])
end;

{ ProcCompareSig: TRUE iff the freshly-parsed signature (regFlags/sis/n,
  hasRetTy/retTy -- exactly ParseProcedure's own locals right after
  ParseParams/the ': RetTy' clause) matches row pi's own already-stored
  signature (SOPLAN.MD's own Phase 5 item 4: "Validate that a FORWARD
  declaration and its definition have compatible signatures"). Compares
  what actually determines calling-convention correctness -- parameter
  COUNT, each parameter's register-vs-stack placement (and which
  register, if a register parameter), each STACK parameter's LONGINT-
  vs-not width (paramIsLong, TSize 4 vs 2 bytes -- AssignParamOffsets'
  own nStack/retn-N accounting depends on this), and whether a return
  type was declared at all plus its value -- NOT full scalar-type
  identity for every non-LONGINT stack parameter (e.g. WORD vs INTEGER),
  since neither changes the actual stack layout or calling convention;
  row pi is assumed already valid/isFwdKnown (checked by the caller via
  ProcFindAny before ever reaching here). why is set to a short English
  reason on a FALSE result, for the caller's own diagnostic text. }
function ProcCompareSig(pi: integer; var regFlags: array of boolean;
  var sis: array of integer; n: integer; hasRetTy: boolean;
  retTy: integer; var why: string): boolean;
  var c: PProcChunk; k, i: integer; wantLong: boolean; nm, idx: string;
begin
  ProcCompareSig := false;
  ProcChunkFor(pi, c, k);
  if c^.nParams[k] <> n then begin
    why := 'parameter count differs from FORWARD declaration'; exit
  end;
  i := 0;
  while i < n do begin
    idx := Util.IntStr(longint(i + 1));
    if c^.paramIsReg[k][i] <> regFlags[i] then begin
      why := 'parameter ' + idx + ' register/stack placement differs';
      exit
    end;
    if regFlags[i] then begin
      SymName(sis[i], nm);
      if c^.paramRegId[k][i] <> Regs86.LookupReg(Util.UpStr(nm)) then begin
        why := 'parameter ' + idx + ' register differs';
        exit
      end
    end else begin
      { Same array-of-LONGINT exemption ProcSetParams itself already
        applies (its own paramIsLong assignment, above) -- a LONGINT[N]
        array parameter is really a 2-byte address, not a 4-byte value,
        so it must NOT count as "long" here either. Without this, a
        FORWARD declaration's own paramIsLong[i]=false (correctly
        exempted when first parsed) never matched this freshly
        recomputed wantLong=true (which ignored the exemption),
        producing a spurious "parameter N type differs" error on a
        real definition whose signature is actually identical -- found
        via "PROCEDURE Foo(buf: LONGINT[4]): WORD; NEAR; FORWARD;"
        followed by the matching real definition. }
      wantLong := (SymTy(sis[i]) = TyLong) and not SymIsArr(sis[i]);
      if c^.paramIsLong[k][i] <> wantLong then begin
        why := 'parameter ' + idx + ' type differs';
        exit
      end
    end;
    Inc(i)
  end;
  if c^.sigHasRetTy[k] <> hasRetTy then begin
    why := 'return type differs from FORWARD declaration'; exit
  end;
  if hasRetTy and (c^.retTy[k] <> retTy) then begin
    why := 'return type differs from FORWARD declaration'; exit
  end;
  ProcCompareSig := true
end;

function ProcFindAny(const nm: string; var isValid: boolean): integer;
  var kind, id: integer; pc: PProcChunk; pk: integer;
begin
  if not (LexTab.Find(nm, kind, id) and (kind = LexProc)) then begin
    ProcFindAny := -1; exit
  end;
  ProcChunkFor(id, pc, pk);
  isValid := pc^.valid[pk];
  ProcFindAny := id
end;

{ ---------------- token fetch ---------------- }

procedure SkipAsmLead;
begin Scan.SkipAsmLead end;

procedure ReadAsmLine(var buf, firstWord: string; var atEnd: boolean);
begin Scan.ReadAsmLine(buf, firstWord, atEnd) end;

{ Next: fetch the next token via Scan.RawNext, then resolve
  gCurKind/gCurId from LexTab for TIdent/TSym tokens (the only two
  kinds that ever name a lexeme) -- -1/-1 for TNum/TStr/TChar/TEof, or
  an identifier/symbol LexTab has never seen. }
procedure Next;
  var kind: integer; text: string; lkKind, lkId: integer;
begin
  Scan.RawNext;
  Scan.GetTokKindText(kind, text);
  gCurKind := -1; gCurId := -1;
  if (kind = Scan.TIdent) or (kind = Scan.TSym) then begin
    if LexTab.Find(UpStr(text), lkKind, lkId) then begin
      gCurKind := lkKind; gCurId := lkId
    end
  end
end;

{ IsKw/IsSym: TRUE if the CURRENT token's already-resolved (kind, id)
  matches (LexKw, kwId) / (LexSym, syId). No string comparison. }
function IsKw(kwId: integer): boolean;
begin IsKw := (gCurKind = LexKw) and (gCurId = kwId) end;

function IsSym(syId: integer): boolean;
begin IsSym := (gCurKind = LexSym) and (gCurId = syId) end;

function IsLexKw(kwId: integer): boolean;
begin
  if IsKw(kwId) then begin Next; IsLexKw := true end
  else IsLexKw := false
end;

function IsLexSym(syId: integer): boolean;
begin
  if IsSym(syId) then begin Next; IsLexSym := true end
  else IsLexSym := false
end;

procedure Expect(syId: integer);
  var msg, text, spelling: string;
begin
  if not IsLexSym(syId) then begin
    Scan.CurTokText(text);
    LexTab.FindText(LexSym, syId, spelling);
    msg := 'expected ''' + spelling + ''' got ''' + text + '''';
    Scan.ReportError(msg)
  end
end;

procedure ExpectKw(kwId: integer);
  var msg, spelling: string;
begin
  if not IsLexKw(kwId) then begin
    LexTab.FindText(LexKw, kwId, spelling);
    msg := 'expected ''' + spelling + '''';
    Scan.ReportError(msg)
  end
end;

{ IsRegName: delegates to LexTab (kind = LexReg). }
function IsRegName(const s: string): boolean;
  var kind, id: integer;
begin
  IsRegName := LexTab.Find(UpStr(s), kind, id) and (kind = LexReg)
end;

{ CurTokIsReg: TRUE if the CURRENT token's own text names a register. }
function CurTokIsReg: boolean;
begin CurTokIsReg := (gCurKind = LexReg) end;

{ ---------------- driver-facing setup/reset ---------------- }

{ OpenInclude: nm + '.SHD' is the path Scan.OpenInclude itself will open
  (same construction, duplicated here only for the cycle check below --
  Scan.OpenInclude builds its own copy internally, including its own
  LIB\ fallback if no local NAME.SHD exists). CYCLE CHECK
  (SOPLAN.MD's own Phase 7 "cycle diagnostics"): before ever touching
  the file system, nm's own resolved path is compared against every
  currently-open ancestor's own path (Scan.AncestorPath(0..depth-1],
  depth = Scan.CurImportDepth at this point, still the INCLUDER's own
  depth -- Scan.OpenInclude hasn't bumped it yet) -- "A IMPORTs B,
  B IMPORTs A" (or a longer cycle, A->B->C->A) is caught here as a clean
  translator error instead of silently exhausting MaxImportDepth (a
  confusing "IMPORT nesting too deep" for what's actually an infinite
  cycle). Case-INsensitive compare: DOS/TASM filenames are already
  case-insensitive throughout this toolchain (8.3 short names), so
  "IMPORT Foo;" then "IMPORT FOO;" from within Foo.SMD must still be
  caught as the same file, not treated as two different ones. }
function OpenInclude(const nm: string): boolean;
  var d, i: integer; path, upNm: string;
begin
  d := Scan.CurImportDepth;
  path := nm + '.SHD';
  if not Scan.FileExistsQuiet(path) then path := 'LIB\' + nm + '.SHD';
  upNm := Util.UpStr(path);
  i := 0;
  while i < d do begin
    if Util.UpStr(Scan.AncestorPath(i)) = upNm then begin
      Scan.ReportError('circular IMPORT: ' + nm + ' is already open (via ' +
        Scan.AncestorPath(i) + ')');
      OpenInclude := false; exit
    end;
    Inc(i)
  end;
  stkCurKind[d] := gCurKind; stkCurId[d] := gCurId;
  if not Scan.OpenInclude(nm) then begin OpenInclude := false; exit end;
  Next;
  OpenInclude := true
end;

procedure CloseInclude;
  var d: integer;
begin
  Scan.CloseInclude;
  d := Scan.CurImportDepth;
  gCurKind := stkCurKind[d]; gCurId := stkCurId[d]
end;

{ RegisterBuiltins: seeds LexTab with every keyword/symbol plus every
  register, and TRUE/FALSE as predeclared CONST entries. Called once
  per file at the start of RunBody, after LexTab itself is cleared.
  LexTab is the single, persistent home for every spelling once seeded
  here -- read back by id via LexTab.FindText (e.g. in Expect/
  ExpectKw); nothing in this unit keeps its own copy. }
procedure RegisterBuiltins;
  var si: integer;
begin
  LexTab.Add('MODULE', LexKw, KwModule); LexTab.Add('IMPORT', LexKw, KwImport);
  LexTab.Add('CONST', LexKw, KwConst); LexTab.Add('TYPE', LexKw, KwType);
  LexTab.Add('RECORD', LexKw, KwRecord); LexTab.Add('END', LexKw, KwEnd);
  LexTab.Add('VAR', LexKw, KwVar); LexTab.Add('PROCEDURE', LexKw, KwProcedure);
  LexTab.Add('FORWARD', LexKw, KwForward); LexTab.Add('INTERRUPT', LexKw, KwInterrupt);
  LexTab.Add('FAR', LexKw, KwFar); LexTab.Add('NEAR', LexKw, KwNear);
  LexTab.Add('REG', LexKw, KwReg); LexTab.Add('BEGIN', LexKw, KwBegin);
  LexTab.Add('RETURN', LexKw, KwReturn); LexTab.Add('IF', LexKw, KwIf);
  LexTab.Add('THEN', LexKw, KwThen); LexTab.Add('ELSIF', LexKw, KwElsif);
  LexTab.Add('ELSE', LexKw, KwElse); LexTab.Add('WHILE', LexKw, KwWhile);
  LexTab.Add('DO', LexKw, KwDo); LexTab.Add('BREAK', LexKw, KwBreak);
  LexTab.Add('CONTINUE', LexKw, KwContinue); LexTab.Add('ASM', LexKw, KwAsm);
  LexTab.Add('INC', LexKw, KwInc); LexTab.Add('DEC', LexKw, KwDec);
  LexTab.Add('PUSH', LexKw, KwPush); LexTab.Add('POP', LexKw, KwPop);
  LexTab.Add('USES', LexKw, KwUses); LexTab.Add('BYTE', LexKw, KwByte);
  LexTab.Add('WORD', LexKw, KwWord); LexTab.Add('INTEGER', LexKw, KwInteger);
  LexTab.Add('LONGINT', LexKw, KwLongint); LexTab.Add('BOOLEAN', LexKw, KwBoolean);
  LexTab.Add('INT', LexKw, KwInt); LexTab.Add('SHL', LexKw, KwShl);
  LexTab.Add('SHR', LexKw, KwShr); LexTab.Add('XOR', LexKw, KwXor);
  LexTab.Add('POINTER', LexKw, KwPointer); LexTab.Add('CHAR', LexKw, KwChar);
  LexTab.Add('DIV', LexKw, KwDiv); LexTab.Add('MOD', LexKw, KwMod);
  LexTab.Add('EXTERNAL', LexKw, KwExternal);
  LexTab.Add('OR', LexKw, KwOr);

  LexTab.Add('(', LexSym, SyLParen); LexTab.Add(')', LexSym, SyRParen);
  LexTab.Add('[', LexSym, SyLBrack); LexTab.Add(']', LexSym, SyRBrack);
  LexTab.Add(',', LexSym, SyComma); LexTab.Add(';', LexSym, SySemi);
  LexTab.Add(':', LexSym, SyColon); LexTab.Add(':=', LexSym, SyAssign);
  LexTab.Add('.', LexSym, SyDot); LexTab.Add('+', LexSym, SyPlus);
  LexTab.Add('-', LexSym, SyMinus); LexTab.Add('*', LexSym, SyStar);
  LexTab.Add('&', LexSym, SyAmp);
  LexTab.Add('~', LexSym, SyTilde); LexTab.Add('=', LexSym, SyEq);
  LexTab.Add('#', LexSym, SyNe); LexTab.Add('<', LexSym, SyLt);
  LexTab.Add('>', LexSym, SyGt); LexTab.Add('<=', LexSym, SyLe);
  LexTab.Add('>=', LexSym, SyGe);

  LexTab.Add('AX', LexReg, Regs86.RegAX); LexTab.Add('CX', LexReg, Regs86.RegCX);
  LexTab.Add('DX', LexReg, Regs86.RegDX); LexTab.Add('BX', LexReg, Regs86.RegBX);
  LexTab.Add('SP', LexReg, Regs86.RegSP); LexTab.Add('BP', LexReg, Regs86.RegBP);
  LexTab.Add('SI', LexReg, Regs86.RegSI); LexTab.Add('DI', LexReg, Regs86.RegDI);
  LexTab.Add('AL', LexReg, Regs86.RegAL); LexTab.Add('CL', LexReg, Regs86.RegCL);
  LexTab.Add('DL', LexReg, Regs86.RegDL); LexTab.Add('BL', LexReg, Regs86.RegBL);
  LexTab.Add('AH', LexReg, Regs86.RegAH); LexTab.Add('CH', LexReg, Regs86.RegCH);
  LexTab.Add('DH', LexReg, Regs86.RegDH); LexTab.Add('BH', LexReg, Regs86.RegBH);
  LexTab.Add('ES', LexReg, Regs86.RegES); LexTab.Add('CS', LexReg, Regs86.RegCS);
  LexTab.Add('SS', LexReg, Regs86.RegSS); LexTab.Add('DS', LexReg, Regs86.RegDS);

  si := SymAppend('TRUE', SymConst); SymSetVal(si, 1);
  si := SymAppend('FALSE', SymConst); SymSetVal(si, 0);

  si := SymAppend('NIL', SymConst); SymSetVal(si, 0)
end;

{ Reset: explicit init, not assumed. Called once per RunBody, before
  RegisterBuiltins. }
procedure Reset;
  var i: integer;
begin
  nTypes := 0; nProcs := 0; nSyms := 0;
  i := 0;
  while i < MaxDetailChunks do begin
    typeDir[i] := nil; procDir[i] := nil; symDir[i] := nil;
    Inc(i)
  end;
  gCurKind := -1; gCurId := -1;
  LexTab.Clear;
  RegisterBuiltins;
  gBuiltinSymCount := nSyms;
  Scan.ResetScanner
end;

{ FreeChunks: dispose every allocated detail-table block, and clear
  LexTab. Called once at the very end of RunBody. }
procedure FreeChunks;
  var i: integer;
begin
  i := 0;
  while i < MaxDetailChunks do begin
    if typeDir[i] <> nil then Dispose(typeDir[i]);
    if procDir[i] <> nil then Dispose(procDir[i]);
    if symDir[i] <> nil then Dispose(symDir[i]);
    Inc(i)
  end;
  LexTab.Clear
end;

begin
  nTypes := 0; nProcs := 0; nSyms := 0;
  gCurKind := -1; gCurId := -1
end.
