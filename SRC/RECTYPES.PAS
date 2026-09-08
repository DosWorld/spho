{$I FLAGS.INC}
{ RecTypes: TYPE-section parsing (RECORD types and scalar aliases) plus
  the scalar-ty helpers every other section of SPHO.PAS also needs
  (TySize/SizeHintFor/ScalarKwTy/ParseBaseType/ParseBaseTypeName/
  ResSuffix/DeclMnemonic) -- split out of SPHO.PAS's own "type parsing"
  section (SRC/SPHO.PAS's own header comment on the split-candidates
  survey: this is the one section nothing else in the expression/
  statement-translation core ever calls back INTO, so it can become a
  real unit without resurrecting the var-parameter-threading rewrite
  TCompilation/TProcedureContext were introduced specifically to avoid,
  see SPHO.PAS's own TCompilation comment).

  ParseRecordType is the only routine here that needs to emit raw NASM
  text (struc/endstruc/resb/resw/resd lines) or touch the current
  output section -- rather than importing SPHO.PAS back (illegal,
  circular uses) or duplicating Emit/Emit2/EnsureSection's own access
  to SPHO.PAS's private `comp` state, it takes them as procedural
  parameters, same "caller hands over exactly the primitive it needs"
  shape PHOpt.Optimize already uses for the operation-list cursor it's
  handed instead of reaching back into SPHO.PAS for it. }
unit RecTypes;

interface

uses SymTab;

{ TySize: byte size of typ.ty (typ.recIdx meaningful only for TyRec).
  The TyRec case must mirror ParseRecordType's own field-alignment
  padding (SPHINX.MD S3.2) exactly, byte for byte, or callers relying on
  TySize for a RECORD's total size (an array-of-RECORD's resb count, or
  this same function applied to a RECORD-typed field nested inside
  another RECORD) would silently disagree with what NASM's struc
  actually laid out. }
function TySize(typ: SymTab.TTypeInfo): integer;

{ SizeHintFor: "byte"/"word" size-prefix hint for ty. }
procedure SizeHintFor(ty: integer; var hint: string);

{ ScalarKwTy: ty for the scalar-type keyword (SymTab.LexKw, kwId) pair,
  or -1 if kwId doesn't name a scalar type -- the one keyword-id-to-ty
  mapping ParseBaseType, ParseBaseTypeName, and SPHO.PAS's own
  ParseProcedure (': RetTy') all need, kept in exactly one place so
  they can never drift apart on which spellings count. CHAR is a plain
  synonym for BYTE; POINTER a plain synonym for LONGINT -- neither is a
  distinct ty. }
function ScalarKwTy(kwId: integer): integer;

{ ParseBaseType: a bare TYPE-section identifier can name either a real
  RECORD type (typ.ty := TyRec, typ.recIdx set) or a non-RECORD alias.
  Stays a procedure with a var TTypeInfo output, not a function
  returning one -- TP7 function results are limited to ordinal/real/
  pointer/string types, not an arbitrary record (same reason
  SymTab.CurLexMark is a procedure, not a function; see its own header
  comment). }
procedure ParseBaseType(var typ: SymTab.TTypeInfo);

{ ParseBaseTypeName: like ParseBaseType's own scalar-keyword matching
  (same ScalarKwTy table), but resolves an already-read, already-
  consumed name string via a plain LexTab lookup instead of the current
  token's own resolved (kind,id) -- used by SIZE(T), where nm's token
  is already behind us by the time the type name must be classified. }
procedure ParseBaseTypeName(const nm: string; var typ: SymTab.TTypeInfo);

procedure ResSuffix(ty: integer; var dst: string);

{ DeclMnemonic: db/dw/dd for ty -- same ty-to-mnemonic shape as
  ResSuffix above, for an initialized (not reserved-space) declaration. }
procedure DeclMnemonic(ty: integer; var dst: string);

{ TEmit1/TEmit2/TEnsureSection: ParseRecordType's own output hooks,
  bound by the caller (SPHO.PAS) to its own Emit/Emit2/EnsureSection --
  see this unit's own header comment on why. }
type
  TEmit1 = procedure(const s: string);
  TEmit2 = procedure(const a, b: string);
  TEnsureSection = procedure(sect: integer);
  TParseArrayBound = function: integer;

{ ParseRecordType: 'RECORD' already consumed by caller. Emits struc..endstruc.
  A field may carry an array bound ('name : T[N];'), same '[N]' syntax
  and parseArrayBound (caller-supplied, SPHO.PAS's own ParseArrayBound)
  as ParseVarSection's own global/local arrays -- the struc line becomes
  'resb/resw/resd N' instead of the scalar '... 1', and the field's own
  total size (elemSz * cnt) is what advances ofs and is stored via
  TypeAddField's cnt, not just the one-element size. Fields are aligned
  to their own natural boundary (SPHINX.MD S3.2): a BYTE/BOOLEAN field
  needs none, but a WORD/INTEGER/LONGINT/RECORD field whose own size is
  >= 2 must start on an even offset -- an unnamed "resb 1" pad byte is
  inserted right before it when the running offset is currently odd.
  ofs tracks that running byte offset by hand (struc's own internal
  offset isn't queryable from here), so it must stay exactly in sync
  with what NASM itself computes from the emitted resb/resw/resd lines
  below. sectStruc is the caller's own SectStruc constant, passed in
  rather than duplicated here. }
procedure ParseRecordType(const nm: string; exported: boolean;
                           sectStruc: integer;
                           emit1: TEmit1; emit2: TEmit2; ensureSect: TEnsureSection;
                           parseArrayBound: TParseArrayBound);

{ ParseTypeSection: the whole 'TYPE ... ' section, one alias/RECORD
  declaration at a time, up to (not consuming) the next CONST/TYPE/VAR/
  PROCEDURE/BEGIN/END keyword. Same emit-hook/parseArrayBound shape as
  ParseRecordType above, threaded straight through to it. }
procedure ParseTypeSection(sectStruc: integer;
                            emit1: TEmit1; emit2: TEmit2; ensureSect: TEnsureSection;
                            parseArrayBound: TParseArrayBound);

implementation

uses Scan, LexTab, Util;

const
  TyByte = SymTab.TyByte; TyBool = SymTab.TyBool; TyWord = SymTab.TyWord;
  TyInt = SymTab.TyInt; TyLong = SymTab.TyLong; TyRec = SymTab.TyRec;
  TIdent = Scan.TIdent;

function TySize(typ: SymTab.TTypeInfo): integer;
  var i, sum, fsz: integer; fnm: string; ftyp: SymTab.TTypeInfo; fcnt: word;
begin
  case typ.ty of
    TyByte, TyBool: begin TySize := 1; exit end;
    TyWord, TyInt:  begin TySize := 2; exit end;
    TyLong:         begin TySize := 4; exit end;
    TyRec: begin
      if typ.recIdx < 0 then begin TySize := 2; exit end;
      sum := 0; i := 0;
      while i < SymTab.TypeNFields(typ.recIdx) do begin
        SymTab.TypeField(typ.recIdx, i, fnm, ftyp, fcnt);
        fsz := TySize(ftyp) * integer(fcnt);
        if (fsz >= 2) and Odd(sum) then Inc(sum);
        sum := sum + fsz;
        Inc(i)
      end;
      TySize := sum; exit
    end
  else TySize := 2
  end
end;

procedure SizeHintFor(ty: integer; var hint: string);
begin
  case ty of
    TyByte, TyBool: hint := 'byte';
    TyWord, TyInt:  hint := 'word';
  else hint := ''
  end
end;

function ScalarKwTy(kwId: integer): integer;
begin
  case kwId of
    SymTab.KwByte, SymTab.KwChar: ScalarKwTy := TyByte;
    SymTab.KwBoolean: ScalarKwTy := TyBool;
    SymTab.KwWord:    ScalarKwTy := TyWord;
    SymTab.KwInteger: ScalarKwTy := TyInt;
    SymTab.KwLongint, SymTab.KwPointer: ScalarKwTy := TyLong;
  else ScalarKwTy := -1
  end
end;

procedure ParseBaseType(var typ: SymTab.TTypeInfo);
  var ti, aliasTy, kwTy: integer; nm: string;
begin
  typ.recIdx := -1;
  kwTy := -1;
  if SymTab.CurTokKind = SymTab.LexKw then kwTy := ScalarKwTy(SymTab.CurTokId);
  if kwTy >= 0 then begin typ.ty := kwTy; SymTab.Next end
  else if Scan.CurTokKind = TIdent then begin
    Scan.CurTokText(nm);
    ti := SymTab.FindType(nm);
    if ti >= 0 then begin
      aliasTy := SymTab.TypeAliasTy(ti);
      if aliasTy = TyRec then begin typ.ty := TyRec; typ.recIdx := ti end
      else typ.ty := aliasTy
    end else
      typ.ty := TyWord;
    SymTab.Next
  end else begin
    typ.ty := TyWord; SymTab.Next
  end
end;

procedure ParseBaseTypeName(const nm: string; var typ: SymTab.TTypeInfo);
  var lkKind, lkId, kwTy: integer; msg: string;
begin
  typ.recIdx := -1;
  kwTy := -1;
  if LexTab.Find(nm, lkKind, lkId) and (lkKind = SymTab.LexKw) then
    kwTy := ScalarKwTy(lkId);
  if kwTy >= 0 then typ.ty := kwTy
  else begin
    msg := 'unknown type name in SIZE(): ' + nm;
    Scan.ReportError(msg); typ.ty := TyWord
  end
end;

procedure ResSuffix(ty: integer; var dst: string);
begin
  case ty of
    TyByte, TyBool: dst := 'resb';
    TyWord, TyInt:  dst := 'resw';
    TyLong:         dst := 'resd';
  else dst := 'resw'
  end
end;

procedure DeclMnemonic(ty: integer; var dst: string);
begin
  case ty of
    TyByte, TyBool: dst := 'db';
    TyWord, TyInt:  dst := 'dw';
    TyLong:         dst := 'dd';
  else dst := 'dw'
  end
end;

procedure ParseRecordType(const nm: string; exported: boolean;
                           sectStruc: integer;
                           emit1: TEmit1; emit2: TEmit2; ensureSect: TEnsureSection;
                           parseArrayBound: TParseArrayBound);
  var ti, elemSz, fsz, ofs: integer; typ: SymTab.TTypeInfo; cnt: word; fieldName: string;
      buf, sfx: string; more: boolean;
begin
  ti := SymTab.TypeAppend(nm, TyRec);
  SymTab.TypeSetExported(ti, exported);
  ensureSect(sectStruc);
  emit2('struc ', nm);
  more := true; ofs := 0;
  while more and (Scan.CurTokKind = TIdent) do begin
    Scan.CurTokText(fieldName); SymTab.Next;
    SymTab.Expect(SymTab.SyColon);
    ParseBaseType(typ);
    cnt := 1;
    if SymTab.IsLexSym(SymTab.SyLBrack) then begin
      cnt := word(parseArrayBound);
      SymTab.Expect(SymTab.SyRBrack)
    end;
    SymTab.TypeAddField(ti, fieldName, typ, cnt);
    elemSz := TySize(typ);
    fsz := elemSz * integer(cnt);
    if (elemSz >= 2) and (Odd(ofs)) then begin
      { TASM's struc requires every member line to have its own label
        (a bare unlabeled 'resb 1', legal in .bss, is rejected inside
        struc..endstruc with "expected RESB/RESW/RESD") -- .__pad<ofs>
        is unique within this one struc (ofs is this pad's own byte
        offset, never repeated by a real field). A user field literally
        named "__pad4" etc. would collide, but that's a TASM duplicate-
        label error at assemble time, not silent corruption -- and
        SPHINX identifiers starting with '_' are legal but not an
        established naming style anywhere in this codebase. }
      buf := '    .__pad' + IntStr(longint(ofs)) + ': resb 1';
      emit1(buf);
      Inc(ofs)
    end;
    if typ.ty = TyRec then
      { A RECORD-typed field (nested record, scalar or array-of-record)
        must reserve its own true byte count -- ResSuffix has no TyRec
        case (falls through to its 'resw' default, 2 bytes, wrong for
        any RECORD bigger than a WORD) since it's shared with the
        scalar-field path below. Same 'resb <TySize*cnt>' shape already
        used for a global RECORD VAR (SPHO.PAS's own ParseVarSection,
        both the array-of-RECORD and single-instance cases). }
      buf := '    .' + fieldName + ': resb ' + IntStr(longint(fsz))
    else begin
      ResSuffix(typ.ty, sfx);
      buf := '    .' + fieldName + ': ' + sfx + ' ' + IntStr(longint(cnt))
    end;
    emit1(buf);
    ofs := ofs + fsz;
    more := SymTab.IsLexSym(SymTab.SySemi)
  end;
  SymTab.ExpectKw(SymTab.KwEnd);
  emit1('endstruc')
end;

procedure ParseTypeSection(sectStruc: integer;
                            emit1: TEmit1; emit2: TEmit2; ensureSect: TEnsureSection;
                            parseArrayBound: TParseArrayBound);
  var nm: string; msg: string; typ: SymTab.TTypeInfo; exported: boolean; ti: integer;
begin
  while (Scan.CurTokKind = TIdent) and not SymTab.IsKw(SymTab.KwConst) and not SymTab.IsKw(SymTab.KwType)
        and not SymTab.IsKw(SymTab.KwVar)
        and not SymTab.IsKw(SymTab.KwProcedure)
        and not SymTab.IsKw(SymTab.KwBegin) and not SymTab.IsKw(SymTab.KwEnd) do begin
    Scan.CurTokText(nm); SymTab.Next;
    exported := false;
    if SymTab.IsLexSym(SymTab.SyStar) then exported := true;
    SymTab.Expect(SymTab.SyEq);
    if SymTab.IsLexKw(SymTab.KwRecord) then
      ParseRecordType(nm, exported, sectStruc, emit1, emit2, ensureSect, parseArrayBound)
    else begin
      { non-RECORD alias (TYPE Foo = LONGINT;): registered with its real
        base type so a later VAR of this type gets correctly sized. }
      ParseBaseType(typ);
      if typ.ty = TyRec then begin
        msg := 'TYPE alias of a RECORD type not supported: ' + nm;
        Scan.ReportError(msg)
      end else begin
        ti := SymTab.TypeAppend(nm, typ.ty);
        SymTab.TypeSetExported(ti, exported)
      end
    end;
    SymTab.Expect(SymTab.SySemi)
  end
end;

end.
