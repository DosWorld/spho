{$I FLAGS.INC}
{ GlobVar: VAR-section parsing (SRC/SPHO.PAS's own "VAR section
  (global)" section, split out -- see SPHO.PAS's own header comment on
  the split-candidates survey). Unlike RecTypes/ShdWrt, this one serves
  BOTH global and local VAR declarations (ParseVarSection's own
  isGlobal parameter) -- SPHO.PAS's own ParseProcedure calls it for a
  procedure body's local VAR section too, which is why it needs a
  frameOfs var parameter (SPHO.PAS's own per-procedure ctx.frameOfs)
  on top of the same Emit/EnsureSection procedural-parameter hooks
  RecTypes.ParseRecordType already uses, PLUS the shared `es` output
  stream itself (Emits.TEmitState, by var) for the BASE64()/FILE()/
  "..." array-literal streaming paths, which write through Emits.Emit/
  es.f directly rather than through the Emit/Emit2 wrapper procedures
  (streamed byte-by-byte as decoded/read, never buffering the whole
  blob -- see ParseArrayLitInit's own header comment). Unit name (and
  this file's own GLOBVAR.PAS) is short for GlobalVars -- DOS 8.3
  filename limit, same reason RecTypes -> RECTYPES.PAS and
  ShdWriter -> ShdWrt/SHDWRT.PAS both are. }
unit GlobVar;

interface

uses SymTab, Emits;

const
  { MaxArrayLit: the largest BASE64()/FILE() decoded byte count this
    translator will accept -- same value and same reasoning as SPHO.PAS's
    own MaxArrayLit (see that file's own header comment); duplicated
    here rather than passed in since it's a fixed translator-wide limit,
    not caller-configurable state. }
  MaxArrayLit = 65535;
  { MaxVarNames: cap on a single comma-separated 'VAR a,b,c : T;' name
    group -- same value as SPHO.PAS's own MaxVarNames. }
  MaxVarNames = 64;

type
  TEmit1 = procedure(const s: string);
  TEnsureSection = procedure(sect: integer);
  TParseArrayBound = function: integer;

{ ParseVarSection: 'NAME: T[N]' -- array of N elements of T.
  'NAME: T[] = BASE64("...")' / '= FILE("...")' -- array literal, sized
  from the decoded data itself, always a real .data value (DOCS/SPHO.MD's
  own "array literal" entry has the full grammar/emission notes).
  isGlobal selects between a real global declaration (.data/.bss,
  SectData/SectBss via ensureSect/sectData/sectBss) and a procedure-
  local one (frame space, offset tracked via the caller's own frameOfs,
  advanced here by var). es is the caller's own shared output stream
  (SPHO.PAS's own `es`, threaded through by var since the BASE64()/
  FILE()/"..." literal paths stream bytes straight to es.f as they're
  decoded/read); emit1/ensureSect are SPHO.PAS's own Emit/EnsureSection,
  same procedural-parameter shape RecTypes.ParseRecordType already
  uses (GlobVar can't call back into SPHO.PAS, circular uses);
  parseArrayBound is SPHO.PAS's own ParseArrayBound (also passed to
  RecTypes.ParseRecordType, for the identical '[N]' syntax on a RECORD
  field's own array bound). }
procedure ParseVarSection(isGlobal: boolean; var frameOfs: integer;
                           var es: Emits.TEmitState;
                           sectData, sectBss: integer;
                           emit1: TEmit1; ensureSect: TEnsureSection;
                           parseArrayBound: TParseArrayBound);

implementation

uses Scan, LexTab, Util, RecTypes;

const
  TyRec = SymTab.TyRec;
  TIdent = Scan.TIdent;
  TStr = Scan.TStr;
  TNum = Scan.TNum;
  SymVar = SymTab.SymVar;

{ EmitVarDecl: a global scalar VAR. hasInit=TRUE ("= value" given, a real
  stored value) belongs in .data; hasInit=FALSE is zero-filled reserved
  space and belongs in .bss instead. }
procedure EmitVarDecl(si: integer; hasInit: boolean; initVal: longint;
                       sectData, sectBss: integer;
                       emit1: TEmit1; ensureSect: TEnsureSection);
  var buf, nm, mn, rsfx: string; ty: integer;
begin
  SymTab.SymName(si, nm); ty := SymTab.SymTy(si);
  if hasInit then begin
    ensureSect(sectData);
    RecTypes.DeclMnemonic(ty, mn);
    buf := nm + ' ' + mn + ' ' + IntStr(initVal);
    emit1(buf)
  end else begin
    ensureSect(sectBss);
    RecTypes.ResSuffix(ty, rsfx);
    buf := nm + ': ' + rsfx + ' 1';
    emit1(buf)
  end
end;

{ ParseArrayLitInit: 'NAME: T[] = BASE64("...")' / '= FILE("...")' --
  already past 'T[]' and '='; the current token is the BASE64/FILE
  identifier itself (already peeked by the caller via
  Scan.TokTextEqICase, not yet consumed). Streams the literal straight
  to es.f as hex "db" lines as it's decoded/read (Util.B64Feed/B64Flush
  for BASE64, Util.StreamFileBytes for FILE -- ensureSect(sectData)
  first, since this form is ALWAYS a real stored value, unlike an
  ordinary uninitialized array, which is .bss), never materializing the
  whole decoded blob (or, for BASE64, the raw source text either -- see
  Scan.SetB64Sink) in memory at once. Returns the decoded byte count so
  the caller can SymSetVal(si, ...) it for SIZE(v) to find later
  (DOCS/SPHO.MD's own "array literal" entry has the full reasoning for
  reusing SymVal here). On any decode/read failure, reports a translator
  error -- the caller still needs a byte count back (0) so it can decide
  whether to touch .bss/.data at all for this declaration. }
function ParseArrayLitInit(const nm: string; var es: Emits.TEmitState;
                            sectData: integer; ensureSect: TEnsureSection): word;
  var isFile: boolean; text, path, dir, msg: string;
      ok: boolean; outLen: word; st: Util.TB64State; c: char;
begin
  ParseArrayLitInit := 0;
  isFile := Scan.TokTextEqICase('FILE');
  SymTab.Next;   { consume BASE64/FILE identifier }
  if isFile then begin
    SymTab.Expect(SymTab.SyLParen);
    if Scan.CurTokKind <> TStr then begin
      Scan.ReportError('expected a "..." string literal in BASE64()/FILE()');
      SymTab.Expect(SymTab.SyRParen); exit
    end;
    { FILE()'s own argument is a short filename/path, never a long
      encoded blob, so the ordinary CurTokText/`string` path is fine
      here -- only BASE64()'s own text (below) needs streaming. }
    Scan.CurTokText(text); SymTab.Next;
    SymTab.Expect(SymTab.SyRParen);
    Scan.SrcPath(path); dir := Util.ExtractDir(path);
    ensureSect(sectData);
    Emits.Emit(es, false, 'section .data');
    ok := Util.StreamFileBytes(es.f, nm, dir + text, MaxArrayLit, outLen);
    if not ok then begin
      msg := 'FILE(): cannot read file, or file exceeds ' + IntStr(MaxArrayLit) + ' bytes: ' + dir + text;
      Scan.ReportError(msg); exit
    end
  end else begin
    { BASE64()'s own text can be far longer than a TP7 `string` (255
      chars) can hold -- e.g. 230 raw bytes encodes to 308 base64 chars
      -- and this translator is one-token-lookahead (SymTab.Next always
      prefetches the token AFTER the one it returns), so by the time
      ordinary code could inspect "the next token is a string", it
      would already be fully scanned. Scan.ArmRawStringNext defeats
      that prefetch specifically for the '"' that Expect(SyLParen)'s
      own internal lookahead would otherwise scan -- called BEFORE
      Expect so the '"' is left unconsumed (Scan.CurTokKind reads as a
      deferred, empty TStr placeholder afterward), then
      Scan.RawStrOpen/RawStrNextCh pull the literal's raw characters
      directly, feeding Util.B64Feed as they're read and writing "db"
      lines to es.f on the fly -- the source text is never copied into
      a buffer at all. SymTab.Next afterward resumes ordinary lookahead
      on whatever token follows the closing quote. }
    ensureSect(sectData);
    Emits.Emit(es, false, 'section .data');
    Util.B64Init(st, es.f, nm, MaxArrayLit);
    Scan.ArmRawStringNext;
    SymTab.Expect(SymTab.SyLParen);
    if Scan.CurTokKind <> TStr then begin
      Scan.ReportError('expected a "..." string literal in BASE64()/FILE()');
      SymTab.Expect(SymTab.SyRParen); exit
    end;
    Scan.RawStrOpen;
    while Scan.RawStrNextCh(c) do Util.B64Feed(st, c);
    SymTab.Next;   { resume ordinary lookahead past the closing quote }
    SymTab.Expect(SymTab.SyRParen);
    ok := Util.B64Flush(st);
    outLen := Util.B64OutLen(st);
    if not ok then begin
      Scan.ReportError('BASE64(): invalid base64 text, or decoded data exceeds ' + IntStr(MaxArrayLit) + ' bytes');
      exit
    end
  end;
  ParseArrayLitInit := outLen
end;

{ ParseArrayStrLitInit: 'NAME: T[] = "text"' -- current token is already
  a TStr; encodes its raw bytes plus a trailing zero (ASCIIZ) into a
  .data 'db' block under nm, same hex-byte emission Util.StreamFileBytes/
  B64Feed already use for BASE64()/FILE(). }
function ParseArrayStrLitInit(const nm: string; var es: Emits.TEmitState;
                               sectData: integer; ensureSect: TEnsureSection): word;
  var text: string; outLen: word; ok: boolean; msg: string;
begin
  ParseArrayStrLitInit := 0;
  Scan.CurTokText(text); SymTab.Next;
  ensureSect(sectData);
  Emits.Emit(es, false, 'section .data');
  ok := Util.StreamStrBytes(es.f, nm, text, MaxArrayLit, outLen);
  if not ok then begin
    msg := '"..." array initializer exceeds ' + IntStr(MaxArrayLit) + ' bytes: ' + nm;
    Scan.ReportError(msg); exit
  end;
  ParseArrayStrLitInit := outLen
end;

procedure ParseVarSection(isGlobal: boolean; var frameOfs: integer;
                           var es: Emits.TEmitState;
                           sectData, sectBss: integer;
                           emit1: TEmit1; ensureSect: TEnsureSection;
                           parseArrayBound: TParseArrayBound);
  var nm: string; si, cnt, elemSz: integer; typ: SymTab.TTypeInfo; litLen: word;
      hasInit, isEmptyArr, isLitInit: boolean; initVal: longint; buf, rsfx: string;
      isArr: boolean;
      names: array[1..MaxVarNames] of string[Scan.MaxName]; nNames, ni: integer;
begin
  while (Scan.CurTokKind = TIdent) and not SymTab.IsKw(SymTab.KwConst) and not SymTab.IsKw(SymTab.KwType)
        and not SymTab.IsKw(SymTab.KwVar)
        and not SymTab.IsKw(SymTab.KwProcedure) and not SymTab.IsKw(SymTab.KwBegin)
        and not SymTab.IsKw(SymTab.KwEnd) do begin
    nNames := 0;
    repeat
      Scan.CurTokText(nm); SymTab.Next;
      if nNames >= MaxVarNames then
        Scan.ReportError('too many names in one VAR group')
      else begin
        nNames := nNames + 1;
        names[nNames] := nm
      end
    until not SymTab.IsLexSym(SymTab.SyComma);
    SymTab.Expect(SymTab.SyColon);
    RecTypes.ParseBaseType(typ);
    isArr := false; isEmptyArr := false; cnt := 1;
    if SymTab.IsLexSym(SymTab.SyLBrack) then begin
      if SymTab.IsSym(SymTab.SyRBrack) then begin
        { 'T[]' -- empty bound, only legal with a BASE64()/FILE()
          initializer right after; SyRBrack is only peeked here (IsSym,
          not IsLexSym), consumed by the Expect below like the [N] path. }
        isEmptyArr := true
      end else begin
        isArr := true;
        cnt := parseArrayBound
      end;
      SymTab.Expect(SymTab.SyRBrack)
    end;
    hasInit := false; initVal := 0; isLitInit := false; litLen := 0;
    if SymTab.IsLexSym(SymTab.SyEq) then begin
      if (nNames > 1) then
        Scan.ReportError('a comma-separated group of VAR names may not share an initializer');
      if (Scan.CurTokKind = TIdent)
         and (Scan.TokTextEqICase('BASE64') or Scan.TokTextEqICase('FILE')) then begin
        if not isEmptyArr then begin
          Scan.ReportError('BASE64()/FILE() initializer requires an empty array bound ''[]'', not an explicit N');
          SymTab.Next   { consume the BASE64/FILE identifier so parsing can continue }
        end else if not isGlobal then begin
          Scan.ReportError('BASE64()/FILE() array initializer is only supported for a global VAR');
          SymTab.Next
        end else begin
          litLen := ParseArrayLitInit(names[1], es, sectData, ensureSect); isLitInit := true
        end
      end else if (Scan.CurTokKind = TStr) and isEmptyArr and isGlobal then begin
        litLen := ParseArrayStrLitInit(names[1], es, sectData, ensureSect); isLitInit := true
      end else if (Scan.CurTokKind = TStr) and isEmptyArr and not isGlobal then begin
        Scan.ReportError('"..." array initializer is only supported for a global VAR');
        SymTab.Next
      end else begin
        hasInit := true; initVal := Scan.CurTokVal; SymTab.Next
      end
    end else if isEmptyArr then begin
      Scan.ReportError('empty array bound ''[]'' requires a BASE64() or FILE() initializer')
    end;
    for ni := 1 to nNames do begin
      nm := names[ni];
      si := SymTab.SymAppend(nm, SymVar);
      SymTab.SymSetTy(si, typ.ty, typ.recIdx); SymTab.SymSetIsLocal(si, not isGlobal);
      { SymSetIsArr: persists this VAR's own array-ness (SOPLAN.MD's own
        Phase 7 item 3) -- EmitCall's own call-site argument parser
        needs to know a plain VAR NAME used as a call argument is
        itself array-typed, to decide whether to auto-ADR() it against
        an array-typed formal parameter. isArr here is TRUE for both
        the 'T[N]' and empty-bound 'T[]' forms (isEmptyArr), matching
        ParseParams' own identical isArr flag for a formal parameter. }
      if isArr or isEmptyArr then SymTab.SymSetIsArr(si, true);
      if isLitInit then
        SymTab.SymSetVal(si, litLen)
      else if isGlobal then begin
        if isArr and (typ.ty = TyRec) then begin
          { array of RECORD: reserve the true byte count directly. }
          ensureSect(sectBss);
          buf := nm + ': resb ' + IntStr(longint(RecTypes.TySize(typ)) * longint(cnt));
          emit1(buf)
        end else if isArr then begin
          ensureSect(sectBss);
          RecTypes.ResSuffix(typ.ty, rsfx);
          buf := nm + ': ' + rsfx + ' ' + IntStr(longint(cnt));
          emit1(buf)
        end else if typ.ty = TyRec then begin
          { a single RECORD instance, no field values ever written into it
            at declaration time -- zero-filled reserved space. }
          ensureSect(sectBss);
          buf := nm + ': resb ' + IntStr(longint(RecTypes.TySize(typ)));
          emit1(buf)
        end else
          EmitVarDecl(si, hasInit, initVal, sectData, sectBss, emit1, ensureSect)
      end else begin
        { local: reserve frame space, offset assigned by caller via
          frameOfs. A local whose own element type is word-sized or
          larger (TySize >= 2, checked BEFORE the isArr multiply so a
          packed BYTE array isn't forced to align) must start on an even
          [bp-N] offset -- bump frameOfs by one pad byte first when the
          running total is currently odd, mirroring RecTypes.
          ParseRecordType's own field-alignment padding. }
        elemSz := RecTypes.TySize(typ);
        if (elemSz >= 2) and Odd(frameOfs) then Inc(frameOfs);
        if isArr then elemSz := elemSz * cnt;
        frameOfs := frameOfs + elemSz;
        SymTab.SymSetOfs(si, frameOfs)
      end
    end;
    SymTab.Expect(SymTab.SySemi)
  end
end;

end.
