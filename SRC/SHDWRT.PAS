{$I FLAGS.INC}
{ ShdWrt: regenerates a top-level module's own .SHD header file after a
  full translation (SRC/SPHO.PAS's own "driver" section, split out --
  see SPHO.PAS's own header comment on the split-candidates survey).
  Unit name (and this file's own SHDWRT.PAS) is short for ShdWriter --
  DOS 8.3 filename limit, same reason every other unit name here is
  abbreviated. Unlike RecTypes, this needed no procedural-parameter
  trick at all: EmitSHD only ever touches SymTab/Emits/LogErr/Util,
  writing through its own local Emits.TEmitState (shdEs) rather than
  SPHO.PAS's own whole-run `es`/`comp`/`ctx` state -- it never calls
  Emit/Emit2/EnsureSection or anything else private to SPHO.PAS, so
  there's nothing here to hand back a callback for. Called exactly
  once, from SPHO.PAS's own RunBody. }
unit ShdWrt;

interface

uses SymTab;

{ EmitSHD: after a full top-level translation, regenerate srcPath's own
  .SHD sibling -- every CONST and TYPE declaration this module parsed
  (verbatim value/shape, not just names), plus one 'PROCEDURE Name(
  params): RetTy; NEAR; EXTERNAL;' line per '*'-exported PROCEDURE
  (SOPLAN.MD-adjacent request: "imported module must have .SHD
  extension... generate text file .SHD" -- IMPORT itself now resolves
  to .SHD, Scan.OpenInclude). No VAR globals ever appear (a caller only
  reaches another module's own state through its exported procedures,
  never a shared global) and non-exported/FORWARD-only PROCEDUREs are
  skipped, matching LIB/FILES.SHD's own hand-written shape exactly (the
  model this was built to match). }
procedure EmitSHD(const srcPath, modName: string);

implementation

uses Emits, LogErr, Util;

const
  TyRec = SymTab.TyRec;

{ TySphinxName: the SPHINX-source keyword spelling for a SymTab.Ty*
  scalar id -- the reverse of RecTypes.ScalarKwTy's own mapping (that
  one goes keyword -> ty; EmitSHD needs ty -> keyword text to print a
  reconstructed CONST/field/parameter/return type). CHAR is BYTE's own
  synonym (DOCS/SPHINX.MD S3.1/S6.4) and POINTER is LONGINT's
  (S3.1) -- both fold to the same ty id as their base type, so this
  always emits the base spelling (BYTE/LONGINT), never the synonym;
  a real RECORD type (ty = TyRec) is named via TypeName(recIdx, ...)
  at the call site instead, since only the caller has recIdx at hand. }
procedure TySphinxName(ty: integer; var dst: string);
begin
  case ty of
    SymTab.TyByte: dst := 'BYTE';
    SymTab.TyBool: dst := 'BOOLEAN';
    SymTab.TyWord: dst := 'WORD';
    SymTab.TyInt:  dst := 'INTEGER';
    SymTab.TyLong: dst := 'LONGINT';
  else dst := 'WORD'
  end
end;

{ EmitFieldType: 'BYTE'/'aRecordTypeName', plus a '[N]' array-bound
  suffix when cnt > 1 -- shared by EmitSHD's own RECORD-field and
  PROCEDURE-parameter printing, since both are (name, TTypeInfo, cnt)
  triples underneath (FieldDef and a parameter's own si, respectively). }
procedure EmitFieldType(typ: SymTab.TTypeInfo; cnt: word; var dst: string);
  var tn: string;
begin
  if typ.ty = TyRec then SymTab.TypeName(typ.recIdx, dst)
  else TySphinxName(typ.ty, dst);
  if cnt > 1 then dst := dst + '[' + IntStr(cnt) + ']'
end;

procedure EmitSHD(const srcPath, modName: string);
  var shdEs: Emits.TEmitState; shdPath: string;
      i, fi, pi, nf, np: integer;
      nm, fnm, tnm, line, retNm: string;
      typ: SymTab.TTypeInfo; cnt: word; any: boolean;
begin
  shdPath := ReplaceExt(srcPath, '.SHD');
  if not Emits.open(shdEs, shdPath) then exit;
  Emits.Emit(shdEs, false, 'MODULE ' + modName + ';');
  Emits.Emit(shdEs, false, '');

  { CONST: only '*'-exported CONSTs this module declared (SymIsExported
    -- same '*' marker PROCEDURE already has), its own final (already-
    folded) value -- SymTab has no "declared as CONST X" text left by
    this point, only the numeric result (SymVal), so a negative
    source literal like 'CONST Foo* = -1;' round-trips as the same
    value via a plain 'Foo = -1;' line either way. }
  any := false;
  for i := SymTab.BuiltinSymCount to SymTab.SymCount - 1 do
    if (SymTab.SymKind(i) = SymTab.SymConst) and SymTab.SymIsExported(i) then any := true;
  if any then begin
    Emits.Emit(shdEs, false, 'CONST');
    for i := SymTab.BuiltinSymCount to SymTab.SymCount - 1 do begin
      if (SymTab.SymKind(i) = SymTab.SymConst) and SymTab.SymIsExported(i) then begin
        SymTab.SymName(i, nm);
        line := '  ' + nm + ' = ' + IntStr(SymTab.SymVal(i)) + ';';
        Emits.Emit(shdEs, false, line)
      end
    end;
    Emits.Emit(shdEs, false, '')
  end;

  { TYPE: only '*'-exported RECORDs this module declared (the only TYPE
    shape DOCS/SPHINX.MD supports -- RecTypes.ParseBaseType's own
    "aliasTy = TyRec" check is the only real TYPE-section form parsed
    anywhere in this translator), fields in their own original
    declaration order (TypeField's own 0-based fi). }
  any := false;
  for i := 0 to SymTab.TypeCount - 1 do
    if SymTab.TypeIsExported(i) then any := true;
  if any then begin
    Emits.Emit(shdEs, false, 'TYPE');
    for i := 0 to SymTab.TypeCount - 1 do begin
      if not SymTab.TypeIsExported(i) then continue;
      SymTab.TypeName(i, nm);
      Emits.Emit(shdEs, false, '  ' + nm + ' = RECORD');
      nf := SymTab.TypeNFields(i);
      for fi := 0 to nf - 1 do begin
        SymTab.TypeField(i, fi, fnm, typ, cnt);
        EmitFieldType(typ, cnt, tnm);
        line := '    ' + fnm + ' : ' + tnm;
        if fi < nf - 1 then line := line + ';';
        Emits.Emit(shdEs, false, line)
      end;
      Emits.Emit(shdEs, false, '  END;')
    end;
    Emits.Emit(shdEs, false, '')
  end;

  { Export the complete declared element type and calling convention. }
  for pi := 0 to SymTab.ProcCount - 1 do begin
    if not SymTab.ProcIsExported(pi) then continue;
    SymTab.ProcName(pi, nm);
    np := SymTab.ProcNParams(pi);
    line := 'PROCEDURE ' + nm + '(';
    for i := 0 to np - 1 do begin
      SymTab.ProcParamName(pi, i, fnm);
      SymTab.ProcParamType(pi, i, typ);
      EmitFieldType(typ, 1, tnm);
      if SymTab.ProcParamIsArray(pi, i) then tnm := tnm + '[]';
      line := line + fnm + ' : ' + tnm;
      if i < np - 1 then line := line + '; '
    end;
    line := line + ')';
    if SymTab.ProcSigHasRetTy(pi) then begin
      TySphinxName(SymTab.ProcRetTy(pi), retNm);
      line := line + ' : ' + retNm
    end;
    { NEAR vs FAR must match the real procedure, not be hardcoded to
      NEAR -- DOCS/SPHINX.MD: an exported ('*') PROCEDURE defaults to
      FAR unless explicitly marked NEAR (ParseProcedure's own
      "isFar := exported" default). A caller re-parsing this .SHD
      (SymTab.OpenInclude) trusts this text's own NEAR/FAR keyword to
      decide EmitCall's own "call" vs "call far" -- printing NEAR here
      for a real FAR procedure previously made a cross-module call
      site emit a plain "call" against a callee whose own "retf"
      epilogue pops one extra segment word the "call" never pushed,
      corrupting the caller's own return address at runtime. }
    if SymTab.ProcIsFar(pi) then line := line + '; FAR; EXTERNAL;'
    else line := line + '; NEAR; EXTERNAL;';
    Emits.Emit(shdEs, false, line)
  end;

  Emits.Emit(shdEs, false, '');
  Emits.Emit(shdEs, false, 'END ' + modName + '.');
  Emits.close(shdEs);
  LogErr.Info2('wrote ', shdPath)
end;

end.
