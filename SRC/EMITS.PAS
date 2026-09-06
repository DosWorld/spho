{$I FLAGS.INC}
unit emits;

interface

type

TEmitState=record
  f    : text;
  name : string;
end;

function  open(var state : TEmitState; const name: string):boolean;
procedure close(var state : TEmitState);

procedure EmitLn(var state : TEmitState);
procedure EmitCh(var state : TEmitState; c:char);
procedure Emit(var state : TEmitState; needtab:boolean; const s: string);
procedure Emit2(var state : TEmitState; needtab:boolean; const a, b: string);
procedure Emit3(var state : TEmitState; needtab:boolean; const a, b, c: string);

procedure EmitOp0(var state : TEmitState; const a: string);
procedure EmitOp1(var state : TEmitState; const a, b: string);
procedure EmitOp2(var state : TEmitState; const a, b, c: string);

procedure EmitDefLabel(var state : TEmitState; const prefix: string; num : word);
procedure EmitOpWithLabel(var state : TEmitState; needtab:boolean; const prefix: string; num : word);

implementation

uses logerr;

const
tab = #9;   { real horizontal tab, not #7/BEL }

function open(var state : TEmitState; const name: string):boolean;
var i : integer;
begin
  assign(state.f, name);
  {$I-}
  rewrite(state.f);
  i := IOResult;
  {$I+}
  if i <> 0 then begin logerr.error2('could not write ',  name);open:=false; exit end;
  state.name := name;
  open := true;
end;

procedure close(var state : TEmitState);
begin
  system.close(state.f)
end;

procedure errorWrite(var state : TEmitState; code : integer);
var snum:string;
begin
  str(code, snum);
  logerr.error2('Write error #'+snum+' to file ',  state.name);
end;

procedure EmitLn(var state : TEmitState);
var i : integer;
begin
  {$I-}
  writeln(state.f);
  i := IOResult;
  {$I+}
  if i <> 0 then errorWrite(state, i);
end;

procedure EmitCh(var state : TEmitState; c:char);
var i : integer;
begin
  {$I-}
  write(state.f, c);
  i := IOResult;
  {$I+}
  if i <> 0 then errorWrite(state, i);
end;

procedure EmitStr(var state : TEmitState; const str:string);
var i : integer;
begin
  {$I-}
  write(state.f, str);
  i := IOResult;
  {$I+}
  if i <> 0 then errorWrite(state, i);
end;

function HexByte(b: byte): string;
  const digits: array[0..15] of char = '0123456789ABCDEF';
begin
  HexByte := '0' + digits[b shr 4] + digits[b and 15] + 'h'
end;

procedure EmitByte(var state : TEmitState; b : byte);
begin
  EmitStr(state, HexByte(b))
end;

procedure Emit(var state : TEmitState; needtab:boolean; const s: string);
var i : integer;
begin
  {$I-}
  if needtab then write(state.f, tab);
  i := IOResult;
  if i = 0 then begin WriteLn(state.f, s); i := IOResult; end;
  {$I+}
  if i <> 0 then errorWrite(state, i);
end;

procedure Emit2(var state : TEmitState; needtab:boolean; const a, b: string);
var i : integer;
begin
  {$I-}
  if needtab then write(state.f, tab);
  i := IOResult;
  if i = 0 then begin WriteLn(state.f, a, b); i := IOResult; end;
  {$I+}
  if i <> 0 then errorWrite(state, i);
end;

procedure Emit3(var state : TEmitState; needtab:boolean; const a, b, c: string);
var i : integer;
begin
  {$I-}
  if needtab then write(state.f, tab);
  i := IOResult;
  if i = 0 then begin WriteLn(state.f, a, b, c); i := IOResult; end;
  {$I+}
  if i <> 0 then errorWrite(state, i);
end;

procedure EmitOp0(var state : TEmitState; const a: string);
var i : integer;
begin
  {$I-}
  WriteLn(state.f, tab, a); i := IOResult;
  {$I+}
  if i <> 0 then errorWrite(state, i);
end;

procedure EmitOp1(var state : TEmitState; const a, b: string);
var i : integer;
begin
  {$I-}
  WriteLn(state.f, tab, a, tab, b); i := IOResult;
  {$I+}
  if i <> 0 then errorWrite(state, i);
end;

procedure EmitOp2(var state : TEmitState; const a, b, c: string);
var i : integer;
begin
  {$I-}
  WriteLn(state.f, tab, a, tab, b, ', ',c); i := IOResult;
  {$I+}
  if i <> 0 then errorWrite(state, i);
end;

procedure EmitDefLabel(var state : TEmitState; const prefix: string; num : word);
var snum:string;
begin
  str(num, snum);
  Emit3(state, false, prefix, snum, ':')
end;

procedure EmitOpWithLabel(var state : TEmitState; needtab:boolean; const prefix: string; num : word);
var snum:string;
begin
  str(num, snum);
  Emit2(state, needtab, prefix, snum)
end;

end.
