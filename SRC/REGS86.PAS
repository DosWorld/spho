{$I FLAGS.INC}
{
  Register lexeme dictionary: maps register names to small integer IDs,
  once, at the point an identifier token is recognized -- every later
  dispatch point in Spho then switches on the integer ID instead of
  repeating a string-equal chain.

  This port only carries the register subset of the original LEX.MOD's
  lookup surface (LookupReg/IsByteReg/IsSegReg): SPHO itself only ever
  classifies register operands (e.g. widen-byte-to-word, segreg-to-segreg
  mov via push/pop). The original's mnemonic/directive/qualifier lookup
  tables (LookupMnem/LookupDirective/LookupQualifier/IsPrefixMnem) belong
  to the DOS-hosted assembler's own instruction dispatch (Enc.Encode,
  Parse's directive/mnemonic routing) -- neither of which exists in this
  port -- so they were dropped rather than carried over unused.

  Lookup uses a "dispatch on first letter, then a short string-equal
  chain" idiom -- the common case (a label/identifier that is NOT a
  register) rejects after one CHAR compare per bucket instead of
  scanning the whole table.
}
unit Regs86;

interface

const
  LNone = 0;

  { ---- registers (1..49 in the original id space; only range this
    port's lookups ever return a nonzero id from) ---- }
  RegAX = 1; RegCX = 2; RegDX = 3; RegBX = 4;
  RegSP = 5; RegBP = 6; RegSI = 7; RegDI = 8;
  RegAL = 9; RegCL = 10; RegDL = 11; RegBL = 12;
  RegAH = 13; RegCH = 14; RegDH = 15; RegBH = 16;
  RegES = 17; RegCS = 18; RegSS = 19; RegDS = 20;

{ LookupReg: name (already uppercased) -> Reg* id, or LNone. }
function LookupReg(const name: string): integer;

{ IsByteReg / IsSegReg: classify an already-resolved register ID. }
function IsByteReg(r: integer): boolean;
function IsSegReg(r: integer): boolean;

{ WordHalves: destReg's own byte halves (AX->AL/AH, BX->BL/BH, CX->CL/CH,
  DX->DL/DH) -- FALSE if destReg has no byte halves. }
function WordHalves(const destReg: string; var lo, hi: string): boolean;

implementation

uses util;


function LookupReg(const name: string): integer;
begin
  LookupReg := LNone;
  if name = '' then exit;
  case name[1] of
    'A':
      if    name = 'AX' then begin LookupReg := RegAX; exit end
      else if name = 'AL' then begin LookupReg := RegAL; exit end
      else if name = 'AH' then begin LookupReg := RegAH; exit end;
    'B':
      if    name = 'BX' then begin LookupReg := RegBX; exit end
      else if name = 'BP' then begin LookupReg := RegBP; exit end
      else if name = 'BL' then begin LookupReg := RegBL; exit end
      else if name = 'BH' then begin LookupReg := RegBH; exit end;
    'C':
      if    name = 'CX' then begin LookupReg := RegCX; exit end
      else if name = 'CL' then begin LookupReg := RegCL; exit end
      else if name = 'CH' then begin LookupReg := RegCH; exit end
      else if name = 'CS' then begin LookupReg := RegCS; exit end;
    'D':
      if    name = 'DX' then begin LookupReg := RegDX; exit end
      else if name = 'DI' then begin LookupReg := RegDI; exit end
      else if name = 'DL' then begin LookupReg := RegDL; exit end
      else if name = 'DH' then begin LookupReg := RegDH; exit end
      else if name = 'DS' then begin LookupReg := RegDS; exit end;
    'S':
      if    name = 'SP' then begin LookupReg := RegSP; exit end
      else if name = 'SI' then begin LookupReg := RegSI; exit end
      else if name = 'SS' then begin LookupReg := RegSS; exit end;
    'E':
      if name = 'ES' then begin LookupReg := RegES; exit end;
  end
end;

function IsByteReg(r: integer): boolean;
begin
  IsByteReg := (r >= RegAL) and (r <= RegBH)
end;

function IsSegReg(r: integer): boolean;
begin
  IsSegReg := (r >= RegES) and (r <= RegDS)
end;

function WordHalves(const destReg: string; var lo, hi: string): boolean;
  var up: string;
begin
  up := UpStr(destReg);
  WordHalves := true;
  if up = 'AX' then begin lo := 'AL'; hi := 'AH'; exit end
  else if up = 'BX' then begin lo := 'BL'; hi := 'BH'; exit end
  else if up = 'CX' then begin lo := 'CL'; hi := 'CH'; exit end
  else if up = 'DX' then begin lo := 'DL'; hi := 'DH'; exit end;
  WordHalves := false
end;

end.
