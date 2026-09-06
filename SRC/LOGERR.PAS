{$I FLAGS.INC}
{
  Single error/diagnostic state
  API surface actually used by SPHO/SPHOLEX/SCAN: ErrorInFile, Error,
  Error2, Info2, HaveErr. A "sticky have-error" flag records
  whether any Error*/ErrorInFile call has fired since initialization.
}
unit LogErr;

interface

function HaveErr: boolean;

procedure Error(const msg: string);
procedure Error2(const prefix, suffix: string);
procedure Info(const msg: string);
procedure Info2(const prefix, suffix: string);
procedure ErrorInFile(const fname: string; line: longint; const msg: string);

implementation

var
  errFlag: boolean;

function HaveErr: boolean;
begin
  HaveErr := errFlag
end;

procedure FireErr;
begin
  errFlag := true
end;

procedure Error(const msg: string);
begin
  WriteLn('ERROR: ', msg);
  FireErr
end;

procedure Error2(const prefix, suffix: string);
begin
  WriteLn('ERROR:', prefix, suffix);
  FireErr
end;

procedure ErrorInFile(const fname: string; line: longint; const msg: string);
begin
  WriteLn(fname, '(', line, '):ERROR:', msg);
  FireErr
end;

procedure Info(const msg: string);
begin
  WriteLn(msg)
end;

procedure Info2(const prefix, suffix: string);
begin
  WriteLn(prefix, suffix)
end;

begin
  errFlag := false
end.
