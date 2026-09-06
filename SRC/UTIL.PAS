{$I FLAGS.INC}
unit Util;

interface

function UpStr(const s: string): string;
function EqualICase(const a, b: string): boolean;
function IntStr(n: longint): string;
function HashCode(const s: string): word;
function TrimStr(const s: string): string;
function ReplaceExt(const path, newExt: string): string;
function ExtractDir(const path: string): string;
function HexByte(b: byte): string;

{ TB64State/B64Init/B64Feed/B64Flush: streaming base64 decoder -- no
  procedural/callback type, just a caller-owned state record the caller
  (Scan.pas, which alone drives the raw "..." character loop) feeds one
  character at a time via B64Feed, in source order, as they're read past
  the opening quote. Each time a decoded byte is ready it's written
  immediately as hex, appended to (or starting) a "db" line on st.outF^
  -- st.outF itself is never buffered or copied, just held by reference,
  so no full-size arrayLitBuf/litTextBuf is ever needed. Whitespace
  (space/tab/CR/LF) is skipped exactly as the old whole-buffer
  Base64Decode did; the SPHINX text "..." scanner itself never embeds a
  real newline, so this only matters for BASE64 text deliberately spread
  across the .SMD source. '='/'==' padding is only legal as the last 1-2
  chars fed before B64Flush. }
type
  TB64State = record
    outF: ^text;
    nm: string;
    group: array[0..3] of integer;
    groupLen: integer;
    padCount: integer;
    outLen: word;
    maxLen: word;
    lineCol: integer;   { bytes emitted on the current db line so far }
    bad: boolean
  end;

procedure B64Init(var st: TB64State; var outF: text; const nm: string; maxLen: word);
procedure B64Feed(var st: TB64State; c: char);
function B64Flush(var st: TB64State): boolean;
function B64OutLen(var st: TB64State): word;

{ StreamFileBytes: FILE("...") support -- reads path byte-by-byte
  (small internal read buffer, not a maxLen-sized one) and writes hex
  "db" lines directly to outF as it goes, same line-batching/labeling
  convention as B64Feed/B64Flush above. FALSE on any open/read error or
  if the file is larger than maxLen; outF has already had a (possibly
  partial) label/db lines written in that case, matching how the old
  whole-buffer ReadFileBytes left buf unspecified on FALSE. }
function StreamFileBytes(var outF: text; const nm, path: string; maxLen: word; var outLen: word): boolean;

{ StreamStrBytes: VAR NAME: T[] = "text" support -- writes str's own
  bytes as hex "db" lines (same line-batching/labeling convention as
  StreamFileBytes/B64Feed above), then one trailing zero byte
  (ASCIIZ terminator). FALSE if str's length + 1 exceeds maxLen. }
function StreamStrBytes(var outF: text; const nm, str: string; maxLen: word; var outLen: word): boolean;

implementation

function HashCode(const s: string): word;
  var h: word; i: integer;
begin
  h := 0;
  for i := 1 to Length(s) do
    h := word((longint(h) * 31 + Ord(s[i])) and $FFFF);
  HashCode := h
end;

function UpStr(const s: string): string;
  var i: integer; r: string;
begin
  r := s;
  for i := 1 to Length(r) do r[i] := UpCase(r[i]);
  UpStr := r
end;

function EqualICase(const a, b: string): boolean;
begin
  EqualICase := UpStr(a) = UpStr(b)
end;

function IntStr(n: longint): string;
  var s: string;
begin
  Str(n, s); IntStr := s
end;

{ TrimStr: strip leading/trailing spaces/tabs, mirroring the Oberon
  Strings.Trim call ParseAsm uses to decide whether a raw ASM body line
  is blank. }
function TrimStr(const s: string): string;
  var i, j: integer;
begin
  i := 1;
  while (i <= Length(s)) and (s[i] in [' ', #9]) do Inc(i);
  j := Length(s);
  while (j >= i) and (s[j] in [' ', #9]) do Dec(j);
  TrimStr := Copy(s, i, j - i + 1)
end;
{ ReplaceExt: swap srcPath's own extension for newExt (".ASM"). Mirrors
  the Oberon Files.ReplaceExt used by RunBody. }
function ReplaceExt(const path, newExt: string): string;
  var i: integer; dotPos: integer;
begin
  dotPos := 0;
  for i := Length(path) downto 1 do begin
    if path[i] = '.' then begin dotPos := i; break end;
    if path[i] in ['/', '\', ':'] then break
  end;
  if dotPos = 0 then ReplaceExt := path + newExt
  else ReplaceExt := Copy(path, 1, dotPos - 1) + newExt
end;

{ ExtractDir: the directory portion of path (including the trailing
  separator), or '' if path has no directory component at all. Same
  separator scan as ReplaceExt above (both '/' and '\' recognized), used
  by SPHO.PAS to resolve a FILE("...") literal's path relative to the
  .SMD source file it appears in, not the process's own CWD (unlike
  IMPORT, which is plain CWD-relative -- SCAN.PAS's own OpenInclude has
  no directory-resolution logic at all). }
function ExtractDir(const path: string): string;
  var i: integer;
begin
  for i := Length(path) downto 1 do begin
    if path[i] in ['/', '\', ':'] then begin
      ExtractDir := Copy(path, 1, i); exit
    end
  end;
  ExtractDir := ''
end;

{ HexByte: "XXh" TASM/NASM hex-immediate text for b -- always 2 hex
  digits plus a leading "0" (so the assembler never misreads a leading
  A-F digit as the start of an identifier) and a trailing "h", e.g.
  255 -> "0FFh", 10 -> "0Ah", 5 -> "05h". Used by the streaming
  BASE64()/FILE() emitters below so their "db" output is hex, not
  decimal. }
function HexByte(b: byte): string;
  const digits: array[0..15] of char = '0123456789ABCDEF';
begin
  HexByte := '0' + digits[b shr 4] + digits[b and 15] + 'h'
end;

procedure B64Init(var st: TB64State; var outF: text; const nm: string; maxLen: word);
begin
  st.outF := @outF; st.nm := nm; st.groupLen := 0; st.padCount := 0;
  st.outLen := 0; st.maxLen := maxLen; st.lineCol := 0; st.bad := false
end;

{ B64EmitByte: write b as one more hex item on the current db line,
  starting a new "NAME: db "/"  db " line every LitBytesPerLine items
  (TASM's 255-byte source-line limit -- see Spho.pas's own
  LitBytesPerLine comment; duplicated here as a local const since Util
  has no dependency on Spho). }
procedure B64EmitByte(var st: TB64State; b: byte);
  const LitBytesPerLine = 20;
begin
  if st.outLen >= st.maxLen then begin st.bad := true; exit end;
  if st.lineCol = 0 then begin
    if st.outLen = 0 then Write(st.outF^, st.nm, ': db ')
    else Write(st.outF^, '  db ')
  end else
    Write(st.outF^, ',');
  Write(st.outF^, HexByte(b));
  Inc(st.outLen); Inc(st.lineCol);
  if st.lineCol >= LitBytesPerLine then begin
    WriteLn(st.outF^); st.lineCol := 0
  end
end;

function B64CharVal(c: char): integer;
begin
  if (c >= 'A') and (c <= 'Z') then begin B64CharVal := Ord(c) - Ord('A'); exit end;
  if (c >= 'a') and (c <= 'z') then begin B64CharVal := Ord(c) - Ord('a') + 26; exit end;
  if (c >= '0') and (c <= '9') then begin B64CharVal := Ord(c) - Ord('0') + 52; exit end;
  if c = '+' then begin B64CharVal := 62; exit end;
  if c = '/' then begin B64CharVal := 63; exit end;
  if c = '=' then begin B64CharVal := -1; exit end;
  B64CharVal := -2
end;

function B64IsWs(c: char): boolean;
begin B64IsWs := (c = ' ') or (c = #9) or (c = #13) or (c = #10) end;

{ B64FlushGroup: st.group[0..st.groupLen-1] (2..4 buffered base64 chars)
  -> groupLen-1 decoded bytes, emitted immediately via B64EmitByte. }
procedure B64FlushGroup(var st: TB64State);
  var b0, b1, b2, b3: integer;
begin
  b0 := st.group[0]; b1 := st.group[1];
  if st.groupLen >= 3 then b2 := st.group[2] else b2 := 0;
  if st.groupLen >= 4 then b3 := st.group[3] else b3 := 0;
  B64EmitByte(st, byte((b0 shl 2) or (b1 shr 4)));
  if st.groupLen >= 3 then B64EmitByte(st, byte(((b1 and 15) shl 4) or (b2 shr 2)));
  if st.groupLen >= 4 then B64EmitByte(st, byte(((b2 and 3) shl 6) or b3))
end;

{ B64Feed: caller (Scan.pas) calls this once per raw character of a
  BASE64("...") literal's text, in order, between the opening and
  closing quote. Sets st.bad on any invalid character, malformed
  padding, or overflow past st.maxLen -- caller checks the B64Flush
  result after the closing quote and reports the translator error
  itself, same contract the old whole-buffer Base64Decode had. }
procedure B64Feed(var st: TB64State; c: char);
begin
  if st.bad then exit;
  if B64IsWs(c) then exit;
  case B64CharVal(c) of
    -2: st.bad := true;   { invalid character }
    -1: begin   { '=' padding -- only legal at the very end, checked in B64Flush }
      Inc(st.padCount);
      if st.padCount > 2 then st.bad := true
    end
  else
    if st.padCount > 0 then begin st.bad := true; exit end;   { data after padding started }
    st.group[st.groupLen] := B64CharVal(c); Inc(st.groupLen);
    if st.groupLen = 4 then begin
      B64FlushGroup(st); st.groupLen := 0
    end
  end
end;

{ B64Flush: call once after the closing quote has been reached. Emits
  any final partial group, writes the label-only line for a zero-length
  literal, terminates the last db line's trailing newline, and returns
  false on any error (invalid char, bad padding, or overflow) -- same
  contract the old whole-buffer Base64Decode had. }
function B64Flush(var st: TB64State): boolean;
begin
  if (not st.bad) and (st.groupLen = 1) then st.bad := true;   { one leftover char can't decode to a whole byte }
  if (not st.bad) and (st.groupLen > 0) then B64FlushGroup(st);
  if st.bad then begin B64Flush := false; exit end;
  if st.outLen = 0 then WriteLn(st.outF^, st.nm, ':')
  else if st.lineCol > 0 then WriteLn(st.outF^);
  B64Flush := true
end;

function B64OutLen(var st: TB64State): word;
begin B64OutLen := st.outLen end;

{ StreamFileBytes: FILE("...") support. Reads path in small fixed-size
  chunks (ReadChunk bytes at a time, not maxLen-sized) and streams each
  byte straight out as hex "db" text via the same line-batching shape
  B64EmitByte uses, so no full-file-sized buffer is ever held in memory. }
function StreamFileBytes(var outF: text; const nm, path: string; maxLen: word; var outLen: word): boolean;
  const ReadChunk = 512; LitBytesPerLine = 20;
  var f: file; sz: longint; got: word; i: integer; ioerr: integer;
      chunk: array[0..ReadChunk-1] of byte; lineCol: integer;
begin
  StreamFileBytes := false;
  outLen := 0;
  Assign(f, path);
  {$I-}
  System.Reset(f, 1);
  ioerr := IOResult;
  {$I+}
  if ioerr <> 0 then exit;
  sz := FileSize(f);
  if sz > longint(maxLen) then begin System.Close(f); exit end;
  lineCol := 0;
  while sz > 0 do begin
    {$I-}
    BlockRead(f, chunk, ReadChunk, got);
    ioerr := IOResult;
    {$I+}
    if (ioerr <> 0) or (got = 0) then begin System.Close(f); exit end;
    for i := 0 to got - 1 do begin
      if lineCol = 0 then begin
        if outLen = 0 then Write(outF, nm, ': db ') else Write(outF, '  db ')
      end else
        Write(outF, ',');
      Write(outF, HexByte(chunk[i]));
      Inc(outLen); Inc(lineCol);
      if lineCol >= LitBytesPerLine then begin WriteLn(outF); lineCol := 0 end
    end;
    sz := sz - longint(got)
  end;
  System.Close(f);
  if outLen = 0 then WriteLn(outF, nm, ':')
  else if lineCol > 0 then WriteLn(outF);
  StreamFileBytes := true
end;

function StreamStrBytes(var outF: text; const nm, str: string; maxLen: word; var outLen: word): boolean;
  const LitBytesPerLine = 20;
  var i, lineCol: integer;
begin
  StreamStrBytes := false;
  outLen := 0;
  if longint(Length(str)) + 1 > longint(maxLen) then exit;
  lineCol := 0;
  for i := 1 to Length(str) do begin
    if lineCol = 0 then begin
      if outLen = 0 then Write(outF, nm, ': db ') else Write(outF, '  db ')
    end else
      Write(outF, ',');
    Write(outF, HexByte(byte(str[i])));
    Inc(outLen); Inc(lineCol);
    if lineCol >= LitBytesPerLine then begin WriteLn(outF); lineCol := 0 end
  end;
  if lineCol = 0 then begin
    if outLen = 0 then Write(outF, nm, ': db ') else Write(outF, '  db ')
  end else
    Write(outF, ',');
  Write(outF, HexByte(0));
  Inc(outLen);
  WriteLn(outF);
  StreamStrBytes := true
end;

end.
