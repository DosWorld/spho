{$I FLAGS.INC}
{
  SPHINX Oberon translator's character-level scanner: reads the source
  file/include byte stream, tracks line/file position, and exposes the
  raw current-token buffer (tokKind/tokText/tokVal) plus the sticky
  "translation failed" flag (okFlag) that every layer above this one
  (SymTab, Spho) reports errors through.

  Merged from two formerly-separate units: this unit (previously named
  Scanner) is SPHO's own live character scanner; the other (previously
  named Scan, a TASM-style tokenizer port of a different original
  module) had only one function anything here ever called --
  ParseNumBuf/ParseHexDigits, now folded in below as private
  implementation details. Everything else Scan.pas carried (its own
  Scanner RECORD type, Init/InitMem/Next/ScanIdent/ScanString/
  ReadRawLine, and its own same-named-but-different TIdent/TNum/token-
  kind constants) was genuinely dead code in this port -- SPHO itself
  never drove any of it -- so it was dropped rather than merged in.
}
unit Scan;

interface

uses
  LogErr, Util;

{ ArmRawStringNext/RawStrOpen/RawStrNextCh: used only by Spho.pas's
  ParseArrayLitInit, to stream a BASE64("...") literal's own text one
  raw character at a time (e.g. straight into Util.B64Feed) without it
  ever being copied into a buffer first -- not even tokText. No
  Util-specific type appears in this unit; it only hands back plain
  characters.

  This translator is one-token-lookahead (SymTab.Next always fetches
  the token AFTER the one it's returning), so by the time ordinary code
  can inspect "the next token is a string", RawNext has already scanned
  it in full. ArmRawStringNext defeats that specifically for the
  opening '"' of a BASE64() literal: call it BEFORE the SymTab.Next/
  SymTab.Expect call that would otherwise prefetch-scan that string (in
  ParseArrayLitInit, that's the Expect(SyLParen) consuming '(' --
  Expect's own internal Next call is what would normally scan the
  following "..." token). While armed, if RawNext's dispatch lands on a
  '"' it does NOT scan the literal at all -- it leaves tokKind=TStr,
  tokText='', and the raw scanner position (ch) sitting exactly on the
  opening quote itself, clears the arm flag, and returns immediately.
  The caller then drives RawStrOpen/RawStrNextCh directly.

  RawStrOpen: call once, right after the deferred TStr token described
  above (ch is positioned on the opening quote). Consumes it.

  RawStrNextCh: call repeatedly after RawStrOpen; each call returns the
  next raw character strictly between the quotes via c and TRUE, or
  consumes the closing quote and returns FALSE once there are no more
  (the caller's own loop condition). After the FALSE call, the scanner
  is positioned exactly where an ordinary RawNext would have left it
  (ch/ch2 just past the closing quote) -- the caller's very next
  SymTab.Next resumes normal lookahead on whatever token follows. }
procedure ArmRawStringNext;
procedure RawStrOpen;
function RawStrNextCh(var c: char): boolean;

const
  MaxTok = 64; MaxLine = 256;
  { MaxName: every identifier-name storage buffer uses this, not a
    disconnected literal 32. }
  MaxName = MaxTok;
  { MaxStrLit: tokText/stkTokText's own bound -- wider than MaxTok on
    purpose. A double-quoted string literal is scanned into tokText the
    same as any other token, but identifiers/numbers stay bounded at
    MaxTok. Stuck at 255 because tokText is a plain TP7 `string`
    (a ShortString under this file's own Turbo-Pascal-7-compatible
    mode, hard-capped at 255 chars regardless of what this constant
    says) -- see MaxLongStr below for the real fix for literals wider
    than that. }
  MaxStrLit = MaxLine;

  { MaxImportDepth: how many IMPORTs may be open at once, INCLUDING the
    top-level file itself (depth=0) -- SOPLAN.MD's own Phase 7 "natural
    multi-level imports with an include stack". Generous, not measured
    against any real program's own nesting (matches this project's
    existing small-fixed-limit style, MaxParams/MaxUses=32 in Spho.pas/
    SymTab.pas) -- OpenInclude rejects a further IMPORT once the stack
    is full with a translator error rather than overflowing the array.
    Exposed here (not just implementation-private) so SymTab.pas's own
    cycle-detection loop over Scan.AncestorPath(0..CurImportDepth-1) has
    a real upper bound to reason about, matching MaxFields/MaxParams'
    own visibility. }
  MaxImportDepth = 8;

  { token kinds -- TStr (double-quoted "...", any length including 0/1
    chars) is a genuine string literal, needing a .data label; TChar
    (single-quoted '...', always exactly one character) is a plain
    numeric CHAR immediate (its ORD value); TRegPair (SEGREG:REG or
    REG:REG, e.g. ES:DI or DX:AX, DOCS/SPHINX.MD S11) is recognized
    directly here at the character level -- see RawNext's own comment
    -- when written with NO whitespace/comment between the register,
    ':', and register (DX : AX is not a TRegPair; it falls back to
    ordinary TIdent/TSym(':')/TIdent tokens, parsed the old way by
    whatever calls SymTab.Next three times, same as every other
    spelling this scanner doesn't specially recognize). CurTokRegPair
    below reads the two register names. }
  TEof = 0; TIdent = 1; TNum = 2; TStr = 3; TSym = 4; TChar = 5; TRegPair = 6;

{ CurTokRegPair: valid only when CurTokKind = TRegPair. Returns the two
  register names exactly as spelled in source (already upper-cased,
  same as every other TIdent token's own text is NOT upper-cased --
  register names are compared case-insensitively by SymTab.IsRegName
  regardless, so this matches that existing convention rather than
  preserving the source's own casing). }
procedure CurTokRegPair(var seg, off: string);

{ ---------------- token-state accessors (wrapper form, per design) ---------------- }

function CurTokKind: integer;
procedure CurTokText(var dst: string);
function CurTokVal: longint;
function TokTextEqICase(const s: string): boolean;

{ ---------------- misc shared-state accessors ---------------- }

procedure SrcPath(var dst: string);
function CurLine: integer;
function Ok: boolean;
procedure SetOk(v: boolean);
procedure ReportError(const msg: string);

{ ---------------- low-level scanning ---------------- }

{ IsIdentStart/IsIdentCh/SkipBlanks/ParseNumText/ParseHexDigits/
  ParseNumBuf are internal to RawNext/ReadAsmLine's own scanning -- no
  caller outside this unit needs them, so they stay implementation-only
  rather than padding the interface. }

procedure SkipAsmLead;
procedure ReadAsmLine(var buf, firstWord: string; var atEnd: boolean);

{ RawNext: fetch the next token's raw text/kind/value into tokKind/
  tokText/tokVal. }
procedure RawNext;

{ GetTokKindText: used only by SymTab.Next, to decide whether the raw
  token needs a lexeme-table resolve (TIdent/TSym). }

procedure GetTokKindText(var kind: integer; var text: string);

{ ---------------- position mark/rewind (same file, mid-stream) ---------------- }

{ TScanMark/Mark/Rewind: save/restore a position WITHIN the current
  file (unlike OpenInclude/CloseInclude, which switch files) -- used by
  RawNext's own TRegPair fast path (see its comment) to back out of a
  tightly-spelled "REG:" prefix that doesn't turn out to be followed by
  a second register name, restoring the scan position to right after
  the first register so it's re-read as an ordinary TIdent token.
  Captures the streamed file's own byte offset (via FilePos, restored
  via Seek -- no whole-file buffer needed, same "no size limit" design
  the rest of this unit already keeps) plus every other byte of
  lookahead state (ch/ch2/gline/tokKind/tokText/tokVal/tokRegSeg/
  tokRegOff). }
type
  TScanMark = record
    pos: longint;
    depth: integer;
    ch, ch2: char;
    gline: integer;
    tokKind: integer;
    tokText: string;
    tokVal: longint;
    { tokRegSeg/tokRegOff: only meaningful when tokKind = TRegPair.
      Added alongside tokText/tokVal above for the same reason those
      are captured -- without this, Rewind restores tokKind = TRegPair
      correctly but leaves tokRegSeg/tokRegOff holding whatever a LATER
      RawNext call (further lookahead past the marked position, before
      the rewind) last wrote into them, not what they were AT the
      marked position -- a caller reading Scan.CurTokRegPair right
      after a Rewind onto a TRegPair token would silently get the
      wrong two register names. }
    tokRegSeg, tokRegOff: string
  end;

procedure Mark(var m: TScanMark);
procedure Rewind(const m: TScanMark);

{ ---------------- driver-facing setup/reset ---------------- }

function OpenSource(const path: string): boolean;
function OpenInclude(const nm: string): boolean;
procedure CloseInclude;
procedure CloseSource;
procedure SetSrcPath(const path: string);
procedure ResetScanner;

{ AncestorPath(i)/CurImportDepth: cycle-detection support for
  SymTab.OpenInclude -- see AncestorPath's own implementation comment. }
function AncestorPath(i: integer): string;
function CurImportDepth: integer;

{ FileExistsQuiet: exported so SymTab.OpenInclude's own cycle check can
  resolve nm to the SAME path OpenInclude below will actually open
  (NAME.SHD, or LIB\NAME.SHD if no local copy exists) -- without this,
  the cycle check compared against a path OpenInclude never actually
  opens, so it never matched and the check was silently dead. }
function FileExistsQuiet(const path: string): boolean;

implementation

var
  { Streamed source: no whole-file RAM buffer, so files aren't size-
    limited. A fixed-size ARRAY of PERMANENT file variables, not one
    save/restored via assignment -- a `file` variable can't legally be
    assigned to another (Assign/Reset/Read/Close are the only sanctioned
    operations on one; `f1 := f2` is an FPC-only relaxation this
    project's plain Turbo Pascal convention avoids), so N independently-
    addressable file variables are the only way to support N levels of
    IMPORT open at once (previously two fixed variables, srcF0/srcF1,
    hard-capping nesting at exactly one level -- see DOCS/SPHO.MD's own
    Phase 7 entry for the history). depth indexes the CURRENTLY ACTIVE
    level (0 = top-level file, no IMPORT open at all); srcStack[i] for
    i < depth stays each ancestor's own still-open, untouched handle,
    exactly as srcF0 used to stay untouched throughout a single IMPORT.
    ch/ch2/gline/gsrcPath are the ACTIVE level's own live lookahead
    state (read/written constantly during scanning, same flat vars as
    before this change) -- OpenInclude/CloseInclude push/pop them into
    stkCh/stkCh2/stkLine/stkPath (indexed by the LEVEL BEING SUSPENDED,
    i.e. the includer, at its own depth) instead of the old single
    outer* slot, so an arbitrary chain of nested IMPORTs can each
    suspend/resume correctly, not just one. }
  srcStack: array[0..MaxImportDepth-1] of file of byte;
  depth: integer;
  ch, ch2: char;
  gline: integer;
  gsrcPath: string;

  stkCh, stkCh2: array[0..MaxImportDepth-1] of char;
  stkLine: array[0..MaxImportDepth-1] of integer;
  stkPath: array[0..MaxImportDepth-1] of string;
  stkTokKind: array[0..MaxImportDepth-1] of integer;
  stkTokText: array[0..MaxImportDepth-1] of string;
  stkTokRegSeg, stkTokRegOff: array[0..MaxImportDepth-1] of string;

  tokKind: integer;
  tokText: string;
  tokVal: longint;
  { tokRegSeg/tokRegOff: valid only when tokKind = TRegPair -- see
    RawNext's own regpair-recognition comment. }
  tokRegSeg, tokRegOff: string;

  okFlag: boolean;

  { rawStrArmed: see ArmRawStringNext's own interface comment.
    rawStrQ: opening quote char, set by RawStrOpen, read by
    RawStrNextCh. }
  rawStrArmed: boolean;
  rawStrQ: char;

procedure ArmRawStringNext;
begin rawStrArmed := true end;

function CurTokKind: integer;
begin CurTokKind := tokKind end;

procedure CurTokText(var dst: string);
begin dst := tokText end;

procedure CurTokRegPair(var seg, off: string);
begin seg := tokRegSeg; off := tokRegOff end;

function CurTokVal: longint;
begin CurTokVal := tokVal end;

function TokTextEqICase(const s: string): boolean;
begin TokTextEqICase := UpStr(tokText) = UpStr(s) end;

{ ---------------- misc shared-state accessors ---------------- }

procedure SrcPath(var dst: string);
begin dst := gsrcPath end;

function CurLine: integer;
begin CurLine := gline end;

function Ok: boolean;
begin Ok := okFlag end;

procedure SetOk(v: boolean);
begin okFlag := v end;

procedure ReportError(const msg: string);
begin
  LogErr.ErrorInFile(gsrcPath, longint(gline), msg); okFlag := false
end;

{ ---------------- low-level scanning ---------------- }

function IsIdentStart(c: char): boolean;
begin IsIdentStart := (Upcase(c) in ['A'..'Z']) or (c = '_') end;

function IsIdentCh(c: char): boolean;
begin IsIdentCh := IsIdentStart(c) or (c in ['0'..'9']) end;

{ NextCh: advance ch/ch2 by one raw byte from the active source file
  (srcStack[depth]); CR is skipped. }
procedure NextCh;
  var b: byte; done: boolean;
begin
  ch := ch2;
  done := false;
  while not done do begin
    if Eof(srcStack[depth]) then begin ch2 := #0; done := true end
    else begin
      Read(srcStack[depth], b);
      if Chr(b) <> #13 then begin ch2 := Chr(b); done := true end
    end
  end
end;

procedure SkipBlanks;
  var more: boolean;
begin
  more := true;
  while more and (ch <> #0) do begin
    if ch = #10 then begin Inc(gline); NextCh end
    else if (ch = ' ') or (ch = #9) then NextCh
    else if (ch = '(') and (ch2 = '*') then begin
      NextCh; NextCh;
      while (ch <> #0) and not ((ch = '*') and (ch2 = ')')) do begin
        if ch = #10 then Inc(gline);
        NextCh
      end;
      if ch <> #0 then begin NextCh; NextCh end
    end else if (ch = '/') and (ch2 = '/') then begin
      { '//' line comment (DOCS/SPHINX.MD's own new S1 note) -- runs to
        end of line, same as every mainstream C-family/Oberon-2 dialect;
        the terminating #10 itself is left for the #10 branch above to
        consume/count on the NEXT loop iteration, not eaten here, so
        gline stays correct without duplicating that bookkeeping. }
      NextCh; NextCh;
      while (ch <> #0) and (ch <> #10) do NextCh
    end else more := false
  end
end;

{ ParseHexDigits: sum buf[from..to0) as hex digits into v (accumulator,
  caller pre-zeroes). Shared by both suffix (h/H) and prefix (0x/0X) hex
  forms. from/to0 are 0-based [from, to0) offsets into buf. Folded in
  from the former unit Scan (see this unit's header). }
procedure ParseHexDigits(const buf: string; from, to0: integer; var v: longint; var bad: boolean);
  var c: integer; hexCh: char;
begin
  c := from;
  while c < to0 do begin
    v := v * 16;
    hexCh := buf[c + 1];  { buf is 1-based Pascal string; from/to0 are 0-based offsets }
    if (hexCh >= '0') and (hexCh <= '9') then v := v + longint(Ord(hexCh) - Ord('0'))
    else if (hexCh >= 'A') and (hexCh <= 'F') then v := v + longint(Ord(hexCh) - Ord('A') + 10)
    else if (hexCh >= 'a') and (hexCh <= 'f') then v := v + longint(Ord(hexCh) - Ord('a') + 10)
    else bad := true;
    Inc(c)
  end
end;

{ ParseNumBuf: classify and compute the value of an already-gathered
  numeric lexeme (decimal, C-style hex prefix "0x1A", trailing-H hex
  "1AH", or trailing-B binary). `buf`/`len` is the raw lexeme text
  exactly as gathered by ParseNumText's caller, INCLUDING any trailing
  h/H/b/B radix suffix. Folded in from the former unit Scan. }
function ParseNumBuf(const buf: string; len: integer; var v: longint; var errMsg: string): boolean;
  var isHexPfx, isHexSfx, bad: boolean; c: integer;
begin
  v := 0;
  isHexSfx := (len >= 1) and ((buf[len] = 'h') or (buf[len] = 'H'));
  isHexPfx := (not isHexSfx) and (len >= 2) and (buf[1] = '0') and ((buf[2] = 'x') or (buf[2] = 'X'));
  if isHexSfx then begin
    if len - 1 > 8 then begin errMsg := 'hex literal too large'; ParseNumBuf := false; exit end;
    bad := false; ParseHexDigits(buf, 0, len - 1, v, bad);
    if bad then begin errMsg := 'bad hex literal'; ParseNumBuf := false; exit end;
    ParseNumBuf := true; exit
  end;
  if isHexPfx then begin
    if len - 2 > 8 then begin errMsg := 'hex literal too large'; ParseNumBuf := false; exit end;
    bad := false; ParseHexDigits(buf, 2, len, v, bad);
    if bad then begin errMsg := 'bad hex literal'; ParseNumBuf := false; exit end;
    ParseNumBuf := true; exit
  end;
  { trailing b/B binary suffix (e.g. "101b", "11111111b"): the digit
    gather loop in RawNext already admits 'b'/'B' as hex digits, so
    it's always inside buf by the time this runs. Detect it after the
    fact: the lexeme is binary iff it ends in b/B and every preceding
    char is '0' or '1'. }
  if (len >= 2) and ((buf[len] = 'b') or (buf[len] = 'B')) then begin
    if len - 1 > 32 then begin errMsg := 'binary literal too large'; ParseNumBuf := false; exit end;
    c := 0;
    while c < len - 1 do begin
      if buf[c+1] = '0' then v := v * 2
      else if buf[c+1] = '1' then v := v * 2 + 1
      else begin errMsg := 'bad binary literal'; ParseNumBuf := false; exit end;
      Inc(c)
    end;
    ParseNumBuf := true; exit
  end;
  if len > 10 then begin errMsg := 'decimal literal too large'; ParseNumBuf := false; exit end;
  c := 0;
  while c < len do begin
    if (buf[c+1] >= '0') and (buf[c+1] <= '9') then
      v := v * 10 + longint(Ord(buf[c+1]) - Ord('0'))
    else begin
      errMsg := 'bad decimal literal'; ParseNumBuf := false; exit
    end;
    Inc(c)
  end;
  ParseNumBuf := true
end;

{ ParseNumText: decimal, C-style hex ("0x1A"), trailing-H hex ("1AH"), or
  trailing-B binary -- delegates to this unit's own ParseNumBuf. }
function ParseNumText(const text: string): longint;
  var v: longint; errMsg: string;
begin
  if not ParseNumBuf(text, Length(text), v, errMsg) then begin
    LogErr.ErrorInFile(gsrcPath, longint(gline), errMsg); okFlag := false
  end;
  ParseNumText := v
end;

procedure SkipAsmLead;
begin SkipBlanks end;

procedure ReadAsmLine(var buf, firstWord: string; var atEnd: boolean);
  var j: integer;
begin
  atEnd := (ch = #0);
  if atEnd then begin buf := ''; firstWord := ''; exit end;
  buf := ''; firstWord := ''; j := -1;
  while (ch <> #0) and (ch <> #10) do begin
    if (j < 0) and IsIdentStart(ch) then j := 0;   { first word starts }
    if (j >= 0) and IsIdentCh(ch) and (j < 30) then begin
      firstWord := firstWord + ch; Inc(j)
    end else if j >= 0 then
      j := -2;   { first word ended (whitespace/punct after it) }
    buf := buf + ch;
    NextCh
  end;
  if ch <> #0 then begin NextCh; Inc(gline) end
end;

{ ScanEscape: called with ch positioned on the character immediately
  after a '\' inside a "..."/'...' literal (the backslash itself
  already consumed by the caller). Consumes the rest of the escape
  sequence and returns its single decoded byte. Supports the C-like
  set DOCS/SPHINX.MD S3.3 documents: \t \n \r (tab/LF/CR), \\ and \'
  and \" (literal backslash/quote), \ooo -- 1 to 3 OCTAL digits (e.g.
  \033 is ESC, 1Bh), and \xHH -- 1 to 2 HEX digits (e.g. \x1b is also
  ESC) -- matching the exact cases in the language request this was
  added for (\033[95m and \x1b, both spellings of the same ANSI color
  escape). An unrecognized escape character, or a '\' immediately
  followed by end of file, is a translator error (okFlag/
  LogErr.ErrorInFile, same severity as the existing empty-char-literal
  '' check just below this procedure's own call site) -- silently
  passing through an unknown \x as literal 'x' would hide real typos
  instead of catching them. }
function ScanEscape: char;
  var v, digits: integer; msg: string;
begin
  if ch = #0 then begin
    msg := 'unterminated escape sequence';
    LogErr.ErrorInFile(gsrcPath, longint(gline), msg); okFlag := false;
    ScanEscape := #0; exit
  end;
  if ch = 't' then begin ScanEscape := #9; NextCh; exit end;
  if ch = 'n' then begin ScanEscape := #10; NextCh; exit end;
  if ch = 'r' then begin ScanEscape := #13; NextCh; exit end;
  if ch = '\' then begin ScanEscape := '\'; NextCh; exit end;
  if ch = '''' then begin ScanEscape := ''''; NextCh; exit end;
  if ch = '"' then begin ScanEscape := '"'; NextCh; exit end;
  if (ch = 'x') or (ch = 'X') then begin
    NextCh; v := 0; digits := 0;
    while (digits < 2) and (Upcase(ch) in ['0'..'9','A'..'F']) do begin
      if ch in ['0'..'9'] then v := v * 16 + (Ord(ch) - Ord('0'))
      else v := v * 16 + (Ord(Upcase(ch)) - Ord('A') + 10);
      NextCh; Inc(digits)
    end;
    if digits = 0 then begin
      msg := 'bad \x escape (no hex digits)';
      LogErr.ErrorInFile(gsrcPath, longint(gline), msg); okFlag := false;
      v := 0
    end;
    ScanEscape := Chr(v); exit
  end;
  if ch in ['0'..'7'] then begin
    v := 0; digits := 0;
    while (digits < 3) and (ch in ['0'..'7']) do begin
      v := v * 8 + (Ord(ch) - Ord('0')); NextCh; Inc(digits)
    end;
    if v > 255 then begin
      msg := 'octal escape out of range';
      LogErr.ErrorInFile(gsrcPath, longint(gline), msg); okFlag := false;
      v := 0
    end;
    ScanEscape := Chr(v); exit
  end;
  msg := 'unknown escape sequence ''\' + ch + '''';
  LogErr.ErrorInFile(gsrcPath, longint(gline), msg); okFlag := false;
  ScanEscape := ch; NextCh
end;

{ IsPairReg: TRUE iff s (already upper-cased by the caller) is one of
  the 12 registers legal on either side of a TRegPair -- the 8 general
  16-bit registers plus the 4 segment registers. Deliberately excludes
  every 8-bit register (AL/AH/CL/CH/DL/DH/BL/BH): DOCS/SPHINX.MD S11's
  own grammar is "SEGREG:REG is ES/DS paired with any general 16-bit
  register, REG:REG is any other register pair" -- an 8-bit register
  never appears in a pair. This list is intentionally hardcoded here
  rather than delegating to SymTab.IsRegName: Scan.pas has no
  dependency on SymTab (this unit is the layer below it, see this
  unit's header comment) and the register set is fixed/closed, so
  duplicating these 12 names is simpler and lower-risk than introducing
  a new cross-layer dependency for it. }
function IsPairReg(const s: string): boolean;
begin
  IsPairReg :=
    (s = 'AX') or (s = 'BX') or (s = 'CX') or (s = 'DX') or
    (s = 'SI') or (s = 'DI') or (s = 'SP') or (s = 'BP') or
    (s = 'ES') or (s = 'CS') or (s = 'SS') or (s = 'DS')
end;

{ RawNext: fetch the next token's raw text/kind/value. }
procedure RawNext;
  var i, j: integer; q: char; msg: string; buf, buf2: string;
      savedMark: TScanMark;
begin
  SkipBlanks;
  tokText := ''; tokVal := 0;
  if ch = #0 then begin tokKind := TEof; exit end;
  if rawStrArmed and (ch = '"') then begin
    { Deferred scan -- see ArmRawStringNext's own interface comment.
      Leave ch positioned exactly on the opening quote; the caller
      drives RawStrOpen/RawStrNextCh from here instead of this
      procedure scanning the literal itself. }
    rawStrArmed := false; tokKind := TStr; exit
  end;
  rawStrArmed := false;
  if IsIdentStart(ch) then begin
    i := 0; buf := '';
    while IsIdentCh(ch) and (i < MaxTok-1) do begin buf := buf + ch; Inc(i); NextCh end;
    tokText := buf; tokKind := TIdent;
    { TRegPair fast path: buf is a register name, immediately (no
      whitespace/comment -- ch is checked raw, not via SkipBlanks)
      followed by ':', immediately followed by another identifier that
      is ALSO a register name -- e.g. "DX:AX" or "ES:DI". "DX : AX"
      (any whitespace/comment inside the pair) does NOT match here and
      falls through to the plain TIdent above, exactly as before this
      feature existed -- the caller sees a bare "DX" token, then ':'
      and "AX" as their own separate tokens on the next two RawNext
      calls, parsed the old (still fully supported) way. A mark/rewind
      guards the attempt: if the character after ':' doesn't start an
      identifier, or that identifier isn't a register name, the scan
      position is restored to exactly where it was right after buf
      (before ':' was consumed) so nothing is lost. }
    if IsPairReg(UpStr(buf)) and (ch = ':') then begin
      Mark(savedMark);
      NextCh;   { consume ':' }
      if IsIdentStart(ch) then begin
        j := 0; buf2 := '';
        while IsIdentCh(ch) and (j < MaxTok-1) do begin buf2 := buf2 + ch; Inc(j); NextCh end;
        if IsPairReg(UpStr(buf2)) then begin
          tokKind := TRegPair;
          tokRegSeg := UpStr(buf);
          tokRegOff := UpStr(buf2);
          { tokText was already set to buf (the first register's own
            text) by the plain-TIdent scan above, before this branch
            knew a TRegPair match was coming -- cleared here so a
            caller that reads Scan.CurTokText on a TRegPair token
            without checking CurTokKind first gets an obviously-empty
            result instead of silently getting back the FIRST
            register's name alone, which is what let SPHO.PAS's
            OperandText silently drop the second register of a regpair
            reaching general operand parsing (e.g. 'TakesWord(DX:AX)'
            against a non-LONGINT parameter) before this line existed. }
          tokText := ''
        end else
          Rewind(savedMark)
      end else
        Rewind(savedMark)
    end
  end else if ch in ['0'..'9'] then begin
    i := 0; buf := '';
    while ((Upcase(ch) in ['0'..'9','A'..'F']) or (ch = 'H') or (ch = 'h') or (ch = 'x') or (ch = 'X'))
          and (i < MaxTok-1) do begin
      buf := buf + ch; Inc(i); NextCh
    end;
    tokText := buf; tokKind := TNum;
    tokVal := ParseNumText(tokText)
  end else if (ch = '"') or (ch = '''') then begin
    { "..."/'...' literal, bounded at MaxStrLit-1 chars like any other
      plain-`string`-typed token (identifiers, error messages, TChar's
      own tokVal) -- a BASE64("...") literal's own text can be far
      longer than this, but that path never reaches here: Spho.pas's
      ParseArrayLitInit calls Scan.RawStrOpen/RawStrNextCh directly
      INSTEAD of SymTab.Next for that one literal, so RawNext (here)
      never has to scan it at all.

      A '\' inside either quote style introduces a C-like escape
      (ScanEscape below), decoded to a single raw byte before being
      appended to buf -- so '\n' is stored as a genuine 0Ah byte, not
      the two source characters '\' and 'n'. This applies to BOTH "..."
      and '...' (a '...' char literal is exactly one character, but
      that character may itself be spelled as an escape, e.g. '\t'). }
    q := ch; NextCh; i := 0; buf := '';
    while (ch <> q) and (ch <> #0) do begin
      if ch = '\' then begin
        NextCh;
        if i < MaxStrLit-1 then begin buf := buf + ScanEscape; Inc(i) end
        else ScanEscape   { buffer full: call only to consume the escape's own characters, result discarded }
      end else begin
        if i < MaxStrLit-1 then begin buf := buf + ch; Inc(i) end;
        NextCh
      end
    end;
    if ch = q then NextCh;
    tokText := buf;
    if q = '"' then
      tokKind := TStr
    else begin
      tokKind := TChar;
      if i = 0 then begin
        { '' (empty single-quoted literal) -- malformed input, not
          silently CHR(0). }
        msg := 'empty char literal ''''';
        LogErr.ErrorInFile(gsrcPath, longint(gline), msg); okFlag := false;
        tokVal := 0
      end else
        tokVal := longint(Ord(tokText[1]))
    end
  end else if (ch = ':') and (ch2 = '=') then begin
    tokText := ':='; tokKind := TSym; NextCh; NextCh
  end else if (ch = '#') then begin
    tokText := '#'; tokKind := TSym; NextCh
  end else if (ch = '<') and (ch2 = '=') then begin
    tokText := '<='; tokKind := TSym; NextCh; NextCh
  end else if (ch = '>') and (ch2 = '=') then begin
    tokText := '>='; tokKind := TSym; NextCh; NextCh
  end else begin
    tokText := ch; tokKind := TSym; NextCh
  end
end;

{ RawStrOpen/RawStrNextCh: see ArmRawStringNext's own interface comment
  for the full contract. rawStrQ remembers the opening quote character
  across RawStrNextCh calls (always '"' in practice, since only
  ParseArrayLitInit's BASE64() path -- never FILE()'s or any '...'
  char-literal path -- ever arms/drives this). }
procedure RawStrOpen;
begin rawStrQ := ch; NextCh end;

function RawStrNextCh(var c: char): boolean;
begin
  if (ch = rawStrQ) or (ch = #0) then begin
    if ch = rawStrQ then NextCh;
    RawStrNextCh := false; exit
  end;
  c := ch; NextCh; RawStrNextCh := true
end;

procedure GetTokKindText(var kind: integer; var text: string);
begin kind := tokKind; text := tokText end;

{ ---------------- driver-facing setup/reset ---------------- }

{ OpenSource: opens path into the currently active level's own file
  variable (srcStack[depth] -- OpenInclude bumps depth before calling
  this, so the active-file selection is already correct by the time
  this runs). }
function OpenSource(const path: string): boolean;
  var ioErr: integer;
begin
  Assign(srcStack[depth], path);
  {$I-}
  System.Reset(srcStack[depth]);
  ioErr := IOResult;
  {$I+}
  if ioErr <> 0 then begin
    LogErr.Error2('cannot open ', path); OpenSource := false; exit
  end;
  gsrcPath := path;
  gline := 1; ch := #0; ch2 := #0;
  NextCh; NextCh;
  OpenSource := true
end;

{ OpenInclude: pushes the includer's own live lookahead state (ch/ch2/
  gline/gsrcPath/current token) onto the stack at its OWN depth (the
  level being suspended), then bumps depth and opens the included file
  into srcStack[depth] -- the includer's own file variable
  (srcStack[depth-1]) is left completely untouched, still mid-read, no
  save/restore needed for the file itself (same reasoning the old two-
  variable design already used, now generalized to N levels via
  MaxImportDepth instead of hardcoding exactly one). FALSE (with depth
  left unchanged) if the stack is already full -- ParseModule's own
  caller (Spho.pas) turns that into a "IMPORT nesting too deep"
  translator error, not a silent array-bounds violation (range checking
  is disabled project-wide, so an unguarded overflow here would be a
  silent memory-corruption bug, not a caught one). }
{ FileExistsQuiet: like SPHO.PAS's own FileExistsLocal, duplicated
  here rather than shared (SCAN.PAS is a lower unit SPHO.PAS itself
  depends on, not the reverse) -- a silent existence probe (no
  LogErr.Error2), so OpenInclude below can try the LIB\ fallback path
  without an intervening spurious "cannot open" error for the CWD
  attempt that was always allowed to fail. }
function FileExistsQuiet(const path: string): boolean;
  var f: file; ioErr: integer;
begin
  Assign(f, path);
  {$I-}
  System.Reset(f);
  ioErr := IOResult;
  {$I+}
  if ioErr = 0 then begin FileExistsQuiet := true; System.Close(f) end
  else FileExistsQuiet := false
end;

function OpenInclude(const nm: string): boolean;
  var path: string;
begin
  if depth >= MaxImportDepth - 1 then begin
    LogErr.Error2('IMPORT nesting too deep (max depth ', Util.IntStr(longint(MaxImportDepth - 1)) + ')');
    OpenInclude := false; exit
  end;
  stkCh[depth] := ch; stkCh2[depth] := ch2; stkLine[depth] := gline;
  stkPath[depth] := gsrcPath;
  stkTokKind[depth] := tokKind; stkTokText[depth] := tokText;
  stkTokRegSeg[depth] := tokRegSeg; stkTokRegOff[depth] := tokRegOff;
  Inc(depth);
  { IMPORTed modules resolve to their own .SHD (Sphinx Oberon HeaDer --
    CONST/TYPE plus '*'-exported PROCEDURE ... EXTERNAL; headers only,
    no bodies), not the full .SMD implementation -- .SHD is generated
    automatically by RunBody's own EmitSHD pass whenever that module is
    itself translated as a top-level file (see SPHO.PAS). Only the
    top-level file being translated is ever opened as .SMD directly
    (Scan.OpenSource in RunBody, a separate call path from this one).

    Tried first as a plain 'NAME.SHD' in the current directory (so a
    project can still shadow/override a shared module locally), then
    as 'LIB\NAME.SHD' if that doesn't exist -- one hardcoded fallback
    subdirectory, since IMPORT itself has no path syntax to say which
    directory a module actually lives in. Lets many project
    directories share one real copy of a common module's own .SHD
    (TASM.EXE/TLINK.EXE still need every .RDF a project links against
    listed explicitly in its own Makefile -- no search path there --
    but via a single 'LIB' directory symlink per project instead of
    one symlink per shared .SHD/.RDF/.SMD file). }
  path := nm + '.SHD';
  if not FileExistsQuiet(path) then path := 'LIB\' + nm + '.SHD';
  if not OpenSource(path) then begin Dec(depth); OpenInclude := false; exit end;
  OpenInclude := true
end;

procedure CloseInclude;
begin
  System.Close(srcStack[depth]);
  Dec(depth);
  ch := stkCh[depth]; ch2 := stkCh2[depth]; gline := stkLine[depth];
  gsrcPath := stkPath[depth];
  tokKind := stkTokKind[depth]; tokText := stkTokText[depth];
  tokRegSeg := stkTokRegSeg[depth]; tokRegOff := stkTokRegOff[depth]
end;

procedure Mark(var m: TScanMark);
begin
  m.pos := FilePos(srcStack[depth]);
  m.depth := depth;
  m.ch := ch; m.ch2 := ch2; m.gline := gline;
  m.tokKind := tokKind; m.tokText := tokText; m.tokVal := tokVal;
  m.tokRegSeg := tokRegSeg; m.tokRegOff := tokRegOff
end;

{ Rewind: m.depth must match the CURRENT depth -- a mark taken mid-file
  is never valid across an IMPORT's own OpenInclude/CloseInclude (every
  Mark/Rewind pair in this unit is purely local backtracking within one
  RawNext call, never spanning an IMPORT boundary), so this doesn't
  attempt to switch files/levels, only seek within the current one. }
procedure Rewind(const m: TScanMark);
begin
  Seek(srcStack[m.depth], m.pos);
  ch := m.ch; ch2 := m.ch2; gline := m.gline;
  tokKind := m.tokKind; tokText := m.tokText; tokVal := m.tokVal;
  tokRegSeg := m.tokRegSeg; tokRegOff := m.tokRegOff
end;

{ CloseSource: closes the top-level file, srcStack[0]. Only ever called
  from RunBody after ParseModule has fully returned -- any IMPORT has
  already gone through its own CloseInclude and unwound depth back to 0
  by then, so this is never reached mid-include. }
procedure CloseSource;
begin System.Close(srcStack[0]) end;

procedure SetSrcPath(const path: string);
begin gsrcPath := path end;

{ CurImportPath/IsAncestorPath: cycle detection support (SOPLAN.MD's own
  Phase 7 "cycle diagnostics") -- SymTab.OpenInclude (below) checks a
  new IMPORT's own resolved path against every currently-open ancestor
  BEFORE calling Scan.OpenInclude, so "A IMPORTs B, B IMPORTs A" is a
  clean translator error instead of silently exhausting MaxImportDepth
  (a confusing "IMPORT nesting too deep" for what's actually an infinite
  cycle) or, in a build without that depth guard, a real stack/resource
  exhaustion. gsrcPath (the ACTIVE level's own path) is level `depth`;
  stkPath[0..depth-1] holds every ancestor's own path, in order. }
function AncestorPath(i: integer): string;
begin
  if i = depth then AncestorPath := gsrcPath else AncestorPath := stkPath[i]
end;

function CurImportDepth: integer;
begin CurImportDepth := depth end;

procedure ResetScanner;
begin
  depth := 0;
  okFlag := true
end;

begin
  depth := 0;
  okFlag := true
end.
