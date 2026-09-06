{$I FLAGS.INC}
{
  Interned lexeme table: name -> (kind, id) pairs, found by exact text
  match (hash-prefiltered scan over chunked storage).

  Bug fixed vs. the original: LEXTAB.MOD's Add* never reassigns
  lexChunks past the first chunk it ever allocates (only lastLexChunk is
  kept current), so the original's own Find is permanently unable to
  see any lex record added after the first chunk fills up. This port's
  Add keeps lexChunks pointing at the true list head on every new
  chunk, so FindByHash actually reaches all of them.

  Clear also diverges from the original: LEXTAB.MOD's Clear* just nils
  out the four list-head/tail vars and relies on Oberon's GC to reclaim
  the chunks. Free Pascal's New/Dispose heap has no GC, so Clear here
  walks and Disposes every chunk first.

  A second bug fixed vs. the original: LEXTAB.MOD's FindByHash scans a
  chunk's own rows oldest-first (FOR i := 0 TO p.count - 1), so a name
  Add'd again later (shadowing an earlier same-spelled entry within the
  same still-filling chunk) resolved to the STALE earlier row, not the
  new one -- broke variable/parameter shadowing wherever a caller relies
  on Add-again-to-shadow (SymTab's SymAppend does, for every PROCEDURE
  parameter and local VAR/CONST). This port's FindByHash scans a chunk's
  rows most-recent-first (DOWNTO), matching the already most-recent-
  chunk-first traversal, so Find is guaranteed most-recent-wins end to
  end -- verified against a global VAR shadowed by a same-named
  PROCEDURE parameter.
}
unit LexTab;

interface

const
  LexChunkSize  = 64;
  TextChunkSize = 8192;

type
  PTextChunk = ^TTextChunk;
  TTextChunk = record
    buf:  array[0..TextChunkSize-1] of char;
    used: integer;
    next: PTextChunk
  end;

  { LexRec: one interned name's location (textChunk/textOff/textLen) plus
    its caller-supplied kind/id. hash is cached at Add time so FindByHash
    can reject a non-matching bucket with one word compare before ever
    touching the text. }
  TLexRec = record
    textChunk: PTextChunk;
    textOff:   integer;
    textLen:   integer;
    hash:      word;
    kind:      integer;
    id:        integer
  end;

  PLexRecChunk = ^TLexRecChunk;
  TLexRecChunk = record
    items: array[0..LexChunkSize-1] of TLexRec;
    count: integer;
    next:  PLexRecChunk
  end;

  { TLexMark: a Mark/Truncate checkpoint -- the lex-record chunk and
    text chunk that were "current" (lastLexChunk/lastTextChunk) at Mark
    time, plus their own count/used at that moment. Truncate rewinds to
    exactly this point: every whole chunk allocated after the mark is
    disposed, and the two marked chunks themselves are trimmed back to
    their saved count/used, discarding every row/byte added since. }
  TLexMark = record
    lc:    PLexRecChunk;
    lcCnt: integer;
    tc:    PTextChunk;
    tcUsed: integer
  end;

{ Find: exact-text lookup. TRUE and kind/id filled in if s is present;
  FALSE (kind/id untouched) otherwise. }
function Find(const s: string; var kind, id: integer): boolean;

{ FindText: the reverse of Find -- given a (kind, id) pair, return the
  spelling it was Add'd under. TRUE and dst filled in if found; FALSE
  (dst untouched) otherwise. Intended for small, fixed, exact-once-per-
  (kind,id) sets (e.g. RegisterBuiltins' keywords/symbols, each id used
  exactly once) -- a linear scan, same cost class as Find's own
  worst case, not indexed by (kind,id). }
function FindText(kind, id: integer; var dst: string): boolean;

{ Add: intern s with the given kind/id, unconditionally -- no dedup
  check against an existing entry (see unit header). FALSE only if s is
  too long to fit a single text chunk (TextChunkSize - 1 chars); TRUE
  otherwise. }
function Add(const s: string; kind, id: integer): boolean;

{ GetText: copy lex's own interned text into dst. }
procedure GetText(const lex: TLexRec; var dst: string);

{ Mark: snapshot the current append position, to later Truncate back to.
  A var parameter, not a function result -- Turbo Pascal function
  results are limited to ordinal/real/pointer/string types, not an
  arbitrary record (an FPC-only relaxation this project avoids). }
procedure Mark(var m: TLexMark);

{ Truncate: discard every row Add'd since m was taken (scope-exit
  cleanup -- e.g. a PROCEDURE's own param names, which must not leak
  into the next procedure's lookups). Every TLexRec returned by a Find
  for a now-discarded row becomes invalid; nothing currently holds one
  across a Truncate call in this codebase. }
procedure Truncate(const m: TLexMark);

{ Clear: drop every chunk (all previously-returned TLexRec values become
  invalid -- their textChunk pointers are no longer reachable from this
  unit, though FPC will not free them until the last reference is
  Dispose'd, same caveat as the Oberon original's GC-collected discard). }
procedure Clear;

implementation

uses
  Util;

var
  lexChunks, lastLexChunk: PLexRecChunk;
  { textChunks: list head, written on first Add/Clear but never read --
    same as the Oberon original (nothing traverses text chunks via next;
    every lookup goes through a LexRec's own textChunk pointer instead).
    FPC's "assigned but never used" note on this var is expected, not a
    porting mistake. }
  textChunks, lastTextChunk: PTextChunk;

{ TextEquals: TRUE iff lex's own interned text equals s (len already
  known equal by the caller, FindByHash, before this is called). }
function TextEquals(const lex: TLexRec; const s: string; len: integer): boolean;
  var i: integer;
begin
  if lex.textLen <> len then begin TextEquals := false; exit end;
  for i := 0 to len - 1 do
    if lex.textChunk^.buf[lex.textOff + i] <> s[i + 1] then begin
      TextEquals := false; exit
    end;
  TextEquals := true
end;

{ FindRowByHash/FindRowByKindId: the shared traversal for Find/FindText
  -- walk every chunk most-recently-added chunk first (new chunks are
  pushed onto the front of lexChunks), and within a chunk most-recently-
  added ROW first too (rows are appended left-to-right as items[0],
  items[1], ... within a chunk, so descending index order = descending
  recency); return the owning chunk + in-chunk index of the first (i.e.
  most recent) matching row, or FALSE if none matched. Guaranteed most-
  recent-wins end to end is required for correct shadowing: a PROCEDURE
  parameter or local VAR/CONST added after an outer/global declaration
  of the same spelling, in the SAME still-filling chunk, must resolve to
  itself, not the stale outer entry. Two entry points (by hash/length/
  text, by kind+id) share this one chunk-walk shape -- Turbo Pascal mode
  has no procedural-value parameters to unify them into a single routine
  without resorting to pointer tricks that would trade this duplication
  for a worse one, so the walk itself (not the match test) is what's
  kept in one place per direction. }
function FindRowByHash(const s: string; h: word; len: integer; var c: PLexRecChunk; var i: integer): boolean;
  var p: PLexRecChunk; k: integer;
begin
  p := lexChunks;
  while p <> nil do begin
    for k := p^.count - 1 downto 0 do
      if (p^.items[k].hash = h) and (p^.items[k].textLen = len) then
      if TextEquals(p^.items[k], s, len) then begin
        c := p; i := k; FindRowByHash := true; exit
      end;
    p := p^.next
  end;
  FindRowByHash := false
end;

function FindRowByKindId(kind, id: integer; var c: PLexRecChunk; var i: integer): boolean;
  var p: PLexRecChunk; k: integer;
begin
  p := lexChunks;
  while p <> nil do begin
    for k := p^.count - 1 downto 0 do
      if (p^.items[k].kind = kind) and (p^.items[k].id = id) then begin
        c := p; i := k; FindRowByKindId := true; exit
      end;
    p := p^.next
  end;
  FindRowByKindId := false
end;

function Find(const s: string; var kind, id: integer): boolean;
  var h: word; len: integer; c: PLexRecChunk; i: integer;
begin
  h := Util.HashCode(s);
  len := Length(s);
  if not FindRowByHash(s, h, len, c, i) then begin Find := false; exit end;
  id := c^.items[i].id;
  kind := c^.items[i].kind;
  Find := true
end;

function FindText(kind, id: integer; var dst: string): boolean;
  var c: PLexRecChunk; i: integer;
begin
  if not FindRowByKindId(kind, id, c, i) then begin FindText := false; exit end;
  GetText(c^.items[i], dst);
  FindText := true
end;

function Add(const s: string; kind, id: integer): boolean;
  var h: word; len: integer; lc: PLexRecChunk; tc: PTextChunk; rec: TLexRec;
begin
  h := Util.HashCode(s);
  len := Length(s);

  if len + 1 > TextChunkSize then begin Add := false; exit end;

  if (lastLexChunk = nil) or (lastLexChunk^.count = LexChunkSize) then begin
    New(lc);
    lc^.count := 0;
    lc^.next := lastLexChunk;
    lastLexChunk := lc;
    { lexChunks always points at the true list head -- the most-recently
      pushed chunk -- so FindByHash's lexChunks-rooted walk reaches every
      chunk, not just the first one ever allocated. See the "bug fixed"
      note in this unit's header: the original LEXTAB.MOD's Add* never
      reassigns lexChunks past the first chunk, so its own Find is
      permanently unable to see any chunk after the first. }
    lexChunks := lc
  end;

  rec.textChunk := nil;
  rec.textOff := 0;
  rec.textLen := len;
  rec.hash := h;
  rec.kind := kind;
  rec.id := id;

  if (lastTextChunk = nil) or (lastTextChunk^.used + len + 1 > TextChunkSize) then begin
    New(tc);
    tc^.used := 0;
    tc^.next := nil;
    if lastTextChunk = nil then textChunks := tc
    else lastTextChunk^.next := tc;
    lastTextChunk := tc
  end;

  rec.textChunk := lastTextChunk;
  rec.textOff := lastTextChunk^.used;
  if len > 0 then Move(s[1], lastTextChunk^.buf[lastTextChunk^.used], len);
  Inc(lastTextChunk^.used, len + 1);

  lastLexChunk^.items[lastLexChunk^.count] := rec;
  Inc(lastLexChunk^.count);

  Add := true
end;

procedure GetText(const lex: TLexRec; var dst: string);
begin
  { dst[0] is a short string's own length byte -- setting it directly is
    the plain Turbo Pascal way to size a string before filling it via
    Move, no library call needed. }
  dst[0] := Chr(lex.textLen);
  if lex.textLen > 0 then Move(lex.textChunk^.buf[lex.textOff], dst[1], lex.textLen)
end;

procedure Mark(var m: TLexMark);
begin
  m.lc := lastLexChunk;
  if lastLexChunk <> nil then m.lcCnt := lastLexChunk^.count else m.lcCnt := 0;
  m.tc := lastTextChunk;
  if lastTextChunk <> nil then m.tcUsed := lastTextChunk^.used else m.tcUsed := 0
end;

{ Truncate: lex-record chunks are pushed onto the FRONT of lexChunks by
  Add (lc^.next := old lastLexChunk), so every chunk allocated after m
  was taken is exactly the run from lexChunks up to (not including) the
  chunk m itself marked -- walk and Dispose that run, then trim the
  marked chunk back to its own saved count. Text chunks are appended at
  the END instead (tc^.next := nil, old lastTextChunk^.next := tc), so
  the run allocated after m is reached by walking m.tc^.next onward
  (or textChunks from the start, if m.tc was nil -- no chunk existed
  yet at Mark time). }
procedure Truncate(const m: TLexMark);
  var lc, lcNext, stopAt: PLexRecChunk; tcFrom, tc, tcNext: PTextChunk;
begin
  stopAt := m.lc;
  lc := lexChunks;
  while (lc <> nil) and (lc <> stopAt) do begin
    lcNext := lc^.next; Dispose(lc); lc := lcNext
  end;
  lexChunks := stopAt;
  lastLexChunk := stopAt;
  if stopAt <> nil then stopAt^.count := m.lcCnt;

  if m.tc = nil then tcFrom := textChunks else tcFrom := m.tc^.next;
  tc := tcFrom;
  while tc <> nil do begin tcNext := tc^.next; Dispose(tc); tc := tcNext end;
  if m.tc <> nil then m.tc^.next := nil;
  lastTextChunk := m.tc;
  if m.tc <> nil then m.tc^.used := m.tcUsed
end;

{ Clear: dispose every allocated chunk (both the lex-record chunks and
  the text chunks), then reset all four list-head/tail vars to nil.
  Unlike the Oberon original -- which just drops the references and
  lets the GC reclaim them -- Free Pascal's New/Dispose heap has no GC,
  so a bare nil-out here would leak every chunk ever allocated; walk
  each chunk list explicitly instead, same pattern as StrTab.Reset. }
procedure Clear;
  var lc, lcNext: PLexRecChunk; tc, tcNext: PTextChunk;
begin
  lc := lexChunks;
  while lc <> nil do begin lcNext := lc^.next; Dispose(lc); lc := lcNext end;

  tc := textChunks;
  while tc <> nil do begin tcNext := tc^.next; Dispose(tc); tc := tcNext end;

  lexChunks := nil;
  lastLexChunk := nil;
  textChunks := nil;
  lastTextChunk := nil
end;

begin
  lexChunks := nil;
  lastLexChunk := nil;
  textChunks := nil;
  lastTextChunk := nil
end.
