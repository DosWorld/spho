{$I FLAGS.INC}
{
  Interned string table.

  Every identifier/name in the symbol table is stored here exactly once; a
  name is identified by a WORD id (1-based; 0 = "no string"). Two names are
  equal iff their ids are equal, so symbol lookup is a WORD compare -- no
  string comparison.

  Storage is RAM-resident and chunked:
    - text chunks: the name characters, densely packed, addressed by
      (chunk index, offset, length) rather than a NUL terminator (Pascal
      strings are length-prefixed, so there is no terminator to scan for
      the way the Oberon original's SYSTEM.FINDBYTE did);
    - entry chunks: per id (hash, text chunk#, text ofs, length, hash-chain next);
    - Buckets hash buckets of id heads for Put/Find.
}
unit StrTab;

interface

type
  TStrTabId = word;

function Count: TStrTabId;

{ Get: copy the text of id into dst (id 0 or out of range -> empty string). }
procedure Get(id: TStrTabId; var dst: string);

{ Find: id of name, or 0 when the name was never interned. Never allocates. }
function Find(const name: string): TStrTabId;

{ Put: id of name, interning it on first sight. }
function Put(const name: string): TStrTabId;

{ Reset: release every chunk and empty the table (all ids become invalid). }
procedure Reset;

implementation

uses Util;

const
  TextSize = 2048;   { chars per text chunk, mirroring the Oberon original's
                        own 2 KB tail-waste-vs-NEW-count tradeoff rationale }
  MaxText  = 48;
  EntPer   = 256;     { entries per entry chunk }
  MaxEnt   = 32;      { up to 8192 distinct names }
  Buckets  = 256;

type
  PTextChunk = ^TTextChunk;
  TTextChunk = record
    ch: array[0..TextSize-1] of char
  end;

  TEntRec = record
    hash:   word;      { hash code of the name }
    tchunk: integer;   { index into textDir }
    tofs:   word;      { offset of the text in that chunk }
    tlen:   word;      { text length (Pascal strings carry no terminator
                          to scan for, unlike the Oberon original's
                          SYSTEM.FINDBYTE-over-a-0X-byte approach) }
    hnext:  TStrTabId  { next id in the same hash bucket; 0 = end }
  end;

  PEntChunk = ^TEntChunk;
  TEntChunk = record
    e: array[0..EntPer-1] of TEntRec
  end;

var
  textDir:  array[0..MaxText-1] of PTextChunk;
  entDir:   array[0..MaxEnt-1] of PEntChunk;
  nText:    integer;   { text chunks allocated }
  textUsed: word;      { used chars in textDir[nText-1] }
  idCount:    TStrTabId;  { ids issued: 1..idCount }
  bucketArr: array[0..Buckets-1] of word;

function Count: TStrTabId;
begin Count := idCount end;

procedure Get(id: TStrTabId; var dst: string);
  var ec: PEntChunk; tc: PTextChunk; o, k, n: word;
begin
  if (id = 0) or (id > idCount) then begin dst := ''; exit end;
  ec := entDir[(id - 1) shr 8];
  k  := (id - 1) and (EntPer - 1);
  tc := textDir[ec^.e[k].tchunk];
  o  := ec^.e[k].tofs;
  n  := ec^.e[k].tlen;
  { dst[0] is a short string's own length byte -- setting it directly is
    the plain Turbo Pascal way to size a string before filling it via
    Move, no library call needed. }
  dst[0] := Chr(n);
  if n > 0 then Move(tc^.ch[o], dst[1], n)
end;

{ FindH: bucket-chain lookup with the hash already computed. }
function FindH(const name: string; h: word): TStrTabId;
  var k: word; ec: PEntChunk; tc: PTextChunk; id: TStrTabId; cand: string;
begin
  id := bucketArr[h and (Buckets - 1)];
  while id <> 0 do begin
    ec := entDir[(id - 1) shr 8];
    k  := (id - 1) and (EntPer - 1);
    if ec^.e[k].hash = h then begin
      tc := textDir[ec^.e[k].tchunk];
      cand[0] := Chr(ec^.e[k].tlen);
      if ec^.e[k].tlen > 0 then Move(tc^.ch[ec^.e[k].tofs], cand[1], ec^.e[k].tlen);
      if cand = name then begin FindH := id; exit end
    end;
    id := ec^.e[k].hnext
  end;
  FindH := 0
end;

function Find(const name: string): TStrTabId;
begin Find := FindH(name, Util.HashCode(name)) end;

function Put(const name: string): TStrTabId;
  var h: word; id: TStrTabId; k, b: word; len: integer; tc: PTextChunk; ec: PEntChunk;
begin
  h  := Util.HashCode(name);
  id := FindH(name, h);
  if id <> 0 then begin Put := id; exit end;

  len := Length(name);
  if len = 0 then begin Put := 0; exit; end;
  { text space (fresh chunk when the current one cannot hold len chars) }
  if (nText = 0) or (word(len) > TextSize - textUsed) then begin
    if nText >= MaxText then begin
      WriteLn('StrTab: name text overflow'); Put := 0; exit
    end;
    New(textDir[nText]);
    Inc(nText); textUsed := 0
  end;
  { entry slot (fresh entry chunk every EntPer ids) }
  if (idCount and (EntPer - 1)) = 0 then begin
    k := idCount shr 8;
    if k >= MaxEnt then begin
      WriteLn('StrTab: too many names'); Put := 0; exit
    end;
    New(entDir[k])
  end;

  Inc(idCount); id := idCount;
  tc := textDir[nText - 1];
  if len > 0 then Move(name[1], tc^.ch[textUsed], len);
  ec := entDir[(id - 1) shr 8];
  k  := (id - 1) and (EntPer - 1);
  ec^.e[k].hash   := h;
  ec^.e[k].tchunk := nText - 1;
  ec^.e[k].tofs   := textUsed;
  ec^.e[k].tlen   := word(len);
  b := h and (Buckets - 1);
  ec^.e[k].hnext := bucketArr[b];
  bucketArr[b] := id;
  Inc(textUsed, word(len));
  Put := id
end;

procedure Reset;
  var k: integer;
begin
  k := 0;
  while k < MaxText do begin
    if textDir[k] <> nil then begin Dispose(textDir[k]); textDir[k] := nil end;
    Inc(k)
  end;
  k := 0;
  while k < MaxEnt do begin
    if entDir[k] <> nil then begin Dispose(entDir[k]); entDir[k] := nil end;
    Inc(k)
  end;
  k := 0;
  while k < Buckets do begin bucketArr[k] := 0; Inc(k) end;
  nText := 0; textUsed := 0; idCount := 0
end;

var
  bi: integer;
begin
  { raw first-time init -- the runtime does not zero module globals,
    same as the Oberon original's own module body. }
  nText := 0; textUsed := 0; idCount := 0;
  bi := 0; while bi < MaxText do begin textDir[bi] := nil; Inc(bi) end;
  bi := 0; while bi < MaxEnt do begin entDir[bi] := nil; Inc(bi) end;
  bi := 0; while bi < Buckets do begin bucketArr[bi] := 0; Inc(bi) end
end.
