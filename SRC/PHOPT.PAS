{$I FLAGS.INC}
{ PHOPT: Peephole Optimizations over one PROCEDURE's own already-
  recorded operation list (Types.TOperation/TOpChunk), post-parse,
  pre-serialization. Operates on the mnemonic:WORD-tagged operation
  stream (Types.Mn* constants) SPHO.PAS's own AppendInstr0/1/2/
  AppendLabelOp/AppendAsmLine calls build -- that redesign's whole
  point was making a real integer-mnemonic comparison possible here
  instead of re-resolving/re-comparing StrTab-interned text on every
  candidate pair.

  Deleting an operation: overwrite its own mnemonic to Types.MnNop in
  place (never splice/shift the chunked list itself -- every other
  chunk/slot reference elsewhere in SPHO.PAS, e.g. CheckPendingCalls'
  own pending-call patch list, stays valid across an Optimize call this
  way). SPHO.PAS's own SerializeOne already skips a MnNop TOpInstr
  entirely, emitting nothing for it -- that's the only hook this unit
  needs into the rest of the pipeline; no changes elsewhere required to
  make a deletion take effect.

  No cross-procedure state: Optimize is called once per PROCEDURE body,
  right after that procedure's own last operation has been appended
  (SPHO.PAS's own ParseProcedure, just before SymTab.LexTruncate) and
  BEFORE the next PROCEDURE's own first operation is appended -- the
  [startChunk,startSlot) .. tail range handed in is exactly (and only)
  this one procedure's own instructions, never a mix of two
  procedures' operations, and never the module-level struc/.data/.bss
  declarations that live outside any PROCEDURE body (those never call
  Optimize at all -- see ParseProcedure's own call site). }
unit PHOpt;

interface

uses Types;

{ Optimize: walk this procedure's own operation range in place,
  [startChunk,startSlot] up to and including the current tail
  (endChunk,endSlot) -- both endpoints inclusive, same 1-based slot
  indexing Types.TOpChunk itself already uses. Mutates operations via
  Types.MnNop deletion (or, for a later real pass, retargeting a
  mnemonic/operand in place the same way SPHO.PAS's own
  CheckPendingCalls/PatchCondRef already patch an operation post-hoc);
  never appends/removes a chunk or slot itself. }
procedure Optimize(startChunk: POpChunk; startSlot: integer;
                    endChunk: POpChunk; endSlot: integer);

implementation

uses StrTab, Util;

{ Advance: step (c,k) one slot forward within [.., endChunk/endSlot]
  (inclusive) -- the one shared cursor-stepping rule every walker below
  uses, so chunk-boundary crossing is written exactly once. Returns
  FALSE (and leaves c/k past the end) once stepping past
  (endChunk,endSlot). }
function Advance(var c: POpChunk; var k: integer; endChunk: POpChunk; endSlot: integer): boolean;
begin
  if (c = endChunk) and (k = endSlot) then begin
    Advance := false; exit
  end;
  if k < c^.count then Inc(k)
  else begin c := c^.next; k := 1 end;
  Advance := true
end;

{ NextReal: advance (c,k) to the next operation in range that is NOT a
  deleted (MnNop) TOpInstr -- "nop must not be counted as instruction"
  (this unit's own caller comment): a peephole match looks through any
  already-nop'd operation as if it were never there at all, so a chain
  of several eliminated jumps in a row still lets a later rule see past
  all of them to whatever real operation actually follows. TOpLabel/
  TOpAsm operations are never nop'd (only TOpInstr's own mnemonic field
  carries MnNop), so this only ever needs to skip TOpInstr rows whose
  mnemonic = MnNop. Returns FALSE if the range is exhausted before a
  real operation is found. }
function NextReal(var c: POpChunk; var k: integer; endChunk: POpChunk; endSlot: integer): boolean;
begin
  while Advance(c, k, endChunk, endSlot) do begin
    if (c^.ops[k].kind <> TOpInstr) or (c^.ops[k].mnemonic <> MnNop) then begin
      NextReal := true; exit
    end
  end;
  NextReal := false
end;

{ IsJump: TRUE for MnJmp or any Jcc (conditional jump) mnemonic -- every
  mnemonic that takes a single label-name operand and can transfer
  control there. Used by ConstCond/JumpChain to find candidate jump
  instructions, regardless of which specific condition (if any) they
  test -- ConstCond's own fold applies the same way to whichever Jcc it
  finds (EvalJcc itself does the condition-specific work); JumpChain's
  own jump-to-jump retarget is likewise exactly the same rewrite for
  every one of them (only the intermediate hop's OWN mnemonic, always
  MnJmp, matters for whether it's safe to skip -- see JumpChain's own
  header comment). }
function IsJump(mn: word): boolean;
begin
  IsJump := (mn = MnJmp) or (mn = MnJe) or (mn = MnJne) or (mn = MnJl)
    or (mn = MnJge) or (mn = MnJg) or (mn = MnJle) or (mn = MnJb)
    or (mn = MnJae) or (mn = MnJa) or (mn = MnJbe) or (mn = MnJc)
    or (mn = MnJnc) or (mn = MnJz) or (mn = MnJnz)
end;

{ ParseDecimalLiteral: TRUE (with the value) iff s is a plain unsigned
  decimal integer -- every digit '0'..'9', at least one digit, nothing
  else (no sign, no H/X/B suffix, no leading '0x'). Deliberately narrow
  -- SPHO.PAS's own IsZeroLiteral covers more literal shapes (hex/
  binary suffixes), but this only needs to recognize the exact shape a
  builtin BOOLEAN constant (TRUE/FALSE, SymTab's own RegisterBuiltins:
  TRUE=1, FALSE=0) or a plain WORD/INTEGER numeric literal actually
  resolves to via OperandText -- getting a hex/binary-suffixed operand
  wrong here would just mean ConstCond below doesn't fire for it
  (missed optimization, not a correctness risk), so staying narrow and
  certain beats trying to parse every literal shape SPHO.PAS itself
  understands. }
function ParseDecimalLiteral(const s: string; var val: word): boolean;
  var i: integer; v: longint;
begin
  ParseDecimalLiteral := false;
  if s = '' then exit;
  for i := 1 to Length(s) do
    if not (s[i] in ['0'..'9']) then exit;
  v := 0;
  for i := 1 to Length(s) do begin
    v := v * 10 + (Ord(s[i]) - Ord('0'));
    if v > 65535 then exit   { out of WORD range -- not a value this
                                 codegen could have produced as a plain
                                 literal operand anyway; bail rather
                                 than wrap/guess. }
  end;
  val := v;
  ParseDecimalLiteral := true
end;

{ EvalJcc: TRUE iff the Jcc mnemonic mn, testing the flags a "cmp a, b"
  (unsigned WORD compare -- a bare literal condition has no ".INTEGER"
  cast, so this matches RelJumpsUnsigned's own default) would set for
  a=aVal, b=bVal, would actually branch. Covers exactly the Jcc set
  RelJumps/RelJumpsUnsigned/FlagJumps can produce as a jt/jf target
  (Types.MnJe..MnJnz) -- see EmitRelational/EmitCondJump, SPHO.PAS. }
function EvalJcc(mn: word; aVal, bVal: word): boolean;
begin
  case mn of
    MnJe:  EvalJcc := aVal = bVal;
    MnJne: EvalJcc := aVal <> bVal;
    MnJb:  EvalJcc := aVal < bVal;
    MnJae: EvalJcc := aVal >= bVal;
    MnJa:  EvalJcc := aVal > bVal;
    MnJbe: EvalJcc := aVal <= bVal;
    { MnJl/MnJge/MnJg/MnJle/MnJc/MnJnc/MnJz/MnJnz: signed-compare or
      flag-only Jcc variants -- never actually reached by a plain
      literal-vs-literal WORD "cmp a,b" (RelJumps' own signed forms
      only apply to a ".INTEGER"-cast register operand, and JC/JNC/JZ/
      JNZ test CFLAG/ZFLAG directly via FlagJumps, not a cmp result at
      all) -- ConstCond's own caller already restricts to this shape,
      so these are unreachable in practice; EvalJcc still has to
      return SOMETHING for TP7's case statement to be exhaustive. }
    else EvalJcc := false
  end
end;

{ ConstCond: "cmp litA, litB" (BOTH operands plain decimal literals,
  ParseDecimalLiteral) immediately followed by a Jcc has a statically
  known outcome -- found via "WHILE TRUE DO ... END" (SPHINX's own
  builtin TRUE=1/FALSE=0, SymTab.RegisterBuiltins): ParseCondition's
  own bare-condition path emits "cmp 1, 0" / "je <exitLabel>" fresh on
  EVERY loop iteration, always false (1<>0), so the je can never
  actually fire -- pure per-iteration overhead for a condition that
  was already known to always hold at translate time. Folds the whole
  cmp+Jcc pair: if EvalJcc says the branch is never taken, both the cmp
  and the Jcc are nop'd (dead weight, same as CheapReturn/DeadCode's
  own "emit nothing" outcome); if EvalJcc says the branch is ALWAYS
  taken, the cmp is nop'd and the Jcc itself is rewritten in place to
  an unconditional MnJmp (same target) -- correct either way since a
  literal comparison's own truth value can never change at runtime,
  so "always branch"/"never branch" is exactly as safe to bake in here
  as it would have been to never emit the test at all. Runs BEFORE
  DeadCode (see Optimize below): an "always taken" fold turning a Jcc
  into an unconditional MnJmp can itself create a fresh dead-code span
  right after it, which DeadCode's own later pass in the same Optimize
  call then cleans up -- no separate/second Optimize call needed for
  that follow-on case, same "one pass feeds the next" composition
  CheapReturn/JumpChain already established. }
procedure ConstCond(startChunk: POpChunk; startSlot: integer;
                     endChunk: POpChunk; endSlot: integer);
  var c, nc: POpChunk; k, nk: integer; aTxt, bTxt: string; aVal, bVal: word;
begin
  c := startChunk; k := startSlot;
  repeat
    if (c^.ops[k].kind = TOpInstr) and (c^.ops[k].mnemonic = MnCmp) then begin
      StrTab.Get(c^.ops[k].op1, aTxt);
      StrTab.Get(c^.ops[k].op2, bTxt);
      if ParseDecimalLiteral(aTxt, aVal) and ParseDecimalLiteral(bTxt, bVal) then begin
        nc := c; nk := k;
        if NextReal(nc, nk, endChunk, endSlot) and (nc^.ops[nk].kind = TOpInstr)
           and IsJump(nc^.ops[nk].mnemonic) and (nc^.ops[nk].mnemonic <> MnJmp) then begin
          if EvalJcc(nc^.ops[nk].mnemonic, aVal, bVal) then
            nc^.ops[nk].mnemonic := MnJmp   { always taken -> unconditional }
          else
            nc^.ops[nk].mnemonic := MnNop;  { never taken -> delete }
          c^.ops[k].mnemonic := MnNop        { the cmp itself is always dead
                                                 weight either way -- its only
                                                 purpose was feeding this Jcc's
                                                 own flags test, now folded. }
        end
      end
    end
  until not Advance(c, k, endChunk, endSlot)
end;

{ Fold only the branch. MOV and OR may leave live register/flag values
  consumed after the branch, so neither instruction is dead by this match. }
procedure ConstOrCond(startChunk: POpChunk; startSlot: integer;
                       endChunk: POpChunk; endSlot: integer);
  var c, nc, jc: POpChunk; k, nk, jk: integer; reg, reg2, rhs, litTxt: string; litVal: word;
begin
  c := startChunk; k := startSlot;
  repeat
    if (c^.ops[k].kind = TOpInstr) and (c^.ops[k].mnemonic = MnMov) then begin
      StrTab.Get(c^.ops[k].op1, reg);
      StrTab.Get(c^.ops[k].op2, litTxt);
      if ParseDecimalLiteral(litTxt, litVal) then begin
        nc := c; nk := k;
        if NextReal(nc, nk, endChunk, endSlot) and (nc^.ops[nk].kind = TOpInstr)
           and (nc^.ops[nk].mnemonic = MnOr) then begin
          StrTab.Get(nc^.ops[nk].op1, reg2);
          StrTab.Get(nc^.ops[nk].op2, rhs);
          if (reg = reg2) and (reg = rhs) then begin
            jc := nc; jk := nk;
            if NextReal(jc, jk, endChunk, endSlot) and (jc^.ops[jk].kind = TOpInstr)
               and IsJump(jc^.ops[jk].mnemonic) and (jc^.ops[jk].mnemonic <> MnJmp) then begin
              if EvalJcc(jc^.ops[jk].mnemonic, litVal, 0) then
                jc^.ops[jk].mnemonic := MnJmp
              else
                jc^.ops[jk].mnemonic := MnNop
            end
          end
        end
      end
    end
  until not Advance(c, k, endChunk, endSlot)
end;

{ CheapReturn: "jmp to next instruction" -- a MnJmp whose own target
  label is the very next REAL (non-MnNop) operation, a TOpLabel with
  that same name, is redundant: control already falls through to that
  label the instant the jmp would have landed there anyway. Marks the
  jmp MnNop in place. Every RETURN mid-procedure-body jumps to the
  procedure's own single epilogue label (SPHO.PAS's own ParseReturn);
  RETURN as a procedure's own LAST statement therefore always compiles
  to exactly this pattern ("jmp .return" immediately followed by
  ".return:", confirmed directly in TESTS/CONTROL.ASM's own output) --
  the name this optimization type was requested under. Not limited to
  .return specifically, though: any MnJmp immediately followed by its
  own target label matches (e.g. an IF/ELSE whose own trailing branch
  falls straight into the shared end label with nothing else emitted
  for it), since the match is purely structural (same label text),
  never keyed off a particular label's own origin. }
procedure CheapReturn(startChunk: POpChunk; startSlot: integer;
                       endChunk: POpChunk; endSlot: integer);
  var c, nc: POpChunk; k, nk: integer; jmpTarget, lbl: string;
begin
  c := startChunk; k := startSlot;
  repeat
    if (c^.ops[k].kind = TOpInstr) and (c^.ops[k].mnemonic = MnJmp) then begin
      nc := c; nk := k;
      if NextReal(nc, nk, endChunk, endSlot) and (nc^.ops[nk].kind = TOpLabel) then begin
        StrTab.Get(c^.ops[k].op1, jmpTarget);
        StrTab.Get(nc^.ops[nk].labelId, lbl);
        if jmpTarget = lbl then c^.ops[k].mnemonic := MnNop
      end
    end
  until not Advance(c, k, endChunk, endSlot)
end;

{ FindLabel: locate the TOpLabel operation within [startChunk,startSlot
  .. endChunk,endSlot] whose own labelId text equals name, starting the
  search from (startChunk,startSlot) itself (inclusive) -- used by
  JumpChain below to look up a jump's own target label (a forward OR
  backward reference; unlike NextReal/CheapReturn's own "check the very
  next operation" shape, a jump target can legitimately be anywhere
  else in the procedure). Returns FALSE if no such label exists in
  range (shouldn't happen for any label this translator itself ever
  generated a jump against, but a not-found search must not touch
  c/k -- the caller checks the boolean result, never assumes c/k moved
  on failure). }
function FindLabel(const name: string; startChunk: POpChunk; startSlot: integer;
                    endChunk: POpChunk; endSlot: integer; var c: POpChunk; var k: integer): boolean;
  var lbl: string;
begin
  c := startChunk; k := startSlot;
  repeat
    if c^.ops[k].kind = TOpLabel then begin
      StrTab.Get(c^.ops[k].labelId, lbl);
      if lbl = name then begin FindLabel := true; exit end
    end
  until not Advance(c, k, endChunk, endSlot);
  FindLabel := false
end;

{ JumpChain: "jump to a jump" -- any jump (MnJmp or a Jcc) whose own
  target label is immediately followed (through NextReal, same
  "nop doesn't count" skip CheapReturn uses) by an UNCONDITIONAL MnJmp
  is retargeted straight to that MnJmp's own destination, skipping the
  redundant intermediate hop through the label -- found via
  EXAMPLES/TARPAK/TARPAK.SMD's own real output ("jmp .L20" landing on
  a label immediately followed by "jmp .L9": retargeting the first
  jump straight to .L9 sees the exact same control-flow result, one
  less instruction actually executed at runtime). Only chains through
  an UNCONDITIONAL intermediate jump -- a Jcc there does not always
  fall through, so retargeting past it would change which branch is
  actually taken whenever that Jcc's own condition is false; not
  attempted, out of scope for this rule. Retargets in place (rewrites
  op1, the jump's own target text) rather than deleting anything, so
  this composes naturally with CheapReturn: a jump retargeted here to
  land on its own very-next label becomes exactly CheapReturn's own
  pattern, caught on this same Optimize call since CheapReturn already
  ran first (see Optimize below) -- no second Optimize pass needed for
  that follow-on case. Does NOT chase a multi-hop chain (a jump landing
  on a label that's itself followed by another such jump-to-jump,
  several deep) -- one hop per Optimize call is enough for every real
  case found so far (EXAMPLES/TARPAK's own instances are single-hop),
  and re-running Optimize would still be idempotent/safe if a deeper
  chain ever did appear (the next call's own single-hop pass would
  collapse one more level). }
procedure JumpChain(startChunk: POpChunk; startSlot: integer;
                     endChunk: POpChunk; endSlot: integer);
  var c, lc, nc: POpChunk; k, lk, nk: integer; target, finalTarget: string;
begin
  c := startChunk; k := startSlot;
  repeat
    if (c^.ops[k].kind = TOpInstr) and (c^.ops[k].mnemonic <> MnNop)
       and IsJump(c^.ops[k].mnemonic) then begin
      StrTab.Get(c^.ops[k].op1, target);
      if FindLabel(target, startChunk, startSlot, endChunk, endSlot, lc, lk) then begin
        nc := lc; nk := lk;
        if NextReal(nc, nk, endChunk, endSlot) and (nc^.ops[nk].kind = TOpInstr)
           and (nc^.ops[nk].mnemonic = MnJmp) then begin
          StrTab.Get(nc^.ops[nk].op1, finalTarget);
          c^.ops[k].op1 := StrTab.Put(finalTarget)
        end
      end
    end
  until not Advance(c, k, endChunk, endSlot)
end;

{ IsUncondTransfer: TRUE for a mnemonic that unconditionally leaves the
  instruction stream right where it is -- MnJmp (unconditional jump),
  MnRetn/MnRetf (procedure return), MnIret (interrupt return). NOT a
  Jcc (a conditional jump can fall through) -- code right after a Jcc
  is genuinely reachable whenever that condition is false, so it's
  never dead just because a Jcc precedes it. }
function IsUncondTransfer(mn: word): boolean;
begin
  IsUncondTransfer := (mn = MnJmp) or (mn = MnRetn) or (mn = MnRetf) or (mn = MnIret)
end;

{ DeadCode: any operation between an unconditional control transfer
  (IsUncondTransfer -- jmp/retn/retf/iret) and the next LABEL is
  unreachable: nothing can fall through the transfer to reach it, and
  it has no label of its own for anything else to jump to -- found via
  TESTS/CONTROL.SMD's own "IF x<5 THEN RETURN 1 ELSE RETURN 2 END"
  (ParseIf's own trailing "jmp endLbl" after the THEN branch's own
  body, even though that body's own RETURN already left unconditionally
  -- the ParseIf-emitted jmp is real, working code, just never actually
  reached). Stops at the FIRST label found (never nops a TOpLabel
  itself, and never looks past one) -- something else may legitimately
  jump directly into that label from outside this dead span, so
  whatever follows it is a separate question this rule leaves alone.
  Both TOpInstr and TOpAsm operations in a dead span are eliminated the
  same way: overwritten to kind=TOpInstr/mnemonic=MnNop in place (a
  TOpAsm has no mnemonic field of its own to flag dead via -- this is
  the one shared "emits nothing" representation SerializeOne already
  understands). Safe for TOpAsm/inline ASM...END blocks specifically
  because this codebase's own convention never hand-writes a label
  inside one (confirmed: ParseAsm's own raw-line text is always a bare
  instruction, e.g. "rep movsb"/"cld" -- nothing outside SPHO's own
  TOpLabel tracking could ever legitimately jump into the middle of
  one). Runs AFTER CheapReturn/JumpChain (see Optimize below): letting
  those two run first means a jmp CheapReturn nops becomes MnNop before
  DeadCode ever looks at IsUncondTransfer on it (a nop'd jmp is not
  itself an unconditional-transfer boundary -- correctly so, since
  nothing was actually left in place there once serialized), and a jmp
  JumpChain retargets is still exactly as much an unconditional
  transfer as before, just landing somewhere else -- either way,
  DeadCode's own final pass sees the same fully-settled operation
  stream SerializeOne itself will later walk. }
procedure DeadCode(startChunk: POpChunk; startSlot: integer;
                    endChunk: POpChunk; endSlot: integer);
  var c: POpChunk; k: integer; inDead: boolean;
begin
  c := startChunk; k := startSlot; inDead := false;
  repeat
    if c^.ops[k].kind = TOpLabel then
      inDead := false
    else if inDead then begin
      c^.ops[k].kind := TOpInstr;
      c^.ops[k].mnemonic := MnNop
    end else if (c^.ops[k].kind = TOpInstr) and IsUncondTransfer(c^.ops[k].mnemonic) then
      inDead := true
  until not Advance(c, k, endChunk, endSlot)
end;

{ Each rule can create a fresh opportunity for another (ConstCond
  turning a Jcc into a MnJmp gives CheapReturn/JumpChain a new
  candidate; DeadCode removing a loop's own now-unreachable body can
  bring a MnJmp and its own target label newly adjacent, which is
  CheapReturn's own pattern but only becomes TRUE after DeadCode has
  already run -- found via "WHILE FALSE DO i := i + 100 END": the
  loop's own body/back-jump only stop separating "jmp .L2" from ".L2:"
  once DeadCode has swept them away, one call too late for that same
  call's own earlier CheapReturn pass to have seen it). Two passes
  (OptimizePass run twice) resolves every such one-call-late case found
  so far without needing a general until-no-change fixed-point loop --
  a third pass over any of the cases in TESTS/ or EXAMPLES/ never finds
  anything the second pass didn't already catch. Each individual rule
  is still idempotent/order-tolerant on its own (a second run over
  content it already settled just finds nothing new to do), so running
  the same sequence twice is always safe, never a correctness risk --
  only ever a question of how much is caught in one Optimize call. }
{ StoreReload: "mov [mem], reg" immediately followed by "mov reg, [mem]"
  -- the SAME mem operand, the SAME register, nothing between them --
  is a redundant reload: reg already holds exactly that value (it's
  what was JUST stored to mem the instruction before; nothing else can
  have touched mem in between, since there IS no "in between"). Deletes
  the reload (MnNop) in place, leaving the store untouched -- found via
  real generated output (TESTS/ARITH.SMD's own "a := a + N;" chain,
  EXAMPLES/TARPAK's own field-store-then-reread idiom): a VAR
  assignment followed by immediately using that same VAR's own new
  value re-reads it from memory instead of keeping it in the register
  that was just used to write it. Deliberately narrow: op1/op2 text
  must match EXACTLY (case-insensitively -- register/operand text
  casing isn't consistent across every call site, Util.EqualICase) on
  BOTH sides (mem operand AND register) -- no attempt to reason about
  aliasing (e.g. two textually-different memory operands that happen to
  address the same byte, such as a RECORD field accessed two different
  ways) or partial overlap (a byte-sized reload of a word-sized store,
  etc); those stay untouched, correctly conservative rather than
  guessing. Never matches a SEGMENT-register store/reload (push/pop is
  the only way to move a segreg on 8086, never a plain mov -- see
  EmitExprFromEx's own header comment -- so "mov [mem], DS" doesn't
  arise in this codegen at all; not specifically excluded here, just
  never actually produced as this shape's own left-hand side). }
procedure StoreReload(startChunk: POpChunk; startSlot: integer;
                       endChunk: POpChunk; endSlot: integer);
  var c, nc: POpChunk; k, nk: integer; storeMem, storeReg, reloadReg, reloadMem: string;
begin
  c := startChunk; k := startSlot;
  repeat
    if (c^.ops[k].kind = TOpInstr) and (c^.ops[k].mnemonic = MnMov) then begin
      StrTab.Get(c^.ops[k].op1, storeMem);
      StrTab.Get(c^.ops[k].op2, storeReg);
      if (storeMem <> '') and (storeMem[1] = '[') then begin
        nc := c; nk := k;
        if NextReal(nc, nk, endChunk, endSlot) and (nc^.ops[nk].kind = TOpInstr)
           and (nc^.ops[nk].mnemonic = MnMov) then begin
          StrTab.Get(nc^.ops[nk].op1, reloadReg);
          StrTab.Get(nc^.ops[nk].op2, reloadMem);
          if Util.EqualICase(reloadReg, storeReg) and Util.EqualICase(reloadMem, storeMem) then
            nc^.ops[nk].mnemonic := MnNop
        end
      end
    end
  until not Advance(c, k, endChunk, endSlot)
end;

{ IsFlagReader: TRUE for a mnemonic that consumes flags left AMBIENT by
  an earlier instruction, rather than computing its own fresh flags
  from its own operands -- only a bare Jcc (IsJump) qualifies. MnOr/
  MnCmp/MnTest do NOT belong here even though they're commonly followed
  by a Jcc in codegen: all three compute and overwrite CF/ZF/SF/OF/PF
  from their OWN two operands, exactly like ADD/SUB/AND/etc -- they
  never read a PRECEDING instruction's flags, only ever set their own
  (IsFlagSetter below already covers this; DOCS/TRBUG.MD's own
  NoOpArith writeup, confirmed via TESTS/NOOPAR.SMD's own
  AddZeroBeforeJump: "add ax, 0" immediately followed (through a label)
  by "cmp ax, 5" is safe to fold THROUGH the cmp, since the cmp's own
  fresh comparison is what the following Jcc actually reads, not the
  add's). A bare Jcc with no CMP/TEST/OR immediately before it (SPHINX's
  own CFLAG/ZFLAG syntax, FlagJumps -- confirmed via TESTS/RVFLAGS.SMD)
  is the one real case that DOES read ambient flags left by whatever
  instruction actually precedes it, which is exactly what NoOpArithSafe
  below must not fold an add/sub's own flags out from under. }
function IsFlagReader(kind: byte; mn: word): boolean;
begin
  IsFlagReader := (kind = TOpInstr) and IsJump(mn)
end;

{ IsFlagSetter: TRUE for a mnemonic that overwrites CF/ZF/SF/OF/PF with
  a fresh result of its own -- every arithmetic/logic mnemonic this
  codegen emits (ADD/SUB/CMP/TEST/XOR/OR/AND/SHL/SHR/NEG/INC/DEC/MUL/
  IMUL/DIV/IDIV). Used by NoOpArithSafe's own forward scan to know when
  it can stop looking: once a flag-setter is reached, the original add/
  sub's own flags are already gone regardless of whether this rule
  deletes it, so anything past this point is safe no matter what. }
function IsFlagSetter(kind: byte; mn: word): boolean;
begin
  IsFlagSetter := (kind = TOpInstr)
    and ((mn = MnAdd) or (mn = MnSub) or (mn = MnCmp) or (mn = MnTest)
      or (mn = MnXor) or (mn = MnOr) or (mn = MnAnd) or (mn = MnShl)
      or (mn = MnShr) or (mn = MnNeg) or (mn = MnInc) or (mn = MnDec)
      or (mn = MnMul) or (mn = MnImul) or (mn = MnDiv) or (mn = MnIdiv))
end;

{ IsFlagPreserving: TRUE for a mnemonic safe for NoOpArithSafe's own
  scan to skip straight past without stopping -- either because it
  PROVABLY does not touch CF/ZF/SF/OF/PF at all on 8086 (MOV/PUSH/POP/
  LEA/LES/LDS/CALL/CALLFAR/CWD), or because it unconditionally leaves
  the instruction stream right where it is (MnJmp/MnRetn/MnRetf/
  MnIret, same IsUncondTransfer set DeadCode already uses -- whatever
  flags exist after one of these is never reached by falling through
  from here, so the op-list slot immediately following it is either
  genuinely unreachable this way, or a jump target from somewhere else
  entirely; either way, scanning one step further and re-evaluating
  THAT slot on its own merits is still correct, just possibly more
  conservative than strictly necessary -- never unsound). Deliberately
  a narrow whitelist, not "everything NoOpArithSafe doesn't otherwise
  recognize": MnPopf genuinely overwrites flags (restoring them from
  the stack -- the entire point of the instruction), and MnInt crosses
  into interrupt-handler code this translator has no visibility into,
  so both must fall through to NoOpArithSafe's own conservative
  default (treat as unsafe, stop the scan) rather than being silently
  skipped past. }
function IsFlagPreserving(kind: byte; mn: word): boolean;
begin
  IsFlagPreserving := (kind = TOpInstr)
    and ((mn = MnMov) or (mn = MnPush) or (mn = MnPop) or (mn = MnLea)
      or (mn = MnLes) or (mn = MnLds) or (mn = MnCall) or (mn = MnCallFar)
      or (mn = MnCwd) or (mn = MnJmp) or (mn = MnRetn) or (mn = MnRetf)
      or (mn = MnIret))
end;

{ NoOpArithSafe: TRUE iff scanning forward from (right after) an add/
  sub's own slot never reaches a flag-reader (IsFlagReader) before
  either a flag-setter (IsFlagSetter -- flags already fresh again from
  there, so the original add/sub's own contribution is moot regardless)
  or the end of range. Only a narrow whitelist of mnemonics PROVABLY
  flag-preserving (IsFlagPreserving) is skipped over rather than
  stopping the scan -- anything not on that whitelist (a Jcc/OR/CMP/
  TEST via IsFlagReader, a flag-setter via IsFlagSetter, or anything
  else entirely -- MnPopf/MnInt/MnIret/MnPushf/MnRetn/MnRetf included,
  none of them provably flag-neutral) conservatively stops the scan as
  unsafe by default, matching every other rule's own "no data-flow
  analysis, stay conservative" bias -- TOpAsm (raw inline ASM...END
  text) is included in that conservative default: its own content is
  opaque to this pass, so it stops the scan rather than being assumed
  flag-neutral. A TOpLabel is the one exception that does NOT stop the
  scan (something could legitimately fall through it from right where
  this scan already is -- SPHO.PAS's own codegen never jumps INTO the
  middle of a flag-dependent sequence from elsewhere, same assumption
  DeadCode's own header comment already relies on for TOpAsm blocks'
  OWN internal safety, a separate question from this scan's), so the
  scan continues straight through a label to whatever real operation
  actually follows. This is what NextReal's own single-hop "next real operation"
  check got wrong (DOCS/TRBUG.MD's own regression, confirmed via
  TESTS/RVFLAGS.SMD: "AX := AX + 0" followed by "BX := 5" (a MOV,
  flag-preserving but NOT the flag consumer) followed by "IF ZFLAG" (a
  bare JZ/JNZ, no CMP needed, FlagJumps) -- the old single-hop check
  saw the intervening MOV as "not a flag reader" and deleted the add,
  leaving the JZ/JNZ silently test flags left over from the wrong
  earlier instruction instead). }
function NoOpArithSafe(c: POpChunk; k: integer; endChunk: POpChunk; endSlot: integer): boolean;
begin
  while Advance(c, k, endChunk, endSlot) do begin
    if (c^.ops[k].kind = TOpInstr) and (c^.ops[k].mnemonic = MnNop) then
      { deleted -- transparent, keep scanning }
    else if c^.ops[k].kind = TOpAsm then begin
      { raw inline ASM...END text -- opaque, could do anything to
        flags; conservatively stop rather than assume it's safe to
        skip past. }
      NoOpArithSafe := false; exit
    end else if IsFlagReader(c^.ops[k].kind, c^.ops[k].mnemonic) then begin
      NoOpArithSafe := false; exit
    end else if IsFlagSetter(c^.ops[k].kind, c^.ops[k].mnemonic) then begin
      NoOpArithSafe := true; exit
    end else if (c^.ops[k].kind = TOpInstr)
                and not IsFlagPreserving(c^.ops[k].kind, c^.ops[k].mnemonic) then begin
      NoOpArithSafe := false; exit   { conservative default: anything not
        provably safe to skip past stops the scan as unsafe. }
    end
    { else: TOpLabel, or a whitelisted flag-preserving TOpInstr -- keep
      scanning. }
  end;
  NoOpArithSafe := true   { end of range reached with no flag-reader found }
end;

{ NoOpArith: "add reg, N"/"sub reg, N" where N is the literal "0" never
  changes reg's own value -- pure no-op arithmetic, deletable purely on
  machine-state grounds regardless of why the source happened to
  compute a +0/-0 (DOCS/TRBUG.MD's own writeup: found via a test
  fixture's own byte-widening codegen path, deliberately written as
  "r + 0" to trigger it). Guarded against the one real risk ADD/SUB
  carries that a plain MOV doesn't: both also write flags, so this only
  fires when NoOpArithSafe's own forward scan confirms nothing
  downstream actually reads THIS add/sub's own flags before they'd be
  overwritten anyway. }
procedure NoOpArith(startChunk: POpChunk; startSlot: integer;
                     endChunk: POpChunk; endSlot: integer);
  var c: POpChunk; k: integer; opnd2: string;
begin
  c := startChunk; k := startSlot;
  repeat
    if (c^.ops[k].kind = TOpInstr)
       and ((c^.ops[k].mnemonic = MnAdd) or (c^.ops[k].mnemonic = MnSub)) then begin
      StrTab.Get(c^.ops[k].op2, opnd2);
      if (opnd2 = '0') and NoOpArithSafe(c, k, endChunk, endSlot) then
        c^.ops[k].mnemonic := MnNop
    end
  until not Advance(c, k, endChunk, endSlot)
end;

procedure OptimizePass(startChunk: POpChunk; startSlot: integer;
                        endChunk: POpChunk; endSlot: integer);
begin
  ConstCond(startChunk, startSlot, endChunk, endSlot);
  ConstOrCond(startChunk, startSlot, endChunk, endSlot);
  CheapReturn(startChunk, startSlot, endChunk, endSlot);
  JumpChain(startChunk, startSlot, endChunk, endSlot);
  DeadCode(startChunk, startSlot, endChunk, endSlot);
  StoreReload(startChunk, startSlot, endChunk, endSlot);
  NoOpArith(startChunk, startSlot, endChunk, endSlot)
end;

procedure Optimize(startChunk: POpChunk; startSlot: integer;
                    endChunk: POpChunk; endSlot: integer);
begin
  OptimizePass(startChunk, startSlot, endChunk, endSlot);
  OptimizePass(startChunk, startSlot, endChunk, endSlot)
end;

end.
