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

{ Stage B (OPT.TXT S5) shared operand/effect types and constants, exported
  so a standalone test driver (TESTS/) can exercise DecodeOperand/
  GetEffects/LocalDeadAfter directly -- see those functions' own headers,
  in the implementation section below, for what each does. }
const
  { Register-bit-mask layout (RegMask, below): one bit per byte-sized
    register SLICE -- AX's own two halves (AL/AH) get separate bits so
    "AL := ..." can be told apart from "AH := ..." (OPT.TXT S3: "AX
    overlaps AL and AH; likewise BX/CX/DX" -- a partial write to AL
    must never be treated as also writing AH, or a later read of AH
    would be wrongly proven dead). SI/DI/BP/SP have no byte halves on
    8086 at all, so each gets exactly one bit representing its own
    whole 16-bit self, set whenever either a word write to it OR
    (meaninglessly, since no such text exists) a byte alias would --
    in practice only the "whole register" bit for those four is ever
    set. A WORD-register operand (AX) sets BOTH RegBitAL and RegBitAH;
    a byte-register operand (AL) sets ONLY RegBitAL. }
  RegBitAL = 1; RegBitAH = 2; RegBitBL = 4; RegBitBH = 8;
  RegBitCL = 16; RegBitCH = 32; RegBitDL = 64; RegBitDH = 128;
  RegBitSI = 256; RegBitDI = 512; RegBitBP = 1024; RegBitSP = 2048;
  RegMaskAX = RegBitAL or RegBitAH;
  RegMaskBX = RegBitBL or RegBitBH;
  RegMaskCX = RegBitCL or RegBitCH;
  RegMaskDX = RegBitDL or RegBitDH;
  RegMaskNone = 0;

  { Flag-bit-mask layout (FlagMask, below): one bit per real 8086
    status flag CMP/TEST/arithmetic actually sets or a Jcc actually
    reads (OPT.TXT S3's own explicit list: "Track individual flags,
    including CF/PF/AF/ZF/SF/OF"). Control flags (DF/IF) are tracked
    separately as a distinct pair of bits in the SAME mask, since
    SetDFlag/SetIFlag (PLAN.TXT S2.5) are real, explicit instructions
    GetEffects must also account for -- OPT.TXT S3's own "and control
    flags used by classified instructions" covers exactly this. }
  FlagCF = 1; FlagPF = 2; FlagAF = 4; FlagZF = 8; FlagSF = 16; FlagOF = 32;
  FlagDF = 64; FlagIF = 128;
  FlagMaskArith = FlagCF or FlagPF or FlagAF or FlagZF or FlagSF or FlagOF;
  FlagMaskNone = 0;

  { TOperandKind: DecodeOperand's own classification result. }
  OpKindUnknown = 0; OpKindReg = 1; OpKindImm = 2; OpKindMem = 3;

  { TMemEffect: GetEffects' own memory-effect classification -- how
    (if at all) an operation touches memory BEYOND the register/flag
    state DecodeOperand+GetEffects already track. MemUnknown is the
    conservative default for anything not explicitly classified below
    (OPT.TXT S3: "Unknown instruction or operand effects reject a
    candidate"). }
  MemNone = 0; MemRead = 1; MemWrite = 2; MemReadWrite = 3; MemUnknown = 4;

  { TTransferKind: GetEffects' own control-transfer classification --
    distinct from IsJump/IsUncondTransfer above (those answer "can
    DeadCode/JumpChain treat this as a jump", a narrower question);
    this is the general "does this operation leave the instruction
    stream, and how" fact Stage C's own dominance/liveness reasoning
    will need. }
  XferNone = 0; XferJump = 1; XferCondJump = 2; XferCall = 3; XferReturn = 4;

  { MaxFrameProof: a conservative cap on the '[bp+N]'/'[bp-N]' offset
    magnitude DecodeOperand will still classify as a "frame object" --
    matches this translator's own existing local-frame size ceiling in
    spirit (no single real procedure's own locals come anywhere close
    to this), just a defensive bound so a malformed/unexpected operand
    text with a huge embedded number can't be mistaken for a plausible
    frame offset. }
  MaxFrameProof = 32767;

type
  { TOperand: DecodeOperand's own result -- one already-classified
    operand, built from its RAW TEXT (never from mnemonic context:
    the same text classifies the same way whether it's an operation's
    op1 or op2, source or destination -- GetEffects, below, is what
    turns "this operand is a register" into "this operation READS or
    WRITES that register", since that direction depends on the
    mnemonic and operand POSITION, not the operand's own text alone). }
  TOperand = record
    kind: integer;          { OpKind* }
    regMask: word;          { RegBit*/RegMask* union -- meaningful only
                                when kind = OpKindReg. }
    isByte: boolean;        { meaningful only when kind = OpKindReg. }
    isWord: boolean;        { meaningful only when kind = OpKindReg. }
    segReg: integer;        { Regs86.Reg* id of an explicit 'SEG:'
                                override on a memory operand (e.g.
                                '[SS:BP-2]' -> RegSS), or 0 if none was
                                written -- OPT.TXT S5: "Return ...
                                segment." Meaningful only when kind =
                                OpKindMem. A memory operand with NO
                                explicit segment (a bare '[BX]') is NOT
                                assumed DS here -- that inference
                                belongs to whatever consumes this
                                record, not to DecodeOperand itself,
                                since the real default varies (DS
                                normally, SS for a BP-based address with
                                no override -- SPHO.PAS's own
                                EmitIndexedOperand/ParseMemOperand
                                convention, PLAN.TXT S1.8/S2.1) and
                                baking one guess in here would silently
                                misclassify the other case. }
    addrRegMask: word;      { RegBit*/RegMask* union of every register
                                READ to compute a memory operand's own
                                effective address (e.g. '[BX+SI+4]'
                                reads both BX and SI) -- OPT.TXT S5's
                                own "address-register reads"; 0 when
                                kind <> OpKindMem or the memory operand
                                has no register component at all (a
                                bare absolute address). }
    isFrameObject: boolean; { TRUE iff this is a PROVEN '[bp+N]'/
                                '[bp-N]' local-frame reference (no
                                other register, no index, no explicit
                                segment override -- OPT.TXT S5's own
                                "any proven frame-object ID/offset/
                                size", the narrowest, most defensible
                                shape worth proving from TEXT alone;
                                '[bp+si-2]' or '[ss:bp-2]' do NOT
                                qualify, even though both are also
                                genuinely frame-relative, since proving
                                THOSE safe needs more than a text
                                pattern match -- a real frame-object
                                identity from Stage B's own emitter
                                metadata, not yet added). }
    frameOffset: longint;   { meaningful only when isFrameObject. }
    rawText: string;        { the original operand text, unchanged --
                                DecodeOperand "normalizes only understood
                                syntax; preserves unparsed expressions"
                                (OPT.TXT S5): a caller that needs the
                                literal text back (to re-emit or compare)
                                always has it, regardless of how much
                                or little of it this function actually
                                understood. }
  end;

  { TEffects: GetEffects' own result -- one operation's complete,
    conservative effect summary. }
  TEffects = record
    known: boolean;         { FALSE for anything GetEffects could not
                                fully classify (an unrecognized
                                mnemonic, TOpAsm, or an operand
                                DecodeOperand left as OpKindUnknown) --
                                OPT.TXT S5's own "and knowness"; every
                                OTHER field is meaningless/conservative-
                                default when known = FALSE, and a
                                caller MUST treat known=FALSE as a
                                barrier (OPT.TXT S3: "Unknown
                                instruction or operand effects reject a
                                candidate"), never inspect the other
                                fields to try to salvage a partial
                                answer. }
    regRead, regWrite: word;      { RegBit*/RegMask* union, INCLUDING
                                      implicit operands (OPT.TXT S5:
                                      "Include implicit operands, such
                                      as AX/DX for arithmetic and CX/
                                      index/segment registers for
                                      string operations"). A register
                                      that is both read AND written
                                      (e.g. "ADD AX,BX" reads+writes
                                      AX) has its bit set in BOTH
                                      masks -- a caller proving
                                      "dead" must still see the read. }
    flagRead, flagWrite: word;    { FlagCF/etc union -- flagWrite is
                                      only ever a DEFINITE write (OPT.TXT
                                      S5: "flag reads/definite writes"
                                      -- an instruction whose OWN flags
                                      are documented-undefined for some
                                      case, e.g. shift-by-a-variable-
                                      count > 1 on some 8086-family
                                      steppings, never sets its own bit
                                      in flagWrite at all here, matching
                                      OPT.TXT S3's own "Undefined output
                                      flags are not known constants"). }
    memEffect: integer;           { MemNone/MemRead/MemWrite/
                                      MemReadWrite/MemUnknown. }
    stackDelta: longint;          { net SP change in BYTES this ONE
                                      operation causes on every path
                                      (PUSH=+2 in the "SP moves toward
                                      lower addresses" sense is written
                                      here as -2, POP as +2, matching
                                      ordinary stack-pointer arithmetic
                                      -- ADD/SUB sp,N reads its own
                                      immediate literal directly).
                                      0 for anything that doesn't touch
                                      SP at all. }
    transferKind: integer;        { Xfer* above. }
  end;

{ DecodeOperand/GetEffects/LocalDeadAfter: see their own header
  comments in the implementation section below for what each does --
  exported here only as bare signatures (TP7 requires a unit's own
  exported procedures/functions be declared in the interface section;
  the body stays in implementation, same split every other exported
  routine in this file already uses for Optimize itself, below). }
procedure DecodeOperand(const text: string; var o: TOperand);
procedure GetEffects(const op: TOperation; var e: TEffects);
function LocalDeadAfter(c: POpChunk; k: integer; endChunk: POpChunk; endSlot: integer;
                         regMask, flagMask: word): boolean;

{ LocalDeadAfterEx: same proof as LocalDeadAfter, but additionally
  reports (via the var reachedRangeEnd output) WHY it returned FALSE --
  a real, previously-latent bug found while building OPT.TXT's own R8
  finding: RemoveRedundantZeroExtend's (R7) and RemoveDeadZeroMov's
  (R8) own two-tier "LocalDeadAfter first, fall back to CFG-wide
  block-exit liveness on failure" composition treated EVERY
  LocalDeadAfter=FALSE outcome as "inconclusive -- ask the CFG," but
  that conflates two genuinely different outcomes: reaching the
  range/block end with nothing yet proven (truly inconclusive -- the
  CFG's own block-exit liveOut IS the right question to ask), versus
  finding a REAL, definitive read or unresolved barrier strictly
  BEFORE the range end (an outright proof of "still live," which the
  CFG's own block-exit liveOut cannot safely override: liveOut only
  ever describes what's live AFTER the block finishes, and has no way
  to know about a read that already happened earlier in the very same
  block). Falling back to the CFG in the second case can wrongly
  declare something dead that a real, in-block instruction just
  proved live, if nothing AFTER the block happens to read it either.
  reachedRangeEnd=TRUE only for the "walked off the end of
  [c,k..endChunk,endSlot] with nothing left unproven" case -- the ONLY
  case where asking the CFG for more information is sound; FALSE (with
  the function result also FALSE) means a definitive live-proof was
  found partway through, and no CFG fallback may override it. }
function LocalDeadAfterEx(c: POpChunk; k: integer; endChunk: POpChunk; endSlot: integer;
                           regMask, flagMask: word; var reachedRangeEnd: boolean): boolean;

{ Stage C (OPT.TXT S6) C4 matchers -- exported the same "bare signature
  only" way as the Stage B trio above, so TESTS/STGC.PAS can call each
  one directly against a hand-built operation list; see each one's own
  header comment in the implementation section below for what it
  does. }
procedure RemoveMovRR(startChunk: POpChunk; startSlot: integer;
                       endChunk: POpChunk; endSlot: integer);
procedure RemoveMovSwapBack(startChunk: POpChunk; startSlot: integer;
                             endChunk: POpChunk; endSlot: integer);
procedure RemoveDeadConstMov(startChunk: POpChunk; startSlot: integer;
                              endChunk: POpChunk; endSlot: integer);
procedure RemoveDeadBranch(startChunk: POpChunk; startSlot: integer;
                            endChunk: POpChunk; endSlot: integer);
procedure ThreadJumpChain(startChunk: POpChunk; startSlot: integer;
                           endChunk: POpChunk; endSlot: integer);
procedure RemoveRepeatedFlagOp(startChunk: POpChunk; startSlot: integer;
                                endChunk: POpChunk; endSlot: integer);
procedure RemoveIdentityLogicOp(startChunk: POpChunk; startSlot: integer;
                                 endChunk: POpChunk; endSlot: integer);

{ FoldSavedOperand: OPT.TXT S6's own C1 -- see its own header comment
  in the implementation section below. Exported the same "bare
  signature only" way as the C4 matchers above. }
procedure FoldSavedOperand(startChunk: POpChunk; startSlot: integer;
                            endChunk: POpChunk; endSlot: integer);

{ FoldSavedOperandSelfDest: OPT.TXT's own R5 finding, a C1 sibling for
  the "ADD/SUB destination is AX itself" shape C1 cannot match -- see
  its own header comment in the implementation section below. Exported
  the same "bare signature only" way as the rest of Stage C above. }
procedure FoldSavedOperandSelfDest(startChunk: POpChunk; startSlot: integer;
                                    endChunk: POpChunk; endSlot: integer);

{ CollapseByteConstScaffolding: OPT.TXT S6's own C2 -- see its own
  header comment in the implementation section below. Exported the
  same "bare signature only" way as the rest of Stage C above. }
procedure CollapseByteConstScaffolding(startChunk: POpChunk; startSlot: integer;
                                        endChunk: POpChunk; endSlot: integer);

{ RemoveUnnecessarySaveRestore: OPT.TXT S6's own C3 -- see its own
  header comment in the implementation section below. Exported the
  same "bare signature only" way as the rest of Stage C above. }
procedure RemoveUnnecessarySaveRestore(startChunk: POpChunk; startSlot: integer;
                                        endChunk: POpChunk; endSlot: integer);

{ Stage D (OPT.TXT S7) shared control-flow/liveness/value-fact types
  and constants, exported so TESTS/STGD.PAS can call BuildCfg/
  ComputeLiveness/PropagateValues directly and inspect their own
  results -- see each type/function's own full header comment in the
  implementation section below for what it does. }
const
  MaxBlocks = 512;
  MaxCfgOps = 8192;
  SuccNone = -1;
  SuccUnknown = -2;
  AllRegMask = $FFFF;
  AllFlagMask = $FFFF;
  { MaxMemFacts: OPT.TXT's own R7 finding -- "bounded object+offset+
    width memory identities/versions," "Start with nonescaping frame
    objects." A small, fixed number of simultaneously-tracked frame-
    object memory facts per block -- real SPHINX procedures rarely
    hold more than a handful of genuinely forwardable local slots live
    at once at any single program point, and a bound here (rather than
    an unbounded per-block list) is what keeps TValueFacts a fixed-size
    heap block instead of another chunked/dynamic structure; exceeding
    it at runtime is never a correctness risk, only a missed
    opportunity (the slot that would have been recorded Nth simply
    never gets a fact at all, exactly like "reject on capacity limit"
    everywhere else in this unit). }
  MaxMemFacts = 4;
  { MaxProcs: OPT.TXT's own R6 finding -- the per-procedure demand table
    (below), plus SPHO.PAS's own parallel optRanges/optConservative
    arrays this analysis is fed through, are all sized to this bound.
    SymTab.PAS's own real theoretical hard cap on how many PROCEDUREs
    one module can ever declare is 4096 (MaxDetailChunks=64 * Chunk=64,
    SRC/SYMTAB.PAS) -- but sizing every one of these arrays to THAT
    bound overflows TP7's own 64KB data segment outright ("Error 49:
    Data segment too large", hit directly while building this pass:
    TProcRange/TProcDemand/a plain boolean array at 4096 entries each
    sum to roughly 86KB before counting anything else this translator's
    own global state already needs). 512 is chosen instead as a REAL,
    measured bound: EXAMPLES/TETRIS/TETRIS.SMD, this translator's own
    largest real example, declares 47 PROCEDUREs -- 512 is generous by
    roughly an order of magnitude over that, the same "measured against
    a real example, not the theoretical structural cap" justification
    MaxOptimizePasses (below) already uses. A module genuinely
    declaring more than 512 PROCEDUREs (SymTab's own cap allows it)
    still translates correctly -- OptimizeAllDeferred's own array-
    filling loops (SRC/SPHO.PAS) simply stop recording past this bound,
    so the analysis silently narrows to fewer procedures than exist
    rather than overflowing; any procedure whose own procId lands
    outside 0..MaxProcs-1 is treated exactly like "never analyzed" by
    DemandFor's own bounds check, its own conservative default. }
  MaxProcs = 512;

type
  TBlock = record
    startChunk, endChunk: POpChunk;
    startSlot, endSlot: integer;
    labelId: StrTab.TStrTabId;
    succ1, succ2: integer;
    isRetnExit: boolean;   { OPT.TXT's own R6 finding -- TRUE iff this
                              block's own succ1=SuccUnknown comes from a
                              genuine RETN/RETF/IRET (BuildCfg's own
                              IsUncondTransfer branch, reached only
                              after MnJmp and Jcc have already been
                              peeled off as their own separate cases),
                              as opposed to a genuinely UNRESOLVED jump
                              target -- both collapse to the same
                              succ1=SuccUnknown marker, but only a real
                              return can ever be narrowed by
                              ComputeLivenessForProc's own per-procedure
                              demand query (DemandFor); an unresolved
                              jump target stays fully conservative no
                              matter what, since this analysis has no
                              way to know where it actually goes. FALSE
                              (the default) for every other block. }
  end;

  { PCfg/PLiveness/PValueFacts: OPT.TXT's own R7 finding surfaced a
    real capacity problem R4's own resolution text had already flagged
    and left unaddressed ("Use heap/chunked TP7 storage, not additional
    large automatic arrays") -- TCfg (~9.7KB at MaxBlocks=512) and
    TLiveness (~4KB) were already BOTH live as stack locals together in
    ByteCompareNoWiden (E4)'s own call frame; R7's own new memory-
    identity fields on TValueFacts (below) push a THIRD ~16KB+
    structure into the same picture for StoreForwarding's own upcoming
    rewrite, which would need TCfg+TValueFacts together (~34KB) against
    this project's own 32000-byte compiled-in stack size (SRC/SPHO.PAS's
    own M-directive) -- a real overflow, not a theoretical one. Every
    one of these three record
    types is now heap-allocated (New/Dispose) instead of a stack local;
    every Build*/Compute*/Propagate* procedure that used to take a
    `var cfg: TCfg` (etc.) out-parameter now takes/returns the POINTER
    type instead, and every caller (every Stage D/E rule, TESTS/
    STGD.PAS's own driver) is responsible for its own Dispose once
    done -- the same "caller owns cleanup" convention Types.POpChunk
    itself already uses throughout this whole codebase, not a new
    pattern. }
  PCfg = ^TCfg;
  PLiveness = ^TLiveness;
  PValueFacts = ^TValueFacts;

  TCfg = record
    blocks: array[0..MaxBlocks-1] of TBlock;
    nBlocks: integer;
    ok: boolean;
  end;

  { TDomBitset: a set of block indices (0..MaxBlocks-1), one bit per
    block, packed 16 to a word -- OPT.TXT's own R12 finding needs
    dominance to build natural loops on. MaxBlocks=512 needs 32 words
    per set; a full TDominance is nBlocks (up to 512) such sets, one
    per block -- large, but this is heap-allocated (PDominance, same
    "OPT.TXT R7 storage fix" convention every other large CFG-derived
    structure in this unit already follows), never a stack local. }
  TDomBitset = array[0..31] of word;

  { TDominance: OPT.TXT's own R12 finding -- "build dominance... on
    R4's reachable CFG." dom[i] is the set of every block that
    DOMINATES block i (every block on EVERY path from the entry block
    0 to block i, including i itself) -- the classical iterative
    dataflow definition: dom of block 0 is the singleton set containing
    ONLY block 0; dom of any other block i is the singleton containing
    ONLY i, unioned with the intersection of dom[p] for every real
    predecessor p of i. Computed to a fixed point, same iterate-to-
    convergence discipline
    ComputeLiveness/PropagateValues already establish. Only blocks
    PROVEN reachable from block 0 (ComputeReachable) ever get a
    meaningful dom[i] at all -- an unreachable block's own dom[i] is
    left as the "all blocks" universal set (the correct, safe "no
    information" starting value for a fixed point that never actually
    updates it, matching this file's own "no analysis exists must
    never be treated as safe" stance: a caller that walks dom[] for an
    unreachable block gets an answer that can never wrongly narrow
    anything, since intersecting with "everything" is a no-op). }
  TDominance = record
    dom: array[0..MaxBlocks-1] of TDomBitset;
    ok: boolean;
  end;
  PDominance = ^TDominance;

  { TNaturalLoop: OPT.TXT's own R12 finding -- "natural loops," the
    classical CFG definition: given a back-edge (latch->header, where
    header DOMINATES latch -- proven via TDominance, not merely a
    backward-looking edge in program order, which could just as easily
    be an irreducible/opaque jump this finding's own resolution
    explicitly says to REJECT rather than mishandle), the natural loop
    is header plus every block that can reach latch via a path
    entirely avoiding header (computed by a backward BFS/worklist from
    latch, stopping at header, matching the standard textbook
    algorithm). members is a TDomBitset (same block-index-set
    representation as TDominance's own dom[] -- this loop can, in
    principle, contain up to MaxBlocks blocks, the same bound
    everything else in this unit already uses). }
  TNaturalLoop = record
    header: integer;
    latch: integer;
    members: TDomBitset;
  end;
  { TLoopSet: every natural loop found in one CFG, bounded by MaxBlocks
    (a loop's own header is a distinct block, and there can never be
    more distinct loop headers than blocks) -- heap-allocated
    (PLoopSet), same convention as every other large CFG-derived
    structure. }
  TLoopSet = record
    loops: array[0..MaxBlocks-1] of TNaturalLoop;
    nLoops: integer;
    ok: boolean;
  end;
  PLoopSet = ^TLoopSet;

  TLiveness = record
    liveIn, liveOut: array[0..MaxBlocks-1] of word;
    flagLiveIn, flagLiveOut: array[0..MaxBlocks-1] of word;
    ok: boolean;
  end;

  { TMemFact: one proven frame-object memory identity -- "this bp-
    relative slot, of this width, currently holds the SAME value some
    known register also holds" (or, more precisely per R7's own "start
    with nonescaping frame objects," the value most recently STORED
    into it by a proven-safe MOV [bp+N],reg this analysis observed,
    with no proven-unsafe write/call/unknown operation crossing it
    since). isByte distinguishes a byte-sized slot from a word-sized
    one at the SAME offset -- two textually different, non-conflicting
    objects on real 8086 (SPHINX's own frame layout never reuses a
    byte offset for two DIFFERENT declared locals of different widths,
    but the field is checked anyway rather than assumed, the same
    "explicit over assumed" precedent isFrameObject's own callers
    already follow). srcReg: the register whose own CURRENT value this
    memory slot is known to match -- byte-width srcReg (AL/AH/etc, not
    just AX/BX/...) when isByte, honoring R7's own "Track known AL/AH
    independently... combine only when both are known." }
  TMemFact = record
    frameOffset: longint;
    isByte: boolean;
    srcReg: integer;
  end;

  TValueFacts = record
    regKnown: array[0..MaxBlocks-1, 1..16] of boolean;
    regVal: array[0..MaxBlocks-1, 1..16] of word;
    memKnown: array[0..MaxBlocks-1, 1..MaxMemFacts] of boolean;
    memFact: array[0..MaxBlocks-1, 1..MaxMemFacts] of TMemFact;
    ok: boolean;
  end;

  { TProcRange: one PROCEDURE body's own [startChunk,startSlot..
    endChunk,endSlot] range plus its SymTab identity (procId) -- OPT.TXT
    R6's own BuildCallGraph (below) takes an ARRAY of these, one per
    PROCEDURE in the whole module, so it can see every call site in
    every procedure at once (the "post-parse... phase, because the
    current immediate per-procedure pass cannot see later callers" this
    finding's own resolution asks for) before any individual range's
    own Optimize call runs. Mirrors SPHO.PAS's own TOptRangeChunk entry
    fields exactly (procId/startChunk/startSlot/endChunk/endSlot) --
    SPHO.PAS's own OptimizeAllDeferred flattens its chunked list into a
    plain array of these to pass across the unit boundary, since a TP7
    open-array parameter can't walk a linked chunk list on its own. }
  TProcRange = record
    procId: integer;
    startChunk, endChunk: POpChunk;
    startSlot, endSlot: integer;
  end;

  { TProcDemand: OPT.TXT's own R6 finding -- one entry per SymTab
    procedure row, "which of AX/DX/flags some caller reads after the
    CALL returns," unioned across every DIRECT, by-name, same-module
    call site BuildCallGraph could find and prove -- see BuildCallGraph
    and DemandFor's own header comments below for the full reasoning.
    known=FALSE (the conservative default, matching every return's own
    behavior before this analysis existed) means "assume every
    register/flag bit is possibly observed," the same as the old,
    unconditional treatment -- used for any procedure BuildCallGraph
    could not fully account for (external, address-taken, exported,
    unresolved/indirect-called, or simply never analyzed at all, e.g.
    if BuildCallGraph itself was never called). }
  TProcDemand = record
    regMask, flagMask: word;
    known: boolean;
  end;

{ BuildCfg/ComputeLiveness/ComputeLivenessForProc/PropagateValues: all
  four now allocate their own OUTPUT via `New` (heap, not a stack
  local -- OPT.TXT R7's own storage fix, TCfg/PCfg's own header
  comment above has the full reasoning) and hand back a POINTER; the
  CALLER owns the returned object and must Dispose() it once done,
  same "caller owns cleanup" convention Types.POpChunk already uses
  throughout this codebase. A caller that already has a cfg/lv/vf it
  no longer needs should Dispose it BEFORE requesting a new one
  (these procedures do not free anything the CALLER already owns --
  only what they themselves just allocated on a later failure path,
  if any). }
procedure BuildCfg(startChunk: POpChunk; startSlot: integer;
                    endChunk: POpChunk; endSlot: integer; var cfg: PCfg);
procedure ComputeLiveness(cfg: PCfg; var lv: PLiveness);
{ ComputeLivenessForProc: OPT.TXT's own R6 finding -- identical to
  ComputeLiveness above, except a block whose own successor is
  SuccUnknown BECAUSE it is a genuine RETN/RETF/IRET (TBlock's own
  isRetnExit, set by BuildCfg) consults DemandFor(procId) instead of
  unconditionally assuming AllRegMask/AllFlagMask; an unresolved JUMP
  target (isRetnExit=FALSE, same SuccUnknown marker) still stays fully
  conservative -- this analysis has no way to know where it goes, and
  DemandFor's own per-procedure fact has nothing to say about a jump
  target's own identity at all. ComputeLiveness itself is UNCHANGED
  (existing callers -- BuildCallGraph's own internal use building each
  CALLER's liveness, TESTS/STGD.PAS's own driver -- keep the old,
  fully-conservative-on-every-return behavior, exactly as before this
  finding; only a caller that actually HAS a real procId to consult a
  demand fact for should ever call this sibling instead). }
procedure ComputeLivenessForProc(cfg: PCfg; procId: integer; var lv: PLiveness);
procedure PropagateValues(cfg: PCfg; var vf: PValueFacts);
{ FindBlockStartingAt: exported alongside the three above so a test
  driver can look up a specific block by its own known start position
  -- see its own full header comment in the implementation section
  below. }
function FindBlockStartingAt(cfg: PCfg; c: POpChunk; k: integer): integer;

{ LoadModifyStore: OPT.TXT S8's own E3 -- see its own header comment
  in the implementation section below. Exported the same "bare
  signature only" way as the rest of Stage C/D above. }
procedure LoadModifyStore(startChunk: POpChunk; startSlot: integer;
                           endChunk: POpChunk; endSlot: integer);

{ StoreForwarding: OPT.TXT S8's own E1 -- see its own header comment
  in the implementation section below. Exported the same "bare
  signature only" way as the rest of Stage C/D above. }
procedure StoreForwarding(startChunk: POpChunk; startSlot: integer;
                           endChunk: POpChunk; endSlot: integer);

{ CrossBlockStoreForwarding: OPT.TXT's own R7 finding ("E1 cross-block
  forwarding") -- see its own header comment in the implementation
  section below. A separate, NEW rule from StoreForwarding above (left
  completely unchanged, zero regression risk to a proven rule already
  covering the within-block case) rather than a rewrite of it, since
  the two rules' own proofs are genuinely different in kind (a local
  forward scan vs. a whole-procedure PropagateValues-based lookup),
  matching this project's own established convention of adding a new,
  independently-verified rule instead of risking an already-tested one
  for a missed-optimization gain alone. }
procedure CrossBlockStoreForwarding(startChunk: POpChunk; startSlot: integer;
                                     endChunk: POpChunk; endSlot: integer);

{ FoldTempOperand: OPT.TXT S8's own E2 tmp-fold sub-case -- see its own
  header comment in the implementation section below. Exported the
  same "bare signature only" way as the rest of Stage C/D/E above. }
procedure FoldTempOperand(startChunk: POpChunk; startSlot: integer;
                           endChunk: POpChunk; endSlot: integer);

{ ByteCompareNoWiden: OPT.TXT S8's own E4 -- see its own header
  comment in the implementation section below. Exported the same "bare
  signature only" way as the rest of Stage C/D/E above. }
{ ByteCompareNoWiden's own procId parameter: OPT.TXT's own R6 finding
  -- threaded through from Optimize/OptimizePass (below), the CURRENT
  procedure's own SymTab identity, so this rule's own internal
  BuildCfg/ComputeLivenessForProc call (in place of the old plain
  ComputeLiveness) can narrow a RETN block's own LiveOut via
  DemandFor(procId) instead of assuming every register/flag bit is
  always observed across every return, unconditionally. procId=0 (or
  any id BuildCallGraph never actually analyzed) safely falls back to
  DemandFor's own "unknown" default -- this parameter is never a
  correctness requirement on ITS OWN, only ever a possible NARROWING
  of an already-sound conservative baseline. }
procedure ByteCompareNoWiden(startChunk: POpChunk; startSlot: integer;
                              endChunk: POpChunk; endSlot: integer; procId: integer);

{ RemoveRedundantZeroExtend: OPT.TXT's own R7 finding -- "Delete
  redundant XOR AH,AH only if AH is already zero AND all affected
  flags are dead; zero knowledge alone is insufficient." Matches a bare
  "XOR AH,AH" and deletes it only when BOTH of two independent proofs
  hold: PropagateValues shows AH is ALREADY known-zero at this exact
  point (regKnown[RegAH]=true, regVal[RegAH]=0 -- typically from an
  earlier "MOV AL,byte [mem]" that this codebase's own real "widen a
  byte load to a word" idiom immediately follows with this same XOR,
  matching R7's own "zero-producing... immediate MOV with correct
  truncation" language: a byte-sized MOV never touches AH at all, so
  AH's own value at that point is whatever it already was -- if that
  was ALSO already proven zero by something earlier, this second XOR
  is provably redundant), and ComputeLivenessForProc shows every
  arithmetic flag the XOR would have set is dead on every REACHABLE
  successor (the same CFG-aware, both-successors proof E4 already
  uses, not just LocalDeadAfter's own single-path linear scan -- "all
  affected flags are dead" genuinely needs the CFG, since a flag read
  on only ONE branch of a later Jcc still makes the XOR's own flag
  SIDE EFFECT observable, exactly the failure mode a plain forward scan
  down one path alone cannot rule out). Requires level>=2 (Stage E),
  wired into OptimizePass the same way ByteCompareNoWiden already is;
  also takes procId for the same DemandFor-narrowed RETN reasoning. }
procedure RemoveRedundantZeroExtend(startChunk: POpChunk; startSlot: integer;
                                     endChunk: POpChunk; endSlot: integer; procId: integer);

{ RemoveDeadZeroMov: OPT.TXT's own R8 finding -- "Delete MOV AH,0 using
  per-instruction backward liveness reconstructed from block LiveOut;
  preserve it for any later AX/AH read on any path. This dead-write
  rule needs no constant proof." A SEPARATE, simpler rule from
  RemoveRedundantZeroExtend above (that rule proves a redundant XOR
  AH,AH is provably a NO-OP, needing PropagateValues' own known-zero
  fact; this rule proves a literal "MOV AH,0" is simply DEAD -- nobody
  downstream ever reads the AH it writes -- which needs no value
  identity at all, matching OPT.TXT's own "needs no constant proof").
  MnMov writes no flags (GetEffects' own MnMov case), so the only
  proof required is that AH itself is unread before being overwritten
  again on every reachable path: LocalDeadAfter's own local linear
  scan first (resolves instantly for the extremely common case of
  another real write to AH/AX arriving before any branch at all),
  falling back to ComputeLivenessForProc's own liveOut for the
  containing block when the local scan reaches the range end
  unresolved (the same two-tier composition RemoveRedundantZeroExtend
  already established for its own analogous "flags dead" proof, here
  applied to a register instead). Real trigger site: SPHO.PAS's own
  EmitExprFromEx, "mov ah,0" after a byte-returning CALL result lands
  in a word-sized destReg (SPHO.PAS's own EmitWidenByteToWord emits
  XOR AH,AH instead in its own path, already covered above -- this
  rule's own literal-MOV shape is a genuinely different emission site,
  not a duplicate). }
procedure RemoveDeadZeroMov(startChunk: POpChunk; startSlot: integer;
                             endChunk: POpChunk; endSlot: integer; procId: integer);

{ RemoveRepeatedFlagOpCrossBlock: OPT.TXT's own R8 finding -- "remove
  CMP/TEST only when needed flags match on all incoming paths," the
  cross-block extension of RemoveRepeatedFlagOp above (left completely
  unchanged, zero regression risk to an already-proven within-block
  rule), same relationship CrossBlockStoreForwarding already has to
  StoreForwarding. On finding a CMP/TEST/OR whose own two operands are
  BOTH register-or-decoded-immediate (RemoveRepeatedFlagOp's own
  existing "never memory" restriction, reused verbatim: no proof exists
  that an unwitnessed memory location stayed unchanged since a
  predecessor block), sitting as the CANDIDATE block's own FIRST real
  operation, with that block having EXACTLY ONE real predecessor whose
  own LAST real operation is an mnemonic-and-operand-IDENTICAL CMP/
  TEST/OR (same "adjacency proves nothing changed" reasoning
  RemoveRepeatedFlagOp already relies on, just carried across exactly
  one proven, unconditional control-flow edge instead of a same-chunk
  NextReal step) -- the candidate is dead, matching the same target as
  RemoveRepeatedFlagOp's own MnNop-out-the-second-one strategy. Undefined
  flags never become "known equal constants" here either: this rule
  proves nothing at all about VALUES, only that the SAME comparison,
  with the SAME operand values (unless something wrote them in
  between, which the single-predecessor/last-op-adjacency proof already
  rules out) already ran immediately before this block started, so its
  own flag outcome is necessarily identical -- the exact same soundness
  argument the within-block rule already uses, just with "immediately
  before" now meaning "the last thing the one proven predecessor did,"
  not "the previous line in the same chunk." }
procedure RemoveRepeatedFlagOpCrossBlock(startChunk: POpChunk; startSlot: integer;
                                          endChunk: POpChunk; endSlot: integer);

{ FoldTempOperandGap: OPT.TXT's own R8 finding -- "FoldTempOperand's
  adjacent shape is currently driver-only. Match real emission
  sequences using a bounded backward scan through independent
  instructions... Prove no operand, address, flag or memory-timing
  dependency crosses the moved operation." A SEPARATE, new sibling of
  FoldTempOperand above (left completely unchanged, zero regression
  risk to an already-proven, STRICTLY-adjacent rule), same relationship
  every other R7/R8 cross-gap extension in this unit already has to its
  own strict, proven original (CrossBlockStoreForwarding/
  StoreForwarding; RemoveRepeatedFlagOpCrossBlock/RemoveRepeatedFlagOp).

  Matches "MOV tmp,src" followed, WITHIN MaxFoldTempGap real operations
  (not necessarily the very next one), by "ADD/SUB/CMP dst,tmp" -- same
  match and same rewrite FoldTempOperand's own header comment already
  documents in full (dst may be register or memory, "ADD mem,reg" is
  legal, dst<>tmp required, dst/src never both memory, dst's own
  address must not depend on tmp). The ADDITIONAL soundness burden this
  version alone carries: every one of the (possibly several)
  instructions strictly BETWEEN the MOV and the ADD/SUB/CMP must be
  PROVEN independent of the fold -- must not write tmp itself (would
  destroy the very value being forwarded), must not write any register
  src's own address depends on if src is memory (addrRegMask -- would
  change WHERE src reads from, breaking "operand values and access
  timing are unchanged"), and must not itself be a real transfer or
  an unknown-effect operation (the same hard-barrier
  discipline LocalDeadAfter already established -- a scan with no CFG
  has no way to reason about what a real branch skips over or where it
  goes). An intervening WRITE to src itself (a bare register, not
  memory) is likewise disqualifying -- if src is a register whose value
  changes before the ADD/SUB/CMP runs, reading it directly there would
  read the WRONG (later) value instead of the one tmp captured. An
  intervening write to dst is explicitly NOT disqualifying (dst's own
  current value at ADD/SUB/CMP time is read by that instruction either
  way, identically, whether or not this fold happens -- this rule never
  moves the ADD/SUB/CMP itself, only rewrites its own second operand).
  Bounded by MaxFoldTempGap real intervening operations -- a small,
  explicit cap, not a convergence/fixed-point bound like
  MaxOptimizePasses/MaxDemandPasses (this is a single linear forward
  scan that always terminates on its own via the range end or a
  disqualifying instruction; the cap exists only to keep an ordinary
  compile fast, not for correctness), matching this unit's own
  "explicit over assumed" bounded-scan precedent (Stage C's own
  MaxBlocks/MaxCfgOps capacity caps play the identical role for BuildCfg
  itself). Requires level>=2 (Stage E), wired into OptimizePass
  immediately after FoldTempOperand itself. }
procedure FoldTempOperandGap(startChunk: POpChunk; startSlot: integer;
                              endChunk: POpChunk; endSlot: integer);

{ LoadModifyStoreProc: OPT.TXT's own R9 finding -- "after R2/R3, use
  CFG liveness for load/modify/store beyond local scans and R6 masks
  at proven normal returns." A SEPARATE, new sibling of LoadModifyStore
  above (left completely unchanged, zero regression risk to an
  already-proven rule), same relationship every other R7/R8/R9
  CFG-fallback extension in this unit already has to its own strict,
  local-scan-only original. LoadModifyStore's own dead-AX proof
  (LocalDeadAfter, scoped to [sc,sk..endChunk,endSlot]) cannot prove AX
  dead when the scan reaches a bare RETN with nothing further reading
  AX afterward -- LocalDeadAfter's own documented "a bare RETN/RETF
  reaching range end is NOT proof of death" stance, correct in
  isolation (a caller might still read the returned value) but overly
  conservative once R6's own BuildCallGraph/DemandFor can PROVE what a
  procedure's own real callers actually read. Matches the exact same
  three-operation shape LoadModifyStore itself already matches (MOV
  AX,mem1 / ADD-or-SUB AX,K / MOV mem1,AX, with every one of
  LoadModifyStore's own safety requirements -- K never memory, K never
  overlapping AX, mem1 a proven-safe frame/global object -- reused
  verbatim), but composes the dead-AX proof via LocalDeadAfterEx first,
  falling back to ComputeLivenessForProc's own liveOut (DemandFor-
  narrowed at any RETN this procedure's own BuildCallGraph pass already
  proved something about) only when the local scan reaches genuine
  range end, never when it finds a real AX read partway through (the
  identical reachedRangeEnd-gated composition RemoveRedundantZeroExtend/
  RemoveDeadZeroMov already established, and the identical bug class
  fixed in the former during R8 -- avoided here from the start). }
procedure LoadModifyStoreProc(startChunk: POpChunk; startSlot: integer;
                               endChunk: POpChunk; endSlot: integer; procId: integer);

{ RemoveDeadLocalStore: OPT.TXT's own R9 finding -- "Implement the
  separate missing dead-local-store rule: backward byte-level object
  liveness, requiring every path to overwrite or exit with a private
  nonescaping object dead. Unknown pointer reads/calls keep stores
  live." A genuinely NEW analysis, not a composition of any existing
  rule's own machinery (no memory-liveness tracking of any kind existed
  anywhere in this unit before this): a "MOV [frameobj],srcReg" store
  to a PROVEN frame-object slot (DecodeOperand's own isFrameObject) is
  dead when BOTH:

  1. ESCAPE PROOF -- no "LEA reg,[mem]" (the ONLY shape SPHO.PAS's own
     ADR() ever emits, EmitAdrOperand) anywhere in the WHOLE procedure
     range takes this exact frame offset's own address. Deliberately
     COARSE and CONSERVATIVE: checked once per candidate store against
     the object's own frameOffset alone (not per-path, not narrowed by
     control flow at all) -- a SINGLE LEA anywhere in the procedure
     targeting this offset disqualifies EVERY store to it, forever,
     even on a path that never reaches that LEA. A real address-escape
     analysis narrowed by reachability is a strictly harder problem
     (proving WHICH paths a taken address could still be read back
     through) not attempted here.
  2. LOCAL DEAD-AFTER PROOF -- a straight-line forward scan (the same
     "adjacency/local scan first" discipline every Stage B/C/E rule in
     this unit already establishes, NOT a full CFG backward fixed-
     point -- OPT.TXT's own "backward byte-level object liveness" is
     approximated here by a bounded FORWARD scan proving the SAME
     thing a true backward analysis would: no read reaches this store's
     own value before it is overwritten or the scan reaches a genuine
     RETN/RETF/IRET) from the store: the SAME frame offset must be
     WRITTEN again (proving the just-stored value dead) OR the scan
     must reach a bare RETN/RETF/IRET with NOTHING in between reading
     this offset -- "exit with... dead" is automatic for any genuinely
     PRIVATE local (never a return value, never observable by a caller
     at all, unlike LoadModifyStoreProc's own AX-in-a-register
     question, which DOES need R6's DemandFor; a frame slot has no
     such caller-visibility question once escape is already ruled out
     by (1) above). A CALL or any unknown-effect instruction anywhere
     in the scanned prefix invalidates the WHOLE proof for every
     candidate whose own address might be reachable through it --
     "unknown pointer reads/calls keep stores live" -- since no per-
     object alias proof exists to narrow that conservatism further
     (matching every other memory-adjacent rule in this unit's own
     "no alias-proof machinery, so any real memory touch blocks"
     stance). A real read of the SAME offset before either outcome
     blocks the match entirely (the store is live). }
procedure RemoveDeadLocalStore(startChunk: POpChunk; startSlot: integer;
                                endChunk: POpChunk; endSlot: integer);

{ FoldConstDivMod: OPT.TXT's own R11 finding -- E5, "constant MUL/DIV/
  MOD". Scoped, per this finding's own explicit resolution text, to
  UNSIGNED DIV/MOD by a constant POWER OF TWO only ("Match unsigned
  powers of two first... Leave signed cases unchanged until
  truncation-toward-zero and overflow proofs are implemented" -- MUL
  and any non-power-of-two divisor are NOT attempted here at all).

  Matches SPHO.PAS's own EmitMulDiv unsigned-DIV/MOD emission shape
  exactly:

    MOV ax,firstOpnd (or firstOpnd already AX)
    MOV cx,K            (LoadMulDivOperand's own non-register-operand
                          fallback -- K a decoded literal)
    XOR dx,dx           (EmitMulDiv's own unsigned zero-extend --
                          textually distinct from CWD, the signed
                          sign-extend, so this shape ALONE already
                          proves the unsigned path was taken, no
                          separate "is this WORD not INTEGER" fact
                          needs to cross the SPHO.PAS/PHOPT.PAS
                          boundary at all)
    DIV cx
    [MOV ax,dx]         (EmitMulDiv's own MulDivMod-only remainder
                          move -- present for MOD, absent for plain
                          DIV; this ONE extra optional operation is
                          the only textual signal distinguishing the
                          two ops in the emitted stream)
    [MOV destReg,ax]    (optional, present whenever destReg <> AX)

  K must be an EXACT power of two, 2..256 (256 is the largest 9-bit
  power of two a WORD divisor can meaningfully be -- 512+ divides any
  16-bit unsigned dividend down to 0 or a tiny remainder either way,
  still a valid rewrite, but not attempted here: SPHO.PAS's own real
  emitted divisors this pass could find were never observed above
  256, and widening the K range is a bounded-value concern separate
  from the fold's own core proof). K=1 is a true no-op DIV (quotient=
  dividend, remainder=0 always) -- NOT matched here: EmitMulDiv itself
  still emits the full DIV sequence for a literal divisor of 1 (no
  earlier constant-fold catches this either), but a DEDICATED "DIV/MOD
  by 1 is always a no-op" rule is a SEPARATE, simpler fold from the
  power-of-two SHIFT/MASK rewrite this one performs, not attempted
  here (a distinct future finding, not part of R11's own named scope).

  DIV rewrite: K=2 (N=1) becomes a bare "SHR ax,1" (2 bytes, the one
  shift-by-implicit-1 form real 8086 hardware has always supported
  directly); K>2 becomes "MOV cl,N; SHR ax,cl" (4 bytes, the CL-count
  form -- ALSO always legal on real 8086, unlike "SHR ax,N" with N>1,
  an immediate count encoding introduced only with the 80186 and
  therefore NEVER emitted here, per this finding's own explicit "Test
  legal one-bit/CL shifts, not post-8086 immediate-count encodings").
  MOD rewrite: "AND ax,K-1" (masks off exactly the low N bits, K-1
  being all-ones in exactly those N bit positions for a power of two)
  -- simpler than the DIV case, touches only AX, needs neither CX nor
  DX at all, and is legal on every 8086 unconditionally (no CL-count
  question at all for a logical AND).

  Safety: CX and DX (the ORIGINAL sequence's own scratch registers)
  must be proven dead after the whole matched sequence (LocalDeadAfterEx,
  same composition R7/R8/R9 already established, falling back to
  ComputeLivenessForProc's own liveOut only on genuine range end) --
  "preserve live quotient/remainder/high-product outputs or reject": DX
  holds DIV's own remainder (needed live by neither rewrite, since the
  DIV rewrite computes ONLY the quotient via a shift and the MOD
  rewrite computes the remainder directly via AND, without ever
  routing through DX at all) and CX is this sequence's own scratch
  divisor register -- both entirely internal to the ORIGINAL sequence,
  never a genuine program value the rewrite could accidentally lose,
  but still checked explicitly rather than assumed, matching this
  file's own "explicit over assumed" precedent throughout. Flags are
  ALSO required dead afterward (FlagMaskArith) -- DIV/IDIV's own flags
  are UNDEFINED on real 8086 (GetEffects' own MnDiv/MnIdiv case already
  reports flagWrite=FlagMaskNone, "undefined output flags are not known
  constants," OPT.TXT S3), so no equivalence with the rewrite's own
  SHR/AND flags (which DO set real, defined flags) could ever be
  claimed or is needed -- requiring them dead on the OUTPUT side
  sidesteps the whole question safely, the same "never claim an
  equivalence you cannot prove, prove irrelevance instead" strategy
  E4's own FlagMaskArith check already uses for SF/OF. }
procedure FoldConstDivMod(startChunk: POpChunk; startSlot: integer;
                           endChunk: POpChunk; endSlot: integer; procId: integer);

{ FoldConstMovArith: OPT.TXT's own R14 finding -- "INC(curCol,GlyphW+Gap)
  emits arithmetic for 3+1. Add width-aware constant-expression folding
  at -O2 with an explicit scratch/flag contract or deadness proof."
  SPHO.PAS's own EmitExpr/EmitExprTail machinery (used for every
  chained arithmetic expression this translator emits, not just an
  INC/DEC amount) never constant-folds two literal operands at parse
  time -- "MOV ax,GlyphW" (a resolved CONST value) immediately followed
  by "ADD ax,Gap" (another resolved CONST value) is real runtime
  arithmetic on two ALREADY-KNOWN-AT-TRANSLATE-TIME values, matching
  this unit's own "K a decoded literal" precedent (E5's own
  FoldConstDivMod) applied to ADD/SUB directly instead of DIV/MOD.

  Match: MOV reg,K1 / ADD-or-SUB reg,K2 (the SAME register on both,
  STRICTLY ADJACENT -- NextReal, matching every other Stage A/C
  bounded-adjacency rule in this unit: an intervening instruction
  could change what reg holds between the MOV and the ADD/SUB, so only
  proven adjacency gives the "these are the exact same two values, in
  this exact order" guarantee this fold needs). K1 and K2 both decoded
  literals (ParseWordLiteral -- R5's own hex/binary-aware parser,
  reused verbatim, so "GlyphW+Gap" folds correctly even if either
  named CONST happens to be hex/binary-literal-valued, not just
  decimal).

  "Verify left-to-right evaluation and wraparound": K1+K2 (or K1-K2)
  is computed here using the SAME width and modular-wraparound
  semantics the two real ADD/SUB instructions being replaced already
  had -- word arithmetic, mod 65536, identical to what the CPU itself
  would compute for "MOV ax,K1; ADD ax,K2" (8086 ADD/SUB on a 16-bit
  register always wraps silently, never traps, so a folded literal
  computed the same way is bit-for-bit identical on every input,
  including the wraparound case OPT.TXT's own acceptance criteria
  names explicitly) -- "evaluate arguments once in original left-to-
  right order" is satisfied by construction: K1 is read first (the
  MOV), K2 second (the ADD/SUB), exactly mirroring the two REAL
  instructions being folded, not re-ordered.

  "Do not discard observable accumulator results or overflow/carry
  merely because the source operands are constants... an explicit
  scratch/flag contract or deadness proof": this fold DOES change
  observable flag state (the original ADD/SUB genuinely sets
  FlagMaskArith to a value that reflects a REAL 16-bit addition/
  subtraction outcome -- CF/OF include real overflow/carry
  information a later instruction COULD legitimately depend on, even
  though both inputs happen to be compile-time constants) -- so this
  rule NEVER claims flag equivalence, matching E5's own FoldConstDivMod
  precedent exactly ("never claim an equivalence you cannot prove,
  prove irrelevance instead"): FlagMaskArith must be proven DEAD
  afterward (LocalDeadAfter) before the fold is ever allowed to fire,
  regardless of what the correct folded flag values would actually
  be. }
procedure FoldConstMovArith(startChunk: POpChunk; startSlot: integer;
                             endChunk: POpChunk; endSlot: integer);

{ InsertOpAfter: OPT.TXT's own R13 finding ("Stage G: retained bodies,
  inlining and specialization") -- the operation-INSERTION primitive
  every rule in this unit has done without so far, and which R12's own
  F1 (PromoteLoopLocal) explicitly declined to build, requiring an
  entry load/exit store to already exist verbatim instead. Splices a
  single new operation (newOp, already fully formed by the caller --
  this procedure copies it in, it does not construct one) immediately
  AFTER the existing operation at (c,k), within the SAME chunked,
  singly-linked TOpChunk list (c,k) already belongs to. Returns the
  newly-inserted operation's own position as (newC,newK).

  TOpChunk is a FIXED-SIZE array (ops: array[1..Chunk] of TOperation,
  Chunk=64) chained via `next` -- SPHO.PAS's own NewOpSlot only ever
  APPENDS a fresh slot at the current TAIL of the whole list (comp.
  opTail), the same append-only discipline every real emitted
  procedure body is built with; nothing anywhere in this codebase, in
  either PHOPT.PAS or SPHO.PAS, has ever inserted a NEW operation
  strictly BETWEEN two existing ones before this. Three cases, all
  producing this SAME "the new operation now sits between (c,k) and
  whatever used to follow it" outcome:

  1. c HAS SLACK (c^.count < Chunk) -- true only for the single chunk
     that happens to be the CURRENT tail of the whole list (SPHO.PAS's
     own emitter always fills a chunk to all 64 slots before
     allocating the next one), or a chunk THIS PRIMITIVE itself
     already split earlier and left with room. Every operation from
     k+1 through c^.count shifts one slot to the right, WITHIN THE
     SAME ARRAY (no new chunk, no relinking) -- the simple, fast case.
     newC=c always here.
  2. c IS FULL and k < Chunk (the common case for any chunk that is
     NOT the list's own current tail, inserting before its own last
     slot). A fresh chunk is allocated; everything from k+1 through
     Chunk (the ENTIRE remainder of c's own array) is copied into the
     new chunk in order, c's own count is truncated to k+1 (the
     original k slots, plus the new operation now occupying slot
     k+1), the new chunk's own `next` is set to c's OLD `next`
     (preserving the rest of the list, whatever it was), and c^.next
     is set to point at the new chunk. The new operation itself lands
     at slot k+1 of the ORIGINAL chunk c, which still has room for it
     after truncating the shifted-out tail away -- so newC=c here too;
     this case allocates a chunk for the shifted-out REMAINDER, not
     for the new operation itself.
  3. c IS FULL and k = Chunk (inserting after c's own LAST slot). No
     remainder exists to move, but c ALSO has no room left for the new
     operation (slot Chunk+1 is out of c's own declared [1..Chunk]
     bound) -- unlike case 2, the new operation cannot land back
     inside c. A fresh chunk holds ONLY the new operation, at its own
     slot 1, threaded into c's own former `next` exactly as in case 2.
     newC=overflow here, NOT c -- this is the one case where newC<>c;
     any caller relying on "newC is always the chunk I passed in" is
     wrong.

  CRITICAL CALLER HAZARD -- read before ever calling this: any
  position (POpChunk,integer) a caller holds that refers to an
  operation ORIGINALLY at slot k+1 or later WITHIN c (in case 1) is
  now WRONG (it still points at chunk c, but the operation that used
  to be there has moved one slot down, or -- in case 2 -- into an
  entirely different chunk); a position referring to c^.next or any
  chunk further down the list is unaffected (their own identity never
  changes, only c's own `next` field is rewired to point through the
  new overflow chunk first). This is why R13 itself must never insert
  while any OTHER rule's own saved position spanning past the
  insertion point is still in use -- do every insertion for one
  transformation FIRST, then rebuild any CFG/liveness/dominance state
  that spans it, exactly the same "analysis reflects the CURRENT
  operation stream, never assume yesterday's positions still apply"
  discipline BuildCfg's own callers already follow after ANY rewrite.

  Bounded the same way every other unbounded-in-principle scan in this
  unit already is: no internal capacity check of its own (this
  primitive does exactly one splice per call, an O(Chunk) worst-case
  cost, never unbounded on its own) -- a CALLER performing many
  insertions across one procedure's own range is responsible for its
  own overall capacity discipline (matching BuildCfg's own MaxCfgOps
  cap, which any rule building a CFG after inserting will already have
  applied downstream). }
procedure InsertOpAfter(c: POpChunk; k: integer; const newOp: TOperation;
                         var newC: POpChunk; var newK: integer);

{ ComputeDominance/FindNaturalLoops/DomBitset*: OPT.TXT's own R12
  finding ("Stage F: implement each loop transformation separately")
  -- shared infrastructure every one of F1/F2/F3 needs, built once
  here and consumed separately, matching this finding's own explicit
  "reject irreducible/opaque loops initially" and "build dominance and
  natural loops on R4's reachable CFG" resolution text. Exported the
  same "bare signature only" way as the rest of Stage D above, so
  TESTS/STGD.PAS-style driver tests can call these directly. }
procedure DomBitsetClear(var s: TDomBitset);
procedure DomBitsetSetAll(var s: TDomBitset; nBlocks: integer);
procedure DomBitsetSet(var s: TDomBitset; i: integer);
function DomBitsetHas(const s: TDomBitset; i: integer): boolean;
procedure DomBitsetIntersect(var dst: TDomBitset; const src: TDomBitset);
function DomBitsetEqual(const a, b: TDomBitset): boolean;

procedure ComputeDominance(cfg: PCfg; var dm: PDominance);
procedure FindNaturalLoops(cfg: PCfg; dm: PDominance; var ls: PLoopSet);

{ PromoteLoopLocal: OPT.TXT's own R12 finding -- Stage F, F1 ("promotes
  only a nonescaping local into a proven free register, with
  initialization on every entry and writeback on each observable
  exit"). Scoped, deliberately and explicitly, to the SIMPLEST natural
  loop shape only: a SINGLE-BLOCK loop (header = latch, the loop body
  is exactly one block -- the common tight counting/scanning-loop
  shape, and the only shape where "every entry"/"each observable exit"
  reduce to a single, unambiguous predecessor edge and a bounded,
  directly-enumerable set of exit transfers, both fully inside ONE
  block's own text). A multi-block loop body (a real IF/BREAK/CONTINUE
  inside the loop, spanning more than one block) is NOT attempted here;
  rejected outright by this rule's own "header <> latch" check.

  This unit has NO operation-INSERTION primitive anywhere (every
  existing rule only ever NOPs or rewrites an EXISTING slot -- adding
  real mid-stream insertion would be a new architectural capability,
  not just a new rule, consulted on directly and deliberately NOT
  built for this first F1 slice). So rather than inserting a fresh
  entry load/exit store, this rule requires ONE to ALREADY exist,
  verbatim, at exactly the position it would need to be inserted at
  anyway: the loop's own single real predecessor block's own LAST real
  operation must ALREADY be "MOV R,[frameobj]" (the load this
  promotion needs at entry), and the operation IMMEDIATELY BEFORE
  EVERY exit transfer inside the loop block must ALREADY be "MOV
  [frameobj],R" (the store this promotion needs at each exit) -- both
  using the SAME register R and the SAME frame offset throughout. Only
  the REDUNDANT loads/stores INSIDE the loop body's own interior
  (between entry and each exit, on every iteration) are ever removed;
  the entry load and exit stores are proven ALREADY PRESENT, not
  synthesized, so no insertion is ever needed.

  Requires: the local is a proven frame-object (DecodeOperand's own
  isFrameObject) with FrameOffsetEscapes proving no LEA ever takes its
  address anywhere in the WHOLE procedure (R9's own escape-proof
  helper, reused verbatim); every in-block access to that exact offset
  is a plain "MOV reg,[frameobj]"/"MOV [frameobj],reg", ALL using the
  SAME register R; the header has EXACTLY ONE real predecessor outside
  the loop; a CALL, any unknown-effect instruction, or a raw ASM line
  anywhere in the block rejects the WHOLE candidate outright (R9's own
  "unknown pointer reads/calls keep stores live" conservatism). R is
  NOT required to be otherwise unused in the block -- unlike allocating
  a brand-new scratch register, this rule never introduces a NEW use of
  R: the proven entry load and exit store already establish that R
  mirrors [frameobj]'s own value across the whole block, so any OTHER
  instruction reading/writing R for the loop body's own real
  computation (an ADD/CMP driving the loop's own counter, for example)
  is exactly the expected, intended use of the now-promoted value, not
  a conflict -- a real design correction found via a driver test that
  originally, wrongly, rejected this exact ordinary shape.

  Rewrite: every in-block "MOV reg,[frameobj]" load becomes a plain
  "MOV reg,reg" self-move (immediately nopped by the pre-existing
  Stage C RemoveMovRR the very next OptimizePass call already cleans
  up); every in-block "MOV [frameobj],reg" store becomes a direct
  MnNop (a store has no register-only equivalent RemoveMovRR could
  clean up, so this rule nops it itself). The proven-already-present
  entry load and exit stores are left completely untouched -- they are
  no longer redundant once the loop's own interior copies are gone;
  they are what makes the promotion correct in the first place. }
procedure PromoteLoopLocal(startChunk: POpChunk; startSlot: integer;
                            endChunk: POpChunk; endSlot: integer);

{ BuildCallGraph: OPT.TXT's own R6 finding ("Return/call observability
  must be proved... this needs a post-parse optimization phase") --
  computes, for every same-module procedure that appears in `ranges`,
  a TProcDemand fact recording which registers/flags some ACTUAL caller
  reads right after a CALL to it returns, unioned across every direct,
  by-name call site this pass could find and prove. Called exactly
  once, by SPHO.PAS's own OptimizeAllDeferred, after CheckPendingCalls
  has resolved every pending call site in the module (so every
  TOperation's own callProcId already refers to a stable, correct
  callee) and BEFORE any individual range's own Optimize call runs.

  `ranges`: one TProcRange per PROCEDURE in the module (SPHO.PAS's own
  flattened comp.optRangeHead list) -- `nRanges` of them, 0-based.
  `isConservative`: parallel array, one boolean per SymTab procId (NOT
  per ranges-array index -- procId-indexed the same way the resulting
  demand table itself is), TRUE for any row this analysis must treat
  as fully unknown regardless of what its own call sites look like:
  EXTERNAL (opaque body outside this translation unit), exported
  (`*`-marked -- some OTHER module may import and call it, entirely
  outside this pass's own visibility), or address-taken (SymTab.
  ProcIsAddressTaken -- may be called indirectly, through a path this
  analysis has no way to see at all). SPHO.PAS's own OptimizeAllDeferred
  fills this from SymTab directly (ProcIsExternal/ProcIsExported/
  ProcIsAddressTaken) -- PHOPT.PAS itself never depends on SymTab, kept
  fully isolated from Types/StrTab/Util/Regs86/Scan the same way it
  already was before this change; a plain parallel array is the
  simplest way to cross that boundary without a new dependency. Sized
  by nProcs (SymTab.ProcCount, so the caller can pass an array no
  larger than actually needed, but PHOPT.PAS itself still declares its
  OWN persistent demand table at the fixed MaxProcs bound above,
  matching SymTab's own hard cap). }
procedure BuildCallGraph(nProcs: integer; nRanges: integer;
                          const ranges: array of TProcRange;
                          const isConservative: array of boolean);

{ DemandFor: the one query BuildCallGraph's own result exists to
  answer -- OPT.TXT R6's own consumers (ComputeLiveness's RETN/
  SuccUnknown case; LocalDeadAfter's linear scan, when it walks past a
  RETN) call this instead of assuming "every return observes
  everything." Hands back a TProcDemand with known=FALSE (matching
  every return's own OLD, fully-conservative behavior) if BuildCallGraph
  was never called at all this run, or procId is out of range/was
  never analyzed. A `var` OUTPUT parameter, not a function result --
  TP7 does not allow a function to return a record type directly
  (Error 34: Invalid function result type). }
procedure DemandFor(procId: integer; var d: TProcDemand);

{ Optimize: walk this procedure's own operation range in place,
  [startChunk,startSlot] up to and including the current tail
  (endChunk,endSlot) -- both endpoints inclusive, same 1-based slot
  indexing Types.TOpChunk itself already uses. Mutates operations via
  Types.MnNop deletion (or, for a later real pass, retargeting a
  mnemonic/operand in place the same way SPHO.PAS's own
  CheckPendingCalls/PatchCondRef already patch an operation post-hoc);
  never appends/removes a chunk or slot itself.

  level: OPT.TXT's own "FIRST PREREQUISITE: COMMAND-LINE OPTIMIZATION
  LEVELS" -- "-O1: Run the existing PHOPT optimizations with the Stage
  A correctness repairs. Do not enable the additional optimizations
  below [Stages B-G]." level=1 runs ONLY the repaired Stage A rules
  (ConstCond/ConstOrCond/CheapReturn/JumpChain/DeadCode/NoOpArith --
  the seven rules that already existed, pre-Stage-C, with their own
  Stage A correctness fixes applied); level>=2 additionally runs every
  Stage C/E rule implemented so far. OPT.TXT's own R1 finding: the
  ORIGINAL version of this call took no level parameter at all, and
  SPHO.PAS's own call site only ever checked "optLevel > 0" -- meaning
  every Stage C/E rule silently ran at -O1 too, contradicting this
  plan's own explicit "-O1... Do not enable the additional
  optimizations" text. Fixed by threading level through explicitly;
  SPHO.PAS's own call site (ParseProcedure) passes optLevel unchanged
  -- callers outside this unit (e.g. TESTS/STGC.PAS/STGE.PAS's own
  drivers, which call individual rule procedures directly, not through
  Optimize at all) are unaffected by this change.

  procId: OPT.TXT's own R6 finding -- this procedure's own SymTab
  identity (SPHO.PAS's own OptimizeAllDeferred passes the real `pi`
  from its own flattened ranges list, the SAME id BuildCallGraph's own
  demand table is keyed by), threaded down to ByteCompareNoWiden (E4)
  so its own RETN-block liveness query can be narrowed via
  DemandFor(procId) rather than always assuming a return is observed
  in full. A caller with no real procedure identity to pass at all
  (e.g. TESTS/STGF.PAS's own hand-built operation-list driver, which
  never calls BuildCallGraph in the first place) can safely pass 0 --
  DemandFor(0) with demandTableValid still FALSE (BuildCallGraph never
  ran) falls back to its own "unknown" default, the exact same fully-
  conservative behavior every consumer already had before this
  parameter existed. }
procedure Optimize(startChunk: POpChunk; startSlot: integer;
                    endChunk: POpChunk; endSlot: integer; level: integer;
                    procId: integer);

implementation

uses StrTab, Util, Regs86, Scan;

var
  { demandTable/demandTableValid: OPT.TXT's own R6 finding -- the
    persistent result of the one BuildCallGraph call SPHO.PAS's own
    OptimizeAllDeferred makes per translation run, consulted by
    DemandFor (and, through it, ComputeLiveness/LocalDeadAfter) for the
    rest of that run. demandTableValid starts FALSE (unit-level `var`s
    are always zero-initialized in TP7, so `known` in every entry also
    starts FALSE) -- DemandFor's own "unknown until BuildCallGraph
    actually ran" default falls out of this initial state directly, no
    separate "never analyzed" flag needed. }
  demandTable: array[0..MaxProcs-1] of TProcDemand;
  demandTableValid: boolean;

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

{ ParseWordLiteral: OPT.TXT's own R5 finding -- "Tetris FontIndex's
  DEC(AL,41H)/DEC(AL,16H) produces C2's BL shape, but C2 calls
  ParseDecimalLiteral and misses hex." OperandText (SRC/SPHO.PAS) emits
  a numeric literal operand as its own VERBATIM source text (Scan.
  CurTokText, not a normalized decimal re-spelling), so "41H" reaches
  this unit's own matchers exactly as written in the .SMD source, not
  as "65". ParseDecimalLiteral (above) only ever proved a plain decimal
  spelling, so a hex- or binary-suffixed literal operand silently never
  matched C2's own "MOV ax,K" shape at all -- a real missed-optimization
  gap, not a correctness bug (C2 just never fired for those forms), but
  a real production-usefulness gap per R5's own acceptance criterion.

  Delegates to Scan.ParseNumBuf, the SAME numeric-literal parser
  SPHO.PAS's own scanner already uses to interpret this exact text at
  parse time (decimal, C-style "0x1A" hex prefix, trailing "1Ah"/"1AH"
  hex suffix, trailing "101b"/"101B" binary suffix) -- reusing it here
  is the "shared numeric parser returning value and width for decimal,
  hex and supported signed forms" OPT.TXT's own R5 resolution asks for,
  rather than a second, independently-maintained parser. Range-checked
  down to WORD the same way ParseDecimalLiteral already is (out-of-
  range/malformed is a definite "do not match", never a guess). }
function ParseWordLiteral(const s: string; var val: word): boolean;
  var v: longint; errMsg: string;
begin
  ParseWordLiteral := false;
  if s = '' then exit;
  if not Scan.ParseNumBuf(s, Length(s), v, errMsg) then exit;
  if (v < 0) or (v > 65535) then exit;
  val := v;
  ParseWordLiteral := true
end;

{ EvalJcc: OPT.TXT's own A1 fix -- "Replace EvalJcc's ambiguous Boolean
  result with success plus an output Taken Boolean." The single-Boolean
  version this replaces conflated two genuinely different outcomes
  under one FALSE result: "this condition IS one of the six proven-safe
  ones, and it evaluates to NOT-taken" versus "this mnemonic isn't one
  of the six at all, I don't know what it means" -- a caller that only
  ever checked the old TRUE/FALSE result had no way to tell those
  apart, and (ConstCond's own pre-fix behavior) silently treated
  "unknown" the exact same as "proven not-taken": deleting a JUMP whose
  real runtime behavior was never actually established. taken is only
  meaningful when the function itself returns TRUE; the caller must
  leave the branch (and its own CMP) completely unchanged on FALSE,
  per this comment's own directive ("both callers must leave the
  branch unchanged in that case").

  Initially accept exactly the six conditions JE/JNE/JB/JAE/JA/JBE
  (OPT.TXT's own explicit list) with proven 16-bit unsigned semantics
  -- a bare literal condition (ConstCond's own only caller) has no
  ".INTEGER" cast, so this matches RelJumpsUnsigned's own default,
  exactly the same Jcc set RelJumps/RelJumpsUnsigned/FlagJumps can
  produce as a jt/jf target for this shape (Types.MnJe..MnJbe -- see
  EmitRelational/EmitCondJump, SPHO.PAS). MnJl/MnJge/MnJg/MnJle (signed
  compare) and MnJc/MnJnc/MnJz/MnJnz (flag-only, FlagJumps -- CFLAG/
  ZFLAG tested directly, never fed by a "cmp litA,litB" at all) are
  aliases/signed conditions OPT.TXT's own A1 explicitly defers ("Add
  aliases and signed conditions only with width-aware evaluation of
  the actual flag producer") -- returning success=false for all four
  is the conservative, currently-correct answer: none of them can
  actually reach this exact literal-vs-literal shape in practice
  (ConstCond's own caller already restricts to what RelJumpsUnsigned
  produces), so success=false here is never observed to reject a real
  candidate, only to make that non-observation an explicit, provable
  fact instead of an accidental one. }
function EvalJcc(mn: word; aVal, bVal: word; var taken: boolean): boolean;
begin
  EvalJcc := true;
  case mn of
    MnJe:  taken := aVal = bVal;
    MnJne: taken := aVal <> bVal;
    MnJb:  taken := aVal < bVal;
    MnJae: taken := aVal >= bVal;
    MnJa:  taken := aVal > bVal;
    MnJbe: taken := aVal <= bVal;
  else begin
    EvalJcc := false; taken := false   { unsupported -- caller must not
                                           fold; taken is meaningless here,
                                           but TP7 requires SOME value on
                                           every path through a var param. }
  end
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
      taken: boolean;
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
          { OPT.TXT A1: EvalJcc's own success result gates the WHOLE
            fold now -- on FALSE (an unsupported Jcc reaching this
            match), neither the Jcc nor the CMP is touched at all, per
            EvalJcc's own header comment ("both callers must leave the
            branch unchanged in that case"). This CMP's own two
            operands are BOTH plain decimal literals either way (this
            branch's own outer condition already proved that) -- a
            literal/literal "cmp litA,litB" is not an encodable 8086
            instruction regardless of whether the Jcc folds, so a
            success=false result here (never actually observed from any
            real caller today, per EvalJcc's own comment) would still
            leave that invalid instruction behind unaddressed; fixing
            THAT is a separate, emitter-side change ("resolve compile-
            time conditions in the emitter, or mark them explicitly",
            OPT.TXT's own wording) out of scope for this PHOPT-side
            repair -- DOCS/TRBUG.MD's own entry for this item records
            it as a known, deliberately-deferred residual. }
          if EvalJcc(nc^.ops[nk].mnemonic, aVal, bVal, taken) then begin
            if taken then
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
    end
  until not Advance(c, k, endChunk, endSlot)
end;

{ Fold only the branch. MOV and OR may leave live register/flag values
  consumed after the branch, so neither instruction is dead by this
  match. OPT.TXT A1: "ConstOrCond must validate a real register and its
  width. Do not evaluate a byte result as an untruncated WORD." reg's
  own text is now resolved through Regs86.LookupReg -- anything that
  isn't a genuine 8086 register name at all (a memory operand, a
  compiler-generated symbol, garbage text) is rejected outright rather
  than folded on a bare string match, and a BYTE register (AL/BL/...)
  has its own literal masked to its real 8-bit range (litVal AND 0FFh)
  before EvalJcc ever sees it -- "MOV AL, 300; OR AL,AL" really loads
  300 MOD 256 = 44 into AL, not the untruncated 300 this rule
  previously fed straight into EvalJcc's own WORD compare, a real
  wrong-fold risk for any byte-register literal outside 0..255. }
procedure ConstOrCond(startChunk: POpChunk; startSlot: integer;
                       endChunk: POpChunk; endSlot: integer);
  var c, nc, jc: POpChunk; k, nk, jk: integer; reg, reg2, rhs, litTxt: string;
      litVal: word; regId: integer; taken: boolean;
begin
  c := startChunk; k := startSlot;
  repeat
    if (c^.ops[k].kind = TOpInstr) and (c^.ops[k].mnemonic = MnMov) then begin
      StrTab.Get(c^.ops[k].op1, reg);
      StrTab.Get(c^.ops[k].op2, litTxt);
      regId := Regs86.LookupReg(Util.UpStr(reg));
      if (regId <> 0) and ParseDecimalLiteral(litTxt, litVal) then begin
        if Regs86.IsByteReg(regId) then litVal := litVal and $FF;
        nc := c; nk := k;
        if NextReal(nc, nk, endChunk, endSlot) and (nc^.ops[nk].kind = TOpInstr)
           and (nc^.ops[nk].mnemonic = MnOr) then begin
          StrTab.Get(nc^.ops[nk].op1, reg2);
          StrTab.Get(nc^.ops[nk].op2, rhs);
          if Util.EqualICase(reg, reg2) and Util.EqualICase(reg, rhs) then begin
            jc := nc; jk := nk;
            if NextReal(jc, jk, endChunk, endSlot) and (jc^.ops[jk].kind = TOpInstr)
               and IsJump(jc^.ops[jk].mnemonic) and (jc^.ops[jk].mnemonic <> MnJmp) then begin
              if EvalJcc(jc^.ops[jk].mnemonic, litVal, 0, taken) then begin
                if taken then jc^.ops[jk].mnemonic := MnJmp
                else jc^.ops[jk].mnemonic := MnNop
              end
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
  pattern -- OPT.TXT's own explicit correction: CheapReturn runs BEFORE
  JumpChain in OptimizePass's own sequence (see Optimize below), so it
  has ALREADY finished its own single pass over this range by the time
  JumpChain retargets anything here; a retarget landing on
  CheapReturn's own pattern is only caught by CheapReturn's SECOND
  pass, on Optimize's own second OptimizePass call, not "this same"
  one -- Optimize's own two-call structure is exactly what supplies
  that follow-on pass; a single OptimizePass call alone would leave
  such a case one call short. Does NOT chase a multi-hop chain (a jump landing
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
  reached). Stops at the FIRST structured label found (never nops a
  TOpLabel itself, and never looks past one) -- something else may
  legitimately jump directly into that label from outside this dead
  span, so whatever follows it is a separate question this rule leaves
  alone.

  OPT.TXT A3: on a TOpAsm operation, retain it AND reset inDead to
  false -- this reverses a PRIOR version of this rule (nop'd a TOpAsm
  exactly like an ordinary dead TOpInstr, on the claimed invariant that
  "this codebase's own convention never hand-writes a label inside
  one"). That invariant was already FALSE for this codebase's own
  real, working code even before this fix: ParseAsm copies arbitrary
  raw lines verbatim (its own header comment says so directly -- "its
  input is not restricted to label-free instructions"), and
  EXAMPLES/TETRIS/TETRIS.SMD's own hand-rolled loops (CalcDiff/Draw,
  ".cdloop:"/".drawrow:" etc, pre-dating this fix) are real, checked-in
  examples of exactly this shape: a raw ASM...END block containing its
  own label, immediately after a real unconditional jmp/return in
  SOME OTHER, unrelated span. The OLD rule would have silently deleted
  such a label (overwriting the TOpAsm's own text with a plain NOP) the
  moment DeadCode's own scan considered it "unreachable" from ITS
  OWN local vantage point, breaking any jump anywhere else in the same
  procedure that targets it -- a real correctness bug, not a
  theoretical one, confirmed directly against real checked-in code.
  Resetting inDead to false on ANY TOpAsm (not just one PROVEN to
  contain a label) is the necessary conservative response: this pass
  has no way to parse a raw ASM line's own text to tell "definitely no
  label in here" apart from "might have one" (ParseAsm's own text is
  opaque past the point it was recorded), so treating every TOpAsm as
  a potential re-entry point, exactly like a real TOpLabel, is the only
  sound choice available without actually parsing the raw text.

  Both TOpInstr operations in a dead span are still eliminated as
  before (overwritten to kind=TOpInstr/mnemonic=MnNop in place) --
  ONLY the TOpAsm handling changed. Runs AFTER CheapReturn/JumpChain
  (see Optimize below): letting those two run first means a jmp
  CheapReturn nops becomes MnNop before DeadCode ever looks at
  IsUncondTransfer on it (a nop'd jmp is not itself an unconditional-
  transfer boundary -- correctly so, since nothing was actually left in
  place there once serialized), and a jmp JumpChain retargets is still
  exactly as much an unconditional transfer as before, just landing
  somewhere else -- either way, DeadCode's own final pass sees the same
  fully-settled operation stream SerializeOne itself will later walk. }
procedure DeadCode(startChunk: POpChunk; startSlot: integer;
                    endChunk: POpChunk; endSlot: integer);
  var c: POpChunk; k: integer; inDead: boolean;
begin
  c := startChunk; k := startSlot; inDead := false;
  repeat
    if c^.ops[k].kind = TOpLabel then
      inDead := false
    else if c^.ops[k].kind = TOpAsm then
      inDead := false   { OPT.TXT A3: retain it AND reset inDead --
                            a raw ASM line may contain its own hand-
                            written label, opaque to this pass; treat
                            it as a possible re-entry point every time. }
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
  never actually produced as this shape's own left-hand side).

  MemOpndPrefix strips a leading "byte "/"word " size prefix before the
  '[' check below -- MoveAxToDest's own header comment: a byte-sized
  store destination's own op1 text is literally "byte [bp-1]", not a
  bare "[bp-1]" the way a word-sized store's is (NASM needs the size
  prefix to disambiguate "mov [mem], al" from ambiguity a plain
  register operand's own width would otherwise resolve automatically).
  Before this, the '[' check here always failed for every byte-sized
  store, so StoreReload silently never fired on ANY byte-sized store/
  reload pair at all -- confirmed via EXAMPLES/MIME/MIME.SMD's own
  generated code, riddled with "mov byte [bp-1], al" / "mov al, byte
  [bp-1]" / "mov ah, 0" triples (every "c := [ES:BX]; ...c used
  immediately after..." local-BYTE-var idiom, e.g. IsBlank/IsSep's own
  parameter, SkipBlanks/GetToken's own scanned-char local) that this
  rule was clearly meant to catch (matches the size-mismatch case this
  same header comment already calls out as a KNOWN, deliberate
  exception) but never actually did, a real gap rather than the
  documented conservative choice. The full "byte "/"word " prefix text
  is still compared as part of storeMem/reloadMem's own EqualICase
  check below (unchanged) -- MemOpndPrefix only affects which strings
  get past the initial "is this even a memory operand" gate, not
  whether two differently-sized operands can still match each other
  (they can't: "byte [bp-1]" and "word [bp-1]" compare unequal via
  EqualICase exactly as before). }
function MemOpndPrefix(const s: string): string;
begin
  if Util.EqualICase(Copy(s, 1, 5), 'byte ') or Util.EqualICase(Copy(s, 1, 5), 'word ')
  then MemOpndPrefix := Copy(s, 6, Length(s) - 5)
  else MemOpndPrefix := s
end;

procedure StoreReload(startChunk: POpChunk; startSlot: integer;
                       endChunk: POpChunk; endSlot: integer);
  var c, nc: POpChunk; k, nk: integer; storeMem, storeReg, reloadReg, reloadMem: string;
      bareStoreMem: string;
begin
  c := startChunk; k := startSlot;
  repeat
    if (c^.ops[k].kind = TOpInstr) and (c^.ops[k].mnemonic = MnMov) then begin
      StrTab.Get(c^.ops[k].op1, storeMem);
      StrTab.Get(c^.ops[k].op2, storeReg);
      bareStoreMem := MemOpndPrefix(storeMem);
      if (bareStoreMem <> '') and (bareStoreMem[1] = '[') then begin
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

{ IsFlagSetter: TRUE for an operation PROVEN to overwrite the FULL
  CF/ZF/SF/OF/PF set with a fresh result of its own, making whatever an
  earlier add/sub left in those flags provably moot from here on.
  ADD/SUB/CMP/TEST/XOR/OR/AND/NEG/MUL/IMUL/DIV/IDIV all genuinely do.

  A real bug found here (an isolated TP7 driver confirmed the actual
  deletion, not just a theoretical read of the code): INC/DEC and a
  variable-count SHL/SHR were ALSO in this list, but neither one is
  actually a full flag reset on real 8086 --
  - INC/DEC update ZF/SF/OF/PF/AF but LEAVE CF COMPLETELY UNCHANGED (a
    deliberate 8086 design choice, so INC/DEC can be used inside a
    multi-word add/subtract chain without clobbering the carry that
    chain depends on). "ADD AX,0; INC BX; JC target" -- the JC still
    reads the ADD's own CF, untouched by the INC in between; the old
    code treated INC as a full reset and let the scan stop right there,
    declaring the ADD AX,0 safe to delete. It is not.
  - SHL/SHR by a VARIABLE count (the 8086 "SHL/SHR reg,CL" form,
    reachable from real SPHINX source via "x SHL y"/"x SHR y" with a
    non-constant y, EmitExprTail, SRC/SPHO.PAS) leaves EVERY flag
    completely UNCHANGED when the count happens to be 0 at runtime --
    a real, architecturally-defined possibility this pass has no way
    to rule out from the operation stream alone (the count is a
    runtime register value, not something foldable here). An
    IMMEDIATE-count shift (a decoded literal operand) has no such
    escape: a literal count of 0 would be genuinely pointless codegen
    this translator never emits, and any REAL nonzero immediate count
    always does perform the full flag write -- so only the immediate
    form is trusted as a setter, the CL form is not.
  INC/DEC are now excluded from this whitelist entirely (never a
  trusted full-reset point, at any operand); SHL/SHR require op2 to be
  a proven decimal literal to qualify -- a CL-based (or any other non-
  literal) shift count falls through to NoOpArithSafe's own
  conservative default (not a setter, not flag-preserving -> stops the
  scan as unsafe), exactly the same "no data-flow analysis, stay
  conservative" bias every other case here already follows. }
function IsFlagSetter(kind: byte; mn: word; const op2: string): boolean;
  var dummyVal: word;
begin
  IsFlagSetter := (kind = TOpInstr)
    and (((mn = MnAdd) or (mn = MnSub) or (mn = MnCmp) or (mn = MnTest)
          or (mn = MnXor) or (mn = MnOr) or (mn = MnAnd) or (mn = MnNeg)
          or (mn = MnMul) or (mn = MnImul) or (mn = MnDiv) or (mn = MnIdiv))
         or (((mn = MnShl) or (mn = MnShr)) and ParseDecimalLiteral(op2, dummyVal)))
end;

{ IsFlagPreserving: TRUE for a mnemonic safe for NoOpArithSafe's own
  scan to skip straight past without stopping -- ONLY because it
  PROVABLY does not touch CF/ZF/SF/OF/PF at all on 8086 (MOV/PUSH/POP/
  LEA/LES/LDS/CWD). OPT.TXT A2's own "report unsafe at any branch
  (including JMP), label, call, return, interrupt" removes JMP/RETN/
  RETF/IRET/CALL/CALLFAR from this whitelist entirely -- the PRIOR
  version of this function (still visible in DOCS/TRBUG.MD's own
  history) treated all six as "safe to skip past" on the reasoning
  that nothing can fall through an unconditional transfer to reach
  whatever textually follows it, so scanning one step further and
  re-evaluating THAT slot on its own merits was "still correct." That
  reasoning is unsound for exactly the cases OPT.TXT's own verification
  list names: a JMP's own TARGET (reached via a completely different
  path than this textual scan) may read flags this add/sub itself
  left live, and CALL/RETURN cross a procedure boundary this pass has
  no visibility into at all (OPT.TXT: "A callee reading incoming
  flags, or a caller reading returned flags" -- treat conservatively
  without a proven ABI summary, which Stage A has none of). Removing
  all six here does not, on its own, make the scan look past a JMP's
  own target -- this function only ever governs whether the scan
  continues onto the NEXT slot; NoOpArithSafe's own default (below)
  already stops as unsafe on anything not in this narrower whitelist,
  which is exactly what's wanted now: an unconditional transfer of any
  kind ends the local scan's own knowledge, full stop, matching every
  other rule's "no data-flow analysis, stay conservative" bias. }
function IsFlagPreserving(kind: byte; mn: word): boolean;
begin
  IsFlagPreserving := (kind = TOpInstr)
    and ((mn = MnMov) or (mn = MnPush) or (mn = MnPop) or (mn = MnLea)
      or (mn = MnLes) or (mn = MnLds) or (mn = MnCwd))
end;

{ NoOpArithSafe: TRUE iff scanning forward from (right after) an add/
  sub's own slot never reaches a flag-reader (IsFlagReader) before
  either a flag-setter (IsFlagSetter -- flags already fresh again from
  there, so the original add/sub's own contribution is moot regardless)
  or the end of range. Only a narrow whitelist of mnemonics PROVABLY
  flag-preserving (IsFlagPreserving) is skipped over rather than
  stopping the scan -- anything not on that whitelist (a Jcc/OR/CMP/
  TEST via IsFlagReader, a flag-setter via IsFlagSetter, or anything
  else entirely -- MnPopf/MnInt/MnIret/MnPushf/MnRetn/MnRetf/MnJmp/
  MnCall/MnCallFar included, none of them provably flag-neutral)
  conservatively stops the scan as unsafe by default, matching every
  other rule's own "no data-flow analysis, stay conservative" bias --
  TOpAsm (raw inline ASM...END text) is included in that conservative
  default: its own content is opaque to this pass, so it stops the
  scan rather than being assumed flag-neutral.

  OPT.TXT A2: a TOpLabel now ALSO stops the scan as unsafe -- this
  reverses a PRIOR version of this function, which deliberately let
  the scan continue straight through a label (found via TESTS/
  RVFLAGS.SMD's own "AX := AX + 0" / "BX := 5" / "IF ZFLAG" case,
  where the old single-hop NextReal check missed an intervening MOV
  and had to be widened into this same forward scan). That prior
  fix's own reasoning -- "SPHO.PAS's own codegen never jumps into the
  middle of a flag-dependent sequence from elsewhere" -- only actually
  rules out a jump landing MID-SEQUENCE; it says nothing about a label
  being a genuine JOIN POINT reachable from some OTHER, unrelated
  branch elsewhere in the same procedure, whose own flags at that
  point could differ completely from whatever this add/sub itself
  left. Without real predecessor/dominance information (Stage D, not
  yet built), there is no sound way to tell "this label only has the
  one predecessor I'm scanning from" apart from "this label is a real
  merge of several different flag states" -- so OPT.TXT's own stricter
  rule is followed here even though it makes RVFLAGS.SMD's own
  specific fold fire less often (verified separately, see this file's
  own change notes / DOCS/TRBUG.MD): correctness over compactness,
  per this whole plan's own stated priority. }
function NoOpArithSafe(c: POpChunk; k: integer; endChunk: POpChunk; endSlot: integer): boolean;
  var op2Txt: string;
begin
  while Advance(c, k, endChunk, endSlot) do begin
    if (c^.ops[k].kind = TOpInstr) and (c^.ops[k].mnemonic = MnNop) then
      { deleted -- transparent, keep scanning }
    else if c^.ops[k].kind = TOpLabel then begin
      NoOpArithSafe := false; exit
    end else if c^.ops[k].kind = TOpAsm then begin
      { raw inline ASM...END text -- opaque, could do anything to
        flags; conservatively stop rather than assume it's safe to
        skip past. }
      NoOpArithSafe := false; exit
    end else if IsFlagReader(c^.ops[k].kind, c^.ops[k].mnemonic) then begin
      NoOpArithSafe := false; exit
    end else if (c^.ops[k].kind = TOpInstr)
                and ((c^.ops[k].mnemonic = MnShl) or (c^.ops[k].mnemonic = MnShr)) then begin
      StrTab.Get(c^.ops[k].op2, op2Txt);
      if IsFlagSetter(c^.ops[k].kind, c^.ops[k].mnemonic, op2Txt) then begin
        NoOpArithSafe := true; exit
      end else begin
        NoOpArithSafe := false; exit   { a variable (non-literal) shift
          count -- IsFlagSetter's own header comment has the full
          reasoning: a runtime count of 0 leaves ALL flags unchanged, a
          possibility this pass cannot rule out from the operand text
          alone, so this must stop the scan as unsafe, not skip past
          it as a trusted flag-fresh checkpoint. }
      end
    end else if IsFlagSetter(c^.ops[k].kind, c^.ops[k].mnemonic, '') then begin
      NoOpArithSafe := true; exit
    end else if (c^.ops[k].kind = TOpInstr)
                and not IsFlagPreserving(c^.ops[k].kind, c^.ops[k].mnemonic) then begin
      NoOpArithSafe := false; exit   { conservative default: anything not
        provably safe to skip past stops the scan as unsafe -- INC/DEC
        (no longer in IsFlagSetter's own whitelist at any operand, see
        its own header comment for why) fall through to here now,
        correctly stopping the scan rather than being trusted as a full
        flag reset. }
    end
    { else: a whitelisted flag-preserving TOpInstr -- keep scanning. }
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
  overwritten anyway.

  OPT.TXT A2: "Restrict NoOpArith to recognized general-purpose
  registers. Memory ADD/SUB zero still reads and writes memory; leave
  it unchanged." -- op1 is now resolved through Regs86.LookupReg
  (rejecting anything that isn't a genuine 8086 register name at all,
  including any '[...]' memory operand, a segment register, or
  malformed/unexpected text) before this rule ever considers folding
  it. Previously op1 was never checked at all: "ADD [somemem], 0"
  matched exactly the same as "ADD AX, 0" as long as op2 was the
  literal "0" and the flag scan passed, silently deleting a real
  memory read+write that a plain register no-op never has -- 8086's
  own "add [mem], 0" genuinely touches memory (a read-modify-write
  cycle) even though the VALUE never changes, which this rule must
  never remove. }
procedure NoOpArith(startChunk: POpChunk; startSlot: integer;
                     endChunk: POpChunk; endSlot: integer);
  var c: POpChunk; k: integer; opnd1, opnd2: string;
begin
  c := startChunk; k := startSlot;
  repeat
    if (c^.ops[k].kind = TOpInstr)
       and ((c^.ops[k].mnemonic = MnAdd) or (c^.ops[k].mnemonic = MnSub)) then begin
      StrTab.Get(c^.ops[k].op1, opnd1);
      StrTab.Get(c^.ops[k].op2, opnd2);
      if (Regs86.LookupReg(Util.UpStr(opnd1)) <> 0) and (opnd2 = '0')
         and NoOpArithSafe(c, k, endChunk, endSlot) then
        c^.ops[k].mnemonic := MnNop
    end
  until not Advance(c, k, endChunk, endSlot)
end;

{ ============================================================
  STAGE B: SHARED OPERAND AND EFFECT HELPERS (OPT.TXT S5)
  ============================================================
  Small TP7 records/helpers private to this unit, built on top of the
  Stage A rules above without changing any of them -- infrastructure
  for the bounded local rewrites Stage C (not yet implemented) will
  need, not a rewrite pass of its own. Nothing in Optimize/OptimizePass
  calls into this section yet; it exists to be exercised by its own
  regression tests (TESTS/STGB*.SMD) until a real Stage C rule
  consumes it. }


{ DecodeOperand: classify ONE operand's raw text (OPT.TXT S5's own
  "Classify register, immediate, supported memory, or unknown"). Reuses
  Regs86.LookupReg/IsByteReg/IsSegReg (OPT.TXT S5: "Reuse REGS86
  definitions") rather than re-deriving register identity from text a
  second, independent way. Accepts exactly the operand-text SHAPES this
  translator's own emitter (SPHO.PAS) actually produces -- a bare
  register name, a bare decimal/hex/'0x'-less numeric literal (this
  unit's own pre-existing ParseDecimalLiteral, unchanged, reused here
  too), or a '[...]' memory operand (optionally 'byte '/'word '-
  prefixed, MemOpndPrefix, already used by StoreReload above) -- ANY
  other shape (a label name used as a jump target reaching here by
  mistake, an unparsed expression, an EMPTY string) is OpKindUnknown,
  never guessed at ("Normalize only understood syntax; preserve
  unparsed expressions"). RegBitFor/DecodeBaseParts (immediately below)
  are its own small helpers, placed first since TP7 requires a
  procedure be declared before its first use. }
function RegBitFor(regId: integer; isByte: boolean): word;
begin
  case regId of
    Regs86.RegAX: RegBitFor := RegMaskAX;
    Regs86.RegBX: RegBitFor := RegMaskBX;
    Regs86.RegCX: RegBitFor := RegMaskCX;
    Regs86.RegDX: RegBitFor := RegMaskDX;
    Regs86.RegAL: RegBitFor := RegBitAL;
    Regs86.RegAH: RegBitFor := RegBitAH;
    Regs86.RegBL: RegBitFor := RegBitBL;
    Regs86.RegBH: RegBitFor := RegBitBH;
    Regs86.RegCL: RegBitFor := RegBitCL;
    Regs86.RegCH: RegBitFor := RegBitCH;
    Regs86.RegDL: RegBitFor := RegBitDL;
    Regs86.RegDH: RegBitFor := RegBitDH;
    Regs86.RegSI: RegBitFor := RegBitSI;
    Regs86.RegDI: RegBitFor := RegBitDI;
    Regs86.RegBP: RegBitFor := RegBitBP;
    Regs86.RegSP: RegBitFor := RegBitSP;
  else RegBitFor := RegMaskNone   { unreachable given the caller's own
                                      segment-register filter, but TP7's
                                      case needs an exhaustive result. }
  end
end;

{ DecodeBaseParts: walks a memory operand's own already-stripped base
  text (no '[', ']', or 'SEG:' prefix left -- DecodeOperand's own
  caller already removed those) for every '+'/'-'-separated piece,
  classifying each as either a register (added to addrMask) or a
  constant (accumulated as the running frame offset, signed by
  whichever separator preceded it). isFrame/frameOff are only ever set
  TRUE/meaningful when the WHOLE base text is exactly 'BP' optionally
  followed by one constant piece -- ANY other register present (even
  alongside BP, e.g. 'BP+SI-2') leaves isFrame FALSE, matching
  TOperand.isFrameObject's own documented narrow scope. }
procedure DecodeBaseParts(const baseTxt: string; var addrMask: word;
                           var isFrame: boolean; var frameOff: longint);
  var i, pieceStart: integer; piece: string; sign: integer;
      nOtherPieces, nValidDisp: integer;
      sawBp, ok: boolean;
  procedure HandlePiece(const p: string; pieceSign: integer);
    { wv, not a `word(v)` variable-typecast var-argument, is deliberate:
      TPC.EXE/emu2 miscompiles a `word(longintVar)` var-typecast used as
      a var-argument from inside a procedure NESTED inside another
      procedure that itself has a `var` parameter (reproduced in
      isolation -- the callee's own var-argument write lands on the
      wrong stack slot, corrupting the local); DecodeBaseParts is
      nested inside DecodeOperand's caller chain and takes var
      params itself, so it hits exactly that shape. A plain `word`
      local plus an explicit widening copy avoids the miscompile
      entirely and is exactly as correct. }
    var rid: integer; wv: word; v: longint;
  begin
    if p = '' then exit;
    rid := Regs86.LookupReg(Util.UpStr(p));
    if (rid <> 0) and not Regs86.IsSegReg(rid) then begin
      addrMask := addrMask or RegBitFor(rid, false);
      if Util.EqualICase(p, 'BP') then sawBp := true
      else nOtherPieces := nOtherPieces + 1   { a REAL index/base
        register other than BP (SI/DI/BX/...) -- e.g. "[BP+SI]" --
        counts against the shape but is NEVER a valid displacement, so
        nValidDisp is deliberately NOT incremented here; see this
        procedure's own header comment on the real bug this distinction
        fixes. }
    end else if ParseDecimalLiteral(p, wv) then begin
      v := wv;
      frameOff := frameOff + longint(pieceSign) * v;
      nOtherPieces := nOtherPieces + 1; nValidDisp := nValidDisp + 1
    end else
      nOtherPieces := nOtherPieces + 1   { unrecognized piece (garbage
        text, an unresolved symbol, anything ParseDecimalLiteral itself
        rejects) -- counts against the "exactly BP, optionally one
        constant" shape via nOtherPieces, but is NEVER a valid
        displacement either, so nValidDisp again stays untouched; see
        this procedure's own header comment. }
  end;
begin
  addrMask := RegMaskNone; isFrame := false; frameOff := 0;
  sawBp := false; nOtherPieces := 0; nValidDisp := 0;
  sign := 1; pieceStart := 1;
  for i := 1 to Length(baseTxt) + 1 do begin
    if (i > Length(baseTxt)) or (baseTxt[i] = '+') or (baseTxt[i] = '-') then begin
      piece := Copy(baseTxt, pieceStart, i - pieceStart);
      HandlePiece(piece, sign);
      if i <= Length(baseTxt) then begin
        if baseTxt[i] = '-' then sign := -1 else sign := 1;
        pieceStart := i + 1
      end
    end
  end;
  { "Exactly BP, optionally one constant displacement, magnitude within
    MaxFrameProof, and nothing else at all" -- the only shape
    TOperand.isFrameObject's own header comment promises.

    TWO real bugs here, found by external review and confirmed via an
    isolated driver: the ORIGINAL check was only "sawBp and (nOtherPieces
    <= 1)" -- nOtherPieces counted EVERY non-BP piece uniformly (a real
    index/base register, a valid constant, OR outright unrecognized
    garbage text), never distinguishing WHICH kind the (at most one)
    extra piece actually was. This let "[BP+SI]" (a genuinely INDEXED
    address -- SI could point ANYWHERE, making this NOT a private,
    non-aliasable frame slot at all, the one thing isFrameObject's own
    documented contract promises) report isFrameObject=TRUE, and
    "[BP+garbage]" (an unresolved/malformed piece ParseDecimalLiteral
    itself already correctly rejected as NOT a valid displacement) ALSO
    reported isFrameObject=TRUE purely because the comment's own claim
    "unrecognized piece... counts against the shape, so isFrame stays
    FALSE" was never actually WIRED to the final check -- nOtherPieces
    alone could not tell "one register" or "one garbage token" apart
    from "one real constant." Every Stage C/E rule that trusts
    isFrameObject (StoreForwarding/LoadModifyStore/
    FoldSavedOperandSelfDest/PropagateValues' own new R7 memory facts,
    among others) relies on it meaning "this exact memory location
    cannot alias anything else this analysis doesn't already know
    about" -- an indexed or malformed address wrongly proven "private"
    this way could let a rule forward/fold across a write that
    genuinely DOES touch the same real memory, a real correctness
    risk, not just a missed optimization. Fixed by requiring the (at
    most one) extra piece to be a PROVEN valid constant specifically
    (nValidDisp = nOtherPieces, not just nOtherPieces <= 1) -- any real
    index/base register OR any unrecognized text now correctly
    disqualifies isFrameObject, exactly as the header comment already
    claimed but the code never actually enforced. }
  ok := sawBp and (nOtherPieces <= 1) and (nValidDisp = nOtherPieces)
        and (frameOff >= -longint(MaxFrameProof)) and (frameOff <= longint(MaxFrameProof));
  isFrame := ok
end;

procedure DecodeOperand(const text: string; var o: TOperand);
  var bare, inner, segTxt, baseTxt, numTxt: string;
      regId, i, colonPos: integer; v: longint; neg: boolean;
begin
  o.kind := OpKindUnknown;
  o.regMask := RegMaskNone; o.isByte := false; o.isWord := false;
  o.segReg := 0; o.addrRegMask := RegMaskNone;
  o.isFrameObject := false; o.frameOffset := 0;
  o.rawText := text;
  bare := MemOpndPrefix(text);   { strip a leading 'byte '/'word ', if any --
                                     already used by StoreReload above; the
                                     size prefix itself isn't separately
                                     recorded here (a memory operand's own
                                     width isn't yet one of this record's
                                     own fields -- Stage C's own consumers
                                     can re-derive it from rawText when
                                     they actually need it; adding it here
                                     unused now would be exactly the
                                     "speculative field" this project's own
                                     Simplicity First rule warns against). }
  if bare = '' then exit;
  if bare[1] = '[' then begin
    if bare[Length(bare)] <> ']' then exit;   { malformed -- unknown }
    inner := Copy(bare, 2, Length(bare) - 2);
    o.kind := OpKindMem;
    { Explicit 'SEG:' override -- only ever the FIRST 2-3 characters
      before a ':' in this translator's own emitted memory-operand
      text (ParseMemOperand/EmitIndexedOperand, SPHO.PAS); a ':' any
      later than that never arises in a real operand this unit's own
      caller ever produced (no general expression syntax inside
      '[...]', SPHINX.MD's own documented address-syntax restriction),
      so the FIRST ':' found is unambiguous. }
    colonPos := 0;
    for i := 1 to Length(inner) do
      if (colonPos = 0) and (inner[i] = ':') then colonPos := i;
    if colonPos > 0 then begin
      segTxt := Util.UpStr(Copy(inner, 1, colonPos - 1));
      baseTxt := Copy(inner, colonPos + 1, Length(inner) - colonPos);
      o.segReg := Regs86.LookupReg(segTxt);
      if (o.segReg <> 0) and not Regs86.IsSegReg(o.segReg) then o.segReg := 0
    end else
      baseTxt := inner;
    { Address-register reads: scan baseTxt for every register NAME it
      contains (BX/BP/SI/DI, PLAN.TXT S2.1's own accepted base/index
      set -- the only registers this translator's own memory-operand
      text ever embeds) by splitting on '+'/'-', the same two
      separators TryParseEffAddr/ParseEffAddrTail (SPHO.PAS) ever
      produce between a base/index/displacement; each split piece is
      then either a known register name (added to addrRegMask) or
      itself a plain constant/offset (an already-folded RECORD field
      offset or displacement) -- ignored here, not misclassified as a
      register. A single trailing constant, or a plain frame-object
      base ('BP-2') with nothing else, is detected via this exact same
      per-piece walk, so isFrameObject/frameOffset below reuse its own
      result rather than re-parsing baseTxt a second time. }
    DecodeBaseParts(baseTxt, o.addrRegMask, o.isFrameObject, o.frameOffset);
    if o.segReg <> 0 then o.isFrameObject := false;   { an explicit
      'SEG:' override disqualifies isFrameObject even when the base
      text alone would otherwise look like a plain 'BP-N' frame
      reference (e.g. '[SS:BP-2]') -- TOperand.isFrameObject's own
      documented scope is "no other register, no index, no explicit
      segment override"; DecodeBaseParts only ever sees the
      already-stripped base text, so it cannot itself know whether a
      segment override preceded it. }
    exit
  end;
  regId := Regs86.LookupReg(Util.UpStr(bare));
  if regId <> 0 then begin
    if Regs86.IsSegReg(regId) then exit;   { a segment register operand
      (e.g. bare 'DS' as a MOV source) is real, but this record's own
      regMask layout has no bit for one at all (OPT.TXT S5 only ever
      asks for GENERAL register classification here -- a segment
      register's own read/write is instead folded directly into
      GetEffects' own per-mnemonic dispatch below, the same way PUSH/
      POP DS already is) -- OpKindUnknown here is deliberately
      conservative, not a real gap: nothing in this unit ever calls
      DecodeOperand on a bare segment-register operand expecting a
      regMask bit back. }
    o.kind := OpKindReg;
    o.isByte := Regs86.IsByteReg(regId);
    o.isWord := not o.isByte;
    o.regMask := RegBitFor(regId, o.isByte);
    exit
  end;
  if ParseDecimalLiteral(bare, word(v)) then begin
    o.kind := OpKindImm; exit
  end;
  { A hex/'H'-suffixed literal (this translator's own emitted immediates
    are always one of decimal or 'NNNNH' -- SPHO.PAS never emits a '0x'-
    prefixed or binary-suffixed form): try that shape too before giving
    up as unknown. }
  if (Length(bare) >= 2) and (UpStr(Copy(bare, Length(bare), 1)) = 'H') then begin
    numTxt := UpStr(Copy(bare, 1, Length(bare) - 1));
    if numTxt <> '' then begin
      v := 0; neg := false;
      for i := 1 to Length(numTxt) do
        if not (numTxt[i] in ['0'..'9', 'A'..'F']) then neg := true;
      if not neg then begin o.kind := OpKindImm; exit end
    end
  end;
  { A leading '-' (a negative displacement literal reaching here as a
    whole operand, not embedded inside '[...]') -- OperandText's own
    unary-minus fallback, SPHO.PAS -- is also a real immediate. }
  if (Length(bare) >= 2) and (bare[1] = '-') then begin
    numTxt := Copy(bare, 2, Length(bare) - 1);
    v := 0; neg := false;
    for i := 1 to Length(numTxt) do
      if not (numTxt[i] in ['0'..'9']) then neg := true;
    if (numTxt <> '') and not neg then begin o.kind := OpKindImm; exit end
  end
  { else: OpKindUnknown -- a label name, a StrTab-interned literal
    offset symbol (a string/BASE64 label), a RECORD.field text with no
    '[' wrapper (never actually emitted as a bare operand by this
    translator, but not assumed impossible here either), or anything
    else this function doesn't recognize. Left exactly as the
    all-zero/false default already set at entry. }
end;

{ GetEffects: OPT.TXT S5's own "Return register reads/writes, flag
  reads/definite writes, memory effects, stack effects, transfer kind,
  and knownness." Dispatches on op.mnemonic; op1/op2 are read via
  DecodeOperand (above) when the mnemonic's own shape needs to know
  what they are. TOpLabel/TOpAsm, and any TOpInstr mnemonic not
  explicitly listed below, produce known=FALSE (OPT.TXT S3: "Unknown
  instruction or operand effects reject a candidate") -- there is no
  partial-credit "I understood the mnemonic but not one operand" case;
  either the WHOLE operation is classified, or none of it is. }
const
  { AccountRW's own dstMode values -- see AccountRW's own header
    comment (below, inside GetEffects) for what each means. }
  DstWrite = 0; DstReadWrite = 1; DstReadOnly = 2;

procedure GetEffects(const op: TOperation; var e: TEffects);
  var o1, o2: TOperand; op1Txt, op2Txt: string;
  procedure MemOpAddrReads(const o: TOperand);
  begin
    if o.kind = OpKindMem then e.regRead := e.regRead or o.addrRegMask
  end;
  procedure MemOpEffect(const o: TOperand; eff: integer);
  begin
    if o.kind = OpKindMem then e.memEffect := eff
    else if o.kind = OpKindUnknown then e.known := false
  end;
  { AccountRW: the ordinary "dest, src" two-operand shape (MOV/ADD/SUB/
    AND/OR/XOR/ADC/SBB/CMP/TEST/LEA) -- src is always only read. dstMode
    says what dest itself is:
      DstWrite     -- pure write, never read first (MOV, LEA's own
                       general-register destination).
      DstReadWrite -- read-modify-write (ADD/SUB/AND/OR/XOR/ADC/SBB).
      DstReadOnly  -- read, never written (CMP/TEST).
    Either side may be OpKindMem (never both -- SPHO.PAS's own emitter,
    like real 8086, never produces a mem,mem pair; DecodeOperand
    doesn't enforce that itself, since it classifies one operand in
    isolation, but this translator's own callers already guarantee
    it). A memory dest's own ADDRESS registers are always a real read
    regardless of dstMode (computing WHERE to write is still a read of
    whatever registers form the address, even for a pure MOV-to-memory
    write) -- only the memory CELL's own read/write classification
    (memEffect) depends on dstMode. }
  procedure AccountRW(const dst, src: TOperand; dstMode: integer);
  begin
    if dst.kind = OpKindReg then begin
      if dstMode <> DstWrite then e.regRead := e.regRead or dst.regMask;
      if dstMode <> DstReadOnly then e.regWrite := e.regWrite or dst.regMask
    end else if dst.kind = OpKindMem then begin
      MemOpAddrReads(dst);
      case dstMode of
        DstWrite: MemOpEffect(dst, MemWrite);
        DstReadWrite: MemOpEffect(dst, MemReadWrite);
        DstReadOnly: MemOpEffect(dst, MemRead);
      end
    end else if dst.kind = OpKindUnknown then e.known := false;
    if src.kind = OpKindReg then e.regRead := e.regRead or src.regMask
    else if src.kind = OpKindMem then begin MemOpAddrReads(src); MemOpEffect(src, MemRead) end
    else if src.kind = OpKindUnknown then e.known := false
  end;
  { AccountUnary: a single read+write operand (INC/DEC/NEG/NOT/SHL/SHR/
    ROL/ROR/RCL/RCR with an implicit-1 or CL count -- the count itself,
    when a register, is accounted for separately by the caller, since
    CL is a READ, never a write, unlike the shifted/rotated operand
    itself). }
  procedure AccountUnary(const dst: TOperand);
  begin
    if dst.kind = OpKindReg then begin
      e.regRead := e.regRead or dst.regMask; e.regWrite := e.regWrite or dst.regMask
    end else if dst.kind = OpKindMem then begin
      MemOpAddrReads(dst); MemOpEffect(dst, MemReadWrite)
    end else if dst.kind = OpKindUnknown then e.known := false
  end;
begin
  e.known := false;
  e.regRead := RegMaskNone; e.regWrite := RegMaskNone;
  e.flagRead := FlagMaskNone; e.flagWrite := FlagMaskNone;
  e.memEffect := MemUnknown; e.stackDelta := 0; e.transferKind := XferNone;
  if op.kind <> TOpInstr then exit;   { TOpLabel/TOpAsm: always unknown --
    a raw ASM line's own effects are opaque by definition (this unit's
    own pre-existing convention throughout Stage A); a label has no
    effects of its own to report, but "known effects: none" is not the
    same claim as "this location is safe to reason about," so it stays
    unknown here too, letting every caller's own barrier logic treat it
    uniformly rather than needing a THIRD case beside known/unknown. }
  if op.mnemonic = MnNop then begin e.known := true; e.memEffect := MemNone; exit end;
  StrTab.Get(op.op1, op1Txt); StrTab.Get(op.op2, op2Txt);
  DecodeOperand(op1Txt, o1); DecodeOperand(op2Txt, o2);
  e.known := true; e.memEffect := MemNone;   { overwritten below by
    whichever branch actually runs; a mnemonic this dispatch never
    reaches at all falls through to the final "else e.known := false"
    with these two defaults harmlessly unused. }
  case op.mnemonic of
    MnMov: AccountRW(o1, o2, DstWrite);
    MnAdd, MnSub, MnAnd, MnOr, MnXor, MnAdc, MnSbb: begin
      AccountRW(o1, o2, DstReadWrite);
      e.flagWrite := FlagMaskArith;
      if (op.mnemonic = MnAdc) or (op.mnemonic = MnSbb) then e.flagRead := FlagCF
    end;
    MnCmp, MnTest: begin AccountRW(o1, o2, DstReadOnly); e.flagWrite := FlagMaskArith end;
    MnInc, MnDec: begin
      AccountUnary(o1);
      { INC/DEC set PF/AF/ZF/SF/OF but leave CF UNCHANGED on real 8086
        -- OPT.TXT A2's own explicit note, "INC/DEC preserve CF", is
        honored here directly: FlagCF is deliberately absent from this
        flagWrite mask (unlike FlagMaskArith, which every OTHER
        arithmetic mnemonic above uses). }
      e.flagWrite := FlagPF or FlagAF or FlagZF or FlagSF or FlagOF
    end;
    MnNeg: begin AccountUnary(o1); e.flagWrite := FlagMaskArith end;
    MnShl, MnShr: begin
      AccountUnary(o1);
      { A shift's own count operand (o2, e.g. '1' or 'cl') is a READ
        only, never a write -- CL specifically is a real register read
        when present (OPT.TXT S5's own "implicit operands... CX... for
        string operations" names CX by name for string ops, but a
        variable-count shift's own CL read is exactly the same shape,
        an implicit-by-convention operand this dispatch must not
        silently drop). A literal count (the overwhelmingly common
        case, '1') contributes no register read at all, correctly. }
      if o2.kind = OpKindReg then e.regRead := e.regRead or o2.regMask;
      { A REAL bug, found by external review and confirmed via an
        isolated driver: this case previously claimed flagWrite :=
        FlagMaskArith UNCONDITIONALLY, even for a variable (CL) count
        -- but "count might be zero" is not just a theoretical OPT.TXT
        warning, it is real 8086 behavior: a shift by a runtime count
        of 0 leaves EVERY flag completely unchanged. Claiming a
        definite flagWrite here that might not actually happen is
        exactly the same class of unsoundness IsFlagSetter's own
        matching fix (Stage A, OPT.TXT R7/review finding 1) already
        addressed for NoOpArithSafe -- LocalDeadAfter (and everything
        built on it: ComputeLiveness, PropagateValues, BuildCallGraph's
        own demand analysis) could wrongly "prove" flags dead across a
        SHL/SHR reg,CL that turns out to have count=0 at runtime,
        exactly the false-positive pattern review finding 2 already
        caught for control transfers -- same root cause, different
        code path. o2.kind = OpKindImm is EXACTLY "this operand was
        successfully decoded as a decimal/hex/negative literal"
        (DecodeOperand's own classification, no second parse needed
        here) -- a proven immediate count always performs the real
        shift and its own real flag write (a literal count of 0 would
        be genuinely pointless codegen this translator never emits,
        and any real nonzero immediate count always writes flags for
        real); reporting FlagMaskNone (not "no flags exist", but "no
        flags PROVEN written by this operation alone") for the CL form
        is the safe direction for every consumer here: "not proven
        written" only ever means "still need to prove it read/dead
        some other way," never "provably still holds its OLD value
        either" -- so this can only make downstream analysis MORE
        conservative, never less sound. }
      if o2.kind = OpKindImm then e.flagWrite := FlagMaskArith
      else e.flagWrite := FlagMaskNone
    end;
    MnRol, MnRor, MnRcl, MnRcr: begin
      AccountUnary(o1);
      if o2.kind = OpKindReg then e.regRead := e.regRead or o2.regMask;
      { ROL/ROR/RCL/RCR set CF (the bit rotated out); OF is defined
        only for a single-bit rotate (the only form this translator's
        own ROL/ROR/RCL/RCR statement syntax accepts, PLAN.TXT S2.4 --
        "a count of 1 or CL", and a CL count of exactly 1 shares the
        same single-bit guarantee) -- PF/AF/ZF/SF are LEFT UNCHANGED
        by a rotate on real 8086, unlike an ordinary shift. RCL/RCR
        additionally READ the incoming CF (OPT.TXT S3's own explicit
        "carry rotates read CF"). }
      e.flagWrite := FlagCF or FlagOF;
      if (op.mnemonic = MnRcl) or (op.mnemonic = MnRcr) then e.flagRead := FlagCF
    end;
    MnLea: begin
      { LEA's own "src" is a memory operand used for its ADDRESS only --
        real 8086 LEA never actually reads the memory cell itself, only
        computes it, so AccountRW's own ordinary src-is-memory path
        (which always claims a MemRead) is not used here: the address
        registers are read (MemOpAddrReads), but memEffect is left at
        MemNone, and dest is DstWrite (LEA never reads its own
        destination first). }
      if o1.kind = OpKindReg then e.regWrite := e.regWrite or o1.regMask
      else if o1.kind = OpKindUnknown then e.known := false;
      if o2.kind = OpKindMem then MemOpAddrReads(o2)
      else if o2.kind = OpKindUnknown then e.known := false
    end;
    MnLes, MnLds: begin
      { LES/LDS read a DWORD from memory (offset:segment) and write
        BOTH the general register (o1) and the matching segment
        register (ES/DS) -- the segment-register write has no regMask
        bit of its own (DecodeOperand's own documented scope), so it's
        not separately recorded here; memEffect still correctly shows
        a real memory READ (unlike LEA, which never touches memory at
        all despite the superficially similar '[...]' source operand). }
      if o1.kind = OpKindReg then begin e.regRead := e.regRead or o1.regMask; e.regWrite := e.regWrite or o1.regMask end
      else if o1.kind = OpKindUnknown then e.known := false;
      MemOpAddrReads(o2); MemOpEffect(o2, MemRead)
    end;
    MnPush: begin
      { A real bug, found by external review and confirmed reachable:
        "PUSH word [bp+N]" (a real, DOCUMENTED emission shape --
        SRC/SPHO.PAS's own EmitCall, pushing a local VAR memory
        argument directly rather than routing it through AX first, to
        avoid clobbering a register-pair argument's own live AX half)
        never accounted for the SOURCE memory operand's own address-
        register reads (MemOpAddrReads) or its own memory READ
        (MemOpEffect...MemRead) at all -- only the STACK write below.
        BP (for a proven frame object) or any other base/index register
        the pushed operand's own address depends on could be wrongly
        "proven dead" across a PUSH that genuinely still needs it to
        compute the address being pushed. }
      if o1.kind = OpKindReg then e.regRead := e.regRead or o1.regMask
      else if o1.kind = OpKindMem then begin MemOpAddrReads(o1); MemOpEffect(o1, MemRead) end
      else if o1.kind = OpKindUnknown then e.known := false;
      { The memEffect above (if o1 was OpKindMem) already reflects the
        SOURCE read; the stack write below is a SEPARATE effect (this
        record has only one memEffect field, so a PUSH of a memory
        operand -- read source, write stack -- is reported as
        MemReadWrite, the most conservative honest answer when BOTH
        happen, same as any other genuine read-modify-write shape this
        table already reports that way elsewhere). }
      if (o1.kind = OpKindMem) and (e.memEffect = MemRead) then e.memEffect := MemReadWrite
      else e.memEffect := MemWrite;
      e.stackDelta := -2
    end;
    MnPop: begin
      if o1.kind = OpKindReg then e.regWrite := e.regWrite or o1.regMask
      else if o1.kind = OpKindUnknown then e.known := false;
      e.memEffect := MemRead; e.stackDelta := 2
    end;
    MnPushf: begin e.flagRead := FlagMaskArith or FlagDF or FlagIF; e.memEffect := MemWrite; e.stackDelta := -2 end;
    MnPopf: begin e.flagWrite := FlagMaskArith or FlagDF or FlagIF; e.memEffect := MemRead; e.stackDelta := 2 end;
    MnCwd: begin e.regRead := RegMaskAX; e.regWrite := RegMaskDX end;
    MnMul, MnImul: begin
      { AX * o1 -> DX:AX for the WORD form (this translator's own
        EmitMulDiv only ever emits the one-operand form) -- OPT.TXT S8's
        own explicit warning, "MUL/DIV and signed variants are not
        blanket known flag replacements," is honored by leaving
        flagWrite at FlagMaskNone (the default) rather than claiming a
        fresh, fully-known result the way ADD/SUB's own FlagMaskArith
        does; MUL/IMUL do define CF/OF (set iff the upper half is
        significant) but leave PF/AF/ZF/SF architecturally undefined,
        so no SINGLE mask here could honestly claim "these flags are
        now fresh" without silently overclaiming the undefined ones
        too -- flagWrite stays empty, deliberately less precise than
        it could be, rather than wrong.

        A REAL bug, found by external review and confirmed reachable:
        a BYTE-width MUL/IMUL (o1 a byte register, e.g. "MUL AL" --
        real, reachable SPHINX codegen via LoadMulDivOperand's own
        "if SymTab.IsRegName(opnd) then dst := opnd" branch, when a
        SPHINX '*' expression's own RHS is written as a bare byte
        register directly, SRC/SPHO.PAS) computes AL * o1 -> AX ONLY --
        it does NOT touch DX at all, unlike the WORD form (AX * o1 ->
        DX:AX). Unconditionally claiming regWrite includes DX here was
        a real over-claim in the UNSAFE direction: LocalDeadAfter could
        wrongly "prove" DX freshly overwritten (and therefore dead)
        across a byte MUL that never actually touched it, when DX's
        own OLD value is genuinely still there. Also narrowed the
        implicit AX read to just AL for a byte-width MUL (AH is never
        read by the byte form) -- the safe over-claim direction, kept
        narrower here purely for precision, not because the wider
        claim was itself unsound. }
      if (o1.kind = OpKindReg) and o1.isByte then e.regRead := RegBitAL
      else e.regRead := RegMaskAX;
      if o1.kind = OpKindReg then e.regRead := e.regRead or o1.regMask
      else if o1.kind = OpKindMem then begin MemOpAddrReads(o1); MemOpEffect(o1, MemRead) end
      else if o1.kind = OpKindUnknown then e.known := false;
      if (o1.kind = OpKindReg) and o1.isByte then e.regWrite := RegMaskAX
      else e.regWrite := RegMaskAX or RegMaskDX
    end;
    MnDiv, MnIdiv: begin
      { Same byte-vs-word distinction as MnMul/MnImul immediately above
        -- a byte-width DIV/IDIV (o1 a byte register, e.g. "DIV BL")
        computes AX / o1 -> AL=quotient, AH=remainder; it reads only AX
        (not DX) and writes only AX (both halves, via AL/AH) -- DX is
        neither read nor written at all by the byte form, unlike the
        WORD form (DX:AX / o1 -> AX=quotient, DX=remainder). The SAME
        real over-claim bug MnMul/MnImul had (found by external review):
        unconditionally including DX in both regRead and regWrite let
        LocalDeadAfter wrongly "prove" DX dead/fresh across a byte DIV
        that never touched it at all. }
      if (o1.kind = OpKindReg) and o1.isByte then e.regRead := RegMaskAX
      else e.regRead := RegMaskAX or RegMaskDX;
      if o1.kind = OpKindReg then e.regRead := e.regRead or o1.regMask
      else if o1.kind = OpKindMem then begin MemOpAddrReads(o1); MemOpEffect(o1, MemRead) end
      else if o1.kind = OpKindUnknown then e.known := false;
      if (o1.kind = OpKindReg) and o1.isByte then e.regWrite := RegMaskAX
      else e.regWrite := RegMaskAX or RegMaskDX   { quotient in AX, remainder
        in DX (word form) -- both genuinely written on every non-trapping
        DIV/IDIV; a real divide-by-zero/overflow trap is an INT0, a
        transfer this record has no separate way to express (DIV/IDIV
        themselves are NOT classified as XferNone-breaking here,
        matching this whole table's own "ordinary case" bias -- Stage
        C's own eventual E5 constant-division work is exactly where
        that nuance would actually matter, not here). }
    end;
    MnRetn, MnRetf: begin e.transferKind := XferReturn; e.memEffect := MemRead end;
    MnCallFar, MnCall: begin
      { A CALL of any kind crosses into code this unit has NO visibility
        into at all -- OPT.TXT S3's own explicit "Calls...may observe
        registers and flags. Without an explicit proven ABI summary,
        treat them conservatively" -- so despite being a real,
        classified mnemonic, this is the ONE case in the whole table
        that deliberately reports known=FALSE anyway: every other
        field here would otherwise need to claim "reads/writes
        EVERYTHING", which is both true and useless (a caller checking
        known=FALSE already stops, without needing a maximal mask to
        also carry). }
      e.known := false; e.transferKind := XferCall
    end;
    MnJmp: e.transferKind := XferJump;
    MnJe, MnJne, MnJl, MnJge, MnJg, MnJle, MnJb, MnJae, MnJa, MnJbe: begin
      e.transferKind := XferCondJump; e.flagRead := FlagMaskArith
    end;
    MnJc, MnJnc: begin e.transferKind := XferCondJump; e.flagRead := FlagCF end;
    MnJz, MnJnz: begin e.transferKind := XferCondJump; e.flagRead := FlagZF end;
    MnCld, MnStd: e.flagWrite := FlagDF;
    MnSti, MnCli: e.flagWrite := FlagIF;
    MnStc, MnClc: e.flagWrite := FlagCF;
    MnLodsb: begin e.regRead := RegBitSI; e.regWrite := RegBitAL or RegBitSI; e.memEffect := MemRead end;
    MnLodsw: begin e.regRead := RegBitSI; e.regWrite := RegMaskAX or RegBitSI; e.memEffect := MemRead end;
    MnStosb: begin e.regRead := RegBitAL or RegBitDI; e.regWrite := RegBitDI; e.memEffect := MemWrite end;
    MnStosw: begin e.regRead := RegMaskAX or RegBitDI; e.regWrite := RegBitDI; e.memEffect := MemWrite end;
    MnRepStosb: begin
      e.regRead := RegBitAL or RegBitDI or RegMaskCX;
      e.regWrite := RegBitDI or RegMaskCX; e.memEffect := MemWrite
    end;
    MnRepStosw: begin
      e.regRead := RegMaskAX or RegBitDI or RegMaskCX;
      e.regWrite := RegBitDI or RegMaskCX; e.memEffect := MemWrite
    end;
    MnMovsb: begin e.regRead := RegBitSI or RegBitDI; e.regWrite := RegBitSI or RegBitDI; e.memEffect := MemReadWrite end;
    MnMovsw: begin e.regRead := RegBitSI or RegBitDI; e.regWrite := RegBitSI or RegBitDI; e.memEffect := MemReadWrite end;
    MnRepMovsb, MnRepMovsw: begin
      e.regRead := RegBitSI or RegBitDI or RegMaskCX;
      e.regWrite := RegBitSI or RegBitDI or RegMaskCX; e.memEffect := MemReadWrite
    end;
    MnInB: begin
      { A real bug, found by external review and confirmed reachable:
        the port operand (o2 here -- SPHO.PAS's own TryEmitInPort emits
        "AppendInstr2(MnInB, 'al', portOpnd)", value first, port
        second) can genuinely be DX (DOCS/SPHINX.MD's own INPORTB(DX)/
        OUTPORTB(DX,...) form, ParsePortOperand explicitly accepting
        "DX or an immediate 0..255") -- when it is, DX SELECTS the port
        being read, a real register READ this case never accounted for
        at all, only the implicit AL write. An immediate port number
        contributes no register read, correctly. }
      e.regWrite := RegBitAL;
      if o2.kind = OpKindReg then e.regRead := e.regRead or o2.regMask
    end;
    MnInW: begin
      e.regWrite := RegMaskAX;
      if o2.kind = OpKindReg then e.regRead := e.regRead or o2.regMask
    end;
    MnOutB: begin
      { Same DX-selects-the-port gap as MnInB/MnInW above, mirrored:
        here the port is o1 (SPHO.PAS's own ParseOutPortStmt emits
        "AppendInstr2(mn, portOpnd, 'al')", port first, value second). }
      e.regRead := RegBitAL;
      if o1.kind = OpKindReg then e.regRead := e.regRead or o1.regMask
    end;
    MnOutW: begin
      e.regRead := RegMaskAX;
      if o1.kind = OpKindReg then e.regRead := e.regRead or o1.regMask
    end;
    MnIret: begin
      e.transferKind := XferReturn; e.memEffect := MemRead;
      e.regWrite := RegMaskAX or RegMaskBX or RegMaskCX or RegMaskDX
        or RegBitSI or RegBitDI or RegBitBP or RegBitSP;   { conservative:
        an interrupt handler's own real effects are entirely opaque to
        this translator (SPHO.PAS's own INTERRUPT procedure support has
        no callee-summary mechanism at all) -- IRET itself only pops
        IP/CS/FLAGS, but whatever ran BEFORE it (the handler body) is
        exactly as unknowable as a CALL's own callee, so the safest
        conservative stance here is "assume the handler could have
        written anything", not "IRET itself writes nothing." }
      e.flagWrite := FlagMaskArith or FlagDF or FlagIF
    end;
  else
    e.known := false   { every Mn* not explicitly listed above (there
      is no such mnemonic left in Types.PAS's own table today, but a
      future addition landing here with no matching branch yet must
      fail closed, not silently fall through as "known, no effects"). }
  end
end;

{ LocalDeadAfter: OPT.TXT S5's own "Scan one straight-line region.
  Reject on read, barrier, or range end before overwrite. Handle
  overlapping register masks and flags." Starting immediately AFTER
  (c,k) (never including it), proves regMask/flagMask are BOTH fully
  dead -- every bit in regMask has been overwritten (never read first)
  and no bit in flagMask is read before something overwrites ALL of it
  -- by or before reaching the end of [.., endChunk/endSlot]. A
  register bit is only ever cleared from the "still need proof" set by
  a WRITE that does not also appear as a READ on that same operation
  (AccountRW's own "read+write" shape, e.g. "ADD reg,src" reading its
  own destination, must NOT count as proof reg is dead going forward);
  a flag bit is cleared by any definite flagWrite covering it,
  regardless of whether that same operation also reads a DIFFERENT
  flag bit not yet proven dead. Reaching a barrier (known=FALSE from
  GetEffects, i.e. TOpLabel/TOpAsm/CALL/anything unrecognized) with
  either mask still nonzero returns FALSE -- OPT.TXT S3's own "Without
  an explicit proven ABI summary, treat them conservatively... Unknown
  instruction or operand effects reject a candidate," and this
  function's own single entry point for every caller's own barrier
  handling, so no Stage C rule needs to re-derive "is this a barrier"
  on its own. }
function LocalDeadAfter(c: POpChunk; k: integer; endChunk: POpChunk; endSlot: integer;
                         regMask, flagMask: word): boolean;
  var reachedEnd: boolean;
begin
  LocalDeadAfter := LocalDeadAfterEx(c, k, endChunk, endSlot, regMask, flagMask, reachedEnd)
end;

function LocalDeadAfterEx(c: POpChunk; k: integer; endChunk: POpChunk; endSlot: integer;
                           regMask, flagMask: word; var reachedRangeEnd: boolean): boolean;
  var eff: TEffects; needReg, needFlag: word;
begin
  reachedRangeEnd := false;
  needReg := regMask; needFlag := flagMask;
  while Advance(c, k, endChunk, endSlot) do begin
    if (c^.ops[k].kind = TOpInstr) and (c^.ops[k].mnemonic = MnNop) then
      { deleted -- transparent, keep scanning, same convention every
        Stage A scan (NoOpArithSafe) already established. }
    else if c^.ops[k].kind = TOpLabel then
      { ALSO transparent -- a bare label has no register/flag effect of
        its own. Made transparent for OPT.TXT's own R9 finding
        (LoadModifyStoreProc's own real target shape, SPHO.PAS's own
        ".return:" epilogue label immediately before a bare RETN,
        previously an unconditional hard barrier that made this
        composition's own reachedRangeEnd-gated CFG fallback
        unreachable for the single most common real shape it exists
        for).

        Soundness: this scan's own [c,k..endChunk,endSlot] bound is
        always exactly one PROCEDURE's own operation range (every
        caller passes the SAME endChunk/endSlot the enclosing
        Optimize/OptimizePass call itself received) -- SPHINX Oberon
        has no cross-procedure goto, so any REAL jump that could ever
        target a label inside this range must itself ALSO be a real
        operation somewhere inside this SAME range. If that jump sits
        AFTER (c,k) in scan order, the scan will walk onto it before
        finishing and correctly hard-stop there regardless of any
        label's own opacity (the transferKind check below, unrelated
        to this one). If it sits BEFORE (c,k) -- i.e. outside what this
        particular call is even looking at -- it was ALREADY outside
        this scan's own visibility before this change, opaque label or
        not: a plain linear walk starting at (c,k) never looks
        backward, so a predecessor jump landing on some label the scan
        walks THROUGH was never actually detected by the label's own
        opacity either, only ever by whatever wrote (c,k)'s own
        starting point being a genuinely fresh write in the first
        place (each caller's own separate proof, e.g. matching a MOV
        that just wrote the tracked register/set the tracked flags).
        Confirmed via three isolated driver reproductions before
        applying this change: (1) a real jump found LATER in the same
        scanned range still correctly blocks (its own transferKind
        check fires, independent of the label removed here); (2) a
        harder shape where the scan starts AFTER an earlier real
        branch targeting a label it will walk through still correctly
        reads whatever real instruction sits at that label (the label
        itself contributes nothing either way); (3) a label with no
        real predecessor at all, immediately followed by a full
        overwrite of the tracked bits, now correctly reports dead
        (previously incorrectly blocked by the label's own opacity
        alone, with nothing else in the scan ever justifying that
        block). }
    else begin
      GetEffects(c^.ops[k], eff);
      if not eff.known then begin LocalDeadAfterEx := false; exit end;
      { A real, previously-unchecked bug (an isolated TP7 driver
        confirmed the actual false-positive, not just a theoretical
        read of the code): this scan is a plain LINEAR walk through the
        operation LIST in textual/append order -- it has no CFG, no
        idea where a real transfer actually goes. GetEffects reports
        known=TRUE with regRead/regWrite=0 for an ordinary JMP/Jcc/RETN
        (its own register effects genuinely are none -- only its OWN
        transferKind marks it as a real branch), so this scan
        previously treated a JMP as fully transparent and kept walking
        STRAIGHT PAST it into whatever text happens to follow -- which
        is NEVER ACTUALLY EXECUTED via fall-through once an
        UNCONDITIONAL transfer diverts control elsewhere. "JMP .outside;
        MOV BX,0" wrongly "proved" BX dead by treating the dead,
        unreachable "MOV BX,0" as a real overwrite -- the MOV never
        runs at all. A conditional Jcc has the SAME problem in the
        other direction (its own FALL-THROUGH text, when taken, is
        never reached either) -- this scan has no way to distinguish
        "definitely proven dead on every path" from "proven dead only
        on the one textual path this linear walk happens to trace," so
        ANY real transfer (transferKind <> XferNone -- JMP/Jcc/CALL/
        RETN/RETF/IRET alike) must be treated as a hard barrier here,
        exactly like an unknown instruction already is. A caller that
        genuinely needs to follow real control flow (BuildCfg/
        ComputeLiveness's own proper backward dataflow, Stage D) has
        that machinery separately; this simple linear scan does not,
        and must not pretend to. }
      if eff.transferKind <> XferNone then begin
        { A real transfer is a hard barrier UNLESS this position IS the
          scan's own final position (c=endChunk, k=endSlot) -- a real,
          previously-latent bug found while building OPT.TXT's own R9
          finding: a caller scoping this scan to a range that legitimately
          ENDS at a RETN/RETF/IRET (e.g. LoadModifyStoreProc's own
          [sc,sk..endChunk,endSlot], where endChunk/endSlot is simply
          "the rest of this procedure," often a bare RETN) had that RETN
          itself treated as an ordinary mid-scan barrier
          (reachedRangeEnd staying FALSE, "a definitive live-proof"),
          even though "the scan legitimately can't see past its own
          given range" is EXACTLY what reachedRangeEnd=TRUE means --
          this is genuine inconclusiveness (ask the CFG), not a
          definitive live-proof, since nothing BEYOND the boundary was
          ever in scope to prove anything about in the first place. A
          transfer found BEFORE the scan's own final position (a real
          JMP/Jcc/CALL/RETN sitting in the MIDDLE of the given range)
          is still correctly treated as a hard, non-range-end barrier:
          this linear scan has no CFG and genuinely cannot see past it. }
        if (c = endChunk) and (k = endSlot) then begin
          reachedRangeEnd := true; LocalDeadAfterEx := false; exit
        end;
        LocalDeadAfterEx := false; exit
      end;
      if (needReg and eff.regRead) <> 0 then begin LocalDeadAfterEx := false; exit end;
      if (needFlag and eff.flagRead) <> 0 then begin LocalDeadAfterEx := false; exit end;
      needReg := needReg and not eff.regWrite;
      needFlag := needFlag and not eff.flagWrite;
      if (needReg = 0) and (needFlag = 0) then begin LocalDeadAfterEx := true; exit end
    end
  end;
  reachedRangeEnd := true;
  LocalDeadAfterEx := false   { range ended with something still
    unproven -- OPT.TXT S5's own "Reject on...range end before
    overwrite": reaching the end of what this pass can see is NOT
    the same as proving the value dead (something outside this
    procedure-local range -- the epilogue, another procedure the
    control flow could reach -- might still read it). }
end;

{ ============================================================
  STAGE C: BOUNDED LOCAL REWRITES (OPT.TXT S6) -- C4 ONLY
  ============================================================
  C4 ("Simple register, branch, and arithmetic cleanup") needs no
  save-pair/frame-object metadata at all -- unlike C1-C3 (folding a
  compiler-generated PUSH/MOV/ADD/POP scratch-save sequence), every C4
  match is provable from the operation stream alone, the same
  "compare operand text/mnemonics, no data-flow analysis" shape every
  Stage A rule already uses. C1-C3 are deferred to a later change,
  once the emitter metadata they require (generated-save-pair
  identity, frame-object escape status) exists.

  Six matches, each its own small procedure below, all called from
  OptimizePass in the order OPT.TXT S6 itself lists last ("Run local
  deletion/shortening to stability... Run fall-through cleanup after
  threading, then DeadCode"): the six C4 matchers first (deletion/
  shortening), then RemoveDeadBranch a second implicit time via
  Optimize's own existing two-OptimizePass-call structure (the same
  "two passes catch what's been observed, not a general fixed-point"
  approach every Stage A rule already relies on -- OPT.TXT's own "Do
  not assume two rounds handle arbitrary input" is honored the same
  way Stage A already honors it: each individual matcher is
  idempotent and safe to under-fire, never wrong to run again), then
  DeadCode (already called from OptimizePass, unchanged). }

{ RemoveMovRR: "MOV r,r" (the exact same register on both sides,
  compared by NAME, not by overlap -- OPT.TXT C4's own "delete for
  recognized 8/16-bit general-purpose registers" is a same-register
  match, not a same-BIT-range match) is a pure no-op: the value was
  already there. Both operands are validated through Regs86.LookupReg
  first, rejecting anything that isn't a genuine general-purpose
  register at all (a memory operand, malformed text) and excluding SP
  (OPT.TXT's own explicit "initially excluding SP" -- SP's own value
  is never something this pass reasons about the liveness of, and a
  literal "MOV SP,SP" is not a shape this codegen is known to ever
  produce anyway, so there is no real win to chase there, only
  unnecessary risk). A segment register (DS/ES/CS/SS) is also excluded
  by the same LookupReg-then-general-purpose-range check -- "MOV
  DS,DS" is a real, legal 8086 instruction that this rule has no
  evidence this codegen ever emits, so it is simply never matched
  rather than assumed safe. }
procedure RemoveMovRR(startChunk: POpChunk; startSlot: integer;
                       endChunk: POpChunk; endSlot: integer);
  var c: POpChunk; k: integer; opnd1, opnd2: string; regId: integer;
begin
  c := startChunk; k := startSlot;
  repeat
    if (c^.ops[k].kind = TOpInstr) and (c^.ops[k].mnemonic = MnMov) then begin
      StrTab.Get(c^.ops[k].op1, opnd1);
      StrTab.Get(c^.ops[k].op2, opnd2);
      if Util.EqualICase(opnd1, opnd2) then begin
        regId := Regs86.LookupReg(Util.UpStr(opnd1));
        if (regId <> 0) and (regId <> Regs86.RegSP) and not Regs86.IsSegReg(regId) then
          c^.ops[k].mnemonic := MnNop
      end
    end
  until not Advance(c, k, endChunk, endSlot)
end;

{ RemoveMovSwapBack: "MOV a,b; MOV b,a" immediately adjacent (NextReal,
  same "skip already-nop'd operations" convention every other matcher
  here uses) -- the second MOV restores b to the value it already had
  before the first MOV ever ran (a<-b then b<-a really means b ends up
  holding its OWN original value again), so it is dead purely on
  machine-state grounds, independent of what a/b are used for
  afterward: b's FINAL value after both instructions is provably
  identical to its value before either ran. Requires a and b be
  DISTINCT, NONOVERLAPPING, same-width general-purpose registers
  (RegBitFor's own bitmask -- reused from Stage B -- makes "distinct
  AND nonoverlapping" one bitwise AND-is-zero check, so "MOV AX,BX;
  MOV BX,AX" matches but "MOV AL,BL; MOV BL,AL" does NOT if BL would
  somehow overlap AL, which it never does on 8086, and "MOV AX,AL"
  itself is never a real instruction shape this codegen emits, so the
  overlap check here is mostly a defensive belt for any future operand
  shape, not a case observed today), excluding SP -- same reasoning as
  RemoveMovRR. }
procedure RemoveMovSwapBack(startChunk: POpChunk; startSlot: integer;
                             endChunk: POpChunk; endSlot: integer);
  var c, nc: POpChunk; k, nk: integer; a, b, a2, b2: string;
      regA, regB: integer;
begin
  c := startChunk; k := startSlot;
  repeat
    if (c^.ops[k].kind = TOpInstr) and (c^.ops[k].mnemonic = MnMov) then begin
      StrTab.Get(c^.ops[k].op1, a);
      StrTab.Get(c^.ops[k].op2, b);
      regA := Regs86.LookupReg(Util.UpStr(a));
      regB := Regs86.LookupReg(Util.UpStr(b));
      if (regA <> 0) and (regB <> 0) and (regA <> Regs86.RegSP) and (regB <> Regs86.RegSP)
         and not Regs86.IsSegReg(regA) and not Regs86.IsSegReg(regB)
         and (Regs86.IsByteReg(regA) = Regs86.IsByteReg(regB))
         and ((RegBitFor(regA, Regs86.IsByteReg(regA)) and RegBitFor(regB, Regs86.IsByteReg(regB))) = 0) then begin
        nc := c; nk := k;
        if NextReal(nc, nk, endChunk, endSlot) and (nc^.ops[nk].kind = TOpInstr)
           and (nc^.ops[nk].mnemonic = MnMov) then begin
          StrTab.Get(nc^.ops[nk].op1, a2);
          StrTab.Get(nc^.ops[nk].op2, b2);
          if Util.EqualICase(a2, b) and Util.EqualICase(b2, a) then
            nc^.ops[nk].mnemonic := MnNop
        end
      end
    end
  until not Advance(c, k, endChunk, endSlot)
end;

{ RemoveDeadConstMov: "MOV r,K1; MOV r,K2" immediately adjacent, same
  register, same width, BOTH operands decoded numeric literals
  (ParseDecimalLiteral -- the exact shape a plain WORD/BYTE constant
  MOV emits; "partial overwrites do not qualify" per OPT.TXT C4 is
  handled implicitly here: this match only ever fires when the SAME
  literal register name appears on both, e.g. "MOV AX,K1; MOV AX,K2",
  never "MOV AL,K1; MOV AH,K2", which is a different register name
  entirely and simply never matches this text-equality check). The
  FIRST MOV is provably dead: nothing between the two (by construction
  -- NextReal finds them immediately adjacent, skipping only already-
  nop'd operations) can have read r's value after the first MOV wrote
  it, since the very next real operation overwrites r again
  unconditionally before anything else touches it. }
procedure RemoveDeadConstMov(startChunk: POpChunk; startSlot: integer;
                              endChunk: POpChunk; endSlot: integer);
  var c, nc: POpChunk; k, nk: integer; r1, r2, k1Txt, k2Txt: string;
      k1Val, k2Val: word;
begin
  c := startChunk; k := startSlot;
  repeat
    if (c^.ops[k].kind = TOpInstr) and (c^.ops[k].mnemonic = MnMov) then begin
      StrTab.Get(c^.ops[k].op1, r1);
      StrTab.Get(c^.ops[k].op2, k1Txt);
      if ParseDecimalLiteral(k1Txt, k1Val) then begin
        nc := c; nk := k;
        if NextReal(nc, nk, endChunk, endSlot) and (nc^.ops[nk].kind = TOpInstr)
           and (nc^.ops[nk].mnemonic = MnMov) then begin
          StrTab.Get(nc^.ops[nk].op1, r2);
          StrTab.Get(nc^.ops[nk].op2, k2Txt);
          if Util.EqualICase(r1, r2) and ParseDecimalLiteral(k2Txt, k2Val) then
            c^.ops[k].mnemonic := MnNop
        end
      end
    end
  until not Advance(c, k, endChunk, endSlot)
end;

{ RemoveDeadBranch: a JMP or Jcc whose own target label is reached by
  falling straight through every operation between here and there --
  i.e. everything in between is either already MnNop or itself a
  TOpLabel (multiple labels stacked at one address, or a label this
  same match already proved reachable by fallthrough) -- is dead: the
  branch and the fallthrough path land on the exact same place either
  way, so branching there at all achieves nothing. Unlike CheapReturn
  (JMP only, target must be the VERY NEXT real operation), this
  matches a Jcc too and tolerates any number of intervening labels/
  already-deleted instructions, not just zero. Flag state is
  unaffected by deleting the branch itself (the Jcc's own flags-read
  is simply never performed, which is exactly as correct as taking
  either arm of a branch that provably goes to the same place) --
  OPT.TXT's own "retain all labels and flag state" is satisfied
  automatically: no label is ever touched, and nothing here alters
  what any OTHER instruction's flags would be. }
procedure RemoveDeadBranch(startChunk: POpChunk; startSlot: integer;
                            endChunk: POpChunk; endSlot: integer);
  var c, sc: POpChunk; k, sk: integer; target, lbl: string; reached: boolean;
begin
  c := startChunk; k := startSlot;
  repeat
    if (c^.ops[k].kind = TOpInstr) and (c^.ops[k].mnemonic <> MnNop)
       and IsJump(c^.ops[k].mnemonic) then begin
      StrTab.Get(c^.ops[k].op1, target);
      sc := c; sk := k; reached := false;
      while Advance(sc, sk, endChunk, endSlot) do begin
        if (sc^.ops[sk].kind = TOpInstr) and (sc^.ops[sk].mnemonic = MnNop) then
          { already deleted -- falls through, keep scanning }
        else if sc^.ops[sk].kind = TOpLabel then begin
          StrTab.Get(sc^.ops[sk].labelId, lbl);
          if lbl = target then begin reached := true; break end
          { a DIFFERENT label -- still pure fallthrough, keep scanning:
            several labels can legitimately stack at one address. }
        end else
          break   { a real instruction reached before the target label
                      -- this branch is NOT provably dead; stop. }
      end;
      if reached then c^.ops[k].mnemonic := MnNop
    end
  until not Advance(c, k, endChunk, endSlot)
end;

{ ThreadJumpChain: follow a LOCAL, ACYCLIC chain of direct JMP-to-JMP
  hops all the way to its real final target in one visit, unlike the
  pre-existing JumpChain (Stage A, above -- one hop per Optimize call,
  relying on repeated Optimize calls to resolve a deeper chain one
  level at a time). OPT.TXT C4's own "Detect cycles using visited
  targets or an operation-count hop bound. On cycles or unresolved
  targets, retain the original target" -- MaxJumpChainHops below is
  the hop-bound half of that (a real acyclic chain in any procedure
  this translator could plausibly emit is nowhere near this deep; it
  exists purely as a defensive backstop against a malformed/adversarial
  input looping forever, not a limit expected to ever bind on real
  code), and hopTargets is the visited-targets half (a target seen
  twice proves a cycle -- retarget to the ORIGINAL first-hop target
  instead, per OPT.TXT's own explicit fallback, never left partially
  retargeted mid-chain). "Stop at raw assembly, section changes, or a
  conditional hop" -- FindLabel/NextReal already only ever see TOpLabel/
  TOpInstr/TOpAsm within ONE procedure's own operation range (no
  section changes are possible inside that range at all -- SPHO.PAS's
  own ParseProcedure never appends a section-changing operation
  mid-procedure), so the only two cases actually reachable here are: a
  TOpAsm sitting where a label was expected (never occurs -- FindLabel
  only ever matches a TOpLabel exactly), or the intermediate jump not
  being an unconditional MnJmp (a Jcc there does not always fall
  through, so chaining through it would be wrong -- checked explicitly
  below, matching the pre-existing single-hop JumpChain's own same
  restriction). }
const MaxJumpChainHops = 64;

procedure ThreadJumpChain(startChunk: POpChunk; startSlot: integer;
                           endChunk: POpChunk; endSlot: integer);
  var c, lc, nc: POpChunk; k, lk, nk: integer;
      origTarget, curTarget, finalTarget: string;
      hopTargets: array[0..MaxJumpChainHops-1] of string;
      nHops, i: integer; cycle: boolean;
begin
  c := startChunk; k := startSlot;
  repeat
    if (c^.ops[k].kind = TOpInstr) and (c^.ops[k].mnemonic <> MnNop)
       and IsJump(c^.ops[k].mnemonic) then begin
      StrTab.Get(c^.ops[k].op1, origTarget);
      curTarget := origTarget; finalTarget := origTarget;
      nHops := 0; cycle := false;
      while (nHops < MaxJumpChainHops) and not cycle do begin
        if FindLabel(curTarget, startChunk, startSlot, endChunk, endSlot, lc, lk) then begin
          nc := lc; nk := lk;
          if NextReal(nc, nk, endChunk, endSlot) and (nc^.ops[nk].kind = TOpInstr)
             and (nc^.ops[nk].mnemonic = MnJmp) then begin
            StrTab.Get(nc^.ops[nk].op1, curTarget);
            for i := 0 to nHops - 1 do
              if hopTargets[i] = curTarget then cycle := true;
            if not cycle then begin
              hopTargets[nHops] := curTarget; nHops := nHops + 1;
              finalTarget := curTarget
            end
          end else
            break   { landed on a real (non-jump) operation or the range's
                        own end -- chain resolved, finalTarget is final. }
        end else
          break   { unresolved target (shouldn't happen for any label
                      this translator itself ever generated a jump
                      against) -- retain whatever was found so far. }
      end;
      if not cycle then c^.ops[k].op1 := StrTab.Put(finalTarget)
      { on a cycle, retain the ORIGINAL target (op1 untouched) -- never
        left partially retargeted mid-chain, per OPT.TXT's own explicit
        "on cycles...retain the original target." }
    end
  until not Advance(c, k, endChunk, endSlot)
end;

{ RemoveRepeatedFlagOp: two ADJACENT (NextReal) operations, same
  mnemonic, one of MnOr/MnCmp/MnTest, with IDENTICAL operand text on
  both sides of BOTH operations -- the second is dead: it recomputes
  exactly the same flag-setting comparison the first one already just
  made, with nothing in between that could have changed either
  operand's value (adjacency, via NextReal, proves that directly: no
  real operation sits between them at all). OPT.TXT's own "for
  register/immediate operands with identical flag effects... Do not
  begin with memory tests" -- both operands of BOTH operations are
  validated as register-or-decoded-immediate (never memory: a memory
  operand could have changed between the two reads even with no
  intervening operation of ITS OWN, via a stale value already sitting
  in cache/hardware terms that doesn't apply here, but more simply:
  OPT.TXT says not to, and there is no proof-of-unchanged-memory
  mechanism this rule has access to, so memory operands are simply
  never matched). "Nonadjacent matches" are out of scope by
  construction (NextReal only ever looks at the IMMEDIATELY following
  real operation). OR r,r (both operands identical, e.g. "OR AX,AX",
  SPHINX's own bare-BOOLEAN-condition test idiom) is covered by the
  same operand-equality check as CMP/TEST -- no separate case needed. }
function IsRegOrImmOperand(const s: string): boolean;
  var v: word;
begin
  IsRegOrImmOperand := (Regs86.LookupReg(Util.UpStr(s)) <> 0) or ParseDecimalLiteral(s, v)
end;

procedure RemoveRepeatedFlagOp(startChunk: POpChunk; startSlot: integer;
                                endChunk: POpChunk; endSlot: integer);
  var c, nc: POpChunk; k, nk: integer; a1, a2, b1, b2: string;
begin
  c := startChunk; k := startSlot;
  repeat
    if (c^.ops[k].kind = TOpInstr)
       and ((c^.ops[k].mnemonic = MnOr) or (c^.ops[k].mnemonic = MnCmp)
            or (c^.ops[k].mnemonic = MnTest)) then begin
      StrTab.Get(c^.ops[k].op1, a1); StrTab.Get(c^.ops[k].op2, a2);
      if IsRegOrImmOperand(a1) and IsRegOrImmOperand(a2) then begin
        nc := c; nk := k;
        if NextReal(nc, nk, endChunk, endSlot) and (nc^.ops[nk].kind = TOpInstr)
           and (nc^.ops[nk].mnemonic = c^.ops[k].mnemonic) then begin
          StrTab.Get(nc^.ops[nk].op1, b1); StrTab.Get(nc^.ops[nk].op2, b2);
          if Util.EqualICase(a1, b1) and Util.EqualICase(a2, b2) then
            nc^.ops[nk].mnemonic := MnNop
        end
      end
    end
  until not Advance(c, k, endChunk, endSlot)
end;

{ RemoveIdentityLogicOp: "OR reg,0" / "XOR reg,0" / "AND reg,0FFFFh (or
  0FFh for a byte register)" never changes reg's own value -- the
  logic-identity counterpart to the pre-existing NoOpArith (Stage A,
  ADD/SUB reg,0 only). Same shape, same safety proof, reusing Stage
  B's own LocalDeadAfter instead of the older NoOpArithSafe forward
  scan (LocalDeadAfter tracks individual flag bits rather than "any
  flag reader blocks," and is exactly the tool OPT.TXT's own Stage B
  was built to hand off to a real Stage C rule) -- proves nothing
  downstream reads any of CF/PF/AF/ZF/SF/OF (FlagMaskArith, the exact
  set OR/XOR/AND actually set) before something else overwrites all of
  them first. op1 is validated through Regs86.LookupReg exactly like
  NoOpArith's own ADD/SUB check (a memory operand still genuinely
  reads/writes memory even though the value never changes, so it is
  never matched here either). AND's own "all_ones" identity is
  width-dependent -- 0FFFFh for a word register, 0FFh for a byte
  register -- decoded via ParseDecimalLiteral and compared against the
  correct constant for op1's own proven width. }
procedure RemoveIdentityLogicOp(startChunk: POpChunk; startSlot: integer;
                                 endChunk: POpChunk; endSlot: integer);
  var c: POpChunk; k: integer; opnd1, opnd2: string; regId: integer;
      litVal: word; isIdentity: boolean;
begin
  c := startChunk; k := startSlot;
  repeat
    if (c^.ops[k].kind = TOpInstr)
       and ((c^.ops[k].mnemonic = MnOr) or (c^.ops[k].mnemonic = MnXor)
            or (c^.ops[k].mnemonic = MnAnd)) then begin
      StrTab.Get(c^.ops[k].op1, opnd1);
      StrTab.Get(c^.ops[k].op2, opnd2);
      regId := Regs86.LookupReg(Util.UpStr(opnd1));
      if (regId <> 0) and ParseDecimalLiteral(opnd2, litVal) then begin
        if c^.ops[k].mnemonic = MnAnd then begin
          if Regs86.IsByteReg(regId) then isIdentity := (litVal = $FF)
          else isIdentity := (litVal = $FFFF)
        end else
          isIdentity := (litVal = 0);
        if isIdentity and LocalDeadAfter(c, k, endChunk, endSlot, RegMaskNone, FlagMaskArith) then
          c^.ops[k].mnemonic := MnNop
      end
    end
  until not Advance(c, k, endChunk, endSlot)
end;

{ ============================================================
  STAGE C: BOUNDED LOCAL REWRITES (OPT.TXT S6) -- C1
  ============================================================
  FoldSavedOperand ("the first performance rule"):

    Before: PUSH AX; MOV AX,src; ADD SI,AX; POP AX
    After:  ADD SI,src

  Unlike C4 (above), this needs the "generated-save and private-stack
  proof" OPT.TXT S6 itself requires -- SPHO.PAS's own genSaveId field
  (TOperation, Types.PAS) is exactly that proof: a nonzero id shared by
  ONE PUSH and its own matching POP, set ONLY at the specific
  EmitIncDecAmountToReg call site that emits this literal shape
  (INC/DEC(otherReg, expr), OPT.TXT C1's own worked example almost
  verbatim) -- never set for a user-written PUSH()/POP() statement or a
  USES register-preservation pair, so a nonzero, MATCHING id on both
  ends is proof this exact PUSH/POP is compiler-owned scratch, not
  proof by mere adjacency or operand-text pattern alone.

  Four operations, ALL FOUR mutually adjacent (via NextReal, the same
  "skip only already-deleted operations" convention every other
  matcher here uses) -- PUSH AX(id) / MOV AX,src / ADD-or-SUB dst,AX /
  POP AX(id), same id on both ends -- collapse to ADD-or-SUB dst,src,
  deleting the other three. "This removes three instructions," per
  OPT.TXT's own count: four found, one kept (rewritten in place),
  three nop'd.

  Requirements (OPT.TXT's own words, each addressed below):
  - "Start with word ADD/SUB" -- MnAdd/MnSub only, and dst/AX must both
    be WORD registers (TOperand.isWord) -- a byte-width version of this
    shape is C2's own separate, narrower rule (byte CL scaffolding),
    not this one.
  - "saved AX" -- both PUSH/POP operands are literally 'ax' (the ONLY
    register EmitGenSavePush/EmitGenSavePop are ever called with
    today); checked directly rather than assumed from genSaveId alone,
    since genSaveId only proves "compiler-owned pair," not WHICH
    register.
  - "a distinct word destination excluding SP" -- dst must be a
    different register than AX (Regs86.LookupReg comparison, not text
    equality -- 'AX' and 'ax' must still compare equal), word-width,
    and not SP.
  - "Accept encodable immediates and proven safe frame loads" -- src
    (MOV AX,src's own op2) must DecodeOperand as OpKindImm, or OpKindMem
    with isFrameObject TRUE (Stage B's own proof, already excluding any
    indexed/segment-overridden shape) -- nothing else (a plain global
    VAR, a RECORD field, an indexed array element) is accepted; "proven
    safe" is exactly what isFrameObject already means.
  - "Reject source values/addresses depending on AX" -- src itself is
    never a bare 'ax'/'al'/'ah' (a self-referential MOV AX,AX, which
    would make the whole rule meaningless -- DecodeOperand would
    already give it OpKindReg, rejected by the immediate-or-frame check
    above, so this is automatically satisfied, not a separate check);
    for a frame-load src, addrRegMask can ONLY ever be RegBitBP by
    isFrameObject's own construction (never AX), so "depending on AX"
    is likewise already impossible for anything DecodeOperand accepts
    here -- no separate check needed beyond what the immediate/frame
    classification itself already guarantees.
  - "stack-sensitive operands... stack-slot aliases... labels...
    barriers" -- guaranteed by STRICT ADJACENCY: NextReal finds all
    four operations with nothing else (real or already-deleted)
    between any consecutive pair, so nothing else could possibly read
    the temporarily-adjusted SP, alias the pushed slot, or be a label/
    barrier sitting in between -- there is no "in between" here at all.
  - "Preserve AX, final SP, arithmetic result and flags" -- AX's own
    final value is whatever it held before the PUSH (POP restored it in
    the original code; the rewrite never touches AX at all, so its
    value is simply never disturbed in the first place, the strongest
    possible preservation). Final SP is identical (PUSH+POP is a net
    zero SP change, so removing the matched pair changes nothing).
    "ADD dst,src" computes the exact same arithmetic result and sets
    the exact same flags "ADD dst,ax" would have, src's value being
    identical to what MOV AX,src loaded into AX in the original code. }
procedure FoldSavedOperand(startChunk: POpChunk; startSlot: integer;
                            endChunk: POpChunk; endSlot: integer);
  var c, mc, ac, pc: POpChunk; k, mk, ak, pk: integer;
      dst, src, axTxt: string; srcOp: TOperand; dstReg: integer;
      pushId: word;
begin
  c := startChunk; k := startSlot;
  repeat
    if (c^.ops[k].kind = TOpInstr) and (c^.ops[k].mnemonic = MnPush)
       and (c^.ops[k].genSaveId <> 0) then begin
      StrTab.Get(c^.ops[k].op1, axTxt);
      if Util.EqualICase(axTxt, 'ax') then begin
        pushId := c^.ops[k].genSaveId;
        mc := c; mk := k;
        if NextReal(mc, mk, endChunk, endSlot) and (mc^.ops[mk].kind = TOpInstr)
           and (mc^.ops[mk].mnemonic = MnMov) then begin
          StrTab.Get(mc^.ops[mk].op1, axTxt);
          if Util.EqualICase(axTxt, 'ax') then begin
            StrTab.Get(mc^.ops[mk].op2, src);
            ac := mc; ak := mk;
            if NextReal(ac, ak, endChunk, endSlot) and (ac^.ops[ak].kind = TOpInstr)
               and ((ac^.ops[ak].mnemonic = MnAdd) or (ac^.ops[ak].mnemonic = MnSub)) then begin
              StrTab.Get(ac^.ops[ak].op1, dst);
              StrTab.Get(ac^.ops[ak].op2, axTxt);
              dstReg := Regs86.LookupReg(Util.UpStr(dst));
              if Util.EqualICase(axTxt, 'ax') and (dstReg <> 0)
                 and not Regs86.IsByteReg(dstReg) and not Regs86.IsSegReg(dstReg)
                 and (dstReg <> Regs86.RegAX) and (dstReg <> Regs86.RegSP) then begin
                pc := ac; pk := ak;
                if NextReal(pc, pk, endChunk, endSlot) and (pc^.ops[pk].kind = TOpInstr)
                   and (pc^.ops[pk].mnemonic = MnPop) and (pc^.ops[pk].genSaveId = pushId) then begin
                  StrTab.Get(pc^.ops[pk].op1, axTxt);
                  if Util.EqualICase(axTxt, 'ax') then begin
                    DecodeOperand(src, srcOp);
                    if (srcOp.kind = OpKindImm)
                       or ((srcOp.kind = OpKindMem) and srcOp.isFrameObject) then begin
                      ac^.ops[ak].op2 := StrTab.Put(src);
                      c^.ops[k].mnemonic := MnNop;
                      mc^.ops[mk].mnemonic := MnNop;
                      pc^.ops[pk].mnemonic := MnNop
                    end
                  end
                end
              end
            end
          end
        end
      end
    end
  until not Advance(c, k, endChunk, endSlot)
end;

{ FoldSavedOperandSelfDest: OPT.TXT's own R5 finding -- "RowOff's
  AX-destination sequence is PUSH AX; MOV AX,src; MOV BX,AX; POP AX;
  ADD AX,BX, which is not C1's distinct-destination shape." A separate,
  real emission shape FoldSavedOperand (C1, above) cannot match at all:
  C1 requires the ADD/SUB's own DESTINATION to be some OTHER register,
  never AX itself (dstReg <> Regs86.RegAX, explicitly checked above) --
  correctly so for C1's own shape, since AX there is restored by the
  POP and then never touched again by the ADD/SUB. This shape is
  different: the ADD/SUB's own destination IS the just-restored AX, so
  the freshly-computed src value cannot stay in AX across the POP at
  all (POP would clobber it) -- SPHO.PAS's own EmitIncDecAmountToReg
  (the nmIsAx branch, "INC(AX, expr)"/"DEC(AX, expr)") carries it
  through BX instead: MOV BX,AX (copy src's value out of AX before the
  POP clobbers it), POP AX (restores the caller's OLD AX), ADD/SUB
  AX,BX (old AX combined with src's value, now safely sitting in BX).

  Before: PUSH AX(id); MOV AX,src; MOV BX,AX; POP AX(id); ADD/SUB AX,BX
  After (BX dead afterward):  ADD/SUB AX,src
  After (BX live afterward):  MOV BX,src

  Proof, mirroring FoldSavedOperand's own "generated-save and private-
  stack proof" (genSaveId tags both PUSH and POP; NextReal treats any
  already-nop'd operation as transparent; every operation in the match
  is REQUIRED strictly adjacent to the next, so nothing could observe
  AX/BX/SP/flags mid-sequence, "no barrier can appear inside a proven
  private compiler-owned save pair"):
  - AX's own FINAL value is identical either way: original code computes
    (old AX) + srcVal via BX after the POP restores old AX; the folded
    "ADD AX,src" computes old AX (undisturbed the whole time, since this
    rewrite -- like C1's own -- never touches AX at all when it fires)
    + srcVal directly. Same arithmetic, same flags (ADD/SUB AX,src sets
    the identical flags ADD/SUB AX,BX would, srcVal being equal either
    way).
  - src must be safe to RE-EVALUATE as a plain operand after the PUSH/
    MOV/MOV/POP window is deleted -- same restriction C1 already applies
    via DecodeOperand: a plain immediate, or a proven-stable frame
    object (BP-relative local/param, never a bare unregistered global or
    an address-register-dependent operand that something in between
    could have changed -- moot here anyway, since nothing DOES sit in
    between, but kept identical to C1's own proof for the same reason
    C1 keeps it: a future looser adjacency requirement must not silently
    inherit an unsound src class).
  - BX's own disposition after the match decides which of the two
    outputs is sound: if LocalDeadAfter proves BX dead from the ADD/SUB
    onward, BX's own value never needs to exist as a real register
    value at all -- fully collapse to "ADD/SUB AX,src" (matching C1's
    own "provably dead scratch -> full collapse" precedent). If BX is
    still live afterward (a real, if perhaps rare, possibility -- this
    rule does not know BX has no other purpose the way C2's own CL/BL
    scratch is a purely compiler-owned choice with a known re-use
    convention), BX must still end up holding srcVal for whatever reads
    it later -- replace the whole PUSH/MOV/MOV/POP window with a single
    "MOV BX,src" instead (AX is simply never routed through at all,
    which is exactly as sound as the full collapse: AX's own value was
    never actually changed by the deleted operations to begin with), and
    leave the trailing "ADD/SUB AX,BX" untouched (BX already holds the
    same srcVal it always did). }
procedure FoldSavedOperandSelfDest(startChunk: POpChunk; startSlot: integer;
                                    endChunk: POpChunk; endSlot: integer);
  var c, mc, bc, pc, ac, oc: POpChunk; k, mk, bk, pk, ak, ok: integer;
      axTxt, bxTxt, src, addrTxt: string; srcOp: TOperand;
      pushId: word; bxRestoredAfter: boolean;
begin
  c := startChunk; k := startSlot;
  repeat
    if (c^.ops[k].kind = TOpInstr) and (c^.ops[k].mnemonic = MnPush)
       and (c^.ops[k].genSaveId <> 0) then begin
      StrTab.Get(c^.ops[k].op1, axTxt);
      if Util.EqualICase(axTxt, 'ax') then begin
        pushId := c^.ops[k].genSaveId;
        mc := c; mk := k;
        if NextReal(mc, mk, endChunk, endSlot) and (mc^.ops[mk].kind = TOpInstr)
           and (mc^.ops[mk].mnemonic = MnMov) then begin
          StrTab.Get(mc^.ops[mk].op1, axTxt);
          if Util.EqualICase(axTxt, 'ax') then begin
            StrTab.Get(mc^.ops[mk].op2, src);
            bc := mc; bk := mk;
            if NextReal(bc, bk, endChunk, endSlot) and (bc^.ops[bk].kind = TOpInstr)
               and (bc^.ops[bk].mnemonic = MnMov) then begin
              StrTab.Get(bc^.ops[bk].op1, bxTxt);
              StrTab.Get(bc^.ops[bk].op2, axTxt);
              if Util.EqualICase(bxTxt, 'bx') and Util.EqualICase(axTxt, 'ax') then begin
                pc := bc; pk := bk;
                if NextReal(pc, pk, endChunk, endSlot) and (pc^.ops[pk].kind = TOpInstr)
                   and (pc^.ops[pk].mnemonic = MnPop) and (pc^.ops[pk].genSaveId = pushId) then begin
                  StrTab.Get(pc^.ops[pk].op1, axTxt);
                  if Util.EqualICase(axTxt, 'ax') then begin
                    ac := pc; ak := pk;
                    if NextReal(ac, ak, endChunk, endSlot) and (ac^.ops[ak].kind = TOpInstr)
                       and ((ac^.ops[ak].mnemonic = MnAdd) or (ac^.ops[ak].mnemonic = MnSub)) then begin
                      StrTab.Get(ac^.ops[ak].op1, axTxt);
                      StrTab.Get(ac^.ops[ak].op2, bxTxt);
                      if Util.EqualICase(axTxt, 'ax') and Util.EqualICase(bxTxt, 'bx') then begin
                        DecodeOperand(src, srcOp);
                        if (srcOp.kind = OpKindImm)
                           or ((srcOp.kind = OpKindMem) and srcOp.isFrameObject) then begin
                          { bxRestoredAfter: SPHO.PAS's own EmitIncDecAmountToReg
                            (nmIsAx branch) now wraps this whole PUSH-AX(id)/
                            MOV-AX,src/MOV-BX,AX/POP-AX(id)/ADD-or-SUB-AX,BX
                            window in an OUTER PUSH BX(id2)/POP BX(id2) pair of
                            its own (a separate fix for a real bug -- BX used
                            to be silently clobbered here, DOCS/TRBUG.MD's own
                            "Related bug found and fixed" entry on this exact
                            shape). When that outer POP BX(id2) immediately
                            follows the ADD/SUB matched here, it UNCONDITIONALLY
                            restores the caller's own real BX right after --
                            so whatever this fold leaves BX holding in between
                            is provably irrelevant, the exact same "no one can
                            observe this register's value" property
                            LocalDeadAfter's own forward scan exists to prove,
                            just proven directly by construction here instead
                            of by scanning. Full collapse is therefore ALWAYS
                            sound when this outer POP is present, without
                            needing LocalDeadAfter at all -- covers the one
                            case LocalDeadAfter itself could never prove (BX
                            genuinely read again later BY THE CALLER after
                            this procedure returns, which is exactly what the
                            outer POP restores it to, so that later read sees
                            the CALLER's own BX, never this fold's scratch
                            value, regardless of what this fold does to BX
                            here). The outer PUSH/POP BX pair itself is left
                            untouched -- removing it too would need a backward
                            scan this unit has no primitive for yet; C3
                            (RemoveUnnecessarySaveRestore) is the natural
                            future home for that, once it accepts a nested
                            push/pop interior (currently rejects one
                            outright). }
                          oc := ac; ok := ak;
                          bxRestoredAfter := NextReal(oc, ok, endChunk, endSlot)
                            and (oc^.ops[ok].kind = TOpInstr)
                            and (oc^.ops[ok].mnemonic = MnPop)
                            and (oc^.ops[ok].genSaveId <> 0)
                            and (oc^.ops[ok].genSaveId <> pushId);
                          if bxRestoredAfter then begin
                            StrTab.Get(oc^.ops[ok].op1, bxTxt);
                            bxRestoredAfter := Util.EqualICase(bxTxt, 'bx')
                          end;
                          if bxRestoredAfter
                             or LocalDeadAfter(ac, ak, endChunk, endSlot, RegMaskBX, FlagMaskNone) then begin
                            { BX provably dead afterward (either proof) --
                              full collapse. }
                            ac^.ops[ak].op2 := StrTab.Put(src);
                            c^.ops[k].mnemonic := MnNop;
                            mc^.ops[mk].mnemonic := MnNop;
                            bc^.ops[bk].mnemonic := MnNop;
                            pc^.ops[pk].mnemonic := MnNop
                          end else begin
                            { BX still live -- route src straight into BX,
                              never through AX at all; leave the trailing
                              ADD/SUB AX,BX untouched. }
                            bc^.ops[bk].op2 := StrTab.Put(src);
                            c^.ops[k].mnemonic := MnNop;
                            mc^.ops[mk].mnemonic := MnNop;
                            pc^.ops[pk].mnemonic := MnNop
                          end
                        end
                      end
                    end
                  end
                end
              end
            end
          end
        end
      end
    end
  until not Advance(c, k, endChunk, endSlot)
end;

{ ============================================================
  STAGE C: BOUNDED LOCAL REWRITES (OPT.TXT S6) -- C2
  ============================================================
  CollapseByteConstScaffolding:

    Before: PUSH AX; MOV AX,K; MOV CL,AL; POP AX; ADD AL,CL
    After:  MOV CL,low8(K); ADD AL,CL

  Same "generated-save and private-stack proof" shape as C1
  (genSaveId, matching on both the PUSH and the POP), five mutually
  adjacent operations instead of four: PUSH AX(id) / MOV AX,K / MOV
  scratch,AL / POP AX(id) / ADD-or-SUB AL,scratch.

  Register scope: OPT.TXT's own literal example is CL-specific ("MOV
  CL,AL"), with an explicit "Do not generalize to other overlapping
  registers without a new proof." This codebase's own real matching
  codegen (SPHO.PAS's EmitIncDecAmountToReg, the nmIsAl branch -- the
  same call site C1 already taps, at byte width) uses BL as its own
  scratch register instead of CL, so a CL-only rule would never
  actually fire on any code this translator emits today. The NEW proof
  BL needs, supplied here rather than assumed: the safety property
  OPT.TXT's own C2 proof actually leans on is "scratch does not
  overlap AX/AL/AH" (so the POP AX below doesn't clobber it, and
  scratch's own eventual value is exactly what the fold preserves) --
  true identically for CL (overlaps CX, not AX) and BL (overlaps BX,
  not AX); nothing else in this shape treats CL as special (not used
  as a shift/rotate count, no CX-specific access anywhere in the five
  operations matched). BL is not a further, UNPROVEN generalization --
  it is the one additional register this exact codebase's own real
  emission site already proves safe by construction (Regs86.IsByteReg
  plus "not AL/AH" is the full check below; SP/segment registers are
  excluded the same way FoldSavedOperand's own dst check excludes
  them, though neither could plausibly appear here as a byte MOV
  destination anyway).

  "Preserve modulo 256 truncation and CL's visible result": K is
  decoded via ParseDecimalLiteral (same helper every other numeric-
  literal check in this unit already uses) and masked with "and $FF"
  before being re-emitted -- 8086's own MOV CL,imm8 already truncates
  any wider literal text this codegen could plausibly produce, but the
  mask here makes that explicit rather than relying on the assembler's
  own behavior. "CL's [or BL's] visible result" -- if LocalDeadAfter
  (Stage B) cannot prove scratch is dead after the ADD/SUB, the MOV
  scratch,low8(K) instruction is KEPT (not folded away entirely, only
  the wasted PUSH/MOV-AX,K/POP triple around it is removed) -- OPT.TXT's
  own explicit "If CL is dead afterward, use ADD/SUB AL,low8(K)
  directly" makes the FULLY-collapsed 2-instruction-to-1 form
  conditional on that extra proof, not automatic. }
procedure CollapseByteConstScaffolding(startChunk: POpChunk; startSlot: integer;
                                        endChunk: POpChunk; endSlot: integer);
  var c, mc, sc, ac, pc, oc: POpChunk; k, mk, sk, ak, pk, ok: integer;
      axTxt, kTxt, scratch, scratch2, alTxt, bxTxt: string;
      kVal: word; scratchReg: integer; pushId: word; scratchRestoredAfter: boolean;
begin
  c := startChunk; k := startSlot;
  repeat
    if (c^.ops[k].kind = TOpInstr) and (c^.ops[k].mnemonic = MnPush)
       and (c^.ops[k].genSaveId <> 0) then begin
      StrTab.Get(c^.ops[k].op1, axTxt);
      if Util.EqualICase(axTxt, 'ax') then begin
        pushId := c^.ops[k].genSaveId;
        mc := c; mk := k;
        if NextReal(mc, mk, endChunk, endSlot) and (mc^.ops[mk].kind = TOpInstr)
           and (mc^.ops[mk].mnemonic = MnMov) then begin
          StrTab.Get(mc^.ops[mk].op1, axTxt);
          StrTab.Get(mc^.ops[mk].op2, kTxt);
          if Util.EqualICase(axTxt, 'ax') and ParseWordLiteral(kTxt, kVal) then begin
            sc := mc; sk := mk;
            if NextReal(sc, sk, endChunk, endSlot) and (sc^.ops[sk].kind = TOpInstr)
               and (sc^.ops[sk].mnemonic = MnMov) then begin
              StrTab.Get(sc^.ops[sk].op1, scratch);
              StrTab.Get(sc^.ops[sk].op2, alTxt);
              scratchReg := Regs86.LookupReg(Util.UpStr(scratch));
              if Util.EqualICase(alTxt, 'al')
                 and ((scratchReg = Regs86.RegCL) or (scratchReg = Regs86.RegBL)) then begin
                pc := sc; pk := sk;
                if NextReal(pc, pk, endChunk, endSlot) and (pc^.ops[pk].kind = TOpInstr)
                   and (pc^.ops[pk].mnemonic = MnPop) and (pc^.ops[pk].genSaveId = pushId) then begin
                  StrTab.Get(pc^.ops[pk].op1, axTxt);
                  if Util.EqualICase(axTxt, 'ax') then begin
                    ac := pc; ak := pk;
                    if NextReal(ac, ak, endChunk, endSlot) and (ac^.ops[ak].kind = TOpInstr)
                       and ((ac^.ops[ak].mnemonic = MnAdd) or (ac^.ops[ak].mnemonic = MnSub)) then begin
                      StrTab.Get(ac^.ops[ak].op1, alTxt);
                      StrTab.Get(ac^.ops[ak].op2, scratch2);
                      if Util.EqualICase(alTxt, 'al') and Util.EqualICase(scratch2, scratch) then begin
                        c^.ops[k].mnemonic := MnNop;
                        mc^.ops[mk].mnemonic := MnNop;
                        pc^.ops[pk].mnemonic := MnNop;
                        { scratchRestoredAfter: when scratch is BL,
                          SPHO.PAS's own EmitIncDecAmountToReg (nmIsAl
                          branch) now wraps this whole window in an OUTER
                          PUSH BX(id2)/POP BX(id2) pair (a real-bug fix --
                          BX used to be silently clobbered here, DOCS/
                          TRBUG.MD's own "Related bug found and fixed"
                          entry). When that outer POP BX(id2) immediately
                          follows the ADD/SUB matched here, it
                          unconditionally restores the caller's own real
                          BX right after -- see FoldSavedOperandSelfDest's
                          own identical proof, just above this rule, for
                          the full reasoning (same shape, same argument).
                          Not checked for CL: nothing in this codebase
                          gives CL an outer save/restore of its own (the
                          CX-clobber bugfix moved this call site to BX
                          entirely; a CL match here only exists for
                          forward-compatibility with OPT.TXT's own
                          CL-specific spec text, never actually emitted by
                          SPHO.PAS today), so CL still relies on
                          LocalDeadAfter alone, unchanged. }
                        scratchRestoredAfter := false;
                        if scratchReg = Regs86.RegBL then begin
                          oc := ac; ok := ak;
                          scratchRestoredAfter := NextReal(oc, ok, endChunk, endSlot)
                            and (oc^.ops[ok].kind = TOpInstr)
                            and (oc^.ops[ok].mnemonic = MnPop)
                            and (oc^.ops[ok].genSaveId <> 0)
                            and (oc^.ops[ok].genSaveId <> pushId);
                          if scratchRestoredAfter then begin
                            StrTab.Get(oc^.ops[ok].op1, bxTxt);
                            scratchRestoredAfter := Util.EqualICase(bxTxt, 'bx')
                          end
                        end;
                        if scratchRestoredAfter
                           or LocalDeadAfter(ac, ak, endChunk, endSlot, RegBitFor(scratchReg, true), FlagMaskNone) then begin
                          { scratch provably dead afterward (either proof)
                            -- fully collapse: drop the MOV scratch,K
                            entirely, fold K straight into the ADD/SUB. }
                          sc^.ops[sk].mnemonic := MnNop;
                          ac^.ops[ak].op2 := StrTab.Put(IntStr(kVal and $FF))
                        end else begin
                          { scratch's own value is still live afterward
                            -- keep "MOV scratch,low8(K)", only remove
                            the wasted PUSH/MOV-AX,K/POP triple around
                            it. }
                          sc^.ops[sk].op2 := StrTab.Put(IntStr(kVal and $FF))
                        end
                      end
                    end
                  end
                end
              end
            end
          end
        end
      end
    end
  until not Advance(c, k, endChunk, endSlot)
end;

{ ============================================================
  STAGE C: BOUNDED LOCAL REWRITES (OPT.TXT S6) -- C3
  ============================================================
  RemoveUnnecessarySaveRestore:

    Before: PUSH BX; MOV AX,src; ADD AX,K; POP BX
    After:  MOV AX,src; ADD AX,K

  Same "generated-save and private-stack proof" shape as C1/C2
  (genSaveId, matching on both the PUSH and the POP) -- but UNLIKE
  those two, the interior here is not a fixed instruction count at
  all: "Initially scan at most eight real interior instructions"
  (OPT.TXT's own words) is a bounded SEARCH, not a fixed MATCH shape --
  the PUSH/POP pair is removed whenever nothing in between could
  possibly need the saved register's OLD value restored, regardless of
  what those interior instructions actually compute.

  No real SPHO.PAS emission site is tagged with genSaveId for THIS
  shape yet (unlike C1/C2, whose own real trigger sites -- both inside
  EmitIncDecAmountToReg -- were identified and tagged directly): the
  one plausible real candidate, EmitAssignRhs's own `saveBase` BX
  save/restore, spans a large, branchy interior (chained operators,
  calls, multiple fast-path exits) that does not currently fit this
  rule's own narrow, provably-safe scope without a lot more analysis
  than is safe to rush -- consulted directly on this before
  implementing; the decision was to implement C3 fully, per spec,
  verified via TESTS/STGC.PAS's own hand-built operation lists (same
  "define and test the rule on its own merits, tag a real trigger site
  later once one is confidently identified" precedent several of the
  C4 rules -- RemoveMovSwapBack, RemoveRepeatedFlagOp, ThreadJumpChain
  -- already established for THIS translator's own current codegen).

  Rejections, each directly from OPT.TXT's own list:
  - "Reject interior writes to BX/BH/BL" -- GENERALIZED to "the saved
    register's own regMask", not literally hardcoded to BX -- the
    saved register in a real future call site might not always be BX;
    OPT.TXT's own repeated "BX" throughout this section is this rule's
    own WORKED EXAMPLE register, not a hardcoded restriction the rule
    itself imposes (C1's own worked example is similarly AX-specific
    text that the actual implementation generalizes to "the saved
    register", not literally hardcoded either). eff.regWrite intersecting
    the saved register's own RegBitFor mask rejects the match.
  - "SP use" -- ANY interior operand text naming SP at all (as either
    operand, not just as a write) rejects the match; a bare SP READ
    (e.g. comparing against it) is exactly as suspicious as a write
    here, since this rule has no way to prove what such a read is
    FOR -- OPT.TXT's own "stack-sensitive operands" language elsewhere
    (C1) makes the same call.
  - "stack manipulation" -- any PUSH/POP/PUSHF/POPF at all (regardless
    of which register) rejects the match -- a NESTED push/pop changes
    what "the saved slot" even means partway through the scan, and
    OPT.TXT's own verify list explicitly calls out "nested pushes."
  - "transfers" -- GetEffects.transferKind <> XferNone (a JMP/Jcc/
    CALL/RETURN of any kind) rejects.
  - "labels" -- a TOpLabel rejects outright (a real predecessor/join
    point this pass has no dominance proof for, same conservative
    stance NoOpArithSafe/LocalDeadAfter already take).
  - "opaque assembly" -- a TOpAsm rejects outright.
  - "possible accesses to the saved slot" + "Unknown memory effects
    reject the match" -- collapsed into ONE conservative check: ANY
    interior memEffect other than MemNone rejects the match. This
    codebase has no real alias-proof machinery (Stage B's own
    isFrameObject proof is about PROVING an access IS a specific safe
    local, not about proving an access is NOT the current stack top,
    a fundamentally different, harder question this rule does not
    attempt), so "any real memory access at all" is the only sound
    over-approximation of "might touch the saved slot" available --
    matching OPT.TXT's own "reject interior... possible accesses,"
    the conservative reading, not "prove no access is possible."
  - Anything GetEffects itself calls unknown (known=FALSE) rejects,
    same as every other rule in this unit.
  - "Reading BX is allowed" -- eff.regRead intersecting the saved
    register's mask does NOT reject the match (only eff.regWrite
    does) -- a bare read of the about-to-be-restored register mid-span
    genuinely observes its CURRENT (not-yet-restored) value, which is
    exactly as correct with or without this rule's own rewrite (the
    PUSH/POP pair, if kept, would not have changed what that read
    sees either -- POP only runs AFTER the read, in program order). }
const MaxSaveRestoreInterior = 8;

procedure RemoveUnnecessarySaveRestore(startChunk: POpChunk; startSlot: integer;
                                        endChunk: POpChunk; endSlot: integer);
  var c, ic, pc: POpChunk; k, ik, pk: integer;
      pushTxt, popTxt: string; pushId: word; savedReg: integer; savedMask: word;
      eff: TEffects; nInterior: integer; ok, found: boolean;
begin
  c := startChunk; k := startSlot;
  repeat
    if (c^.ops[k].kind = TOpInstr) and (c^.ops[k].mnemonic = MnPush)
       and (c^.ops[k].genSaveId <> 0) then begin
      StrTab.Get(c^.ops[k].op1, pushTxt);
      savedReg := Regs86.LookupReg(Util.UpStr(pushTxt));
      if (savedReg <> 0) and not Regs86.IsSegReg(savedReg) and (savedReg <> Regs86.RegSP) then begin
        pushId := c^.ops[k].genSaveId;
        savedMask := RegBitFor(savedReg, Regs86.IsByteReg(savedReg));
        ic := c; ik := k; nInterior := 0; ok := true; found := false; pc := c; pk := k;
        while ok and Advance(ic, ik, endChunk, endSlot) do begin
          if (ic^.ops[ik].kind = TOpInstr) and (ic^.ops[ik].mnemonic = MnNop) then
            { deleted -- transparent, does not count against the
              interior budget, same "skip already-nop'd operations"
              convention every other matcher here uses. }
          else if (ic^.ops[ik].kind = TOpInstr) and (ic^.ops[ik].mnemonic = MnPop)
                  and (ic^.ops[ik].genSaveId = pushId) then begin
            { the matching POP -- stop scanning, match found (pc/pk
              records its own location for the rewrite below). }
            pc := ic; pk := ik; found := true; break
          end else begin
            nInterior := nInterior + 1;
            if nInterior > MaxSaveRestoreInterior then begin ok := false; break end;
            if ic^.ops[ik].kind = TOpLabel then begin ok := false; break end;
            if ic^.ops[ik].kind = TOpAsm then begin ok := false; break end;
            if (ic^.ops[ik].mnemonic = MnPush) or (ic^.ops[ik].mnemonic = MnPop)
               or (ic^.ops[ik].mnemonic = MnPushf) or (ic^.ops[ik].mnemonic = MnPopf) then begin
              ok := false; break   { stack manipulation of ANY kind --
                including a DIFFERENT genSaveId pair nested inside this
                one, "nested pushes" per OPT.TXT's own verify list. }
            end;
            GetEffects(ic^.ops[ik], eff);
            if not eff.known then begin ok := false; break end;
            if (eff.regWrite and savedMask) <> 0 then begin ok := false; break end;
            if eff.transferKind <> XferNone then begin ok := false; break end;
            if eff.memEffect <> MemNone then begin ok := false; break end;
            { "SP use": any operand naming SP at all, read or write --
              checked directly on regRead/regWrite rather than assuming
              GetEffects's own per-mnemonic table already flags every
              SP-referencing shape as a barrier (PUSH/POP already are,
              caught above; an ordinary "MOV ax,sp" or "CMP sp,..." is
              a real, GetEffects-known instruction that would otherwise
              pass every other check here). }
            if ((eff.regRead or eff.regWrite) and RegBitSP) <> 0 then begin ok := false; break end
          end
        end;
        if ok and found then begin
          { A real matching POP was found (pc/pk moved) within budget,
            with every interior operation accepted. }
          c^.ops[k].mnemonic := MnNop;
          pc^.ops[pk].mnemonic := MnNop
        end
      end
    end
  until not Advance(c, k, endChunk, endSlot)
end;

{ ============================================================
  STAGE D: CONTROL FLOW, LIVENESS, AND VALUE FACTS (OPT.TXT S7)
  ============================================================
  Temporary, per-procedure analysis, built fresh by BuildCfg (and, on
  top of it, ComputeLiveness/PropagateValues) each time Optimize is
  called, released implicitly when the caller's own local TCfg/
  TLiveness/TValueFacts variables go out of scope (TP7 stack-allocated
  records, no heap involved at all -- "release them after the
  procedure" is automatic here, not something this code must do by
  hand). Nothing in OptimizePass/Optimize calls into this section yet
  -- pure infrastructure for a later Stage E rewrite rule to consume,
  the same "define and verify the analysis before any rule depends on
  it" precedent Stage B (DecodeOperand/GetEffects/LocalDeadAfter) and
  several Stage C matchers already established for this project.

  Capacity: MaxBlocks/MaxCfgOps below are generous, fixed, defensive
  caps -- confirmed against this project's own real, checked-in
  EXAMPLES/TETRIS/TETRIS.SMD (the largest procedure body found there,
  Draw, is well under 100 real instructions) -- not a limit expected to
  bind on any real procedure this translator is likely to see. OPT.TXT
  S7 item 3's own "Initially disable graph-dependent rewrites... Verify
  capacity limits" is honored by BuildCfg setting cfg.ok := FALSE
  (rather than truncating or guessing) the instant either cap would be
  exceeded -- every caller of BuildCfg/ComputeLiveness/PropagateValues
  MUST check cfg.ok before trusting ANY block/liveness/value-fact
  field; a resource-limit fallback here means "treat this procedure as
  if no analysis exists at all," never a partial/best-effort graph. }
{ MaxBlocks/MaxCfgOps/SuccNone/SuccUnknown/TBlock/TCfg are declared in
  the interface section above (exported for TESTS/STGD.PAS) -- see
  their own comments there for what each means; not re-declared here.

  FindBlockStartingAt: the 0-based index of the block in cfg whose own
  (startChunk,startSlot) equals (c,k) exactly, or -1 if none does --
  BuildCfg's own private lookup used while wiring successors (every
  jump target/fall-through point is always EXACTLY a block start, by
  BuildCfg's own construction, so an exact-position match is always
  the right question to ask, never a "which block CONTAINS this
  position" search). }
function FindBlockStartingAt(cfg: PCfg; c: POpChunk; k: integer): integer;
  var i: integer;
begin
  FindBlockStartingAt := -1;
  for i := 0 to cfg^.nBlocks - 1 do
    if (cfg^.blocks[i].startChunk = c) and (cfg^.blocks[i].startSlot = k) then begin
      FindBlockStartingAt := i; exit
    end
end;

{ FindBlockContainingAny: unlike FindBlockContainingFirstReal (below,
  in this same unit), some callers' own candidate operation can sit
  ANYWHERE inside its own containing block, not just at the block's
  own first real instruction (RemoveDeadZeroMov's "MOV AH,0";
  LoadModifyStoreProc's own dead-AX store) -- so this walks forward
  from each candidate block's own recorded start, via the plain
  Advance (not NextReal: (c,k) must be matched at every slot along the
  way, including labels/nops, since it's comparing literal chunk/slot
  identity, not filtering for "real" operations), all the way to that
  block's own recorded end, checking for a literal (c,k) match at each
  step. Defined here, ahead of FindBlockContainingFirstReal's own
  later definition, so every earlier caller in this unit (LoadModifyStoreProc
  among them) can reach it -- TP7 requires definition before use within
  a unit's own implementation section. }
function FindBlockContainingAny(cfg: PCfg; c: POpChunk; k: integer): integer;
  var i: integer; bc: POpChunk; bk: integer; more: boolean;
begin
  FindBlockContainingAny := -1;
  for i := 0 to cfg^.nBlocks - 1 do begin
    bc := cfg^.blocks[i].startChunk; bk := cfg^.blocks[i].startSlot;
    if (bc = c) and (bk = k) then begin FindBlockContainingAny := i; exit end;
    repeat
      more := (bc <> cfg^.blocks[i].endChunk) or (bk <> cfg^.blocks[i].endSlot);
      if more then more := Advance(bc, bk, cfg^.blocks[i].endChunk, cfg^.blocks[i].endSlot);
      if more and (bc = c) and (bk = k) then begin
        FindBlockContainingAny := i; exit
      end
    until not more
  end
end;

{ BuildCfg: OPT.TXT S7 items 1-3. Two passes over [startChunk,startSlot
  .. endChunk,endSlot] (inclusive, same convention as every other
  top-level scan in this unit): the first pass discovers every BLOCK
  START position (entry, every label, and every position immediately
  after a transfer -- JMP/Jcc/CALL/CALLFAR/RETN/RETF/IRET, "after
  transfers" per item 1; a CALL is included even though it isn't a
  BLOCK-ENDING transfer on its own account -- calls fall through --
  because item 4's own liveness treatment needs calls to be their own
  block boundary too, so a later Stage E rule could in principle attach
  a narrower per-call summary to exactly one block edge instead of an
  entire block; not exploited yet, but free to reserve now while
  building the block set the first time) and records each block's own
  extent; the second pass wires succ1/succ2 for each block by
  inspecting its own LAST real operation. A TOpAsm operation found in
  EITHER pass sets cfg.ok := FALSE immediately and stops (item 3's own
  explicit stance -- see TCfg.ok's own comment). }
procedure BuildCfg(startChunk: POpChunk; startSlot: integer;
                    endChunk: POpChunk; endSlot: integer; var cfg: PCfg);
  var c, lastRealC: POpChunk; k, lastRealK: integer; nScanned: integer;
      atBlockStart: boolean; lbl: string; i: integer;
  procedure StartBlock(sc: POpChunk; sk: integer);
  begin
    if cfg^.nBlocks >= MaxBlocks then begin cfg^.ok := false; exit end;
    cfg^.blocks[cfg^.nBlocks].startChunk := sc;
    cfg^.blocks[cfg^.nBlocks].startSlot := sk;
    if sc^.ops[sk].kind = TOpLabel then cfg^.blocks[cfg^.nBlocks].labelId := sc^.ops[sk].labelId
    else cfg^.blocks[cfg^.nBlocks].labelId := 0;
    cfg^.blocks[cfg^.nBlocks].succ1 := SuccNone;
    cfg^.blocks[cfg^.nBlocks].succ2 := SuccNone;
    cfg^.blocks[cfg^.nBlocks].isRetnExit := false;
    cfg^.nBlocks := cfg^.nBlocks + 1
  end;
begin
  New(cfg);   { OPT.TXT R7's own storage fix -- heap, not a stack
    local; the caller owns this and must Dispose() it once done, see
    PCfg's own header comment. }
  cfg^.nBlocks := 0; cfg^.ok := true;
  { Pass 1: discover every block-start position, in one forward walk.
    The procedure's own ENTRY position always starts block 0
    unconditionally -- but otherwise goes through EXACTLY the same
    "is this a label, or does atBlockStart say so, then check whether
    THIS operation is itself a transfer" logic every other position
    does, via a single shared loop body (firstIter selects between
    "look at (startChunk,startSlot) itself" and "Advance to the next
    position first") -- entry's own first operation must still be
    checked for being a transfer/CALL itself (a procedure that begins
    "JE .somewhere; ..." needs block 0 to end at that JE, exactly like
    a JE appearing anywhere else would), which a separate one-off
    StartBlock call before the loop, with no transfer check of its
    own, would silently skip -- confirmed the hard way via
    TESTS/STGD.PAS's own diamond-shape case (found nBlocks=3, not the
    expected 4: the entry JE and the immediately-following MOV/JMP
    were wrongly left in the SAME block). }
  c := startChunk; k := startSlot;
  nScanned := 0; lastRealC := c; lastRealK := k;
  atBlockStart := true;   { forces StartBlock at the very first real
    position seen, entry included, via the same "atBlockStart"
    mechanism every later transfer already uses -- no special-casing
    needed beyond this initial value. }
  while cfg^.ok do begin
    nScanned := nScanned + 1;
    if nScanned > MaxCfgOps then begin cfg^.ok := false; break end;
    if c^.ops[k].kind = TOpAsm then begin cfg^.ok := false; break end;
    if (c^.ops[k].kind = TOpInstr) and (c^.ops[k].mnemonic = MnNop) then
      { deleted -- transparent, never a block boundary on its own. }
    else begin
      if (c^.ops[k].kind = TOpLabel) or atBlockStart then StartBlock(c, k);
      atBlockStart := false;
      if c^.ops[k].kind = TOpInstr then begin
        if IsUncondTransfer(c^.ops[k].mnemonic) or IsJump(c^.ops[k].mnemonic)
           or (c^.ops[k].mnemonic = MnCall) or (c^.ops[k].mnemonic = MnCallFar) then
          atBlockStart := true
      end;
      lastRealC := c; lastRealK := k
    end;
    if not (cfg^.ok and Advance(c, k, endChunk, endSlot)) then break
  end;
  if not cfg^.ok then exit;
  { Pass 2: wire succ1/succ2 for each block, from its own LAST real
    operation (found the same way DeadCode/etc already scan: walk
    forward from the block's own start to either the next block's own
    start, or the range's own end, whichever comes first -- a block's
    own extent is exactly "up to but not including the next block's
    own start position," by construction from pass 1). }
  for i := 0 to cfg^.nBlocks - 1 do begin
    { Find this block's own extent (endChunk/endSlot -- up to but not
      including the next block's own start position, or the whole
      range's own end for the procedure's own last block) AND its own
      LAST REAL (non-MnNop) operation, in one forward walk from the
      block's own start. }
    c := cfg^.blocks[i].startChunk; k := cfg^.blocks[i].startSlot;
    lastRealC := c; lastRealK := k;
    cfg^.blocks[i].endChunk := c; cfg^.blocks[i].endSlot := k;
    while true do begin
      if (c^.ops[k].kind <> TOpInstr) or (c^.ops[k].mnemonic <> MnNop) then begin
        lastRealC := c; lastRealK := k
      end;
      if (c = endChunk) and (k = endSlot) then break;
      if not Advance(c, k, endChunk, endSlot) then break;
      if (i + 1 < cfg^.nBlocks) and (cfg^.blocks[i+1].startChunk = c)
         and (cfg^.blocks[i+1].startSlot = k) then break;   { next block starts here }
      cfg^.blocks[i].endChunk := c; cfg^.blocks[i].endSlot := k
    end;
    if lastRealC^.ops[lastRealK].kind = TOpInstr then begin
      if lastRealC^.ops[lastRealK].mnemonic = MnJmp then begin
        StrTab.Get(lastRealC^.ops[lastRealK].op1, lbl);
        if FindLabel(lbl, startChunk, startSlot, endChunk, endSlot, c, k) then
          cfg^.blocks[i].succ1 := FindBlockStartingAt(cfg, c, k)
        else
          cfg^.blocks[i].succ1 := SuccUnknown   { unresolved target }
      end else if IsJump(lastRealC^.ops[lastRealK].mnemonic) then begin
        { Jcc: succ1 = taken target, succ2 = fall-through (the next
          block in sequence, if this isn't the procedure's own last
          block). }
        StrTab.Get(lastRealC^.ops[lastRealK].op1, lbl);
        if FindLabel(lbl, startChunk, startSlot, endChunk, endSlot, c, k) then
          cfg^.blocks[i].succ1 := FindBlockStartingAt(cfg, c, k)
        else
          cfg^.blocks[i].succ1 := SuccUnknown;
        if i + 1 < cfg^.nBlocks then cfg^.blocks[i].succ2 := i + 1
        else cfg^.blocks[i].succ2 := SuccUnknown
      end else if IsUncondTransfer(lastRealC^.ops[lastRealK].mnemonic) then begin
        { RETN/RETF/IRET: reaches an unknown exit -- OPT.TXT S7 item 2's
          own "Returns/unresolved exits reach an unknown exit." Marked
          isRetnExit (OPT.TXT R6) so ComputeLivenessForProc can later
          tell this apart from a genuinely unresolved jump target
          (which also uses succ1=SuccUnknown, but can never be
          narrowed by a per-procedure demand query -- this analysis
          has no idea where an unresolved jump actually goes). Only
          MnRetn/MnRetf reach here as a genuine PROCEDURE return in
          this codebase's own real emitted code (ParseProcedure emits
          exactly one of the two, per PROCEDURE, at .return: -- see
          SPHO.PAS's own header comment there); MnIret (INTERRUPT
          procedures only) is included in the SAME conservative
          treatment here since R6's own analysis is scoped to ordinary
          PROCEDURE call/return pairs (an INTERRUPT handler is never
          the target of an ordinary CALL/CALLFAR at all -- SPHO.PAS's
          own EmitCall path has no way to reach one), so isRetnExit
          being TRUE for an IRET block is harmless (DemandFor is never
          actually consulted for a procId that names an INTERRUPT
          procedure, since no callProcId-tagged CALL site could ever
          target one), not a proof either way. }
        cfg^.blocks[i].succ1 := SuccUnknown;
        cfg^.blocks[i].isRetnExit := true
      end else begin
        { an ordinary instruction (including CALL/CALLFAR, which fall
          through after returning) -- falls into the next block, if
          any; the procedure's own last block, if it doesn't end in a
          real transfer at all, has no successor (SuccNone stays). }
        if i + 1 < cfg^.nBlocks then cfg^.blocks[i].succ1 := i + 1
      end
    end else begin
      { the block's own last real operation is a TOpLabel (a block
        containing ONLY a label, or ending right before another label
        with nothing else in between -- CheapReturn/DeadCode's own
        already-deleted operations can leave exactly this shape) --
        falls straight through, same as an ordinary instruction. }
      if i + 1 < cfg^.nBlocks then cfg^.blocks[i].succ1 := i + 1
    end
  end
end;

{ TLiveness: OPT.TXT S7 item 4 -- backward register/flag liveness,
  computed to a fixed point over cfg's own block graph.
    LiveOut[B] = union of successor LiveIn sets
    LiveIn[B]  = Use[B] union (LiveOut[B] minus Def[B])
  Use/Def are computed once per block (GetEffects summed over every
  real operation in the block, in FORWARD order within the block, so a
  register read before it's written within the SAME block correctly
  counts as a real Use of whatever reached the block from OUTSIDE it --
  a register written before being read within the block does NOT
  count as a Use at all, exactly the standard "upward-exposed use"
  definition this equation set assumes). "Def contains definite writes
  only" -- GetEffects.regWrite/flagWrite are already exactly that (see
  GetEffects' own header comment: undefined-flag cases never set their
  own bit). "Unknown exits observe all state" -- a block whose own
  succ1/succ2 is SuccUnknown contributes the ALL-BITS mask to that
  block's own LiveOut, per item 4's own explicit instruction; no
  documented ABI summary mechanism exists in this codebase to narrow
  that, so this is always the maximal, conservative case. TLiveness/
  AllRegMask/AllFlagMask are declared in the interface section above,
  not re-declared here. }
procedure ComputeLiveness(cfg: PCfg; var lv: PLiveness);
  var use, def: array[0..MaxBlocks-1] of word;
      flagUse, flagDef: array[0..MaxBlocks-1] of word;
      i, j, succ: integer; c: POpChunk; k: integer; eff: TEffects;
      newIn, newFlagIn: word; changed: boolean; iterCount: integer;
begin
  New(lv);   { OPT.TXT R7's own storage fix -- heap, not a stack local. }
  lv^.ok := cfg^.ok;
  if not cfg^.ok then exit;
  { Per-block Use/Def, one forward walk each. }
  for i := 0 to cfg^.nBlocks - 1 do begin
    use[i] := 0; def[i] := 0; flagUse[i] := 0; flagDef[i] := 0;
    c := cfg^.blocks[i].startChunk; k := cfg^.blocks[i].startSlot;
    while true do begin
      if c^.ops[k].kind = TOpInstr then begin
        if (c^.ops[k].mnemonic = MnCall) or (c^.ops[k].mnemonic = MnCallFar) then begin
          { A CALL's own GetEffects is DELIBERATELY known=FALSE (Stage
            B's own GetEffects header comment: no documented callee-ABI
            summary exists in this codebase) -- but unlike an operation
            GetEffects calls unknown for lack of a classified mnemonic
            at all, a CALL is still a real, STRUCTURALLY understood
            operation (BuildCfg already treats it as its own block
            boundary), so it must not disable the WHOLE liveness
            computation the way a genuinely unrecognized operation
            does. Treated as observing (reading) and clobbering
            (writing) EVERY register/flag bit -- the same "no ABI
            summary, so assume everything" conservative stance
            ComputeLiveness's own "unknown exits observe all state"
            already takes for the mirror-image graph-exit question,
            applied here to a call boundary instead. Found via
            TESTS/STGD.PAS's own TestLivenessCallObservesAll: the
            original code called GetEffects unconditionally here and
            bailed to lv^.ok:=FALSE the instant it saw known=FALSE,
            silently disabling liveness for ANY procedure containing a
            CALL at all -- almost every real procedure this translator
            emits. }
          use[i] := use[i] or (AllRegMask and not def[i]);
          def[i] := def[i] or AllRegMask;
          flagUse[i] := flagUse[i] or (AllFlagMask and not flagDef[i]);
          flagDef[i] := flagDef[i] or AllFlagMask
        end else if c^.ops[k].mnemonic <> MnNop then begin
          GetEffects(c^.ops[k], eff);
          if not eff.known then begin lv^.ok := false; exit end;
          use[i] := use[i] or (eff.regRead and not def[i]);
          def[i] := def[i] or eff.regWrite;
          flagUse[i] := flagUse[i] or (eff.flagRead and not flagDef[i]);
          flagDef[i] := flagDef[i] or eff.flagWrite
        end
      end;
      if (c = cfg^.blocks[i].endChunk) and (k = cfg^.blocks[i].endSlot) then break;
      Advance(c, k, cfg^.blocks[i].endChunk, cfg^.blocks[i].endSlot)
    end
  end;
  { Backward fixed-point: initialize every LiveIn/LiveOut to empty,
    then repeatedly recompute LiveOut from successors' LiveIn and
    LiveIn from Use/Def until nothing changes -- "Iterate loops; never
    trust only the first predecessor visited" (item 5's own words,
    equally true of this backward pass: a block visited before ALL of
    its own successors have their final LiveIn settled must be
    revisited once they do, which is exactly what iterating to a fixed
    point guarantees, never assumed after one single backward sweep). }
  for i := 0 to cfg^.nBlocks - 1 do begin
    lv^.liveIn[i] := 0; lv^.liveOut[i] := 0;
    lv^.flagLiveIn[i] := 0; lv^.flagLiveOut[i] := 0
  end;
  iterCount := 0;
  repeat
    changed := false;
    iterCount := iterCount + 1;
    for i := 0 to cfg^.nBlocks - 1 do begin
      lv^.liveOut[i] := 0; lv^.flagLiveOut[i] := 0;
      for j := 1 to 2 do begin
        if j = 1 then succ := cfg^.blocks[i].succ1 else succ := cfg^.blocks[i].succ2;
        if succ = SuccUnknown then begin
          lv^.liveOut[i] := AllRegMask; lv^.flagLiveOut[i] := AllFlagMask
        end else if succ >= 0 then begin
          lv^.liveOut[i] := lv^.liveOut[i] or lv^.liveIn[succ];
          lv^.flagLiveOut[i] := lv^.flagLiveOut[i] or lv^.flagLiveIn[succ]
        end
        { SuccNone contributes nothing. }
      end;
      newIn := use[i] or (lv^.liveOut[i] and not def[i]);
      newFlagIn := flagUse[i] or (lv^.flagLiveOut[i] and not flagDef[i]);
      if (newIn <> lv^.liveIn[i]) or (newFlagIn <> lv^.flagLiveIn[i]) then begin
        lv^.liveIn[i] := newIn; lv^.flagLiveIn[i] := newFlagIn; changed := true
      end
    end
  until not changed or (iterCount > MaxBlocks + 1);
  { OPT.TXT's own R4 finding: "A cap is not a proof." The comment this
    replaces argued the cap "should never bind" on a real, monotonic,
    bounded-lattice fixed point -- true, but "should never" is an
    argument, not a proof this function itself can act on: if the loop
    above DID exit via the cap while `changed` was still TRUE (an
    incomplete analysis, whatever the cause), lv^.liveIn/liveOut hold
    whatever partial state the last iteration left them in, which is
    NOT a proven fixed point, and every caller trusting lv^.ok=TRUE has
    no way to tell the difference from here. Set ok=FALSE explicitly
    in that case -- "on an unfinished capped analysis set ok=false and
    reject its dependent rewrites" -- so E4 (the only current consumer
    of ComputeLiveness) correctly treats an unfinished analysis exactly
    like any other "no analysis exists" case, never silently trusting
    a partial result. }
  if changed then lv^.ok := false
end;

{ ComputeLivenessForProc: see its own header comment in the interface
  section above. Identical to ComputeLiveness immediately above, except
  the succ=SuccUnknown case additionally checks TBlock's own
  isRetnExit: TRUE narrows via DemandFor(procId) instead of assuming
  AllRegMask/AllFlagMask unconditionally; FALSE (an unresolved jump
  target, not a return) keeps the old fully-conservative behavior --
  every other line is a byte-for-byte copy of ComputeLiveness's own
  body (duplicated rather than sharing an inner helper, since TP7 has
  no default/optional parameters to express "procId, or NONE" any more
  cheaply than two separate procedures already does, and this unit's
  own established convention throughout is one bare, directly-readable
  procedure per rule/pass rather than a shared parameterized core). }
procedure ComputeLivenessForProc(cfg: PCfg; procId: integer; var lv: PLiveness);
  var use, def: array[0..MaxBlocks-1] of word;
      flagUse, flagDef: array[0..MaxBlocks-1] of word;
      i, j, succ: integer; c: POpChunk; k: integer; eff: TEffects;
      newIn, newFlagIn: word; changed: boolean; iterCount: integer;
      demand: TProcDemand;
begin
  New(lv);   { OPT.TXT R7's own storage fix -- heap, not a stack local. }
  lv^.ok := cfg^.ok;
  if not cfg^.ok then exit;
  for i := 0 to cfg^.nBlocks - 1 do begin
    use[i] := 0; def[i] := 0; flagUse[i] := 0; flagDef[i] := 0;
    c := cfg^.blocks[i].startChunk; k := cfg^.blocks[i].startSlot;
    while true do begin
      if c^.ops[k].kind = TOpInstr then begin
        if (c^.ops[k].mnemonic = MnCall) or (c^.ops[k].mnemonic = MnCallFar) then begin
          use[i] := use[i] or (AllRegMask and not def[i]);
          def[i] := def[i] or AllRegMask;
          flagUse[i] := flagUse[i] or (AllFlagMask and not flagDef[i]);
          flagDef[i] := flagDef[i] or AllFlagMask
        end else if c^.ops[k].mnemonic <> MnNop then begin
          GetEffects(c^.ops[k], eff);
          if not eff.known then begin lv^.ok := false; exit end;
          use[i] := use[i] or (eff.regRead and not def[i]);
          def[i] := def[i] or eff.regWrite;
          flagUse[i] := flagUse[i] or (eff.flagRead and not flagDef[i]);
          flagDef[i] := flagDef[i] or eff.flagWrite
        end
      end;
      if (c = cfg^.blocks[i].endChunk) and (k = cfg^.blocks[i].endSlot) then break;
      Advance(c, k, cfg^.blocks[i].endChunk, cfg^.blocks[i].endSlot)
    end
  end;
  for i := 0 to cfg^.nBlocks - 1 do begin
    lv^.liveIn[i] := 0; lv^.liveOut[i] := 0;
    lv^.flagLiveIn[i] := 0; lv^.flagLiveOut[i] := 0
  end;
  iterCount := 0;
  repeat
    changed := false;
    iterCount := iterCount + 1;
    for i := 0 to cfg^.nBlocks - 1 do begin
      lv^.liveOut[i] := 0; lv^.flagLiveOut[i] := 0;
      for j := 1 to 2 do begin
        if j = 1 then succ := cfg^.blocks[i].succ1 else succ := cfg^.blocks[i].succ2;
        if succ = SuccUnknown then begin
          { OPT.TXT R6: a genuine RETN/RETF/IRET (isRetnExit) narrows
            via this procedure's own proven output demand instead of
            assuming every bit is observed -- an unresolved jump target
            (isRetnExit still FALSE, only ever set by BuildCfg's own
            RETN/RETF/IRET branch) keeps the OLD fully-conservative
            behavior, since this analysis genuinely has no idea where
            an unresolved jump goes. j=2 (succ2) reaching SuccUnknown
            only ever happens for a Jcc's own fall-through slot when
            this is the procedure's own last block with no real
            fall-through at all (BuildCfg's own succ2 assignment) --
            never a RETN (a RETN only ever sets succ1), so isRetnExit
            is correctly FALSE there too, no extra check needed. }
          if (j = 1) and cfg^.blocks[i].isRetnExit then begin
            DemandFor(procId, demand);
            lv^.liveOut[i] := lv^.liveOut[i] or demand.regMask;
            lv^.flagLiveOut[i] := lv^.flagLiveOut[i] or demand.flagMask
          end else begin
            lv^.liveOut[i] := AllRegMask; lv^.flagLiveOut[i] := AllFlagMask
          end
        end else if succ >= 0 then begin
          lv^.liveOut[i] := lv^.liveOut[i] or lv^.liveIn[succ];
          lv^.flagLiveOut[i] := lv^.flagLiveOut[i] or lv^.flagLiveIn[succ]
        end
        { SuccNone contributes nothing. }
      end;
      newIn := use[i] or (lv^.liveOut[i] and not def[i]);
      newFlagIn := flagUse[i] or (lv^.flagLiveOut[i] and not flagDef[i]);
      if (newIn <> lv^.liveIn[i]) or (newFlagIn <> lv^.flagLiveIn[i]) then begin
        lv^.liveIn[i] := newIn; lv^.flagLiveIn[i] := newFlagIn; changed := true
      end
    end
  until not changed or (iterCount > MaxBlocks + 1);
  if changed then lv^.ok := false
end;

{ TValueFacts: OPT.TXT S7 items 5-6 -- forward constant/register-value
  propagation. One fact per general-purpose register PER BLOCK ENTRY/
  EXIT: either "unknown" (regKnown[i][r] = FALSE) or "holds this exact
  constant WORD value" (regKnown[i][r] = TRUE, regVal[i][r] = value).
  Deliberately narrow -- OPT.TXT's own "register/memory value
  identities" is broader (e.g. "register R holds the same value as
  memory location M"), but a constant-propagation lattice is the
  smallest sound version of this that is still genuinely useful to a
  later Stage E rule, and the one this implementation actually
  verifies; memory-value identity tracking is not attempted here (no
  Stage E rule depends on it yet, and Stage B's own alias-proof gaps
  already make it the harder half of item 5's own scope). TValueFacts
  is declared in the interface section above, not re-declared here.

  JoinFact: OPT.TXT S7 item 5's own "At joins retain only equal facts
  from every reachable predecessor" -- combining two entry-fact states
  for the SAME register at a block with more than one predecessor:
  known+equal -> stays known at that value; anything else (either side
  unknown, or both known but at DIFFERENT values) -> unknown. }
procedure JoinFact(aKnown: boolean; aVal: word; bKnown: boolean; bVal: word;
                    var known: boolean; var val: word);
begin
  if aKnown and bKnown and (aVal = bVal) then begin known := true; val := aVal end
  else begin known := false; val := 0 end
end;

{ PropagateValues: forward fixed-point over cfg's own block graph.
  Entry facts start unknown everywhere (item 5: "Entry facts start
  unknown"); the procedure's own FIRST block also starts unknown (no
  caller-supplied constant-argument tracking exists in this codebase
  at all, so there is nothing sound to seed it with). Each block's own
  EXIT facts are computed by walking its own operations forward from
  its ENTRY facts (join of every predecessor's own exit facts, or
  unknown for the first block / a block with no predecessors found in
  cfg at all): a MOV reg,K (K a decoded literal) sets that register's
  own fact to known/K; ANY OTHER write to a register (from GetEffects'
  own regWrite mask, not just an exhaustive per-mnemonic list here)
  invalidates that register's own fact to unknown -- OPT.TXT item 6's
  own "Invalidate overlapping register facts" is handled by
  invalidating every register whose OWN regMask bit overlaps the
  write, not just an exact-name match (looked up via the fixed
  Regs86.RegAX..RegBH id range, comparing RegBitFor masks the same way
  Stage C's own overlap-aware matchers already do). A CALL, or any
  operation GetEffects itself calls unknown, invalidates EVERY
  register's own fact entirely (item 6: "effects of calls/unknowns") --
  conservative, since no documented per-call ABI summary exists here
  either, same stance ComputeLiveness's own "unknown exits observe all
  state" already takes for the mirror-image liveness question. }
{ ComputeReachable: OPT.TXT's own R4 finding -- "It joins all
  predecessor blocks without an entry-reachability filter." A block
  physically HAVING a Jcc/JMP edge pointing at it (BuildCfg's own
  succ1/succ2) does not mean that edge's own SOURCE block is itself
  ever actually reached from the procedure's entry (block 0) -- dead
  code (something DeadCode/RemoveDeadBranch et al haven't cleaned up
  in an EARLIER pass, or simply code this pass runs before those do)
  can still contain a live-looking JMP/Jcc targeting a real block,
  wrongly counted as a genuine predecessor by a naive "scan every
  block for an edge into i" join -- forcing PropagateValues' own join
  to UNKNOWN even when every block ACTUALLY reachable from entry
  agrees on a constant. Plain forward reachability from block 0 over
  succ1/succ2 (a worklist, not recursion -- TP7's own stack is not
  sized for procedure-length-deep recursion), computed once before
  the whole fixed-point loop runs (reachability itself never changes
  across PropagateValues' own iterations -- only the FACTS at each
  reachable block do), gives every join below a precise "is this
  candidate predecessor real" test. }
procedure ComputeReachable(cfg: PCfg; var reachable: array of boolean);
  var worklist: array[0..MaxBlocks-1] of integer;
      head, tail, i, cur: integer;
begin
  for i := 0 to cfg^.nBlocks - 1 do reachable[i] := false;
  if cfg^.nBlocks = 0 then exit;
  reachable[0] := true;
  worklist[0] := 0; head := 0; tail := 1;
  while head < tail do begin
    cur := worklist[head]; head := head + 1;
    if (cfg^.blocks[cur].succ1 >= 0) and not reachable[cfg^.blocks[cur].succ1] then begin
      reachable[cfg^.blocks[cur].succ1] := true;
      worklist[tail] := cfg^.blocks[cur].succ1; tail := tail + 1
    end;
    if (cfg^.blocks[cur].succ2 >= 0) and not reachable[cfg^.blocks[cur].succ2] then begin
      reachable[cfg^.blocks[cur].succ2] := true;
      worklist[tail] := cfg^.blocks[cur].succ2; tail := tail + 1
    end
  end
end;

procedure PropagateValues(cfg: PCfg; var vf: PValueFacts);
  var i, j, p, r, m: integer; entryKnown: array[1..16] of boolean;
      entryVal: array[1..16] of word;
      c: POpChunk; k: integer; eff: TEffects; opnd1, opnd2: string;
      litVal: word; dstReg: integer; anyPred: boolean; changed: boolean;
      iterCount: integer;
      pass1Known: boolean; pass1Val: word;
      reachable: array[0..MaxBlocks-1] of boolean;
      entryMemKnown: array[1..MaxMemFacts] of boolean;
      entryMemFact: array[1..MaxMemFacts] of TMemFact;
      memOp: TOperand; srcReg: integer; nMemUsed: integer;
      matchIdx: integer; mjExitKnown: boolean; mjExitFact: TMemFact;

  { MemFactIndexOf: the slot index (1..MaxMemFacts) already tracking
    this exact (frameOffset,isByte) object among entryMemKnown/Fact, or
    0 if none does. }
  function MemFactIndexOf(const offs: longint; isByte: boolean): integer;
    var q: integer;
  begin
    MemFactIndexOf := 0;
    for q := 1 to MaxMemFacts do
      if entryMemKnown[q] and (entryMemFact[q].frameOffset = offs)
         and (entryMemFact[q].isByte = isByte) then begin
        MemFactIndexOf := q; exit
      end
  end;

  { MemFactInvalidateReg: OPT.TXT R7's own "invalidate... aliases" --
    any memory fact whose own srcReg OVERLAPS regMask (a write to that
    register, or an overlapping byte half of it) can no longer be
    trusted to equal that register's CURRENT value, so it is dropped
    entirely rather than left stale. }
  procedure MemFactInvalidateReg(regMask: word);
    var q: integer;
  begin
    for q := 1 to MaxMemFacts do
      if entryMemKnown[q]
         and ((RegBitFor(entryMemFact[q].srcReg, entryMemFact[q].isByte) and regMask) <> 0) then
        entryMemKnown[q] := false
  end;

begin
  New(vf);   { OPT.TXT R7's own storage fix -- heap, not a stack local. }
  vf^.ok := cfg^.ok;
  if not cfg^.ok then exit;
  ComputeReachable(cfg, reachable);
  for i := 0 to cfg^.nBlocks - 1 do begin
    for r := 1 to 16 do begin vf^.regKnown[i][r] := false; vf^.regVal[i][r] := 0 end;
    for m := 1 to MaxMemFacts do vf^.memKnown[i][m] := false
  end;
  iterCount := 0;
  repeat
    changed := false;
    iterCount := iterCount + 1;
    for i := 0 to cfg^.nBlocks - 1 do begin
      { Entry facts: join of every OTHER block's own exit facts where
        this block (i) is a successor -- "never trust only the first
        predecessor visited" is honored by scanning ALL blocks for a
        predecessor edge into i, joining every one found, not stopping
        at the first. Block 0 (the procedure's own entry) additionally
        always starts unknown even if some pathological input made it
        someone's successor too (a real generated procedure's own
        entry is never itself a jump target from inside the same
        procedure, but this is a defensive floor, not an assumption). }
      for r := 1 to 16 do begin entryKnown[r] := false; entryVal[r] := 0 end;
      for m := 1 to MaxMemFacts do entryMemKnown[m] := false;
      anyPred := false;
      if i > 0 then begin
        for j := 0 to cfg^.nBlocks - 1 do begin
          if reachable[j] and ((cfg^.blocks[j].succ1 = i) or (cfg^.blocks[j].succ2 = i)) then begin
            if not anyPred then begin
              for r := 1 to 16 do begin
                entryKnown[r] := vf^.regKnown[j][r]; entryVal[r] := vf^.regVal[j][r]
              end;
              for m := 1 to MaxMemFacts do begin
                entryMemKnown[m] := vf^.memKnown[j][m];
                entryMemFact[m] := vf^.memFact[j][m]
              end;
              anyPred := true
            end else begin
              for r := 1 to 16 do begin
                pass1Known := entryKnown[r]; pass1Val := entryVal[r];
                JoinFact(pass1Known, pass1Val, vf^.regKnown[j][r], vf^.regVal[j][r],
                         entryKnown[r], entryVal[r])
              end;
              { OPT.TXT R7's own "At joins retain a memory/register
                equivalence only when every reachable predecessor
                proves it": a memory fact is keyed by its own
                (frameOffset,isByte) identity, not a fixed slot index
                (predecessor A might track "[bp-4]" in its own slot 2,
                predecessor B in slot 1 -- the SAME object, a different
                position), so joining means looking up THIS SAME object
                by identity in predecessor j, not comparing raw slots
                positionally the way the fixed-width register array
                above can. Retained only if j ALSO proves it known, for
                the exact SAME srcReg (a different register holding
                the object's value in a different predecessor is not a
                sound join -- this analysis has no way to prove EITHER
                register still holds that value after the join without
                re-deriving it, so the fact is simply dropped, never
                guessed). }
              for m := 1 to MaxMemFacts do begin
                if entryMemKnown[m] then begin
                  matchIdx := 0;
                  for p := 1 to MaxMemFacts do
                    if vf^.memKnown[j][p]
                       and (vf^.memFact[j][p].frameOffset = entryMemFact[m].frameOffset)
                       and (vf^.memFact[j][p].isByte = entryMemFact[m].isByte) then
                      matchIdx := p;
                  if (matchIdx = 0) or (vf^.memFact[j][matchIdx].srcReg <> entryMemFact[m].srcReg) then
                    entryMemKnown[m] := false
                end
              end
            end
          end
        end
      end;
      { Walk this block's own operations forward from entryKnown/Val,
        producing this iteration's own exit facts. }
      c := cfg^.blocks[i].startChunk; k := cfg^.blocks[i].startSlot;
      while true do begin
        if c^.ops[k].kind = TOpInstr then begin
          if c^.ops[k].mnemonic = MnCall then begin
            for r := 1 to 16 do entryKnown[r] := false;  { item 6: calls
              invalidate every register's own fact. }
            for m := 1 to MaxMemFacts do entryMemKnown[m] := false   {
              OPT.TXT R7's own "invalidate... unknown calls" -- a CALL
              of any kind may write to ANY frame slot this analysis has
              no visibility into (no callee-ABI summary exists, same
              conservative stance GetEffects/ComputeLiveness already
              take for a CALL's own register effects). }
          end else if c^.ops[k].mnemonic <> MnNop then begin
            GetEffects(c^.ops[k], eff);
            if not eff.known then begin
              for r := 1 to 16 do entryKnown[r] := false;
              for m := 1 to MaxMemFacts do entryMemKnown[m] := false
            end else if c^.ops[k].mnemonic = MnMov then begin
              StrTab.Get(c^.ops[k].op1, opnd1); StrTab.Get(c^.ops[k].op2, opnd2);
              dstReg := Regs86.LookupReg(Util.UpStr(opnd1));
              if (dstReg >= Regs86.RegAX) and (dstReg <= Regs86.RegBH)
                 and ParseDecimalLiteral(opnd2, litVal) then begin
                { first invalidate every OVERLAPPING register (item 6:
                  "overlapping register facts"), then set dstReg's own
                  fact to the fresh known constant. }
                for r := 1 to 16 do
                  if (r <> dstReg) and ((RegBitFor(r, Regs86.IsByteReg(r))
                      and RegBitFor(dstReg, Regs86.IsByteReg(dstReg))) <> 0) then
                    entryKnown[r] := false;
                entryKnown[dstReg] := true; entryVal[dstReg] := litVal;
                MemFactInvalidateReg(RegBitFor(dstReg, Regs86.IsByteReg(dstReg)))
              end else begin
                { OPT.TXT R7's own "Start with nonescaping frame
                  objects": "MOV [frameobj],srcReg" -- a proven-safe
                  store into a PROVEN frame object (DecodeOperand's own
                  isFrameObject proof, the SAME narrow scope C1/E1
                  already require) with a real, non-segment source
                  register RECORDS a fresh memory fact (this frame
                  slot's own value now equals srcReg's own CURRENT
                  value), reusing an already-tracked slot for the same
                  (frameOffset,isByte) identity if one exists, or the
                  next free slot up to MaxMemFacts (silently skipped if
                  none free -- a missed opportunity, never a
                  correctness risk, same "reject on capacity limit"
                  convention every other bounded scan here uses). Any
                  OTHER memory write (an unproven target, or the write
                  side of a read-modify-write like "ADD [x],K")
                  conservatively invalidates EVERY tracked memory fact
                  -- this analysis has no alias proof to rule out that
                  write touching the SAME frame slot some OTHER fact
                  already tracks. }
                DecodeOperand(opnd1, memOp);
                srcReg := Regs86.LookupReg(Util.UpStr(opnd2));
                if (memOp.kind = OpKindMem) and memOp.isFrameObject
                   and (srcReg <> 0) and not Regs86.IsSegReg(srcReg) then begin
                  MemFactInvalidateReg(RegBitFor(srcReg, Regs86.IsByteReg(srcReg)));
                  matchIdx := MemFactIndexOf(memOp.frameOffset, Regs86.IsByteReg(srcReg));
                  if matchIdx = 0 then begin
                    nMemUsed := 0;
                    for m := 1 to MaxMemFacts do if entryMemKnown[m] then nMemUsed := nMemUsed + 1;
                    if nMemUsed < MaxMemFacts then begin
                      m := 1;
                      while entryMemKnown[m] do m := m + 1;
                      matchIdx := m
                    end
                  end;
                  if matchIdx <> 0 then begin
                    entryMemKnown[matchIdx] := true;
                    entryMemFact[matchIdx].frameOffset := memOp.frameOffset;
                    entryMemFact[matchIdx].isByte := Regs86.IsByteReg(srcReg);
                    entryMemFact[matchIdx].srcReg := srcReg
                  end
                end else if (eff.memEffect = MemWrite) or (eff.memEffect = MemReadWrite)
                            or (eff.memEffect = MemUnknown) then
                  for m := 1 to MaxMemFacts do entryMemKnown[m] := false;
                { an ordinary write (or a MOV this pass doesn't prove a
                  constant for, e.g. a memory/frame source) -- for
                  every general-purpose register whose own mask
                  overlaps eff.regWrite, invalidate its own fact.

                  A REAL bug, found while verifying OPT.TXT R7's own
                  cross-block StoreForwarding rewrite: this (and the
                  identically-shaped check just below, for the
                  "ordinary instruction" branch) previously invalidated
                  every tracked memory fact for ANY memEffect at all,
                  including a bare MemRead -- a PLAIN memory READ can
                  NEVER alias/corrupt an unrelated memory location's own
                  value, only a WRITE (or MemUnknown, a real "could be
                  anything" barrier) can. The original over-broad check
                  meant a proven frame-object STORE's own fact was
                  wiped out by the very next instruction that merely
                  READ any memory at all (e.g. "CMP byte [bp+4],1" right
                  after a real store) -- confirmed directly: this
                  silently defeated CrossBlockStoreForwarding's own
                  cross-block proof entirely, every predecessor block's
                  own exit fact was empty whenever ANYTHING memory-
                  adjacent ran after the store, which is most real
                  code. Narrowed to WRITE/READWRITE/UNKNOWN only -- a
                  bare read leaves every tracked fact correctly
                  untouched. }
                for r := 1 to 16 do
                  if (RegBitFor(r, Regs86.IsByteReg(r)) and eff.regWrite) <> 0 then
                    entryKnown[r] := false
              end
            end else begin
              for r := 1 to 16 do
                if (RegBitFor(r, Regs86.IsByteReg(r)) and eff.regWrite) <> 0 then
                  entryKnown[r] := false;
              MemFactInvalidateReg(eff.regWrite);
              if (eff.memEffect = MemWrite) or (eff.memEffect = MemReadWrite)
                 or (eff.memEffect = MemUnknown) then
                for m := 1 to MaxMemFacts do entryMemKnown[m] := false
            end
          end
        end;
        if (c = cfg^.blocks[i].endChunk) and (k = cfg^.blocks[i].endSlot) then break;
        Advance(c, k, cfg^.blocks[i].endChunk, cfg^.blocks[i].endSlot)
      end;
      for r := 1 to 16 do
        if (entryKnown[r] <> vf^.regKnown[i][r]) or (entryVal[r] <> vf^.regVal[i][r]) then begin
          vf^.regKnown[i][r] := entryKnown[r]; vf^.regVal[i][r] := entryVal[r]; changed := true
        end;
      for m := 1 to MaxMemFacts do begin
        mjExitKnown := entryMemKnown[m]; mjExitFact := entryMemFact[m];
        if (mjExitKnown <> vf^.memKnown[i][m])
           or (mjExitKnown and ((mjExitFact.frameOffset <> vf^.memFact[i][m].frameOffset)
                               or (mjExitFact.isByte <> vf^.memFact[i][m].isByte)
                               or (mjExitFact.srcReg <> vf^.memFact[i][m].srcReg))) then begin
          vf^.memKnown[i][m] := mjExitKnown; vf^.memFact[i][m] := mjExitFact; changed := true
        end
      end
    end
  until not changed or (iterCount > MaxBlocks + 1);
  { OPT.TXT's own R4 finding: "A cap is not a proof" -- see
    ComputeLiveness's own identical fix, immediately above, for the
    full reasoning. Applies here too: PropagateValues' own lattice
    (known/unknown per register per block) is likewise monotonic and
    bounded, so the cap "should never bind" is equally true here, but
    equally not something this function can rely on without checking. }
  if changed then vf^.ok := false
end;

{ ============================================================
  STAGE E: DATA-FLOW-DEPENDENT REWRITES (OPT.TXT S8) -- E3
  ============================================================
  LoadModifyStore ("load/modify/store and dead local stores"):

    MOV AX,[counter]; ADD AX,1; MOV [counter],AX
      -> ADD word [counter],1

  The first Stage E rule implemented -- chosen first (consulted
  directly on Stage E's own scope before implementing) as the most
  self-contained of the five: a single straight-line, three-operation
  pattern with a clear worked example, needing a dead-AX proof and an
  alias proof, but NOT cross-block merged facts the way E1/E2's own
  "Start within blocks, then use merged facts across branch edges"
  explicitly calls for -- Stage B's own LocalDeadAfter (already proven
  throughout Stage C) is the right tool here, not Stage D's own
  CFG-based ComputeLiveness, since the whole match is three MUTUALLY
  ADJACENT operations with no branch inside it at all.

  Match: MOV AX,mem / ADD-or-SUB AX,K / MOV mem,AX (same mem operand
  text on both ends), all three mutually adjacent (NextReal, same
  "skip already-nop'd operations" convention every other matcher uses).
  Collapses to ADD-or-SUB word mem,K, deleting the two MOVs -- "This
  removes two instructions, not a memory read: both forms read and
  write the counter once" (OPT.TXT's own words) is satisfied by
  construction: the original reads mem once (into AX) and writes it
  once (from AX); the rewrite reads-modifies-writes mem once via the
  ADD/SUB itself, the same single memory access either way.

  Requirements (OPT.TXT's own words, each addressed below):
  - "Require dead AX" -- Stage B's own LocalDeadAfter, scanning forward
    from the rewritten ADD/SUB's own slot, proves nothing downstream
    reads AX (RegMaskAX) before something else overwrites it first.
  - "identical ordinary-memory location/width" -- mem's own text must
    be IDENTICAL on both the load and the store (a plain string
    comparison, the same "text equality, not full alias analysis"
    baseline every other Stage A-C memory-adjacent matcher already
    uses); width is implicitly WORD, since AX (a word register) is
    what's loaded/stored.
  - "Reject volatile/shared or potentially aliased memory" -- mem must
    DecodeOperand as OpKindMem with EITHER isFrameObject TRUE (Stage
    B's own proven-local proof) OR addrRegMask = 0 (no register
    contributes to the address at all -- a plain '[name]' global
    reference, exactly OPT.TXT's own worked example, '[counter]'):
    both shapes are addresses no RUNTIME indexing could have changed
    mid-sequence, the narrowest defensible "not potentially aliased by
    something this pass could have seen coming" proof available
    without a real alias-analysis pass (none exists in this codebase).
    An INDEXED memory operand (a register contributing to the address,
    e.g. '[bx]' or '[bp+si-2]') is never accepted -- its own effective
    address could differ between the load and the store if anything in
    between touched the index register, and even though nothing DOES
    here (strict adjacency, only AX itself is touched), this rule
    stays conservative rather than trying to prove that negative case
    too.
  - "identical arithmetic flags" -- trivially true: the SAME single
    ADD/SUB instruction (just relocated onto the memory operand
    directly) produces the flags; nothing about moving its destination
    from AX to the memory operand changes what value it computes or
    what flags that computation sets.
  - "Use ADD; changing to INC also requires dead CF" -- this
    implementation only ever emits ADD/SUB (matching the mnemonic
    already present), never converts to INC/DEC at all -- INC/DEC's
    own CF-preservation difference (OPT.TXT A2, Stage A) is a
    completely separate, narrower proof this rule does not attempt. }
procedure LoadModifyStore(startChunk: POpChunk; startSlot: integer;
                           endChunk: POpChunk; endSlot: integer);
  var c, ac, sc: POpChunk; k, ak, sk: integer;
      axTxt, mem1, mem2, kTxt: string; memOp, kOp: TOperand;
begin
  c := startChunk; k := startSlot;
  repeat
    if (c^.ops[k].kind = TOpInstr) and (c^.ops[k].mnemonic = MnMov) then begin
      StrTab.Get(c^.ops[k].op1, axTxt);
      if Util.EqualICase(axTxt, 'ax') then begin
        StrTab.Get(c^.ops[k].op2, mem1);
        DecodeOperand(mem1, memOp);
        if (memOp.kind = OpKindMem)
           and (memOp.isFrameObject or (memOp.addrRegMask = RegMaskNone)) then begin
          ac := c; ak := k;
          if NextReal(ac, ak, endChunk, endSlot) and (ac^.ops[ak].kind = TOpInstr)
             and ((ac^.ops[ak].mnemonic = MnAdd) or (ac^.ops[ak].mnemonic = MnSub)) then begin
            StrTab.Get(ac^.ops[ak].op1, axTxt);
            StrTab.Get(ac^.ops[ak].op2, kTxt);
            DecodeOperand(kTxt, kOp);
            { K must be a register or immediate, NEVER memory -- 8086
              has no memory-to-memory ADD/SUB encoding at all; rewriting
              "MOV AX,mem1; ADD AX,[BX]; MOV mem1,AX" (mem1 provably
              dead-after and a proven safe mem1, but K itself being a
              SECOND, independent memory operand) into "ADD word
              mem1,[BX]" would emit exactly that illegal encoding.
              Found via TESTS/ARRPARAM.SMD's own real generated code
              (TASM.EXE itself rejected it outright, "unsupported ALU
              operand combination") -- a genuine correctness bug in
              this rule's own first draft, not a theoretical one.

              K must ALSO never OVERLAP AX itself (OPT.TXT's own R3
              finding, a second, separate real correctness bug this
              same first draft had): "MOV AX,mem1; ADD AX,AX; MOV
              mem1,AX; MOV AX,0" would otherwise rewrite to "ADD word
              mem1,AX" -- but K's own text is literally 'AX', which the
              rewrite reads AFTER the load it just deleted, not BEFORE
              (the original computed mem1 := mem1 + mem1, doubling;
              the rewrite would compute mem1 := mem1 + <mem1's own
              JUST-LOADED value into AX>, which happens to still be
              correct for this EXACT doubling case by coincidence, but
              is wrong in general the instant AX held anything else at
              entry -- "MOV AX,mem1; ADD AX,AX" is not the only way K
              could equal 'AX': K could just as easily be a completely
              unrelated prior AX value if this were, e.g., "ADD
              AX,K-that-happens-to-be-textually-AX" fed from a
              different code shape). Rejected outright by checking
              kOp's own regMask overlap against RegMaskAX -- not just a
              text comparison against 'AX', since AL/AH individually
              also overlap and must be rejected the same way. }
            if Util.EqualICase(axTxt, 'ax') and (kOp.kind <> OpKindMem)
               and not ((kOp.kind = OpKindReg) and ((kOp.regMask and RegMaskAX) <> 0)) then begin
              sc := ac; sk := ak;
              if NextReal(sc, sk, endChunk, endSlot) and (sc^.ops[sk].kind = TOpInstr)
                 and (sc^.ops[sk].mnemonic = MnMov) then begin
                StrTab.Get(sc^.ops[sk].op1, mem2);
                StrTab.Get(sc^.ops[sk].op2, axTxt);
                if (mem1 = mem2) and Util.EqualICase(axTxt, 'ax')
                   and LocalDeadAfter(sc, sk, endChunk, endSlot, RegMaskAX, FlagMaskNone) then begin
                  c^.ops[k].mnemonic := MnNop;
                  ac^.ops[ak].op1 := StrTab.Put('word ' + mem1);
                  sc^.ops[sk].mnemonic := MnNop
                end
              end
            end
          end
        end
      end
    end
  until not Advance(c, k, endChunk, endSlot)
end;

{ LoadModifyStoreProc: see its own header comment in the interface
  section above. }
procedure LoadModifyStoreProc(startChunk: POpChunk; startSlot: integer;
                               endChunk: POpChunk; endSlot: integer; procId: integer);
  var c, ac, sc: POpChunk; k, ak, sk: integer;
      axTxt, mem1, mem2, kTxt: string; memOp, kOp: TOperand;
      cfg: PCfg; lv: PLiveness; blk: integer; reachedEnd, deadProven: boolean;
begin
  c := startChunk; k := startSlot;
  repeat
    if (c^.ops[k].kind = TOpInstr) and (c^.ops[k].mnemonic = MnMov) then begin
      StrTab.Get(c^.ops[k].op1, axTxt);
      if Util.EqualICase(axTxt, 'ax') then begin
        StrTab.Get(c^.ops[k].op2, mem1);
        DecodeOperand(mem1, memOp);
        if (memOp.kind = OpKindMem)
           and (memOp.isFrameObject or (memOp.addrRegMask = RegMaskNone)) then begin
          ac := c; ak := k;
          if NextReal(ac, ak, endChunk, endSlot) and (ac^.ops[ak].kind = TOpInstr)
             and ((ac^.ops[ak].mnemonic = MnAdd) or (ac^.ops[ak].mnemonic = MnSub)) then begin
            StrTab.Get(ac^.ops[ak].op1, axTxt);
            StrTab.Get(ac^.ops[ak].op2, kTxt);
            DecodeOperand(kTxt, kOp);
            { Same K-never-memory / K-never-overlapping-AX safety proof
              LoadModifyStore itself already establishes in full -- see
              its own header comment above for the complete rationale,
              unchanged here. }
            if Util.EqualICase(axTxt, 'ax') and (kOp.kind <> OpKindMem)
               and not ((kOp.kind = OpKindReg) and ((kOp.regMask and RegMaskAX) <> 0)) then begin
              sc := ac; sk := ak;
              if NextReal(sc, sk, endChunk, endSlot) and (sc^.ops[sk].kind = TOpInstr)
                 and (sc^.ops[sk].mnemonic = MnMov) then begin
                StrTab.Get(sc^.ops[sk].op1, mem2);
                StrTab.Get(sc^.ops[sk].op2, axTxt);
                if (mem1 = mem2) and Util.EqualICase(axTxt, 'ax') then begin
                  { Dead-AX proof: LocalDeadAfterEx first (resolves
                    instantly for the common case -- a real overwrite of
                    AX arriving before any branch/RETN at all). Only
                    when the local scan reaches genuine range end
                    (reachedEnd=TRUE, never when it found a real AX read
                    partway through) does this fall back to CFG-wide,
                    DemandFor-narrowed liveness -- OPT.TXT's own "use
                    CFG liveness... beyond local scans and R6 masks at
                    proven normal returns." }
                  deadProven := LocalDeadAfterEx(sc, sk, endChunk, endSlot, RegMaskAX,
                                                  FlagMaskNone, reachedEnd);
                  if (not deadProven) and reachedEnd then begin
                    BuildCfg(startChunk, startSlot, endChunk, endSlot, cfg);
                    if cfg^.ok then begin
                      blk := FindBlockContainingAny(cfg, sc, sk);
                      if blk >= 0 then begin
                        ComputeLivenessForProc(cfg, procId, lv);
                        if lv^.ok and ((lv^.liveOut[blk] and RegMaskAX) = 0) then
                          deadProven := true;
                        Dispose(lv)
                      end
                    end;
                    Dispose(cfg)
                  end;
                  if deadProven then begin
                    c^.ops[k].mnemonic := MnNop;
                    ac^.ops[ak].op1 := StrTab.Put('word ' + mem1);
                    sc^.ops[sk].mnemonic := MnNop
                  end
                end
              end
            end
          end
        end
      end
    end
  until not Advance(c, k, endChunk, endSlot)
end;

{ RemoveDeadLocalStore: see its own header comment in the interface
  section above. }
function FrameOffsetEscapes(startChunk: POpChunk; startSlot: integer;
                             endChunk: POpChunk; endSlot: integer;
                             offs: longint): boolean;
  var c: POpChunk; k: integer; srcTxt: string; srcOp: TOperand;
begin
  FrameOffsetEscapes := false;
  c := startChunk; k := startSlot;
  repeat
    if (c^.ops[k].kind = TOpInstr) and (c^.ops[k].mnemonic = MnLea) then begin
      StrTab.Get(c^.ops[k].op2, srcTxt);
      DecodeOperand(srcTxt, srcOp);
      if (srcOp.kind = OpKindMem) and srcOp.isFrameObject and (srcOp.frameOffset = offs) then begin
        FrameOffsetEscapes := true; exit
      end
    end
  until not Advance(c, k, endChunk, endSlot)
end;

procedure RemoveDeadLocalStore(startChunk: POpChunk; startSlot: integer;
                                endChunk: POpChunk; endSlot: integer);
  var c, sc: POpChunk; k, sk: integer;
      dstTxt, srcTxt: string; dstOp: TOperand; srcReg: integer;
      dstIsByte, dead, blocked: boolean; eff: TEffects;
      scanOp1Txt, scanOp2Txt: string;
      scanSrcReg: integer;

  { TouchesOurSlot: TRUE if operand text op decodes to a frame object at
    OUR OWN offset -- used to test both op1 and op2 of whatever
    instruction the forward scan is currently looking at. }
  function TouchesOurSlot(const opTxt: string): boolean;
    var o: TOperand;
  begin
    DecodeOperand(opTxt, o);
    TouchesOurSlot := (o.kind = OpKindMem) and o.isFrameObject and (o.frameOffset = dstOp.frameOffset)
  end;

begin
  c := startChunk; k := startSlot;
  repeat
    if (c^.ops[k].kind = TOpInstr) and (c^.ops[k].mnemonic = MnMov) then begin
      StrTab.Get(c^.ops[k].op1, dstTxt);
      DecodeOperand(dstTxt, dstOp);
      StrTab.Get(c^.ops[k].op2, srcTxt);
      srcReg := Regs86.LookupReg(Util.UpStr(srcTxt));
      if (dstOp.kind = OpKindMem) and dstOp.isFrameObject
         and (srcReg <> 0) and not Regs86.IsSegReg(srcReg)
         and not FrameOffsetEscapes(startChunk, startSlot, endChunk, endSlot, dstOp.frameOffset) then begin
        dstIsByte := Regs86.IsByteReg(srcReg);
        { Forward scan from the store: the SAME frame offset (and
          width -- a byte slot and a word slot at the same offset are
          two different objects, same TMemFact convention R7's own
          PropagateValues already established) must be WRITTEN again by
          a plain MOV of matching width (proving the just-stored value
          dead) before any READ of it, or the scan must reach a bare
          RETN/RETF/IRET with nothing in between reading it -- "exit
          with... dead" needs no further proof for a private, proven-
          nonescaping local (unlike LoadModifyStoreProc's own AX case,
          a frame slot has no caller-visibility question at all once
          escape is already ruled out above). A CALL or any unknown-
          effect instruction anywhere in the scanned prefix blocks the
          WHOLE match -- "unknown pointer reads/calls keep stores
          live," no per-object alias proof exists to narrow that
          conservatism further. Any OTHER instruction touching our own
          offset (a read-modify-write, a differently-sized MOV, our
          offset as a SOURCE operand) is a genuine read and blocks too. }
        sc := c; sk := k; dead := false; blocked := false;
        while (not dead) and (not blocked) and Advance(sc, sk, endChunk, endSlot) do begin
          if (sc^.ops[sk].kind = TOpInstr) and (sc^.ops[sk].mnemonic = MnNop) then
            { deleted -- transparent, keep scanning. }
          else if (sc^.ops[sk].kind = TOpInstr)
                  and ((sc^.ops[sk].mnemonic = MnRetn) or (sc^.ops[sk].mnemonic = MnRetf)
                       or (sc^.ops[sk].mnemonic = MnIret)) then
            dead := true   { exit reached with nothing in between having
              read this offset -- proven dead. }
          else begin
            GetEffects(sc^.ops[sk], eff);
            if (not eff.known) or (sc^.ops[sk].mnemonic = MnCall)
               or (sc^.ops[sk].mnemonic = MnCallFar) then
              blocked := true
            else if eff.transferKind <> XferNone then
              blocked := true
            else begin
              StrTab.Get(sc^.ops[sk].op1, scanOp1Txt);
              StrTab.Get(sc^.ops[sk].op2, scanOp2Txt);
              if (sc^.ops[sk].mnemonic = MnMov) and TouchesOurSlot(scanOp1Txt)
                 and not TouchesOurSlot(scanOp2Txt) then begin
                { A fresh MOV of our own offset FROM something other
                  than itself -- either a genuine overwrite (proven
                  dead, if the source is a matching-width real
                  register) or an unrecognized store shape (blocks,
                  conservatively -- "no proof" is never treated as
                  "safe"). }
                scanSrcReg := Regs86.LookupReg(Util.UpStr(scanOp2Txt));
                if (scanSrcReg <> 0) and not Regs86.IsSegReg(scanSrcReg)
                   and (Regs86.IsByteReg(scanSrcReg) = dstIsByte) then
                  dead := true
                else
                  blocked := true
              end else if TouchesOurSlot(scanOp1Txt) or TouchesOurSlot(scanOp2Txt) then
                blocked := true   { our own offset appears anywhere else
                  at all -- a real read (or a read-modify-write, or a
                  differently-sized access), blocks unconditionally. }
            end
          end
        end;
        if dead then c^.ops[k].mnemonic := MnNop
      end
    end
  until not Advance(c, k, endChunk, endSlot)
end;

{ IsPowerOfTwo: TRUE iff v is an exact power of two in 2..256 --
  FoldConstDivMod's own K restriction. The classic "v and (v-1) = 0"
  bit trick correctly also accepts v=0 (0 and -1 = 0), so 0 is
  excluded explicitly; the upper 256 bound is this fold's own
  deliberate scope limit (see its own header comment). }
function IsPowerOfTwo(v: word): boolean;
begin
  IsPowerOfTwo := (v >= 2) and (v <= 256) and ((v and (v - 1)) = 0)
end;

{ Log2PowerOfTwo: v already proven a power of two (2..256) by
  IsPowerOfTwo -- returns the shift count N such that v = 1 shl N. }
function Log2PowerOfTwo(v: word): integer;
  var n: integer; x: word;
begin
  n := 0; x := v;
  while x > 1 do begin x := x shr 1; n := n + 1 end;
  Log2PowerOfTwo := n
end;

{ FoldConstDivMod: see its own header comment in the interface section
  above. }
procedure FoldConstDivMod(startChunk: POpChunk; startSlot: integer;
                           endChunk: POpChunk; endSlot: integer; procId: integer);
  var c, xc, dc, mc, ec: POpChunk; k, xk, dk, mk, ek: integer;
      axTxt, cxTxt, kTxt, dxTxt, ax2Txt: string;
      kVal: word; isMod: boolean; shiftN: integer;
      reachedEnd, deadProven: boolean; cfg: PCfg; lv: PLiveness; blk: integer;
begin
  c := startChunk; k := startSlot;
  repeat
    if (c^.ops[k].kind = TOpInstr) and (c^.ops[k].mnemonic = MnMov) then begin
      StrTab.Get(c^.ops[k].op1, cxTxt);
      if Util.EqualICase(cxTxt, 'cx') then begin
        StrTab.Get(c^.ops[k].op2, kTxt);
        if ParseWordLiteral(kTxt, kVal) and IsPowerOfTwo(kVal) then begin
          xc := c; xk := k;
          if NextReal(xc, xk, endChunk, endSlot) and (xc^.ops[xk].kind = TOpInstr)
             and (xc^.ops[xk].mnemonic = MnXor) then begin
            StrTab.Get(xc^.ops[xk].op1, dxTxt);
            StrTab.Get(xc^.ops[xk].op2, ax2Txt);
            if Util.EqualICase(dxTxt, 'dx') and Util.EqualICase(ax2Txt, 'dx') then begin
              dc := xc; dk := xk;
              if NextReal(dc, dk, endChunk, endSlot) and (dc^.ops[dk].kind = TOpInstr)
                 and (dc^.ops[dk].mnemonic = MnDiv) then begin
                StrTab.Get(dc^.ops[dk].op1, axTxt);
                if Util.EqualICase(axTxt, 'cx') then begin
                  { EmitMulDiv's own optional MOD-only remainder move --
                    present (isMod=TRUE) or absent (isMod=FALSE) is the
                    ONLY textual signal distinguishing "a DIV" from "a
                    MOD" in this emitted stream; the last real operation
                    of the matched sequence either way is ec/ek, used
                    below for both the dead-register scan's own start
                    point and (when the fold fires) the DIV/XOR/CX-MOV
                    deletion boundary. }
                  ec := dc; ek := dk; isMod := false;
                  mc := dc; mk := dk;
                  if NextReal(mc, mk, endChunk, endSlot) and (mc^.ops[mk].kind = TOpInstr)
                     and (mc^.ops[mk].mnemonic = MnMov) then begin
                    StrTab.Get(mc^.ops[mk].op1, axTxt);
                    StrTab.Get(mc^.ops[mk].op2, dxTxt);
                    if Util.EqualICase(axTxt, 'ax') and Util.EqualICase(dxTxt, 'dx') then begin
                      isMod := true; ec := mc; ek := mk
                    end
                  end;
                  { Dead CX/DX/flags proof: LocalDeadAfterEx first
                    (resolves instantly for the common case), falling
                    back to CFG-wide liveness ONLY on genuine range end
                    -- same composition R7/R8/R9 already established. }
                  deadProven := LocalDeadAfterEx(ec, ek, endChunk, endSlot,
                                                  RegMaskCX or RegMaskDX, FlagMaskArith, reachedEnd);
                  if (not deadProven) and reachedEnd then begin
                    BuildCfg(startChunk, startSlot, endChunk, endSlot, cfg);
                    if cfg^.ok then begin
                      blk := FindBlockContainingAny(cfg, ec, ek);
                      if blk >= 0 then begin
                        ComputeLivenessForProc(cfg, procId, lv);
                        if lv^.ok and ((lv^.liveOut[blk] and (RegMaskCX or RegMaskDX)) = 0)
                           and ((lv^.flagLiveOut[blk] and FlagMaskArith) = 0) then
                          deadProven := true;
                        Dispose(lv)
                      end
                    end;
                    Dispose(cfg)
                  end;
                  if deadProven then begin
                    if isMod then begin
                      { AND ax,K-1 -- masks off exactly the low N bits;
                        touches only AX, needs neither CX nor DX, legal
                        on every 8086 unconditionally. }
                      c^.ops[k].mnemonic := MnNop;
                      xc^.ops[xk].mnemonic := MnNop;
                      dc^.ops[dk].mnemonic := MnAnd;
                      dc^.ops[dk].op1 := StrTab.Put('ax');
                      dc^.ops[dk].op2 := StrTab.Put(IntStr(longint(kVal) - 1));
                      mc^.ops[mk].mnemonic := MnNop
                    end else begin
                      shiftN := Log2PowerOfTwo(kVal);
                      c^.ops[k].mnemonic := MnNop;
                      xc^.ops[xk].mnemonic := MnNop;
                      if shiftN = 1 then begin
                        dc^.ops[dk].mnemonic := MnShr;
                        dc^.ops[dk].op1 := StrTab.Put('ax');
                        dc^.ops[dk].op2 := StrTab.Put('1')
                      end else begin
                        { MOV cl,N; SHR ax,cl -- the CL-count form, ALSO
                          legal on every 8086 unconditionally, unlike
                          "SHR ax,N" with N>1 (an 80186+ immediate-count
                          encoding this fold must never emit, per its
                          own explicit "legal one-bit/CL shifts, not
                          post-8086 immediate-count encodings"). Reuses
                          the ORIGINAL "MOV cx,K" operation's own slot
                          (already proven dead as a value, its CX-sized
                          text simply repurposed) instead of inserting a
                          brand-new operation -- no extra TOpChunk slot
                          bookkeeping needed. }
                        c^.ops[k].mnemonic := MnMov;
                        c^.ops[k].op1 := StrTab.Put('cl');
                        c^.ops[k].op2 := StrTab.Put(IntStr(longint(shiftN)));
                        dc^.ops[dk].mnemonic := MnShr;
                        dc^.ops[dk].op1 := StrTab.Put('ax');
                        dc^.ops[dk].op2 := StrTab.Put('cl')
                      end
                    end
                  end
                end
              end
            end
          end
        end
      end
    end
  until not Advance(c, k, endChunk, endSlot)
end;

{ FoldConstMovArith: see its own header comment in the interface
  section above. }
procedure FoldConstMovArith(startChunk: POpChunk; startSlot: integer;
                             endChunk: POpChunk; endSlot: integer);
  var c, ac: POpChunk; k, ak: integer;
      regTxt, k1Txt, ax2Txt, k2Txt: string;
      regId: integer; k1Val, k2Val: word; folded: longint;
begin
  c := startChunk; k := startSlot;
  repeat
    if (c^.ops[k].kind = TOpInstr) and (c^.ops[k].mnemonic = MnMov) then begin
      StrTab.Get(c^.ops[k].op1, regTxt);
      regId := Regs86.LookupReg(Util.UpStr(regTxt));
      if (regId <> 0) and not Regs86.IsSegReg(regId) then begin
        StrTab.Get(c^.ops[k].op2, k1Txt);
        if ParseWordLiteral(k1Txt, k1Val) then begin
          ac := c; ak := k;
          if NextReal(ac, ak, endChunk, endSlot) and (ac^.ops[ak].kind = TOpInstr)
             and ((ac^.ops[ak].mnemonic = MnAdd) or (ac^.ops[ak].mnemonic = MnSub)) then begin
            StrTab.Get(ac^.ops[ak].op1, ax2Txt);
            StrTab.Get(ac^.ops[ak].op2, k2Txt);
            if Util.EqualICase(ax2Txt, regTxt) and ParseWordLiteral(k2Txt, k2Val)
               and LocalDeadAfter(ac, ak, endChunk, endSlot, RegMaskNone, FlagMaskArith) then begin
              { Left-to-right, identical width/wraparound to the two
                REAL instructions being folded: word arithmetic, mod
                65536 -- longint arithmetic here only to avoid a
                Pascal integer-overflow trap on the intermediate sum
                before the explicit "and $FFFF" truncation, never a
                claim about the VALUE itself exceeding 16 bits. }
              if ac^.ops[ak].mnemonic = MnAdd then
                folded := (longint(k1Val) + longint(k2Val)) and $FFFF
              else
                folded := (longint(k1Val) - longint(k2Val)) and $FFFF;
              c^.ops[k].op2 := StrTab.Put(IntStr(folded));
              ac^.ops[ak].mnemonic := MnNop
            end
          end
        end
      end
    end
  until not Advance(c, k, endChunk, endSlot)
end;

{ InsertOpAfter: see its own header comment in the interface section
  above. }
procedure InsertOpAfter(c: POpChunk; k: integer; const newOp: TOperation;
                         var newC: POpChunk; var newK: integer);
  var overflow: POpChunk; i: integer;
begin
  if c^.count < Chunk then begin
    { Case 1: slack in this same array -- shift ops[k+1..count] right
      by one slot, in place, walking BACKWARD so no slot is
      overwritten before its own old value has already been copied
      out of it. }
    for i := c^.count downto k + 1 do
      c^.ops[i + 1] := c^.ops[i];
    c^.ops[k + 1] := newOp;
    c^.count := c^.count + 1;
    newC := c; newK := k + 1
  end else if k < Chunk then begin
    { Case 2: c is full but k is not its own last slot -- allocate a
      fresh chunk, move ops[k+1..Chunk] (the ENTIRE remainder) into it
      in order, thread it into the list in c's own former next's
      place, and truncate c itself to end right after the new
      operation. }
    New(overflow);
    overflow^.count := Chunk - k;
    for i := k + 1 to Chunk do
      overflow^.ops[i - k] := c^.ops[i];
    overflow^.next := c^.next;
    c^.next := overflow;
    c^.count := k + 1;
    c^.ops[k + 1] := newOp;
    newC := c; newK := k + 1
  end else begin
    { Case 3: c is full AND k is its own last slot (Chunk) -- there is
      no remainder to move (nothing follows slot Chunk within c), and
      no room left in c for the new operation either (slot Chunk+1 is
      out of c's own declared [1..Chunk] bound). A fresh chunk holds
      ONLY the new operation, threaded in c's own former next's place;
      c itself is untouched. }
    New(overflow);
    overflow^.count := 1;
    overflow^.ops[1] := newOp;
    overflow^.next := c^.next;
    c^.next := overflow;
    newC := overflow; newK := 1
  end
end;

{ ============================================================
  STAGE F: LOOP TRANSFORMATIONS (OPT.TXT S9) -- shared dominance/
  natural-loop infrastructure
  ============================================================
  See each exported procedure/function's own header comment in the
  interface section above for what it does; implementations below. }

procedure DomBitsetClear(var s: TDomBitset);
  var i: integer;
begin
  for i := 0 to 31 do s[i] := 0
end;

procedure DomBitsetSetAll(var s: TDomBitset; nBlocks: integer);
  var i: integer;
begin
  { Set exactly bits 0..nBlocks-1 -- not simply "every bit in every
    word" (which would also set bits for block indices >= nBlocks,
    nonexistent blocks that must never spuriously compare equal/
    intersect against a real bitset). }
  DomBitsetClear(s);
  for i := 0 to nBlocks - 1 do DomBitsetSet(s, i)
end;

procedure DomBitsetSet(var s: TDomBitset; i: integer);
begin
  if (i >= 0) and (i < 512) then
    s[i div 16] := s[i div 16] or (word(1) shl (i mod 16))
end;

function DomBitsetHas(const s: TDomBitset; i: integer): boolean;
begin
  if (i >= 0) and (i < 512) then
    DomBitsetHas := (s[i div 16] and (word(1) shl (i mod 16))) <> 0
  else
    DomBitsetHas := false
end;

procedure DomBitsetIntersect(var dst: TDomBitset; const src: TDomBitset);
  var i: integer;
begin
  for i := 0 to 31 do dst[i] := dst[i] and src[i]
end;

function DomBitsetEqual(const a, b: TDomBitset): boolean;
  var i: integer;
begin
  DomBitsetEqual := true;
  for i := 0 to 31 do
    if a[i] <> b[i] then begin DomBitsetEqual := false; exit end
end;

{ ComputeDominance: see its own header comment in the interface
  section above. Classical iterative dataflow: block 0's own dom set
  contains ONLY block 0; a reachable block i (i<>0) starts as the
  singleton containing only i, unioned with the intersection of
  dom[p] for every real predecessor p -- initialized to the UNIVERSAL
  set for
  every reachable block except 0 (dom[0]), matching every other
  fixed-point analysis in this unit's own "start as unconstrained as
  possible, only ever NARROW via intersection" discipline (the same
  shape ComputeLiveness's own liveIn/liveOut fixed point already
  uses, just with set-intersection instead of union). An unreachable
  block's own dom[i] is LEFT at the universal set -- correct and safe:
  no real caller ever asks a dominance question about a block that
  cannot be reached from the entry at all (FindNaturalLoops' own
  back-edge search only ever considers REAL, resolved successor
  edges between blocks BuildCfg already produced). }
procedure ComputeDominance(cfg: PCfg; var dm: PDominance);
  var reachable: array[0..MaxBlocks-1] of boolean;
      i, j, p, iterCount: integer; changed: boolean;
      newDom: TDomBitset; anyPred: boolean;
begin
  New(dm);   { OPT.TXT R7's own storage fix -- heap, not a stack local. }
  dm^.ok := cfg^.ok;
  if not cfg^.ok then exit;
  ComputeReachable(cfg, reachable);
  for i := 0 to cfg^.nBlocks - 1 do
    if i = 0 then begin DomBitsetClear(dm^.dom[i]); DomBitsetSet(dm^.dom[i], 0) end
    else DomBitsetSetAll(dm^.dom[i], cfg^.nBlocks);
  iterCount := 0;
  repeat
    changed := false;
    iterCount := iterCount + 1;
    for i := 1 to cfg^.nBlocks - 1 do begin
      if reachable[i] then begin
        anyPred := false;
        DomBitsetSetAll(newDom, cfg^.nBlocks);
        for j := 0 to cfg^.nBlocks - 1 do
          if reachable[j] and ((cfg^.blocks[j].succ1 = i) or (cfg^.blocks[j].succ2 = i)) then begin
            DomBitsetIntersect(newDom, dm^.dom[j]);
            anyPred := true
          end;
        if not anyPred then DomBitsetClear(newDom);   { a reachable block
          with no real predecessor found here can only be the entry
          (handled separately, i=0) -- a defensive floor, never
          actually reached for i>0 given ComputeReachable's own
          definition, but "no predecessor found means no constraint"
          would be UNSOUND (the universal set), so this clears instead. }
        DomBitsetSet(newDom, i);
        if not DomBitsetEqual(newDom, dm^.dom[i]) then begin
          dm^.dom[i] := newDom; changed := true
        end
      end
    end
  until not changed or (iterCount > cfg^.nBlocks + 1);
  if changed then dm^.ok := false   { same "own convergence bound
    exceeded" conservative-reject stance ComputeLiveness already
    takes -- should never actually trigger (dominance over a DAG-like
    reducible CFG converges in at most nBlocks passes), but "no
    analysis exists" must never be silently treated as "assume it's
    safe" if it somehow did. }
end;

{ FindNaturalLoops: see its own header comment in the interface
  section above. For every block L with a real successor H such that H
  DOMINATES L (a back-edge L->H, proven via ComputeDominance, not a
  bare "successor index is numerically smaller" guess -- an
  irreducible/opaque jump that merely LOOKS backward in block order
  but where H does NOT dominate L is correctly never treated as a
  natural loop at all, satisfying "reject irreducible/opaque loops
  initially" by construction), the natural loop's own member set is H
  plus every block reachable BACKWARD from L (via real predecessor
  edges) without passing through H -- a worklist/BFS seeded with L,
  stopping at H, the standard textbook algorithm. }
procedure FindNaturalLoops(cfg: PCfg; dm: PDominance; var ls: PLoopSet);
  var i, j, w, p: integer; worklist: array[0..MaxBlocks-1] of integer;
      wCount, wi: integer; inLoop: array[0..MaxBlocks-1] of boolean;
      header, latch: integer;
begin
  New(ls);   { OPT.TXT R7's own storage fix -- heap, not a stack local. }
  ls^.nLoops := 0; ls^.ok := cfg^.ok and dm^.ok;
  if not ls^.ok then exit;
  for i := 0 to cfg^.nBlocks - 1 do begin
    for j := 1 to 2 do begin
      if j = 1 then w := cfg^.blocks[i].succ1 else w := cfg^.blocks[i].succ2;
      if (w >= 0) and (w < cfg^.nBlocks) and DomBitsetHas(dm^.dom[i], w) then begin
        { A real back-edge: i (the latch) -> w (the header), proven by
          w dominating i. }
        latch := i; header := w;
        if ls^.nLoops >= MaxBlocks then continue;   { capacity limit --
          "reject on capacity limit" convention, same as every other
          bounded scan in this unit; silently skipped, never a
          correctness risk, just a missed opportunity. }
        for p := 0 to cfg^.nBlocks - 1 do inLoop[p] := false;
        inLoop[header] := true; inLoop[latch] := true;
        worklist[0] := latch; wCount := 1;
        wi := 0;
        while wi < wCount do begin
          { Walk BACKWARD from worklist[wi]: every real predecessor not
            already in the loop, and not the header itself (already
            marked, so the "not already in loop" check alone already
            stops the walk there too -- kept as an explicit second
            condition purely for readability, not a separate proof). }
          for p := 0 to cfg^.nBlocks - 1 do
            if (cfg^.blocks[p].succ1 = worklist[wi]) or (cfg^.blocks[p].succ2 = worklist[wi]) then
              if not inLoop[p] then begin
                inLoop[p] := true;
                if wCount < MaxBlocks then begin
                  worklist[wCount] := p; wCount := wCount + 1
                end
              end;
          wi := wi + 1
        end;
        ls^.loops[ls^.nLoops].header := header;
        ls^.loops[ls^.nLoops].latch := latch;
        DomBitsetClear(ls^.loops[ls^.nLoops].members);
        for p := 0 to cfg^.nBlocks - 1 do
          if inLoop[p] then DomBitsetSet(ls^.loops[ls^.nLoops].members, p);
        ls^.nLoops := ls^.nLoops + 1
      end
    end
  end
end;

{ LastNonTransferReal: a block's own recorded endChunk/endSlot is its
  LAST real operation, which is very often the block's own TERMINATOR
  (a JMP/Jcc/CALL/RETN -- whatever caused BuildCfg to end the block
  there in the first place), not the ordinary instruction immediately
  before it that a caller like RemoveRepeatedFlagOpCrossBlock/
  PromoteLoopLocal actually needs to compare against (a real, found-
  the-hard-way bug: a predecessor block's own last op is nearly always
  a JMP/Jcc in exactly the single-predecessor-via-jump shape those
  rules exist to match, so comparing against endChunk/endSlot
  directly, unmodified, means the mnemonic check almost never even
  matches). Walks forward from the block's own recorded start via
  NextReal, remembering the last REAL operation visited that is NOT
  itself the block's own final position -- i.e., the last ordinary
  instruction strictly BEFORE any terminating transfer. Returns FALSE
  if the block has no such operation (a block consisting of nothing
  but its own terminator, e.g. a bare label immediately followed by a
  JMP). Defined here, ahead of PromoteLoopLocal's own earlier
  definition in this unit, so it can reach this helper too -- TP7
  requires definition before use within a unit's own implementation
  section. }
function LastNonTransferReal(cfg: PCfg; blk: integer; var lc: POpChunk; var lk: integer): boolean;
  var c: POpChunk; k: integer; found: boolean;
begin
  found := false;
  c := cfg^.blocks[blk].startChunk; k := cfg^.blocks[blk].startSlot;
  if (c^.ops[k].kind = TOpInstr) and (c^.ops[k].mnemonic <> MnNop) then begin
    if (c = cfg^.blocks[blk].endChunk) and (k = cfg^.blocks[blk].endSlot) then begin
      LastNonTransferReal := false; exit
    end;
    lc := c; lk := k; found := true
  end;
  while NextReal(c, k, cfg^.blocks[blk].endChunk, cfg^.blocks[blk].endSlot) do begin
    if (c = cfg^.blocks[blk].endChunk) and (k = cfg^.blocks[blk].endSlot) then break;
    lc := c; lk := k; found := true
  end;
  LastNonTransferReal := found
end;

{ PromoteLoopLocal: see its own header comment in the interface
  section above. }
procedure PromoteLoopLocal(startChunk: POpChunk; startSlot: integer;
                            endChunk: POpChunk; endSlot: integer);
  var cfg: PCfg; dm: PDominance; ls: PLoopSet; li, hb, i, nPreds, predBlock: integer;
      pc: POpChunk; pk: integer;
      loadTxt, memTxt: string; loadOp: TOperand;
      candOffset: longint; candReg: integer; candIsByte: boolean;
      ok: boolean;

  { CollectCandidate: walk the header block's own operations once,
    looking for exactly one (frameOffset, register) pair used
    consistently for every plain-MOV access, rejecting outright
    (result:=false) on a CALL/unknown/raw-ASM anywhere in the block, or
    a SECOND, DIFFERENT frame-object/register combination. }
  function CollectCandidate: boolean;
    var cc: POpChunk; ck: integer; t1, t2: string; mo: TOperand; rid: integer;
        eff: TEffects; haveCand: boolean; okC: boolean;
  begin
    { okC, a SEPARATE local, not the bare function-name identifier, is
      this loop's own condition variable -- a real, previously-latent
      TP7 identifier-ambiguity bug found while building OPT.TXT's own
      R12 finding (the same class of gotcha this unit's own R7 entry
      in DOCS/TRBUG.MD already documents once, for a DIFFERENT
      identifier): "while CollectCandidate do" (the bare function name
      used as a VALUE, not assigned to) is a RECURSIVE CALL to
      CollectCandidate itself in TP7, not a read of the pending result
      -- silently recursing without ever reaching a real base case
      (each nested call re-enters this exact same loop), overflowing
      the stack. Found via a temporary stack-checking-on scratch
      rebuild reporting "Runtime error 202" (stack overflow) instead
      of the silent hang/corruption stack checking normally being off
      here otherwise lets through unnoticed. }
    haveCand := false; candOffset := 0; candReg := 0; candIsByte := false;
    okC := true;
    cc := cfg^.blocks[hb].startChunk; ck := cfg^.blocks[hb].startSlot;
    while okC do begin
      if cc^.ops[ck].kind = TOpAsm then begin okC := false; break end;
      if (cc^.ops[ck].kind = TOpInstr) and (cc^.ops[ck].mnemonic <> MnNop) then begin
        if (cc^.ops[ck].mnemonic = MnCall) or (cc^.ops[ck].mnemonic = MnCallFar) then begin
          okC := false; break
        end;
        GetEffects(cc^.ops[ck], eff);
        if not eff.known then begin okC := false; break end;
        if cc^.ops[ck].mnemonic = MnMov then begin
          StrTab.Get(cc^.ops[ck].op1, t1); StrTab.Get(cc^.ops[ck].op2, t2);
          DecodeOperand(t1, mo);
          if (mo.kind = OpKindMem) and mo.isFrameObject then
            rid := Regs86.LookupReg(Util.UpStr(t2))
          else begin
            DecodeOperand(t2, mo);
            if (mo.kind = OpKindMem) and mo.isFrameObject then
              rid := Regs86.LookupReg(Util.UpStr(t1))
            else
              rid := 0
          end;
          if (mo.kind = OpKindMem) and mo.isFrameObject then begin
            if (rid = 0) or Regs86.IsSegReg(rid) then begin
              okC := false; break
            end;
            if not haveCand then begin
              haveCand := true; candOffset := mo.frameOffset;
              candReg := rid; candIsByte := Regs86.IsByteReg(rid)
            end else if (mo.frameOffset <> candOffset) or (rid <> candReg) then begin
              okC := false; break
            end
          end
        end
      end;
      if (cc = cfg^.blocks[hb].endChunk) and (ck = cfg^.blocks[hb].endSlot) then break;
      Advance(cc, ck, cfg^.blocks[hb].endChunk, cfg^.blocks[hb].endSlot)
    end;
    CollectCandidate := okC and haveCand
  end;

  { IsPromotedAccess: TRUE iff this exact operation is a plain
    "MOV candReg,[candOffset]" or "MOV [candOffset],candReg". }
  function IsPromotedAccess(const op: TOperation): boolean;
    var t1, t2: string; mo: TOperand;
  begin
    IsPromotedAccess := false;
    if op.mnemonic <> MnMov then exit;
    StrTab.Get(op.op1, t1); StrTab.Get(op.op2, t2);
    DecodeOperand(t1, mo);
    if (mo.kind = OpKindMem) and mo.isFrameObject and (mo.frameOffset = candOffset)
       and (Regs86.LookupReg(Util.UpStr(t2)) = candReg) then begin
      IsPromotedAccess := true; exit
    end;
    DecodeOperand(t2, mo);
    if (mo.kind = OpKindMem) and mo.isFrameObject and (mo.frameOffset = candOffset)
       and (Regs86.LookupReg(Util.UpStr(t1)) = candReg) then
      IsPromotedAccess := true
  end;

  { ExitsHaveProvenStore: walk the header block FORWARD once, tracking
    the previous real operation seen so far; whenever a real transfer
    is found whose OWN target is NOT the header itself (a genuine exit
    -- the back-edge to the header needs no store at all, since the
    value stays correctly resident in candReg for the next iteration),
    the PREVIOUS real operation must ALREADY be a promoted store
    "MOV [candOffset],candReg" -- proven-already-present, never
    synthesized (this unit has no insertion primitive). RETN/RETF/
    IRET (an unresolved SuccUnknown exit, or a genuine return) are
    real exits needing a proven store too, correctly included since
    neither is ever the header block index itself. }
  function ExitsHaveProvenStore: boolean;

    { SuccExitOk: succ is one of hb's own two successor slots (succ1 --
      the Jcc's own taken target, or an unconditional JMP's own sole
      target; succ2 -- a Jcc's own fall-through, or SuccNone for an
      unconditional JMP with no fall-through at all). TRUE if this
      particular successor slot is either NOT a real exit at all (it
      IS hb itself -- the loop's own back-edge, needing no store since
      the value stays correctly resident in candReg for the next
      iteration; or SuccNone -- no such edge exists), or a real exit
      with its own proven store already in place. Two genuinely
      different store LOCATIONS depending on the exit's own shape: a
      RESOLVED successor block (succ >= 0, <> hb) needs its OWN proven
      store as that block's own FIRST real operation (the exit is a
      real jump/fall-through INTO a different block entirely, so the
      store cannot live inside hb at all); SuccUnknown (a bare RETN/
      RETF/IRET, or an unresolved jump this whole candidate would
      already have been rejected for via CollectCandidate's own
      known-effects requirement) needs the store immediately before
      hb's own terminating operation instead, via LastNonTransferReal. }
    function SuccExitOk(succ: integer): boolean;
      var fc: POpChunk; fk: integer;
    begin
      if (succ = hb) or (succ = SuccNone) then begin
        SuccExitOk := true; exit
      end;
      if succ = SuccUnknown then begin
        SuccExitOk := LastNonTransferReal(cfg, hb, fc, fk) and IsPromotedAccess(fc^.ops[fk]);
        exit
      end;
      { A resolved, different block -- the store must be ITS OWN first
        real operation. }
      fc := cfg^.blocks[succ].startChunk; fk := cfg^.blocks[succ].startSlot;
      if (fc^.ops[fk].kind <> TOpInstr) or (fc^.ops[fk].mnemonic = MnNop) then begin
        if not NextReal(fc, fk, cfg^.blocks[succ].endChunk, cfg^.blocks[succ].endSlot) then begin
          SuccExitOk := false; exit
        end
      end;
      SuccExitOk := IsPromotedAccess(fc^.ops[fk])
    end;

  begin
    ExitsHaveProvenStore := SuccExitOk(cfg^.blocks[hb].succ1) and SuccExitOk(cfg^.blocks[hb].succ2)
  end;

  { RewriteBlock: every promoted access INSIDE hb becomes redundant and
    is removed -- a load "MOV candReg,[candOffset]" becomes "MOV
    candReg,candReg" (self-move, nopped by the very next OptimizePass
    call's own RemoveMovRR); a store "MOV [candOffset],candReg" becomes
    MnNop directly (no register-only equivalent to fold to). Every
    proven exit store ExitsHaveProvenStore already found lives OUTSIDE
    hb entirely (a resolved successor block's own first real
    operation) EXCEPT the one SuccUnknown case (a bare RETN/RETF/IRET
    terminating hb itself, where the store sits immediately before that
    terminator, still WITHIN hb) -- so this rule only needs to skip
    hb's own LITERAL LAST real operation (via endChunk/endSlot) when
    hb's own succ1 is SuccUnknown; every OTHER promoted access in hb,
    including one immediately before a transfer to a RESOLVED block, is
    unconditionally a redundant interior copy (its own protected
    counterpart, if any, lives in that OTHER block, never touched
    here). }
  procedure RewriteBlock;
    var cc: POpChunk; ck: integer; t1: string; isLast: boolean;
  begin
    cc := cfg^.blocks[hb].startChunk; ck := cfg^.blocks[hb].startSlot;
    while true do begin
      isLast := (cc = cfg^.blocks[hb].endChunk) and (ck = cfg^.blocks[hb].endSlot);
      if (cc^.ops[ck].kind = TOpInstr) and (cc^.ops[ck].mnemonic <> MnNop)
         and not (isLast and (cfg^.blocks[hb].succ1 = SuccUnknown))
         and IsPromotedAccess(cc^.ops[ck]) then begin
        StrTab.Get(cc^.ops[ck].op1, t1);
        DecodeOperand(t1, loadOp);
        if (loadOp.kind = OpKindMem) and loadOp.isFrameObject then
          cc^.ops[ck].mnemonic := MnNop
        else
          cc^.ops[ck].op2 := cc^.ops[ck].op1
      end;
      if isLast then break;
      Advance(cc, ck, cfg^.blocks[hb].endChunk, cfg^.blocks[hb].endSlot)
    end
  end;

begin
  BuildCfg(startChunk, startSlot, endChunk, endSlot, cfg);
  if cfg^.ok then begin
    ComputeDominance(cfg, dm);
    if dm^.ok then begin
      FindNaturalLoops(cfg, dm, ls);
      if ls^.ok then begin
        for li := 0 to ls^.nLoops - 1 do begin
          if ls^.loops[li].header = ls^.loops[li].latch then begin
            hb := ls^.loops[li].header;
            nPreds := 0; predBlock := -1;
            for i := 0 to cfg^.nBlocks - 1 do
              if (i <> hb) and ((cfg^.blocks[i].succ1 = hb) or (cfg^.blocks[i].succ2 = hb)) then begin
                nPreds := nPreds + 1; predBlock := i
              end;
            ok := CollectCandidate
                  and not FrameOffsetEscapes(startChunk, startSlot, endChunk, endSlot, candOffset);
            if (nPreds = 1) and ok then begin
              { The needed entry load may be the predecessor block's
                own LITERAL last operation (a plain fall-through into
                the loop, no separate jump at all -- BuildCfg's own
                endChunk/endSlot IS a block's last real op by
                definition) OR, when the predecessor instead reaches
                the loop via a real transfer (a JMP/Jcc targeting the
                header), the operation immediately BEFORE that
                transfer (LastNonTransferReal, R8's own helper) --
                tried second, only when the literal last op itself
                isn't the load this rule needs. }
              pc := cfg^.blocks[predBlock].endChunk; pk := cfg^.blocks[predBlock].endSlot;
              StrTab.Get(pc^.ops[pk].op1, loadTxt); StrTab.Get(pc^.ops[pk].op2, memTxt);
              DecodeOperand(memTxt, loadOp);
              ok := (pc^.ops[pk].kind = TOpInstr) and (pc^.ops[pk].mnemonic = MnMov)
                    and (Regs86.LookupReg(Util.UpStr(loadTxt)) = candReg)
                    and (loadOp.kind = OpKindMem) and loadOp.isFrameObject
                    and (loadOp.frameOffset = candOffset);
              if (not ok) and LastNonTransferReal(cfg, predBlock, pc, pk) then begin
                StrTab.Get(pc^.ops[pk].op1, loadTxt); StrTab.Get(pc^.ops[pk].op2, memTxt);
                DecodeOperand(memTxt, loadOp);
                ok := (pc^.ops[pk].mnemonic = MnMov)
                      and (Regs86.LookupReg(Util.UpStr(loadTxt)) = candReg)
                      and (loadOp.kind = OpKindMem) and loadOp.isFrameObject
                      and (loadOp.frameOffset = candOffset)
              end;
              if ok and ExitsHaveProvenStore then
                RewriteBlock
            end
          end
        end
      end;
      Dispose(ls)
    end;
    Dispose(dm)
  end;
  Dispose(cfg)
end;

{ ============================================================
  STAGE E: DATA-FLOW-DEPENDENT REWRITES (OPT.TXT S8) -- E1
  ============================================================
  StoreForwarding ("store forwarding and repeated loads"):

    MOV byte [bp-1],AL; MOV BX,table; MOV CL,[bp-1]
      -> retain store; replace reload with MOV CL,AL.

  Implemented WITHIN ONE BLOCK ONLY -- OPT.TXT's own explicit staging,
  "Start within blocks, then use merged facts across branch edges":
  the cross-block half (propagating a store's own forwarded value
  through Stage D's ComputeLiveness/PropagateValues merged facts at a
  join) is deferred; this rule scans forward from a store only until
  it hits a label, a transfer, or any other block-ending shape, same
  "stop, do not chase across a join" conservative stance every earlier
  local-only rule in this file already takes.

  Match: MOV mem,srcReg (a store FROM a register), then scan forward
  (Advance, one real operation at a time -- NOT NextReal's own
  "immediately next" restriction: OPT.TXT's own "independent
  intervening instructions" verification item requires tolerating
  unrelated operations in between, unlike C1/C2/C3/E3's own strict
  four/five-operation adjacency) until EITHER:
  - a MOV dstReg,mem is found with the SAME mem text -- the match
    succeeds: the reload's own op2 is rewritten from mem to srcReg
    directly (the store itself is RETAINED, unlike E3 -- OPT.TXT's own
    "retain store; replace reload" is explicit: this is forwarding a
    value already known to be live in a register, not eliminating a
    memory access the way E3 does).
  - anything disqualifies the match first, and the whole attempt is
    abandoned (no partial rewrite):
    - a write overlapping srcReg (RegBitFor mask intersection, not
      exact-name match -- OPT.TXT's own explicit "A store from BL
      followed by overwriting BX must not forward BL": a WORD write to
      BX overlaps BL's own bits even though the text differs entirely).
    - ANY real memory access at all (this codebase's own recurring
      "no alias-proof machinery, so any real memory touch blocks"
      stance, same as RemoveUnnecessarySaveRestore's own C3 and this
      same file's own StoreReload's disabled-for-this-exact-reason
      history) -- OPT.TXT's own "aliases" verification item.
    - a label, TOpAsm, or any transfer (GetEffects.transferKind <>
      XferNone) -- block boundary, per the "within one block" staging
      above.
    - anything GetEffects itself calls unknown.
  - the given operation range is exhausted before either -- not a
    match (same "range end is not proof" conservative stance
    LocalDeadAfter/every other forward scan in this file already
    takes).

  "Require the same proven object, offset, width, segment" -- object/
  offset/segment identity is the plain text-equality check (mem1 =
  mem2, the same baseline every other memory-adjacent matcher in this
  file uses); WIDTH identity is implicit in matching srcReg's own
  width against how mem was originally stored (a byte store, "MOV
  byte [bp-1],AL", can only ever be safely forwarded to a byte-width
  reload -- checked via Regs86.IsByteReg on BOTH srcReg and the
  reload's own dstReg, rejecting a byte-store/word-reload mismatch or
  vice versa outright, rather than assuming the two operand widths
  happen to already agree). "Unchanged source bits" is exactly the
  overlap-aware srcReg-write check above. }
procedure StoreForwarding(startChunk: POpChunk; startSlot: integer;
                           endChunk: POpChunk; endSlot: integer);
  var c, sc: POpChunk; k, sk: integer;
      mem1, mem2, mem1Stripped, mem2Stripped, srcTxt, dstTxt: string;
      memOp: TOperand; srcReg, dstReg: integer; srcMask, addrMask, blockMask: word;
      eff: TEffects; found, blocked: boolean;
begin
  c := startChunk; k := startSlot;
  repeat
    if (c^.ops[k].kind = TOpInstr) and (c^.ops[k].mnemonic = MnMov) then begin
      StrTab.Get(c^.ops[k].op1, mem1);
      StrTab.Get(c^.ops[k].op2, srcTxt);
      DecodeOperand(mem1, memOp);
      srcReg := Regs86.LookupReg(Util.UpStr(srcTxt));
      if (memOp.kind = OpKindMem) and (memOp.isFrameObject or (memOp.addrRegMask = RegMaskNone))
         and (srcReg <> 0) and not Regs86.IsSegReg(srcReg) then begin
        srcMask := RegBitFor(srcReg, Regs86.IsByteReg(srcReg));
        { OPT.TXT's own R2 finding, a real correctness bug: this rule
          previously only ever tracked writes to srcReg (the VALUE
          being forwarded), never to any register the memory operand's
          own ADDRESS depends on -- "MOV [bp-2],AX; MOV BP,100; MOV
          CX,[bp-2]" would have wrongly forwarded AX, even though the
          second "[bp-2]" is a COMPLETELY DIFFERENT address once BP
          itself changed (BP=100 makes it a wild, almost certainly
          invalid access, not the same local slot the store wrote at
          all). memOp.addrRegMask already carries exactly the
          registers the proven-safe store's own address depends on
          (Stage B's own DecodeOperand -- BP itself, for any proven
          frame object; empty for a bare unregistered global, which
          has no address-register dependency to begin with) -- folded
          into the SAME overlap-checked write-blocking mask as srcMask,
          so a write to EITHER the value register OR the address base
          blocks the match identically. }
        addrMask := memOp.addrRegMask;
        blockMask := srcMask or addrMask;
        { mem1's own text may (MOV byte [g],AL) or may not (MOV
          [bp-2],AX -- ParseMemOperand only ever emits an explicit
          'byte '/'word ' size PREFIX when the destination's own width
          isn't otherwise inferable from context) carry a leading size
          prefix; a later reload of the SAME object often has no
          reason to carry one at all (e.g. "MOV CL,[g]" -- CL's own
          width already says byte, no prefix needed) even though it
          names the identical memory object -- comparing RAW op text
          would therefore wrongly treat 'byte [g]' and '[g]' as
          different locations. Compare the PREFIX-STRIPPED text
          instead (MemOpndPrefix, the same helper DecodeOperand itself
          already uses internally) -- width identity is separately and
          explicitly enforced via the Regs86.IsByteReg comparison
          below, so stripping the prefix here does not weaken the
          "same object, offset, width" proof at all, it just stops the
          textual comparison from being fooled by a prefix that's
          present on one side and absent on the other for reasons that
          have nothing to do with whether they're the same object.
          Found via a real generated-code probe during this rule's own
          development: "MOV byte [g],AL; MOV BX,100; MOV CL,[g]" never
          matched at all under the original raw-text comparison. }
        mem1Stripped := MemOpndPrefix(mem1);
        sc := c; sk := k; found := false; blocked := false;
        while not found and not blocked and Advance(sc, sk, endChunk, endSlot) do begin
          if (sc^.ops[sk].kind = TOpInstr) and (sc^.ops[sk].mnemonic = MnNop) then
            { deleted -- transparent, keep scanning. }
          else if sc^.ops[sk].kind = TOpLabel then blocked := true
          else if sc^.ops[sk].kind = TOpAsm then blocked := true
          else if (sc^.ops[sk].mnemonic = MnMov) then begin
            StrTab.Get(sc^.ops[sk].op1, dstTxt);
            StrTab.Get(sc^.ops[sk].op2, mem2);
            mem2Stripped := MemOpndPrefix(mem2);
            dstReg := Regs86.LookupReg(Util.UpStr(dstTxt));
            if (mem1Stripped = mem2Stripped) and (dstReg <> 0) and not Regs86.IsSegReg(dstReg)
               and (Regs86.IsByteReg(dstReg) = Regs86.IsByteReg(srcReg)) then begin
              sc^.ops[sk].op2 := StrTab.Put(srcTxt);
              found := true
            end else begin
              GetEffects(sc^.ops[sk], eff);
              if not eff.known then blocked := true
              else if (eff.regWrite and blockMask) <> 0 then blocked := true
              else if eff.transferKind <> XferNone then blocked := true
              else if eff.memEffect <> MemNone then blocked := true
            end
          end else begin
            GetEffects(sc^.ops[sk], eff);
            if not eff.known then blocked := true
            else if (eff.regWrite and blockMask) <> 0 then blocked := true
            else if eff.transferKind <> XferNone then blocked := true
            else if eff.memEffect <> MemNone then blocked := true
          end
        end
      end
    end
  until not Advance(c, k, endChunk, endSlot)
end;

{ CrossBlockStoreForwarding: OPT.TXT's own R7 finding -- "E1 cross-block
  forwarding". StoreForwarding above is a pure LOCAL forward scan,
  correctly (per Stage E's own established conservative convention)
  stopping dead at any label/transfer it encounters -- sound, but blind
  to a store and its own reload sitting in DIFFERENT blocks, even when
  PropagateValues' own R7 memory-fact analysis can prove the value
  survives the block boundary untouched.

  Match: a "MOV reg,[mem]" reload where [mem] is a PROVEN frame object
  (DecodeOperand's own isFrameObject, the same narrow "start with
  nonescaping frame objects" scope R7's own resolution text specifies),
  sitting at the very START of its own containing block (found via
  BuildCfg's own block table) with EXACTLY ONE real predecessor block
  -- the same "single-predecessor, block-start-only" bound
  RemoveRedundantZeroExtend already established for an analogous
  ENTRY-fact question (PropagateValues' own regKnown/regVal/memKnown/
  memFact fields are EXIT facts, never stored per-instruction or as a
  separate entry fact -- proving "this reload's own memory identity is
  already known right HERE" needs the single predecessor's own exit
  fact to stand in for this block's entry fact, sound only when there
  is exactly one candidate and the reload is the very first thing in
  this block, so nothing INSIDE this block could have invalidated it
  first). If that predecessor's own exit fact for the SAME
  (frameOffset,isByte) identity is known, rewrite the reload's own
  source operand directly to the fact's srcReg -- the exact same
  "forward a proven register identity into a reload" rewrite
  StoreForwarding itself performs, just sourced from PropagateValues'
  own cross-block-safe fact instead of a local scan.

  A multi-predecessor join, or a reload strictly INSIDE a block (not at
  its own start), are both left unreached here -- the same "future
  refinement, not attempted" scope RemoveRedundantZeroExtend's own
  header comment already documents for the identical structural
  limitation; PropagateValues itself would need to expose per-
  instruction (or at least per-position) facts, not just per-block EXIT
  facts, to go further than this. }
{ RegIdToText: the one reverse mapping (Regs86.Reg* id -> its own bare
  NASM lowercase text) this unit needs but neither Regs86.PAS nor
  PHOPT.PAS itself already had -- Regs86.LookupReg only ever goes
  text-to-id, never the other direction. Only the 16 ids
  DecodeOperand/RegBitFor's own dispatch already recognizes
  (RegAX..RegBH) are handled; '' for anything else (never actually
  reached by this rule's own caller, which only ever passes a srcReg a
  real memory fact already proved via one of these exact same 16
  ids). }
function RegIdToText(r: integer): string;
begin
  case r of
    Regs86.RegAX: RegIdToText := 'ax'; Regs86.RegCX: RegIdToText := 'cx';
    Regs86.RegDX: RegIdToText := 'dx'; Regs86.RegBX: RegIdToText := 'bx';
    Regs86.RegSP: RegIdToText := 'sp'; Regs86.RegBP: RegIdToText := 'bp';
    Regs86.RegSI: RegIdToText := 'si'; Regs86.RegDI: RegIdToText := 'di';
    Regs86.RegAL: RegIdToText := 'al'; Regs86.RegCL: RegIdToText := 'cl';
    Regs86.RegDL: RegIdToText := 'dl'; Regs86.RegBL: RegIdToText := 'bl';
    Regs86.RegAH: RegIdToText := 'ah'; Regs86.RegCH: RegIdToText := 'ch';
    Regs86.RegDH: RegIdToText := 'dh'; Regs86.RegBH: RegIdToText := 'bh';
  else
    RegIdToText := ''
  end
end;

{ FindBlockContainingFirstReal: like FindBlockStartingAt, but proves
  (c,k) is the block's own FIRST REAL operation rather than requiring
  it to be the literal recorded start position -- a block almost
  ALWAYS starts at a TOpLabel when one is present (BuildCfg's own
  "atBlockStart" convention: entry, every label, and every position
  right after a transfer all start a new block), with the first REAL
  (non-label, non-nop) instruction sitting one or more slots after
  that, so a caller wanting "is (c,k) the first thing this block
  actually EXECUTES" -- CrossBlockStoreForwarding's own real question
  -- must walk forward from each candidate block's own recorded start
  via NextReal, not compare positions directly the way
  FindBlockStartingAt does (confirmed the hard way via an isolated
  driver: FindBlockStartingAt(cfg, reloadPos) returned -1 for a real
  ".L1: MOV ax,[bp-2]" shape, since op7's own literal position is
  NOT block 2's own recorded start -- op6, the LABEL, is). }
function FindBlockContainingFirstReal(cfg: PCfg; c: POpChunk; k: integer): integer;
  var i: integer; bc: POpChunk; bk: integer;
begin
  FindBlockContainingFirstReal := -1;
  for i := 0 to cfg^.nBlocks - 1 do begin
    bc := cfg^.blocks[i].startChunk; bk := cfg^.blocks[i].startSlot;
    if (bc^.ops[bk].kind = TOpInstr) and (bc^.ops[bk].mnemonic <> MnNop) then begin
      if (bc = c) and (bk = k) then begin FindBlockContainingFirstReal := i; exit end
    end else if NextReal(bc, bk, cfg^.blocks[i].endChunk, cfg^.blocks[i].endSlot)
                and (bc = c) and (bk = k) then begin
      FindBlockContainingFirstReal := i; exit
    end
  end
end;

procedure CrossBlockStoreForwarding(startChunk: POpChunk; startSlot: integer;
                                     endChunk: POpChunk; endSlot: integer);
  var c: POpChunk; k: integer; dstTxt, srcTxt, srcRegTxt: string;
      dstReg: integer; memOp: TOperand;
      cfg: PCfg; vf: PValueFacts; blk, i, predBlock, nPreds, m, matchIdx: integer;
begin
  c := startChunk; k := startSlot;
  repeat
    if (c^.ops[k].kind = TOpInstr) and (c^.ops[k].mnemonic = MnMov) then begin
      StrTab.Get(c^.ops[k].op1, dstTxt);
      StrTab.Get(c^.ops[k].op2, srcTxt);
      dstReg := Regs86.LookupReg(Util.UpStr(dstTxt));
      DecodeOperand(srcTxt, memOp);
      if (dstReg <> 0) and not Regs86.IsSegReg(dstReg)
         and (memOp.kind = OpKindMem) and memOp.isFrameObject then begin
        BuildCfg(startChunk, startSlot, endChunk, endSlot, cfg);
        if cfg^.ok then begin
          PropagateValues(cfg, vf);
          if vf^.ok then begin
            blk := FindBlockContainingFirstReal(cfg, c, k);
            if blk >= 0 then begin
              nPreds := 0; predBlock := -1;
              for i := 0 to cfg^.nBlocks - 1 do
                if (cfg^.blocks[i].succ1 = blk) or (cfg^.blocks[i].succ2 = blk) then begin
                  nPreds := nPreds + 1; predBlock := i
                end;
              if nPreds = 1 then begin
                matchIdx := 0;
                for m := 1 to MaxMemFacts do
                  if vf^.memKnown[predBlock][m]
                     and (vf^.memFact[predBlock][m].frameOffset = memOp.frameOffset)
                     and (vf^.memFact[predBlock][m].isByte = Regs86.IsByteReg(dstReg)) then
                    matchIdx := m;
                if (matchIdx <> 0)
                   and (Regs86.IsByteReg(vf^.memFact[predBlock][matchIdx].srcReg)
                        = Regs86.IsByteReg(dstReg)) then begin
                  srcRegTxt := RegIdToText(vf^.memFact[predBlock][matchIdx].srcReg);
                  if srcRegTxt <> '' then
                    c^.ops[k].op2 := StrTab.Put(srcRegTxt)
                end
              end
            end
          end;
          Dispose(vf)
        end;
        Dispose(cfg)
      end
    end
  until not Advance(c, k, endChunk, endSlot)
end;

{ ============================================================
  STAGE E: DATA-FLOW-DEPENDENT REWRITES (OPT.TXT S8) -- E2 (tmp-fold)
  ============================================================
  FoldTempOperand -- the third of OPT.TXT's own E2 sub-cases
  ("Repeated comparisons, dead preparation, and temporary operands"),
  and the first implemented (chosen first per the user's own explicit
  scoping decision: the most self-contained of E2's own three pieces
  -- single-block, adjacency-based like C1/E3, a dead-tmp proof via
  Stage B's own LocalDeadAfter, no genSaveId or cross-block merge
  needed at all, unlike E2's other two sub-cases). E2's own remaining
  two pieces (repeated CMP/TEST across merged paths; dead MOV AH,0) are
  NOT implemented yet.

    MOV tmp,src; ADD dst,tmp -> ADD dst,src
    (same discipline for SUB/CMP -- "Apply the same discipline to
    separately tested SUB/CMP forms")

  This is the REGISTER-only analog of C1's own FoldSavedOperand: no
  PUSH/POP/genSaveId proof is needed at all here (nothing is being
  saved/restored around evaluating src -- tmp is simply a scratch
  register the compiler already had `src`'s own value sitting in, one
  instruction before using it), so the safety proof rests entirely on
  local adjacency plus a dead-tmp check, the same overall shape E3
  already established for this stage.

  Match: MOV tmp,src / ADD-or-SUB-or-CMP dst,tmp, STRICTLY ADJACENT
  (NextReal, not a tolerant forward scan like E1's own StoreForwarding
  -- OPT.TXT's own "operand values and access timing are unchanged" is
  the reason: anything intervening could change what src itself
  evaluates to, or when its own memory access (if any) actually
  happens relative to other memory operations, so only PROVEN-adjacent
  instructions get that guarantee for free, the same reasoning C1/E3
  already rely on for their own strict adjacency). Rewrites the ADD/
  SUB/CMP's own second operand from tmp directly to src, deleting the
  MOV.

  Requirements (OPT.TXT's own words, each addressed below):
  - "tmp is dead" -- Stage B's own LocalDeadAfter, scanning forward
    from the rewritten instruction's own slot, proves nothing
    downstream reads tmp before something else overwrites it first.
  - "operand values and access timing are unchanged" -- guaranteed by
    strict adjacency (nothing sits between the MOV and the ADD/SUB/CMP
    at all, so src's own value and the timing of any memory access it
    performs are identical whether read via tmp or read directly).
  - "the result is encodable" -- dst and src can never both be memory
    (8086 has no memory-to-memory ALU encoding, the exact bug E3's own
    first draft hit -- checked the same way here, via DecodeOperand
    classification, never assumed from context).
  - "tmp/address overlap" -- if dst and tmp are the SAME register, this
    rule does NOT apply at all (dst <> tmp is required): "ADD tmp,tmp"
    rewritten to "ADD tmp,src" would be a genuinely different
    computation (a self-add doubles tmp's own prior value; substituting
    src changes what's being added to what). If src is itself a memory
    operand whose own address depends on a register overlapping dst,
    the rewrite is still sound (src's own address is evaluated identically
    either way, and dst's own value isn't written until the ADD/SUB/CMP
    itself completes, same single-instruction read-before-write
    ordering 8086 already guarantees) -- not rejected, since nothing
    about moving src's own evaluation one instruction later changes
    what address it computes.
  - "Apply the same discipline to separately tested SUB/CMP forms" --
    MnAdd/MnSub/MnCmp are all matched by this ONE implementation
    (deliberately not three separate near-duplicate procedures), since
    every one of the safety requirements above is identical regardless
    of which of the three the second instruction turns out to be. }
procedure FoldTempOperand(startChunk: POpChunk; startSlot: integer;
                           endChunk: POpChunk; endSlot: integer);
  var c, ac: POpChunk; k, ak: integer;
      tmpTxt, srcTxt, dstTxt, ax2Txt: string;
      tmpReg, dstReg: integer; tmpMask: word;
      dstIsByte, widthOk: boolean; srcOp, dstOp: TOperand;
begin
  c := startChunk; k := startSlot;
  repeat
    if (c^.ops[k].kind = TOpInstr) and (c^.ops[k].mnemonic = MnMov) then begin
      StrTab.Get(c^.ops[k].op1, tmpTxt);
      StrTab.Get(c^.ops[k].op2, srcTxt);
      tmpReg := Regs86.LookupReg(Util.UpStr(tmpTxt));
      if (tmpReg <> 0) and not Regs86.IsSegReg(tmpReg) then begin
        tmpMask := RegBitFor(tmpReg, Regs86.IsByteReg(tmpReg));
        ac := c; ak := k;
        if NextReal(ac, ak, endChunk, endSlot) and (ac^.ops[ak].kind = TOpInstr)
           and ((ac^.ops[ak].mnemonic = MnAdd) or (ac^.ops[ak].mnemonic = MnSub)
                or (ac^.ops[ak].mnemonic = MnCmp)) then begin
          StrTab.Get(ac^.ops[ak].op1, dstTxt);
          StrTab.Get(ac^.ops[ak].op2, ax2Txt);
          DecodeOperand(dstTxt, dstOp);
          { dst may be a REGISTER or a MEMORY operand -- "ADD mem,reg"
            is a real, legal 8086 encoding, not just "ADD reg,reg"; a
            register dst is checked for the "not the same register as
            tmp" and register-width-match requirements below, a memory
            dst instead reuses its own decoded width knowledge
            (dstOp.isByte, Stage B's own DecodeOperand classification)
            -- there is no "same register as tmp" question for a
            memory dst at all (a memory operand and a general-purpose
            register can never collide by definition). }
          dstReg := Regs86.LookupReg(Util.UpStr(dstTxt));
          if dstOp.kind = OpKindReg then
            widthOk := (dstReg <> 0) and not Regs86.IsSegReg(dstReg) and (dstReg <> tmpReg)
                       and (Regs86.IsByteReg(dstReg) = Regs86.IsByteReg(tmpReg))
          else if dstOp.kind = OpKindMem then
            { A memory dst has no REGISTER IDENTITY to collide with tmp
              (as a VALUE being written) -- "ADD mem,reg" is a real,
              legal 8086 encoding, distinct from the "mem,mem" case
              rejected below. Width compatibility between dst and tmp
              is ALREADY proven by construction: the original,
              UNCHANGED "ADD dst,tmp" instruction this rule found was
              already a valid, previously-emitted instruction (SPHO.PAS's
              own emitter never produces a width-mismatched ADD/SUB/CMP
              in the first place).

              A REAL bug, found by external review and confirmed via an
              isolated driver: dst's own memory ADDRESS can independently
              depend on tmp too -- "MOV BX,SI; ADD WORD [BX],BX;
              MOV BX,0" folds to "ADD WORD [BX],SI", but [BX]'s own
              ADDRESS still reads BX, which this fold just deleted the
              ONLY assignment of (BX's own proven-dead-AFTER-the-ADD
              status, the fold's own dead-tmp proof, says nothing about
              whether BX was needed to COMPUTE the address the ADD
              itself reads/writes -- those are two entirely different
              questions this rule previously conflated). dstOp.
              addrRegMask (Stage B's own DecodeOperand -- exactly the
              registers dst's own address depends on) overlapping tmpMask
              means folding away the "MOV tmp,src" that established
              tmp's OWN value would silently corrupt the very address
              this ADD/SUB/CMP computes from -- rejected outright, same
              "explicit over assumed" precedent every other address-
              dependency proof in this unit already follows. }
            widthOk := (dstOp.addrRegMask and tmpMask) = 0
          else
            widthOk := false;
          if Util.EqualICase(ax2Txt, tmpTxt) and widthOk
             and LocalDeadAfter(ac, ak, endChunk, endSlot, tmpMask, FlagMaskNone) then begin
            DecodeOperand(srcTxt, srcOp);
            if not ((dstOp.kind = OpKindMem) and (srcOp.kind = OpKindMem)) then begin
              ac^.ops[ak].op2 := StrTab.Put(srcTxt);
              c^.ops[k].mnemonic := MnNop
            end
          end
        end
      end
    end
  until not Advance(c, k, endChunk, endSlot)
end;

const MaxFoldTempGap = 8;   { see FoldTempOperandGap's own header
  comment in the interface section above -- a small, explicit cap on
  the number of intervening REAL operations tolerated between the "MOV
  tmp,src" and its own "ADD/SUB/CMP dst,tmp", purely to keep an
  ordinary compile fast; not a soundness bound (the scan itself always
  terminates via the range end or the first disqualifying instruction,
  whichever comes first). }

{ FoldTempOperandGap: see its own header comment in the interface
  section above. }
procedure FoldTempOperandGap(startChunk: POpChunk; startSlot: integer;
                              endChunk: POpChunk; endSlot: integer);
  var c, ac, gc: POpChunk; k, ak, gk: integer; gapCount: integer;
      tmpTxt, srcTxt, dstTxt, ax2Txt: string;
      tmpReg, dstReg, srcReg: integer; tmpMask, srcAddrMask: word;
      widthOk, blocked: boolean; srcOp, dstOp: TOperand; eff: TEffects;
begin
  c := startChunk; k := startSlot;
  repeat
    if (c^.ops[k].kind = TOpInstr) and (c^.ops[k].mnemonic = MnMov) then begin
      StrTab.Get(c^.ops[k].op1, tmpTxt);
      StrTab.Get(c^.ops[k].op2, srcTxt);
      tmpReg := Regs86.LookupReg(Util.UpStr(tmpTxt));
      if (tmpReg <> 0) and not Regs86.IsSegReg(tmpReg) then begin
        tmpMask := RegBitFor(tmpReg, Regs86.IsByteReg(tmpReg));
        DecodeOperand(srcTxt, srcOp);
        srcReg := Regs86.LookupReg(Util.UpStr(srcTxt));
        if srcOp.kind = OpKindMem then srcAddrMask := srcOp.addrRegMask
        else srcAddrMask := RegMaskNone;
        { Walk forward, via NextReal (never a literal Advance -- labels/
          already-deleted operations are transparent, same convention
          every other scan in this unit already follows), tolerating up
          to MaxFoldTempGap intervening real operations PROVEN
          independent of this fold. Stops (blocked=true) the instant
          any candidate fails that proof; the loop's own exit when
          ac^.ops[ak] finally IS the matching ADD/SUB/CMP is handled
          separately, below, once the loop ends normally. }
        ac := c; ak := k; gapCount := 0; blocked := false;
        while (not blocked) and (gapCount < MaxFoldTempGap)
              and NextReal(ac, ak, endChunk, endSlot)
              and not ((ac^.ops[ak].kind = TOpInstr)
                       and ((ac^.ops[ak].mnemonic = MnAdd) or (ac^.ops[ak].mnemonic = MnSub)
                            or (ac^.ops[ak].mnemonic = MnCmp))) do begin
          if ac^.ops[ak].kind <> TOpInstr then begin blocked := true; break end;
          if ac^.ops[ak].mnemonic = MnNop then begin
            { deleted -- transparent, does not count against the gap
              budget at all (matches LocalDeadAfter's own "already
              deleted" convention: a NOP was never real code to begin
              with, so skipping it costs nothing). }
          end else begin
            GetEffects(ac^.ops[ak], eff);
            if (not eff.known) or (eff.transferKind <> XferNone) then begin
              blocked := true; break
            end;
            if (eff.regWrite and tmpMask) <> 0 then begin blocked := true; break end;
            if (srcAddrMask <> 0) and ((eff.regWrite and srcAddrMask) <> 0) then begin
              blocked := true; break
            end;
            if (srcReg <> 0) and not Regs86.IsSegReg(srcReg)
               and ((eff.regWrite and RegBitFor(srcReg, Regs86.IsByteReg(srcReg))) <> 0) then begin
              blocked := true; break
            end;
            gapCount := gapCount + 1
          end
        end;
        if (not blocked) and (ac^.ops[ak].kind = TOpInstr)
           and ((ac^.ops[ak].mnemonic = MnAdd) or (ac^.ops[ak].mnemonic = MnSub)
                or (ac^.ops[ak].mnemonic = MnCmp)) then begin
          StrTab.Get(ac^.ops[ak].op1, dstTxt);
          StrTab.Get(ac^.ops[ak].op2, ax2Txt);
          DecodeOperand(dstTxt, dstOp);
          { Same width/collision/address-dependency proof FoldTempOperand
            itself already established -- see its own header comment for
            the full rationale, unchanged here. }
          dstReg := Regs86.LookupReg(Util.UpStr(dstTxt));
          if dstOp.kind = OpKindReg then
            widthOk := (dstReg <> 0) and not Regs86.IsSegReg(dstReg) and (dstReg <> tmpReg)
                       and (Regs86.IsByteReg(dstReg) = Regs86.IsByteReg(tmpReg))
          else if dstOp.kind = OpKindMem then
            widthOk := (dstOp.addrRegMask and tmpMask) = 0
          else
            widthOk := false;
          if Util.EqualICase(ax2Txt, tmpTxt) and widthOk
             and LocalDeadAfter(ac, ak, endChunk, endSlot, tmpMask, FlagMaskNone) then begin
            if not ((dstOp.kind = OpKindMem) and (srcOp.kind = OpKindMem)) then begin
              ac^.ops[ak].op2 := StrTab.Put(srcTxt);
              c^.ops[k].mnemonic := MnNop
            end
          end
        end
      end
    end
  until not Advance(c, k, endChunk, endSlot)
end;

{ ============================================================
  STAGE E: DATA-FLOW-DEPENDENT REWRITES (OPT.TXT S8) -- E4
  ============================================================
  ByteCompareNoWiden ("byte comparisons without widening"):

    MOV AL,byte [bp+4]; XOR AH,AH; CMP AX,32; JB L
      -> CMP byte [bp+4],32; JB L

  The first rule in this whole optimizer effort that actually BUILDS
  and CONSULTS Stage D's own CFG-based liveness (BuildCfg/
  ComputeLiveness) rather than Stage B's simpler LocalDeadAfter --
  "dead resulting AX... with comparison flags dead afterward on both
  successors" cannot be proven by a single linear forward scan the way
  E3/C1/FoldTempOperand's own dead-tmp proofs are: LocalDeadAfter walks
  straight through a Jcc as if it always falls through, never actually
  following the TAKEN branch to its own separate target elsewhere in
  the procedure -- exactly the "both successors" gap Stage D's own
  ComputeLiveness (LiveOut[B] = union of every real successor's own
  LiveIn, item 4) was built to close.

  Match: MOV AL,mem / XOR AH,AH / CMP AX,K / Jcc L, four STRICTLY
  ADJACENT operations (NextReal). Requires:
  - mem is a proven-safe (frame-object or unregistered-global) BYTE
    memory operand -- DecodeOperand's own OpKindMem classification,
    same non-indexed-address proof every other memory-adjacent rule in
    this stage already uses.
  - K is a decoded literal in 0..255 ("an unsigned comparison constant
    in 0..255" -- a byte CMP can never encode anything wider, and a
    constant outside this range could never have compared equal/
    unsigned-ordered against a byte value the same way the WORD CMP
    would have, so K itself must already be byte-range for the two
    forms to be provably equivalent at all).
  - Jcc is one of the six conditions EvalJcc already recognizes
    (JE/JNE/JB/JAE/JA/JBE -- "the immediate unsigned/equality branch,"
    the exact same six-condition whitelist Stage A's own ConstCond/
    ConstOrCond already rely on) -- "signed branches... are not
    allowed" is satisfied by construction: JL/JGE/JG/JLE are simply
    never matched here at all.
  - AX (both AL and AH -- the FULL RegMaskAX) and FlagMaskArith are
    BOTH absent from the Jcc's own block's own LiveOut, proven via
    BuildCfg+ComputeLiveness over the WHOLE procedure range -- "dead
    resulting AX... with comparison flags dead afterward on both
    successors" in one single check, since LiveOut already unions
    every real successor's own LiveIn (the taken target AND the
    fall-through, exactly "both successors"). If BuildCfg/
    ComputeLiveness itself reports not-ok (raw ASM present, capacity
    exceeded, or any other barrier) the match is rejected outright --
    "no analysis exists" must never be treated as "assume it's safe."
  - "Byte and word CMP need not agree on SF/OF... later arbitrary flag
    readers are not allowed" -- already covered by requiring the FULL
    FlagMaskArith (not just CF/ZF) be dead on both successors, not a
    narrower subset; a later PUSHF or an arbitrary flag reader would
    already make FlagMaskArith non-empty in LiveOut, correctly
    blocking the match without needing a separate special case.
  - "Preserve memory location/access ordering" -- trivially true: mem
    is read exactly once either way (the original reads it via MOV,
    the rewrite reads it via CMP directly), at the same point in the
    instruction stream relative to everything else. }
procedure ByteCompareNoWiden(startChunk: POpChunk; startSlot: integer;
                              endChunk: POpChunk; endSlot: integer; procId: integer);
  var c, xc, cc, jc: POpChunk; k, xk, ck, jk: integer;
      alTxt, ahTxt, axTxt, memTxt, kTxt, jccTxt: string;
      memOp: TOperand; kVal: word; taken: boolean;
      cfg: PCfg; lv: PLiveness; i, jccBlock: integer;
begin
  c := startChunk; k := startSlot;
  repeat
    if (c^.ops[k].kind = TOpInstr) and (c^.ops[k].mnemonic = MnMov) then begin
      StrTab.Get(c^.ops[k].op1, alTxt);
      StrTab.Get(c^.ops[k].op2, memTxt);
      DecodeOperand(memTxt, memOp);
      if Util.EqualICase(alTxt, 'AL')
         and (memOp.kind = OpKindMem) and (memOp.isFrameObject or (memOp.addrRegMask = RegMaskNone)) then begin
        xc := c; xk := k;
        if NextReal(xc, xk, endChunk, endSlot) and (xc^.ops[xk].kind = TOpInstr)
           and (xc^.ops[xk].mnemonic = MnXor) then begin
          StrTab.Get(xc^.ops[xk].op1, ahTxt);
          StrTab.Get(xc^.ops[xk].op2, axTxt);
          if Util.EqualICase(ahTxt, 'AH') and Util.EqualICase(axTxt, 'AH') then begin
            cc := xc; ck := xk;
            if NextReal(cc, ck, endChunk, endSlot) and (cc^.ops[ck].kind = TOpInstr)
               and (cc^.ops[ck].mnemonic = MnCmp) then begin
              StrTab.Get(cc^.ops[ck].op1, axTxt);
              StrTab.Get(cc^.ops[ck].op2, kTxt);
              if Util.EqualICase(axTxt, 'AX') and ParseDecimalLiteral(kTxt, kVal) and (kVal <= 255) then begin
                jc := cc; jk := ck;
                if NextReal(jc, jk, endChunk, endSlot) and (jc^.ops[jk].kind = TOpInstr)
                   and IsJump(jc^.ops[jk].mnemonic) and (jc^.ops[jk].mnemonic <> MnJmp)
                   and EvalJcc(jc^.ops[jk].mnemonic, 0, 0, taken) then begin
                  { EvalJcc's own success flag (ignoring taken here --
                    only used to confirm this Jcc mnemonic is one of
                    the six recognized unsigned/equality conditions)
                    doubles as the exact "immediate unsigned/equality
                    branch" whitelist E4 itself requires. }
                  BuildCfg(startChunk, startSlot, endChunk, endSlot, cfg);
                  if cfg^.ok then begin
                    { OPT.TXT R6: ComputeLivenessForProc (not the plain
                      ComputeLiveness) so a RETN block's own LiveOut can
                      be narrowed via this procedure's own proven output
                      demand (DemandFor(procId)) instead of assuming
                      every register/flag bit is always observed across
                      every return -- exactly the "why this rule cannot
                      fire on any procedure ending in a bare RETN" gap
                      this same rule's own DOCS/TRBUG.MD investigation
                      already documented and left open pending this
                      finding. }
                    ComputeLivenessForProc(cfg, procId, lv);
                    if lv^.ok then begin
                      jccBlock := -1;
                      for i := 0 to cfg^.nBlocks - 1 do
                        if (cfg^.blocks[i].endChunk = jc) and (cfg^.blocks[i].endSlot = jk) then
                          jccBlock := i;
                      if (jccBlock >= 0) and ((lv^.liveOut[jccBlock] and RegMaskAX) = 0)
                         and ((lv^.flagLiveOut[jccBlock] and FlagMaskArith) = 0) then begin
                        { Force an explicit 'byte ' prefix on the
                          rewritten CMP's own destination, regardless
                          of whether memTxt already carried one --
                          memTxt is whatever text the ORIGINAL "MOV
                          AL,mem" happened to use (which needed no
                          prefix at all when unambiguous from AL's own
                          width), but "CMP mem,K" with mem otherwise
                          untyped and K a bare literal is a genuinely
                          different, WIDTH-AMBIGUOUS instruction on
                          real 8086/NASM -- unlike E1's own reload
                          case, where the reload's own destination
                          register already disambiguated the width,
                          nothing here does that for a freshly
                          constructed CMP, so the prefix must be
                          written explicitly, matching OPT.TXT's own
                          literal worked example exactly ("CMP byte
                          [bp+4],32"). }
                        cc^.ops[ck].op1 := StrTab.Put('byte ' + MemOpndPrefix(memTxt));
                        c^.ops[k].mnemonic := MnNop;
                        xc^.ops[xk].mnemonic := MnNop
                      end
                    end;
                    Dispose(lv)   { OPT.TXT R7's own storage fix -- this
                      call's own heap-allocated lv, done being read. }
                  end;
                  Dispose(cfg)   { likewise, this call's own cfg. }
                end
              end
            end
          end
        end
      end
    end
  until not Advance(c, k, endChunk, endSlot)
end;

{ RemoveRedundantZeroExtend: see its own header comment in the
  interface section above. PropagateValues' own regKnown/regVal are
  EXIT facts (the state after a whole block has executed), never
  stored per-instruction or as a separate ENTRY fact -- so proving "AH
  is already zero right before THIS XOR" needs the block CONTAINING
  the XOR to have exactly one real predecessor whose own EXIT fact
  already proves AH=0, AND the XOR to be that block's own FIRST real
  operation (nothing else in the same block could have touched AH
  first, since nothing textually precedes it there at all) -- a
  narrower, more conservative proof than a full per-instruction
  dataflow walk would give, but a sound one: single-predecessor,
  block-start-only. A multi-predecessor join or a strictly-interior
  match (not attempted here) would need PropagateValues itself to
  expose ENTRY facts too, a larger change left for a future
  refinement. }
procedure RemoveRedundantZeroExtend(startChunk: POpChunk; startSlot: integer;
                                     endChunk: POpChunk; endSlot: integer; procId: integer);
  var c: POpChunk; k: integer; ahTxt, ah2Txt: string;
      cfg: PCfg; vf: PValueFacts; lv: PLiveness; blk, i, predBlock, nPreds: integer;
      reachedEnd: boolean;
begin
  c := startChunk; k := startSlot;
  repeat
    if (c^.ops[k].kind = TOpInstr) and (c^.ops[k].mnemonic = MnXor) then begin
      StrTab.Get(c^.ops[k].op1, ahTxt);
      StrTab.Get(c^.ops[k].op2, ah2Txt);
      if Util.EqualICase(ahTxt, 'AH') and Util.EqualICase(ah2Txt, 'AH') then begin
        BuildCfg(startChunk, startSlot, endChunk, endSlot, cfg);
        if cfg^.ok then begin
          PropagateValues(cfg, vf);
          if vf^.ok then begin
            blk := FindBlockContainingFirstReal(cfg, c, k);   { NOT
              FindBlockStartingAt -- a real, previously-latent bug found
              while building OPT.TXT's own R8 finding (see this
              procedure's own header comment for the full writeup):
              FindBlockStartingAt only ever matches a block's LITERAL
              recorded start position (almost always the LABEL itself,
              when one precedes this candidate XOR), never the first
              REAL instruction sitting one or more slots after it -- so
              this rule could never fire on ANY realistic
              single-predecessor-via-jump shape at all (every such
              shape has a label immediately before the XOR), only ever
              matching a XOR sitting at literal slot 0 with no label of
              its own, which the required "single real predecessor"
              proof can never hold for in the first place (a
              procedure's own entry block has no predecessor at all).
              CrossBlockStoreForwarding, above, already hit and fixed
              this identical class of bug independently; confirmed via
              a driver sanity check here too (a minimal single-
              predecessor XOR AH,AH after a label failed to fold before
              this fix, folds correctly after). }
            if blk >= 0 then begin
              { Find this block's own SINGLE real predecessor, if it
                has exactly one -- a join with more than one candidate
                predecessor cannot be soundly proven this way (see this
                procedure's own header comment). }
              nPreds := 0; predBlock := -1;
              for i := 0 to cfg^.nBlocks - 1 do
                if (cfg^.blocks[i].succ1 = blk) or (cfg^.blocks[i].succ2 = blk) then begin
                  nPreds := nPreds + 1; predBlock := i
                end;
              if (nPreds = 1) and vf^.regKnown[predBlock][Regs86.RegAH]
                 and (vf^.regVal[predBlock][Regs86.RegAH] = 0) then begin
                { Flags-dead proof: LocalDeadAfterEx's own linear scan
                  WITHIN this block first (proves dead the instant it
                  finds a real overwrite before any read, e.g. the very
                  common "XOR AH,AH; ADD ax,mem" shape -- the ADD
                  overwrites FlagMaskArith before anything downstream
                  in the SAME block could read the XOR's own flags).
                  Only fall back to the CROSS-block CFG proof
                  (ComputeLivenessForProc's flagLiveOut) when the local
                  scan reached the BLOCK'S OWN END with nothing yet
                  resolved (reachedEnd=TRUE) -- a real, previously-
                  latent bug found while building OPT.TXT's own R8
                  finding: gating the fallback on a bare "not proven
                  dead" result (LocalDeadAfter's plain boolean, as this
                  code used to call it) rather than distinguishing
                  "reached the end, genuinely inconclusive" from "found
                  a REAL in-block flag READ, definitively still live"
                  let a real in-block PUSHF (or similar) get silently
                  overridden by flagLiveOut[blk]'s own block-EXIT-only
                  view whenever nothing AFTER the block also happened
                  to read those flags -- block-exit liveness has no way
                  to know about a read that already happened earlier in
                  the SAME block. See LocalDeadAfterEx's own header
                  comment for the full explanation; confirmed via an
                  isolated driver reproduction before this fix. }
                if LocalDeadAfterEx(c, k, cfg^.blocks[blk].endChunk, cfg^.blocks[blk].endSlot,
                                    RegMaskNone, FlagMaskArith, reachedEnd) then
                  c^.ops[k].mnemonic := MnNop
                else if reachedEnd then begin
                  ComputeLivenessForProc(cfg, procId, lv);
                  if lv^.ok and ((lv^.flagLiveOut[blk] and FlagMaskArith) = 0) then
                    c^.ops[k].mnemonic := MnNop;
                  Dispose(lv)   { ComputeLivenessForProc always
                    allocates, ok or not -- Dispose unconditionally,
                    not just on the lv^.ok path. }
                end
              end
            end
          end;
          Dispose(vf)
        end;
        Dispose(cfg)
      end
    end
  until not Advance(c, k, endChunk, endSlot)
end;

{ RemoveDeadZeroMov: see its own header comment in the interface
  section above. Matches a literal "MOV AH,0" and deletes it purely on
  a dead-write proof -- no PropagateValues, no predecessor/join
  reasoning, since MnMov writes no flags at all and this instruction's
  own written value (0) is not itself in question, only whether
  anything downstream ever reads what it wrote. }
procedure RemoveDeadZeroMov(startChunk: POpChunk; startSlot: integer;
                             endChunk: POpChunk; endSlot: integer; procId: integer);
  var c: POpChunk; k: integer; ahTxt, zeroTxt: string; zeroVal: word;
      cfg: PCfg; lv: PLiveness; blk: integer; reachedEnd: boolean;
begin
  c := startChunk; k := startSlot;
  repeat
    if (c^.ops[k].kind = TOpInstr) and (c^.ops[k].mnemonic = MnMov) then begin
      StrTab.Get(c^.ops[k].op1, ahTxt);
      StrTab.Get(c^.ops[k].op2, zeroTxt);
      if Util.EqualICase(ahTxt, 'AH') and ParseDecimalLiteral(zeroTxt, zeroVal)
         and (zeroVal = 0) then begin
        { Local proof first (resolves instantly for the common case: a
          real overwrite of AH/AX arriving before any branch at all,
          e.g. this MOV immediately followed by "MOV destReg,ax"'s own
          later unrelated reuse of AX for something else entirely). }
        if LocalDeadAfterEx(c, k, endChunk, endSlot, RegBitFor(Regs86.RegAH, true),
                             FlagMaskNone, reachedEnd) then
          c^.ops[k].mnemonic := MnNop
        else if reachedEnd then begin
          { Local scan reached the range end unresolved (never found
            either a real read OR a full overwrite) -- ONLY here is it
            sound to fall back to CFG-wide liveness for this
            instruction's own containing block (OPT.TXT's own
            "per-instruction backward liveness reconstructed from block
            LiveOut"). If the local scan instead found a genuine
            in-block read (reachedEnd=FALSE), that is a DEFINITIVE
            live-proof this fallback must never override -- block-exit
            liveOut only describes what's live AFTER the block ends,
            and cannot see a read that already happened earlier in the
            very same block (a real bug: caught by a driver test built
            for this exact rule, see LocalDeadAfterEx's own header
            comment; RemoveRedundantZeroExtend's own analogous
            composition, above, had the identical latent bug and was
            fixed the same way). }
          BuildCfg(startChunk, startSlot, endChunk, endSlot, cfg);
          if cfg^.ok then begin
            blk := FindBlockContainingAny(cfg, c, k);
            if blk >= 0 then begin
              ComputeLivenessForProc(cfg, procId, lv);
              if lv^.ok and ((lv^.liveOut[blk] and RegBitFor(Regs86.RegAH, true)) = 0) then
                c^.ops[k].mnemonic := MnNop;
              Dispose(lv)
            end
          end;
          Dispose(cfg)
        end
      end
    end
  until not Advance(c, k, endChunk, endSlot)
end;

procedure RemoveRepeatedFlagOpCrossBlock(startChunk: POpChunk; startSlot: integer;
                                          endChunk: POpChunk; endSlot: integer);
  var c, pc: POpChunk; k, pk: integer; a1, a2, b1, b2: string;
      cfg: PCfg; blk, i, predBlock, nPreds: integer;
begin
  c := startChunk; k := startSlot;
  repeat
    if (c^.ops[k].kind = TOpInstr)
       and ((c^.ops[k].mnemonic = MnOr) or (c^.ops[k].mnemonic = MnCmp)
            or (c^.ops[k].mnemonic = MnTest)) then begin
      StrTab.Get(c^.ops[k].op1, a1); StrTab.Get(c^.ops[k].op2, a2);
      if IsRegOrImmOperand(a1) and IsRegOrImmOperand(a2) then begin
        BuildCfg(startChunk, startSlot, endChunk, endSlot, cfg);
        if cfg^.ok then begin
          blk := FindBlockContainingFirstReal(cfg, c, k);
          if blk >= 0 then begin
            nPreds := 0; predBlock := -1;
            for i := 0 to cfg^.nBlocks - 1 do
              if (cfg^.blocks[i].succ1 = blk) or (cfg^.blocks[i].succ2 = blk) then begin
                nPreds := nPreds + 1; predBlock := i
              end;
            if (nPreds = 1) and LastNonTransferReal(cfg, predBlock, pc, pk) then begin
              if (pc^.ops[pk].kind = TOpInstr) and (pc^.ops[pk].mnemonic = c^.ops[k].mnemonic) then begin
                StrTab.Get(pc^.ops[pk].op1, b1); StrTab.Get(pc^.ops[pk].op2, b2);
                if Util.EqualICase(a1, b1) and Util.EqualICase(a2, b2) then
                  c^.ops[k].mnemonic := MnNop
              end
            end
          end
        end;
        Dispose(cfg)
      end
    end
  until not Advance(c, k, endChunk, endSlot)
end;

{ DemandFor: see its own header comment in the interface section
  above. }
procedure DemandFor(procId: integer; var d: TProcDemand);
begin
  if demandTableValid and (procId >= 0) and (procId < MaxProcs) then
    d := demandTable[procId]
  else begin
    d.known := false; d.regMask := AllRegMask; d.flagMask := AllFlagMask
  end
end;

{ BuildCallGraph: see its own header comment in the interface section
  above for the full "what"/"why". Two passes:

  Pass 1: initialize every row conservative (known=FALSE) by default,
  then for each row NOT flagged isConservative, start it proven-empty
  (known=TRUE, regMask=0, flagMask=0) -- an internal, non-exported,
  non-address-taken procedure with ZERO real call sites anywhere in the
  module (dead code, or only ever called indirectly in a way this pass
  can't see -- but that would already be caught by isConservative via
  address-taken) genuinely has no caller to observe anything at all,
  so an empty (not unknown) demand is the SOUND starting point -- the
  union in pass 2 can only ever GROW it from there, never shrink it.

  Pass 2: for each range (one per procedure -- the CALLER), build its
  own CFG/liveness ONCE, then scan its own operation range for every
  MnCall/MnCallFar with a nonzero callProcId (Types.TOperation) --
  the CALLEE. If the calling block's own fall-through successor exists
  (SuccNone only for a CALL that is a procedure's own very last real
  operation with nothing after it in this range at all -- vanishingly
  rare, but real: DOCS/SPHINX.MD's own tail-call-shaped code, or a
  procedure ending in "Foo(); RETURN" with no separate RETURN-value use
  after it), union that successor block's own liveIn/flagLiveIn into
  the callee's own row; a missing successor unions in the FULL
  conservative mask instead (no fall-through code to observe means this
  call site itself cannot NARROW the callee's own demand at all, so it
  must not be allowed to -- unioning "everything" is the same as
  leaving that call site's own contribution out entirely, and is
  simpler than a special "this call site does not count" exclusion).
  If the caller's own CFG/liveness itself is not ok (raw ASM present, a
  capacity limit hit, or any other barrier BuildCfg/ComputeLiveness
  already refuse), every callee THIS caller calls is forced fully
  conservative too -- this caller's own unprovable code could observe
  anything after any of its own calls, so none of them can be narrowed
  from this caller's own contribution.

  No recursion/SCC convergence loop is needed here at all, unlike a
  typical interprocedural fixed-point analysis: this pass never asks
  "what does procedure P's own body require of ITS OWN callees" (a
  question that WOULD need iterating over a call cycle to answer
  soundly) -- it only ever asks "what does the code textually
  following a CALL TO P, inside some OTHR procedure's own body,
  read" -- a purely LOCAL fact about the CALLER's own instruction
  stream, unrelated to P's own body at all. A direct or indirect
  recursive call (P calls P, or P calls Q calls P) is handled
  correctly by the very same single pass: the call site "CALL P" sitting
  inside P's own body is scanned exactly like any other call site,
  contributing whatever P's own post-call code reads into P's own row,
  with no special-casing and no risk of an unbounded loop (this pass
  makes exactly one full scan over `ranges`, always terminates). }
const MaxDemandPasses = 64;   { same "justified convergence bound"
  precedent MaxOptimizePasses already established (OPT.TXT R4) --
  demand masks only ever GROW (union, never shrink) and are bounded by
  two fixed 16-bit lattices (regMask/flagMask), so any one procedure's
  own row can change at most 32 times total (one bit flipping 0->1,
  ever, per changed bit) before it necessarily stops changing; 64 full
  passes over every range is generous by roughly an order of magnitude
  over any real, finite chain of "caller Y's own demand narrows once
  callee X's demand is known, which itself depends on Y" this
  translator's own real call graphs could plausibly produce. }

procedure BuildCallGraph(nProcs: integer; nRanges: integer;
                          const ranges: array of TProcRange;
                          const isConservative: array of boolean);
  var i, ri, callee, passNum: integer; cfg: PCfg; lv: PLiveness;
      c: POpChunk; k: integer; succBlock, curBlock: integer;
      callerOk, changed, grew, lvAllocated: boolean;

  { MarkConservative: force callee's own row fully unknown -- the one
    "this call site cannot narrow anything" outcome every barrier case
    below collapses to. Returns whether this actually changed anything
    (a row already fully conservative marking conservative again is not
    a real change), for the outer convergence loop's own `changed`
    tracking. }
  function MarkConservative(callee: integer): boolean;
  begin
    MarkConservative := demandTable[callee].known
      or (demandTable[callee].regMask <> AllRegMask)
      or (demandTable[callee].flagMask <> AllFlagMask);
    demandTable[callee].known := false;
    demandTable[callee].regMask := AllRegMask;
    demandTable[callee].flagMask := AllFlagMask
  end;

  { UnionInto: OR demand/flag masks into callee's own row, returning
    whether either mask actually grew (a real change, for `changed`). }
  function UnionInto(callee: integer; regBits, flagBits: word): boolean;
    var newReg, newFlag: word;
  begin
    newReg := demandTable[callee].regMask or regBits;
    newFlag := demandTable[callee].flagMask or flagBits;
    UnionInto := (newReg <> demandTable[callee].regMask)
                 or (newFlag <> demandTable[callee].flagMask);
    demandTable[callee].regMask := newReg;
    demandTable[callee].flagMask := newFlag
  end;

begin
  for i := 0 to MaxProcs - 1 do begin
    demandTable[i].known := false;
    demandTable[i].regMask := AllRegMask; demandTable[i].flagMask := AllFlagMask
  end;
  for i := 0 to nProcs - 1 do begin
    if (i < MaxProcs) and not isConservative[i] then begin
      demandTable[i].known := true;
      demandTable[i].regMask := 0; demandTable[i].flagMask := 0
    end
  end;
  demandTableValid := true;   { set BEFORE the convergence loop below,
    not after -- ComputeLivenessForProc's own DemandFor calls (used for
    EACH CALLER's own RETN-block narrowing, inside this very loop) must
    already see this analysis as "in progress" (the table it reads IS
    demandTable, mid-convergence) rather than falling back to the
    "BuildCallGraph never ran at all" default the FALSE state means
    elsewhere -- a mid-convergence row's own worst case is exactly the
    conservative default it was seeded with in the loop above, never
    something LESS sound, so reading it early is safe. }
  passNum := 0;
  repeat
    changed := false;
    passNum := passNum + 1;
    for ri := 0 to nRanges - 1 do begin
      BuildCfg(ranges[ri].startChunk, ranges[ri].startSlot,
               ranges[ri].endChunk, ranges[ri].endSlot, cfg);
      callerOk := cfg^.ok;
      lvAllocated := callerOk;   { OPT.TXT R7's own storage fix -- tracks
        whether ComputeLivenessForProc (below) was actually called, and
        therefore whether lv needs Dispose()ing, SEPARATELY from
        callerOk itself: callerOk gets REASSIGNED to lv^.ok right after
        the call (a few lines down), so "callerOk at Dispose time" is
        NOT the same question as "was lv ever allocated at all" -- a
        caller whose OWN liveness fails (lv^.ok=FALSE) still had lv
        allocated (ComputeLivenessForProc's own New(lv) runs
        unconditionally), and gating its Dispose on the reassigned
        callerOk would leak it. Found via direct review of this exact
        pattern (already partly caught and fixed at RemoveRedundantZeroExtend's
        own analogous call site above). }
      if callerOk then begin
        { OPT.TXT R6: the CALLER's own liveness is now ALSO computed
          via ComputeLivenessForProc (not plain ComputeLiveness) --
          found via direct instrumentation that a call site's own
          successor block very often ALSO contains that SAME caller's
          own RETN (e.g. "CALL X; MOV ax,9; RETN" is one single block,
          no separate transfer in between), so the caller's own RETN
          being treated fully conservatively (plain ComputeLiveness)
          poisoned the very liveIn this analysis reads back for X's own
          demand, even though nothing between the CALL and the RETN
          actually reads anything. Using the caller's own (possibly
          still mid-convergence) demand row here is exactly why this
          whole pass now needs to iterate to a fixed point: caller Y's
          own narrowing depends on Y's own demand table row, which
          itself depends on every call site targeting Y across the
          whole module, possibly scanned in a LATER iteration of this
          very loop. }
        ComputeLivenessForProc(cfg, ranges[ri].procId, lv);
        callerOk := lv^.ok
      end;
      { curBlock: tracked incrementally in lockstep with (c,k) as it
        walks forward, rather than looked up per call site via
        FindBlockStartingAt -- that helper only ever matches a block's
        own START position, but a CALL sits at the END of its own block
        (BuildCfg's own "atBlockStart := true" fires AFTER a CALL is
        processed, not before), so it would almost never match a real
        call site directly. Blocks are discovered in the SAME forward
        program order (c,k) itself advances in (BuildCfg's own pass 1),
        so advancing curBlock exactly when (c,k) reaches the NEXT
        block's own recorded start position keeps it correct throughout
        this single forward walk, with no per-call-site search needed. }
      curBlock := 0;
      c := ranges[ri].startChunk; k := ranges[ri].startSlot;
      repeat
        if callerOk and (curBlock + 1 < cfg^.nBlocks)
           and (cfg^.blocks[curBlock+1].startChunk = c)
           and (cfg^.blocks[curBlock+1].startSlot = k) then
          curBlock := curBlock + 1;
        if (c^.ops[k].kind = TOpInstr)
           and ((c^.ops[k].mnemonic = MnCall) or (c^.ops[k].mnemonic = MnCallFar))
           and (c^.ops[k].callProcId <> 0) then begin
          callee := c^.ops[k].callProcId;
          if (callee >= 0) and (callee < MaxProcs) then begin
            if not callerOk then begin
              if MarkConservative(callee) then changed := true
            end else begin
              succBlock := cfg^.blocks[curBlock].succ1;
              if succBlock >= 0 then begin
                if demandTable[callee].known then begin
                  grew := UnionInto(callee, lv^.liveIn[succBlock], lv^.flagLiveIn[succBlock]);
                  if grew then changed := true
                end
              end else begin
                if MarkConservative(callee) then changed := true
              end
            end
          end
        end
      until not Advance(c, k, ranges[ri].endChunk, ranges[ri].endSlot);
      if lvAllocated then Dispose(lv);   { OPT.TXT R7's own storage fix
        -- gated on lvAllocated (was ComputeLivenessForProc actually
        called), NOT on callerOk (which may have since been reassigned
        to lv^.ok itself, a DIFFERENT question -- see lvAllocated's own
        assignment above for the full reasoning). }
      Dispose(cfg)   { likewise, this iteration's own cfg -- always
        allocated (BuildCfg's own New(cfg) runs unconditionally). }
    end
  until not changed or (passNum >= MaxDemandPasses)
end;

procedure OptimizePass(startChunk: POpChunk; startSlot: integer;
                        endChunk: POpChunk; endSlot: integer; level: integer;
                        procId: integer);
begin
  ConstCond(startChunk, startSlot, endChunk, endSlot);
  ConstOrCond(startChunk, startSlot, endChunk, endSlot);
  { OPT.TXT's own R1 finding: Stage C/E rules must stay behind level>=2
    -- "-O1: Run the existing PHOPT optimizations with the Stage A
    correctness repairs. Do not enable the additional optimizations
    below." Every rule inside this "if level >= 2" block is Stage C or
    Stage E; every rule OUTSIDE it (ConstCond/ConstOrCond above,
    CheapReturn/JumpChain/DeadCode/NoOpArith below) is a Stage A rule,
    already present (with Stage A's own correctness repairs applied)
    before Stage C ever existed, and stays enabled at level=1. }
  if level >= 2 then begin
    { Stage C, C4 -- deletion/shortening matches first (OPT.TXT S6:
      "Run local deletion/shortening to stability"; Optimize's own
      two-OptimizePass-call structure supplies the repeated-pass part,
      same as every Stage A rule already relies on). Order among these
      six does not matter for correctness (each is independently
      sound on the operation stream as it stands when it runs -- none
      depends on another having already run first within the same
      OptimizePass call), only for how much one call catches before
      the next. }
    { Stage C, C1/C2/R5's FoldSavedOperandSelfDest -- FoldSavedOperand/
      CollapseByteConstScaffolding/FoldSavedOperandSelfDest. Independent
      of the C4 matchers (all three require a nonzero genSaveId on the
      PUSH/POP pair, which none of the C4 rules ever produce or consume)
      and of EACH OTHER (their own third-operation check -- "ADD/SUB
      dst,ax" for C1, "MOV scratch,al" for C2, "MOV bx,ax" for
      FoldSavedOperandSelfDest -- is mutually exclusive on the very same
      PUSH/MOV-AX,K prefix, so at most one of the three can ever match a
      given PUSH regardless of which runs first), so their position here
      is likewise not a correctness question, only how much one call
      catches. }
    FoldSavedOperand(startChunk, startSlot, endChunk, endSlot);
    FoldSavedOperandSelfDest(startChunk, startSlot, endChunk, endSlot);
    CollapseByteConstScaffolding(startChunk, startSlot, endChunk, endSlot);
    { RemoveUnnecessarySaveRestore (C3) runs AFTER C1/C2: its own match
      is broader (any genSaveId'd PUSH...POP within 8 interior
      instructions, not a fixed 4/5-operation shape) and would
      otherwise risk deleting a PUSH/POP pair C1/C2 could have folded
      MORE precisely (collapsing the interior arithmetic too, not just
      removing the save/restore itself) had they run first on the
      exact same pair -- running C1/C2 first means whichever ALSO
      matches their own narrower shape gets the fuller collapse; C3
      only ever sees whatever's left. }
    RemoveUnnecessarySaveRestore(startChunk, startSlot, endChunk, endSlot);
    RemoveMovRR(startChunk, startSlot, endChunk, endSlot);
    RemoveMovSwapBack(startChunk, startSlot, endChunk, endSlot);
    RemoveDeadConstMov(startChunk, startSlot, endChunk, endSlot);
    RemoveRepeatedFlagOp(startChunk, startSlot, endChunk, endSlot);
    RemoveIdentityLogicOp(startChunk, startSlot, endChunk, endSlot);
    { Stage E, E1/E3 -- StoreForwarding/LoadModifyStore. Independent of
      every Stage C rule (neither requires a genSaveId, and neither
      overlaps their own shapes), so their position among the C4
      matchers above is not a correctness question for THIS pass alone
      -- forwarding a store's own source register into a same-register
      reload (e.g. "MOV [x],AX" ... "MOV AX,[x]") can produce a fresh
      "MOV AX,AX" the C4 RemoveMovRR matcher above already ran past by
      the time StoreForwarding creates it; Optimize's own two-
      OptimizePass-call structure catches it on the SECOND call, the
      same "two passes, not a general fixed-point" precedent every
      earlier multi-rule interaction in this file already relies on. }
    StoreForwarding(startChunk, startSlot, endChunk, endSlot);
    { OPT.TXT R7's own "E1 cross-block forwarding" -- a separate,
      independently-verified rule from StoreForwarding above (its own
      header comment has the full reasoning for why this is a NEW rule,
      not a rewrite of the proven-working one). Runs AFTER
      StoreForwarding so a within-block match (cheaper, more direct)
      is always tried first; the two rules' own matches are otherwise
      disjoint (StoreForwarding only ever matches a reload reachable by
      its own local scan without crossing a label/transfer, this rule
      only ever matches one that IS at a block start), so their
      relative order here is not a correctness question, only which one
      gets first refusal on a given reload. Builds its own fresh
      BuildCfg/PropagateValues internally, same "not performance-tuned"
      caveat E4/RemoveRedundantZeroExtend's own comments already
      note. }
    CrossBlockStoreForwarding(startChunk, startSlot, endChunk, endSlot);
    LoadModifyStore(startChunk, startSlot, endChunk, endSlot);
    { OPT.TXT R9's own "use CFG liveness... beyond local scans and R6
      masks at proven normal returns" -- LoadModifyStore's own new
      sibling, tried second (after the local-scan-only rule already had
      its chance) since it does strictly more work per candidate;
      independent of every rule above the same way LoadModifyStore
      itself already is. }
    LoadModifyStoreProc(startChunk, startSlot, endChunk, endSlot, procId);
    { OPT.TXT R9's own "Implement the separate missing dead-local-store
      rule" -- a genuinely new rule (no shared match shape with anything
      above), so its position here is not a correctness question. }
    RemoveDeadLocalStore(startChunk, startSlot, endChunk, endSlot);
    { OPT.TXT R11's own "E5 constant MUL/DIV/MOD" -- unsigned DIV/MOD by
      a constant power of two only (MUL and non-power-of-two divisors
      not attempted, per this finding's own explicit scope); a
      genuinely new rule (no shared match shape with anything above),
      so its position here is not a correctness question. }
    FoldConstDivMod(startChunk, startSlot, endChunk, endSlot, procId);
    { OPT.TXT R14's own "INC(curCol,GlyphW+Gap) emits arithmetic for
      3+1... add width-aware constant-expression folding" -- a
      genuinely new rule (no shared match shape with anything above),
      so its position here is not a correctness question. }
    FoldConstMovArith(startChunk, startSlot, endChunk, endSlot);
    { Stage E, E2 (tmp-fold sub-case) -- FoldTempOperand. Independent
      of every rule above (its own match, "MOV tmp,src; ADD/SUB/CMP
      dst,tmp", doesn't overlap any of theirs), so its position here
      is likewise not a correctness question. }
    FoldTempOperand(startChunk, startSlot, endChunk, endSlot);
    { OPT.TXT R8's own "FoldTempOperand's adjacent shape is currently
      driver-only... match real emission sequences using a bounded
      backward scan" -- FoldTempOperand's own new sibling, tried second
      (after the strict-adjacency rule already had its chance) since it
      does strictly more work per candidate; independent of every rule
      above the same way FoldTempOperand itself already is. }
    FoldTempOperandGap(startChunk, startSlot, endChunk, endSlot);
    { Stage E, E4 -- ByteCompareNoWiden. Independent of every rule
      above (its own four-operation match doesn't overlap any of
      theirs), so its position here is likewise not a correctness
      question. Builds its own fresh Stage D BuildCfg/ComputeLiveness
      internally, over the SAME [startChunk,startSlot..endChunk,
      endSlot] range every other rule here already receives --
      correctness-first, not performance-tuned: a fresh CFG/liveness
      pass per MATCH ATTEMPT (not just per OptimizePass call) is real,
      avoidable repeated work for a procedure with more than one
      candidate site, left as a later optimization of the OPTIMIZER
      ITSELF if it ever proves to matter, not attempted here. }
    ByteCompareNoWiden(startChunk, startSlot, endChunk, endSlot, procId);
    { OPT.TXT R7's own "Delete redundant XOR AH,AH only if AH is
      already zero AND all affected flags are dead" -- independent of
      every rule above (its own match, a bare "XOR AH,AH", doesn't
      overlap any of theirs), so its position here is likewise not a
      correctness question. Also builds its own fresh Stage D BuildCfg/
      PropagateValues/ComputeLivenessForProc internally, same "not
      performance-tuned" caveat E4's own comment above already notes. }
    RemoveRedundantZeroExtend(startChunk, startSlot, endChunk, endSlot, procId);
    { OPT.TXT R8's own "Delete MOV AH,0 using per-instruction backward
      liveness... needs no constant proof" -- independent of every rule
      above (its own match, a literal "MOV AH,0", doesn't overlap any
      of theirs, including RemoveRedundantZeroExtend's own XOR AH,AH,
      a textually different emission site). }
    RemoveDeadZeroMov(startChunk, startSlot, endChunk, endSlot, procId);
    { OPT.TXT R8's own "remove CMP/TEST only when needed flags match on
      all incoming paths" -- the cross-block extension of
      RemoveRepeatedFlagOp (Stage C, still called separately below);
      independent of every rule above (its own match, a CMP/TEST/OR at
      a single-predecessor block start, doesn't overlap any of theirs). }
    RemoveRepeatedFlagOpCrossBlock(startChunk, startSlot, endChunk, endSlot);
    RemoveDeadBranch(startChunk, startSlot, endChunk, endSlot);
    ThreadJumpChain(startChunk, startSlot, endChunk, endSlot);
    { OPT.TXT S6: "Run fall-through cleanup after threading, then
      DeadCode" -- RemoveDeadBranch again, now that ThreadJumpChain may
      have retargeted a branch straight onto a label immediately
      followed by more dead-fallthrough shape it couldn't see before
      threading ran. (CheapReturn's own "fall-through cleanup" run is
      unconditional, below, since it is itself a Stage A rule.) }
    RemoveDeadBranch(startChunk, startSlot, endChunk, endSlot);
    { OPT.TXT R12's own Stage F, F1 -- PromoteLoopLocal. Consumes a
      proven-STABLE single-block-loop load/store shape (its own
      "already present, never synthesized" entry/exit proof), so run
      LAST among this level's own rewrites, after everything else has
      had its own chance to shape the loop body's final text first;
      Optimize's own multi-pass convergence loop still re-tries it on
      any later pass if an earlier rule's own rewrite this same pass
      newly exposes the shape. Gated the same level>=2 threshold as
      every other Stage C/E rule here (no separate CLI level exists for
      Stage F -- ParseOptLevel only ever accepts -O0/-O1/-O2). }
    PromoteLoopLocal(startChunk, startSlot, endChunk, endSlot)
  end;
  CheapReturn(startChunk, startSlot, endChunk, endSlot);
  JumpChain(startChunk, startSlot, endChunk, endSlot);
  CheapReturn(startChunk, startSlot, endChunk, endSlot);
  DeadCode(startChunk, startSlot, endChunk, endSlot);
  { OPT.TXT A4: StoreReload is DISABLED, not just tightened -- "Validate
    register, width, segment, and ordinary-memory classification...
    Initially allow memory elision only for proven compiler-owned frame
    objects without escape or aliasing access. If current text cannot
    prove this, disable the affected match until Stage B supplies
    metadata." StoreReload's own match today (unchanged, still defined
    below, just no longer called from here) proves NONE of that: it
    compares storeMem/reloadMem by plain TEXT equality alone, with no
    classification of whether that operand is a real, provably-private
    [bp+N]/[bp-N] local-frame slot, a global VAR, a RECORD field, or
    something else entirely -- and even for a genuine local, has no way
    to prove its address was never taken (ADR()) anywhere else in the
    same procedure, which would make eliding this reload a real
    correctness bug (the reload could legitimately observe a write made
    through that escaped address, not just the store immediately
    before it). Stage B's own DecodeOperand/frame-object-identity
    metadata is what would let this rule finally prove what it
    currently only assumes -- until that exists, OPT.TXT's own explicit
    fallback is followed literally here: no call, not even a narrowed
    one, rather than risk shipping an unsound rule "for now."
    TESTS/STORELD.SMD/TESTS/STORELDB.SMD's own header comments have
    been updated to reflect the reload no longer being removed (runtime
    correctness is completely unaffected either way -- only the
    codegen-shape assertion those two files also checked changes).
    StoreReload(startChunk, startSlot, endChunk, endSlot); }
  NoOpArith(startChunk, startSlot, endChunk, endSlot)
end;

{ SignatureOf: OPT.TXT's own R4 finding -- "make rewrites report
  Changed; run shrinking/canonicalizing local rules to stability with a
  monotone termination measure... Use a worklist or a justified
  convergence bound." Rewriting all ~24 existing rule procedures into
  functions that each thread their own "did I change anything" boolean
  back to a caller would be a much larger, more INVASIVE change across
  every already-verified rule in this unit -- real correctness risk for
  a large diff whose only purpose is detecting change, not making one.
  Chosen instead: OptimizePass's own caller (Optimize, below) computes
  a cheap CONTENT SIGNATURE of the whole operation range before and
  after each pass and keeps calling OptimizePass again as long as the
  signature keeps changing, up to a justified bound -- this detects
  EVERY kind of change any rule could make (deletion via MnNop,
  operand retargeting via StrTab.Put, mnemonic rewriting) without
  needing any individual rule to report anything itself, and gives the
  exact same "stop once nothing changes" guarantee OPT.TXT's own
  "Changed" language asks for, from the OUTSIDE rather than threading
  it through every call site. A simple additive/rotate checksum over
  kind/mnemonic/labelId/op1/op2/sect for every slot in range -- not
  cryptographically strong, but collisions here only cost one WASTED
  extra pass (mistaking "changed" for "unchanged" would need two
  DIFFERENT operation streams to hash identically, vanishingly
  unlikely for the small, real operation counts this translator's own
  procedures ever reach, and even if it did happen, a wasted pass is
  strictly a nop -- never a correctness risk, only a missed
  optimization opportunity). }
function SignatureOf(startChunk: POpChunk; startSlot: integer;
                      endChunk: POpChunk; endSlot: integer): longint;
  var c: POpChunk; k: integer; sig: longint;
  { Mix: OPT.TXT R4 found a REAL collision here during this rule's own
    development -- the original "(sig shl 5) or (sig shr 11)) xor v"
    is NOT a true 32-bit rotate (5+11=16, not 32, so 16 bits of sig
    are discarded outright every call, not redistributed), and XOR
    alone means Mix(0) -- hit on every all-zero field, e.g. sect=0 or
    labelId=0 on a non-label operation, which is most of them -- is a
    pure no-op on the xor term, leaving the collision entirely up to
    the lossy shift/or above it. Confirmed via a standalone trace: two
    genuinely different 3-operation streams (one with a reloaded "MOV
    bx,[g]", the other with StoreForwarding's own rewrite to
    "MOV bx,bx") produced the IDENTICAL final signature, because the
    second-to-last Mix step already differed by exactly one bit that
    the following Mix(0) call's lossy shift/or then discarded --
    Optimize's own convergence loop mistook a REAL change for
    "unchanged" and stopped one pass early, the exact false-negative
    this rule exists to rule out (a wasted extra pass would have been
    harmless; silently under-converging is not). Fixed with a
    multiplicative mix instead (odd constant 1000003, diffusing bits
    across the FULL 32-bit width on every call, unlike a partial
    shift/or that discards bits outright) XOR'd with v+1 rather than
    bare v, so v=0 (sect on most operations, labelId on every non-
    label one) still changes sig instead of being a pure no-op. Same
    trace data that exposed the original collision (see above) was
    re-run against this replacement and produced two DIFFERENT final
    signatures, as expected. }
  procedure Mix(v: longint);
  begin
    sig := (sig * 1000003) xor (v + 1)
  end;
begin
  c := startChunk; k := startSlot; sig := 17;
  repeat
    Mix(longint(c^.ops[k].kind));
    Mix(longint(c^.ops[k].mnemonic));
    Mix(longint(c^.ops[k].labelId));
    Mix(longint(c^.ops[k].op1));
    Mix(longint(c^.ops[k].op2));
    Mix(longint(c^.ops[k].sect))
  until not Advance(c, k, endChunk, endSlot);
  SignatureOf := sig
end;

{ MaxOptimizePasses: the "justified convergence bound" itself. Each
  Stage A/C4 deletion rule strictly REDUCES the live (non-MnNop)
  instruction count whenever it fires at all, and retargeting rules
  (JumpChain/ThreadJumpChain) only ever move a jump CLOSER to its real
  final target (never backward -- ThreadJumpChain's own cycle guard
  already prevents oscillation) -- so any one OptimizePass call either
  makes REAL, bounded progress (fewer live instructions, or jump
  targets strictly closer to final), or finds nothing left to do and
  the signature stops changing. A bound many times larger than any
  real procedure's own instruction count (EXAMPLES/TETRIS's own
  largest procedure, Draw, is under 100 real instructions -- the same
  measurement BuildCfg's own MaxBlocks/MaxCfgOps comments already
  cite) is a defensive termination guarantee, not a claim about how
  many passes real code ever needs; 64 is generous by roughly an
  order of magnitude over anything a real, finite chain of "one rule's
  output becomes another rule's input" interactions in this unit could
  plausibly need. }
const MaxOptimizePasses = 64;

{ Optimize: OPT.TXT R4's own "justified convergence bound" -- run
  OptimizePass repeatedly while the operation range's own content
  signature (SignatureOf, above) keeps changing, capped at
  MaxOptimizePasses. Always runs at least once (matching the pre-
  existing "at least the Stage A rules run" behavior at level=1) and
  at least twice when anything changes on the first call (matching
  every existing rule-interaction comment in this file that already
  assumed "the SECOND OptimizePass call catches it" -- still true,
  just no longer hardcoded to EXACTLY twice regardless of whether more
  passes would keep finding real work). }
procedure Optimize(startChunk: POpChunk; startSlot: integer;
                    endChunk: POpChunk; endSlot: integer; level: integer;
                    procId: integer);
  var before, after: longint; passCount: integer;
begin
  passCount := 0;
  before := SignatureOf(startChunk, startSlot, endChunk, endSlot);
  repeat
    OptimizePass(startChunk, startSlot, endChunk, endSlot, level, procId);
    passCount := passCount + 1;
    after := SignatureOf(startChunk, startSlot, endChunk, endSlot);
    if after = before then break;
    before := after
  until passCount >= MaxOptimizePasses
end;

end.
