# Usage:
#   make          — translate/assemble every shared LIB/*.SMD module and
#                   bundle their .RDF object files into SPHO.LIB (via
#                   TOLIB.EXE), then remove the intermediate .ASM/.RDF
#                   files (SPHO.LIB is the only linkable artifact this
#                   Makefile leaves behind; .SHD headers stay, since
#                   IMPORT resolution needs them)
#   make clean    — remove SPHO.LIB, every .ASM/.RDF/.SHD, and this
#                   directory's own tool copies

XT    = emu2
XTRUN = $(XT)

SPHO  = spho.exe
TASM  = TASM.EXE
TLINK = TLINK.EXE
TOLIB = TOLIB.EXE

LIB = SPHO.LIB

# Every shared module living in this directory. Each is translated as
# its own top-level file (no BEGIN...END in any of them), so each also
# gets its own NAME.SHD alongside NAME.ASM (DOCS/SPHINX.MD's own
# auto-generation rule) -- that's what every example's own IMPORT
# resolves against via the LIB\ fallback search path. Listed in
# DEPENDENCY order, not alphabetical: a module's own IMPORT needs its
# dependency's .SHD to already exist on disk by the time THIS Makefile
# gets to it (SYSTEM before CMDLINE, FILES before LZPLIB/LZSSLIB --
# the latter two already happened to sort alphabetically right, CMDLINE
# does not).
MODULES = SYSTEM ALLOC CHARS CMDLINE FILES KBD LZPLIB LZSSLIB OUT STRINGS

RDFS = $(addsuffix .RDF,$(MODULES))

all: $(LIB)

%.ASM: %.SMD $(SPHO)
	$(XTRUN) $(SPHO) -O2 $*.SMD

%.RDF: %.ASM $(TASM)
	$(XTRUN) $(TASM) $<
	rm -f $<

# SPHO.LIB bundles every module's own .RDF into one linkable library
# (TOLIB.EXE create) so an example's own Makefile can link against a
# single LIB/SPHO.LIB instead of listing every LIB/<name>.RDF it needs
# explicitly. Once bundled, the individual .ASM/.RDF files are removed
# -- only SPHO.LIB (plus each module's own .SHD, still needed for
# IMPORT resolution) is left behind.
$(LIB): $(RDFS) $(TOLIB)
	rm -f $(LIB)
	$(XTRUN) $(TOLIB) create $(LIB) $(RDFS)
	rm -f $(RDFS)

# emu2's own DOS layer lowercases every filename it creates regardless
# of the argument's own case (confirmed elsewhere in this project,
# e.g. TESTS/run_tests.py's own clean()) -- ALLOC.SHD may actually be
# sitting on disk as alloc.shd. Harmless on this project's own
# case-insensitive host filesystem, but rm -f both cases anyway so
# clean works the same on a case-sensitive one too.
clean:
	rm -f $(LIB) $(ASMS) $(RDFS) $(addsuffix .SHD,$(MODULES))
	rm -f spho.lib $(addsuffix .rdf,$(MODULES)) $(addsuffix .shd,$(MODULES))

.PHONY: all clean
