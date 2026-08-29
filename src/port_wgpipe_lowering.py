"""Gate-emitted write-gather-pipe lowering (GX vertex submission).

THE PROBLEM, measured rather than assumed. Gotcha Force does not submit
vertices by calling a function. It calls `gnt4_GXBegin_bl(prim, vtxfmt,
nverts)` and then STORES the vertex components directly to the GameCube's
memory-mapped write-gather pipe at 0xCC008000. In the decompiled export those
stores appear as `DAT_cc008000 = ...` / `DAT_cc008000._0_1_ = ...` /
`DAT_cc008000._0_2_ = ...` -- 1143 of them -- and there is no GXEnd symbol at
all (the SDK's GXEnd is an empty macro), so a primitive ends when its vertex
count is satisfied.

The composed wasm module's linear memory is 0x807A0000 bytes. 0xCC008000 is
past the end, so a literal store there is out of bounds and TRAPS. Every ROM
draw path is therefore unportable until those stores are lowered.

This module is the lowering half. At window link time the assembly gate
(src/port_assembly_gate.py) asks it to rewrite the DERIVED sources -- never the
verbatim unit.c, which the gate copies untouched -- turning each pipe store
into a call to one of the four host imports the browser HLE host's FIFO
decoder already services (packages/rom-runtime/src/gx/fifo.ts,
`registerWgPipeAdapters` in .../gx/adapters.ts):

    void __gf_gx_wgpipe_u8 (unsigned int value);   -> fifo.writeU8
    void __gf_gx_wgpipe_u16(unsigned int value);   -> fifo.writeU16
    void __gf_gx_wgpipe_u32(unsigned int value);   -> fifo.writeU32
    void __gf_gx_wgpipe_f32(float value);          -> fifo.writeF32

BYTE ORDER. The decoder is deliberately BIG-endian: the FIFO is a register-
order byte stream that never lived in memory, so it keeps the console's order,
unlike the little-endian arena. The imports take VALUES, not bytes, and the
host does the big-endian serialization (`writeU16` emits hi then lo). So the
lowering's whole job is to preserve the store's WIDTH and its VALUE, and to
keep a 32-bit float store a float store -- a `stfs` to the pipe puts the f32
bit pattern on the wire, and routing it through the integer import would put
the truncated integer there instead.

WIDTH AND FLOATNESS ARE NOT GUESSED. Width comes from the Ghidra field
spelling, which is the decompiler's record of the store instruction's width.
Floatness is decided by the C type system at compile time via `_Generic` in
the emitted header, not by pattern-matching the right-hand side -- so a bare
`DAT_cc008000 = fVar1;` (no cast in the text) still routes to the f32 import.
The routing table itself is proved by `_Static_assert` in the header.

FAIL CLOSED. Every occurrence of the pipe window (0xCC008000..0xCC00801F) in
the derived source must be consumed by a recognized store shape. Anything left
over -- a read of the pipe, a compound assignment, an unrecognized field
spelling, an address in the window this lowering does not model -- is a loud
`wgpipe_lowering_failed` refusal. A silent pass-through would leave a literal
out-of-bounds store in the module, which is a runtime TRAP: strictly worse
than a refusal, and invisible until the frame dies.

OPT-IN. Like the G2/H3 dispatch companion, this runs only when the gate is
asked for it (`wgpipe_lowering=True`, driven by OGHIDRA_PORT_WGPIPE_LOWERING),
so the live gate stays byte-identical until the owner deliberately enables it.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Iterable

HEADER_FILENAME = "gf_gx_wgpipe.h"

#: The host imports, in width order. Mirrors WGPIPE_SYMBOLS in
#: packages/rom-runtime/src/gx/adapters.ts -- these names are the host's, not
#: this module's, and must never be "improved" here.
WGPIPE_IMPORTS: tuple[str, ...] = (
    "__gf_gx_wgpipe_u8",
    "__gf_gx_wgpipe_u16",
    "__gf_gx_wgpipe_u32",
    "__gf_gx_wgpipe_f32",
)

WGPIPE_ABI_VERSION = 1

#: The write-gather pipe is a 32-byte window; the hardware gathers a write to
#: ANY address in it into the same stream, in program order. Measured in the
#: export: only 0xCC008000 (1143 stores) and 0xCC008004 (31, the second word
#: of the SDK's 8-byte matrix pushes) actually occur.
PIPE_BASE = 0xCC008000
PIPE_LIMIT = 0xCC008020
#: Offsets this lowering models. An occurrence anywhere else in the window is
#: refused rather than assumed to gather identically.
LOWERABLE_OFFSETS = (0x0, 0x4)

# Any hex spelling of an address inside the pipe window, wherever it appears:
# as the tail of a Ghidra global name (DAT_cc008000), as a bare literal
# (0xcc008000), inside a comment-free identifier of any shape. This is the
# DETECTOR, deliberately broader than the rewriter.
_PIPE_HEX = re.compile(r"cc0080[01][0-9a-fA-F]", re.IGNORECASE)

# Expand a detector hit to the whole token it sits in, so refusals can name it.
_TOKEN_CHAR = re.compile(r"[0-9A-Za-z_]")

# The lowerable store shapes, anchored at a token start. `field` is Ghidra's
# sub-object spelling: absent = the full 4-byte object, `._0_1_` = the byte at
# offset 0, `._0_2_` = the halfword at offset 0. On a BIG-endian target offset
# 0 is the most significant end, which is exactly what a `stb`/`sth` to the
# pipe puts on the wire first -- so `._0_N_` is an N-byte store, not a
# sub-field of a value that also needs the rest of the word.
_STORE = re.compile(
    r"(?P<name>_{0,2}[A-Za-z][0-9A-Za-z_]*_(?P<addr>cc0080[01][0-9A-Fa-f]))"
    r"(?P<field>\._0_(?P<width>[1248])_)?"
    r"[ \t]*=(?!=)",
    re.IGNORECASE,
)

_WIDTH_MACRO = {1: "GF_WGPIPE_W8", 2: "GF_WGPIPE_W16", 4: "GF_WGPIPE_W32"}

# Characters that may legally precede a statement-initial token. `)` covers an
# unbraced `if (...) DAT_cc008000 = 0;` body; `:` covers a label or a case.
_STATEMENT_PRECEDERS = frozenset(";{}):")
_STATEMENT_KEYWORDS = ("else", "do")


HEADER_TEXT = """/* gf_gx_wgpipe.h -- GameCube write-gather-pipe lowering, ABI version 1.
 *
 * AUTO-GENERATED by the assembly gate (src/port_wgpipe_lowering.py).
 * DERIVED artifact: never hand-edited, regenerated on every window link.
 *
 * WHY THIS EXISTS. The ROM submits vertices by storing them to the memory-
 * mapped write-gather pipe at 0xCC008000, not by calling a function (1143
 * such stores in the decompiled export; the SDK's GXEnd is an empty macro, so
 * primitives end on vertex count). The composed module's linear memory is
 * 0x807A0000 bytes, so a literal store to 0xCC008000 is out of bounds and
 * traps. The gate rewrites each store into one of the calls below, which the
 * browser HLE host services with its FIFO decoder
 * (packages/rom-runtime/src/gx/fifo.ts).
 *
 * THE CONTRACT. Each import receives ONE store's VALUE, at the store's
 * WIDTH, in program order. The host does the serialization, and it is
 * BIG-endian: the FIFO carries console register-order bytes, unlike the
 * little-endian linear memory the rest of the runtime uses. So u16 0x0280
 * reaches the wire as 02 80, and f32 1.0f as 3f 80 00 00.
 *
 * WIDTH is carried by the macro the gate chose, which comes from the Ghidra
 * field spelling -- the decompiler's record of the store instruction's width.
 *
 * FLOATNESS is decided HERE, by the C type system, not by the rewriter
 * looking at the text. A 32-bit store of a float must put the f32 bit
 * pattern on the wire (`stfs`), while a 32-bit store of an integer must put
 * the integer there; the two are different bytes for the same numeric value.
 * `_Generic` routes on the static type of the stored expression, so a bare
 * `DAT_cc008000 = fVar1;` with no cast in the text still reaches the f32
 * import. The routing table is proved below by _Static_assert, so a compiler
 * that disagreed with this comment would fail the build rather than draw a
 * wrong frame.
 *
 * NARROW STORES (8/16-bit) route unconditionally through the integer
 * imports. That is not an assumption about the corpus: `DAT_cc008000._0_1_ =
 * v` in C means "convert v to a 1-byte object", and `(unsigned int)(v) &
 * 0xff` is that conversion for every scalar type v can have, floating-point
 * included. (Measured: zero narrow stores in the export have a floating-point
 * right-hand side.)
 */
#ifndef GF_GX_WGPIPE_H
#define GF_GX_WGPIPE_H

#define GF_WGPIPE_ABI_VERSION 1

/* The pipe window, for the record and for the assertions below. */
#define GF_WGPIPE_BASE 0xCC008000u
#define GF_WGPIPE_LIMIT 0xCC008020u

/* The host imports. Names are the HOST's (packages/rom-runtime/src/gx/
 * adapters.ts, WGPIPE_SYMBOLS) and are matched exactly. */
extern void __gf_gx_wgpipe_u8(unsigned int value);
extern void __gf_gx_wgpipe_u16(unsigned int value);
extern void __gf_gx_wgpipe_u32(unsigned int value);
extern void __gf_gx_wgpipe_f32(float value);

/* Static routing predicate: 1 for a floating-point stored expression, 0
 * otherwise. The controlling expression of _Generic is never evaluated, so
 * this costs nothing and has no side effects. */
#define GF_WGPIPE_IS_FP(v) \\
    _Generic((v), float: 1, double: 1, long double: 1, default: 0)

/* The two conversions. Exactly one is ever evaluated (the untaken arm of the
 * conditional below is not evaluated, and _Generic never evaluates an
 * unselected association), so a stored expression with side effects is
 * evaluated exactly once -- same as the assignment it replaces. Every
 * association type-checks for every scalar type, which is why the unselected
 * ones are harmless: (unsigned int)(v) is a legal explicit cast from a
 * pointer or a float, and (float)(v) is legal from any arithmetic type. */
#define GF_WGPIPE_AS_F32(v) \\
    _Generic((v), \\
             float: (float)(v), \\
             double: (float)(v), \\
             long double: (float)(v), \\
             default: 0.0f)
#define GF_WGPIPE_AS_U32(v) \\
    _Generic((v), \\
             float: 0u, \\
             double: 0u, \\
             long double: 0u, \\
             default: (unsigned int)(v))

/* One pipe store, at each width. GF_WGPIPE_IS_FP folds at compile time, so
 * the 32-bit form is a single direct call in the generated code. */
#define GF_WGPIPE_W32(v) \\
    (GF_WGPIPE_IS_FP(v) ? __gf_gx_wgpipe_f32(GF_WGPIPE_AS_F32(v)) \\
                        : __gf_gx_wgpipe_u32(GF_WGPIPE_AS_U32(v)))
#define GF_WGPIPE_W16(v) __gf_gx_wgpipe_u16((unsigned int)(v) & 0xffffu)
#define GF_WGPIPE_W8(v)  __gf_gx_wgpipe_u8((unsigned int)(v) & 0xffu)

/* --- compiler-proved invariants ------------------------------------------
 * These are the claims the lowering rests on. If the toolchain ever
 * disagrees with one, the window fails to compile instead of drawing a
 * wrong frame. */
_Static_assert(GF_WGPIPE_LIMIT - GF_WGPIPE_BASE == 32u,
               "the write-gather pipe is a 32-byte window");
_Static_assert(sizeof(float) == 4,
               "a 32-bit pipe store of a float must be exactly 4 bytes on the wire");
_Static_assert(sizeof(unsigned int) == 4,
               "the integer pipe imports carry a 32-bit store");
_Static_assert(GF_WGPIPE_IS_FP(1.0f) == 1,
               "a float store must route to the f32 import");
_Static_assert(GF_WGPIPE_IS_FP(1.0) == 1,
               "a double store must route to the f32 import");
_Static_assert(GF_WGPIPE_IS_FP(1u) == 0,
               "an unsigned store must route to the integer import");
_Static_assert(GF_WGPIPE_IS_FP((char)1) == 0,
               "a narrow integer store must route to the integer import");
_Static_assert(GF_WGPIPE_IS_FP((unsigned long long)1) == 0,
               "a wide integer store must route to the integer import");
_Static_assert(GF_WGPIPE_IS_FP((void *)0) == 0,
               "a pointer store must route to the integer import");
_Static_assert(GF_WGPIPE_AS_U32(0x1234abcdu) == 0x1234abcdu,
               "the integer conversion is value-preserving for 32-bit integers");
_Static_assert((unsigned int)((unsigned char)0x1ff) == 0xffu,
               "the 8-bit narrowing this header performs is the C conversion");

#endif /* GF_GX_WGPIPE_H */
"""

HEADER_SHA256 = hashlib.sha256(HEADER_TEXT.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class WgpipeProblem:
    """One reason a unit cannot be lowered. Always a refusal, never a skip."""

    unit: str
    code: str
    detail: str
    line: int

    def to_dict(self) -> dict[str, object]:
        return {
            "unit": self.unit,
            "code": self.code,
            "detail": self.detail,
            "line": self.line,
        }


@dataclass(frozen=True)
class WgpipeStore:
    """One lowered store, for the evidence record."""

    line: int
    address: int
    width: int


@dataclass
class WgpipeUnit:
    """The lowering outcome for one derived source."""

    unit: str
    source_relpath: str
    text: str | None = None
    stores: list[WgpipeStore] = field(default_factory=list)
    problems: list[WgpipeProblem] = field(default_factory=list)

    @property
    def rewritten(self) -> bool:
        return bool(self.stores)


@dataclass
class WgpipeLowering:
    """The whole window's lowering plan."""

    units: list[WgpipeUnit] = field(default_factory=list)

    @property
    def problems(self) -> list[WgpipeProblem]:
        return [problem for unit in self.units for problem in unit.problems]

    @property
    def store_count(self) -> int:
        return sum(len(unit.stores) for unit in self.units)


# --------------------------------------------------------------- masking


def mask_code(text: str) -> str:
    """Return `text` with comments and literal contents blanked to spaces.

    Length and line structure are preserved exactly, so every index into the
    mask is a valid index into the original. Scanning the mask means a
    `DAT_cc008000` inside a string or a comment is invisible to both the
    detector and the rewriter -- which is correct: neither is a store.
    """
    out = list(text)
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if ch == "/" and i + 1 < n and text[i + 1] == "/":
            while i < n and text[i] != "\n":
                out[i] = " "
                i += 1
            continue
        if ch == "/" and i + 1 < n and text[i + 1] == "*":
            out[i] = out[i + 1] = " "
            i += 2
            while i < n and not (text[i] == "*" and i + 1 < n and text[i + 1] == "/"):
                if text[i] != "\n":
                    out[i] = " "
                i += 1
            if i < n:
                out[i] = " "
                if i + 1 < n:
                    out[i + 1] = " "
                i += 2
            continue
        if ch in ("'", '"'):
            quote = ch
            i += 1
            while i < n and text[i] != quote:
                if text[i] == "\\" and i + 1 < n:
                    out[i] = " "
                    if text[i + 1] != "\n":
                        out[i + 1] = " "
                    i += 2
                    continue
                if text[i] != "\n":
                    out[i] = " "
                i += 1
            if i < n:
                i += 1
            continue
        i += 1
    return "".join(out)


def _line_of(text: str, index: int) -> int:
    return text.count("\n", 0, index) + 1


def _token_at(text: str, index: int) -> tuple[int, int]:
    """Expand `index` to the whole [0-9A-Za-z_] token containing it."""
    start = index
    while start > 0 and _TOKEN_CHAR.match(text[start - 1]):
        start -= 1
    end = index
    while end < len(text) and _TOKEN_CHAR.match(text[end]):
        end += 1
    return start, end


def _statement_start(mask: str, index: int) -> bool:
    """True when `index` begins a statement.

    A pipe store that is NOT statement-initial (`x = DAT_cc008000 = 3;`,
    `f(DAT_cc008000 = 3)`) has a value the surrounding expression consumes,
    and the lowering has no value to give back. Refused rather than mangled.
    """
    j = index - 1
    while j >= 0 and mask[j].isspace():
        j -= 1
    if j < 0:
        return True
    if mask[j] in _STATEMENT_PRECEDERS:
        return True
    word_end = j + 1
    while j >= 0 and _TOKEN_CHAR.match(mask[j]):
        j -= 1
    return mask[j + 1 : word_end] in _STATEMENT_KEYWORDS


def _find_terminator(mask: str, start: int) -> int:
    """Index of the `;` closing the statement whose value begins at `start`.

    Bracket-aware over the masked text, so a `;` inside a string, a comment or
    a parenthesized sub-expression cannot end the statement early. Returns -1
    when no terminator is found at depth zero.
    """
    depth = 0
    for i in range(start, len(mask)):
        ch = mask[i]
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
            if depth < 0:
                return -1
        elif ch == ";" and depth == 0:
            return i
    return -1


# --------------------------------------------------------------- lowering


def lower_source(unit: str, source_relpath: str, text: str) -> WgpipeUnit:
    """Lower every write-gather-pipe store in one derived source.

    Returns a WgpipeUnit whose `text` is the rewritten source (None when the
    source contains no pipe reference at all, so untouched sources stay
    byte-identical) and whose `problems` list, if non-empty, is a refusal.
    """
    outcome = WgpipeUnit(unit=unit, source_relpath=source_relpath)
    mask = mask_code(text)
    if not _PIPE_HEX.search(mask):
        return outcome

    pieces: list[str] = []
    cursor = 0
    consumed: list[tuple[int, int]] = []

    for match in _STORE.finditer(mask):
        start = match.start("name")
        address = int(match.group("addr"), 16)
        line = _line_of(text, start)
        if address < PIPE_BASE or address >= PIPE_LIMIT:
            # Some other Ghidra global whose name merely looks like the
            # window. The detector below will decide whether it matters.
            continue
        offset = address - PIPE_BASE
        if offset not in LOWERABLE_OFFSETS:
            outcome.problems.append(
                WgpipeProblem(
                    unit,
                    "wgpipe_offset_unsupported",
                    f"{source_relpath}:{line}: store to 0x{address:08x} is inside the "
                    "write-gather window but at an offset this lowering does not "
                    f"model (modelled: "
                    + ", ".join(f"0x{PIPE_BASE + o:08x}" for o in LOWERABLE_OFFSETS)
                    + ")",
                    line,
                )
            )
            continue
        if not _statement_start(mask, start):
            outcome.problems.append(
                WgpipeProblem(
                    unit,
                    "wgpipe_store_not_statement",
                    f"{source_relpath}:{line}: the pipe store is not statement-"
                    "initial, so its assignment value is consumed by the "
                    "surrounding expression; the lowering has no value to return",
                    line,
                )
            )
            continue
        width = int(match.group("width")) if match.group("width") else 4
        macro = _WIDTH_MACRO.get(width)
        if macro is None:
            outcome.problems.append(
                WgpipeProblem(
                    unit,
                    "wgpipe_width_unsupported",
                    f"{source_relpath}:{line}: {match.group(0).strip()} is a "
                    f"{width}-byte pipe store; the host FIFO imports carry 1, 2 and "
                    "4-byte stores only",
                    line,
                )
            )
            continue
        rhs_start = match.end()
        terminator = _find_terminator(mask, rhs_start)
        if terminator < 0:
            outcome.problems.append(
                WgpipeProblem(
                    unit,
                    "wgpipe_unterminated_store",
                    f"{source_relpath}:{line}: no statement terminator found for "
                    f"{match.group('name')}; the stored expression cannot be bounded",
                    line,
                )
            )
            continue
        rhs = text[rhs_start:terminator].strip()
        if not rhs:
            outcome.problems.append(
                WgpipeProblem(
                    unit,
                    "wgpipe_empty_store",
                    f"{source_relpath}:{line}: pipe store with an empty right-hand side",
                    line,
                )
            )
            continue
        # The stored expression is wrapped in its own parentheses so that a
        # top-level comma operator stays ONE macro argument.
        pieces.append(text[cursor:start])
        pieces.append(f"{macro}(({rhs}));")
        cursor = terminator + 1
        consumed.append((start, terminator + 1))
        outcome.stores.append(WgpipeStore(line=line, address=address, width=width))

    pieces.append(text[cursor:])

    # THE FAIL-CLOSED SWEEP. Every occurrence of the pipe window in the
    # masked source must have been consumed by a rewrite above. A survivor is
    # a literal out-of-bounds access that would TRAP at runtime, so it refuses
    # the unit instead of passing through.
    for hit in _PIPE_HEX.finditer(mask):
        if any(start <= hit.start() < end for start, end in consumed):
            continue
        token_start, token_end = _token_at(text, hit.start())
        line = _line_of(text, hit.start())
        if any(problem.line == line for problem in outcome.problems):
            continue
        snippet = text[token_start:token_end]
        context = text[max(0, token_start - 40) : token_end + 40].replace("\n", " ")
        outcome.problems.append(
            WgpipeProblem(
                unit,
                "wgpipe_unlowerable_site",
                f"{source_relpath}:{line}: `{snippet}` references the write-gather "
                "window but is not a lowerable store (recognized: "
                "`NAME = v;`, `NAME._0_1_ = v;`, `NAME._0_2_ = v;`, "
                "`NAME._0_4_ = v;`); leaving it would be an out-of-bounds trap. "
                f"context: ...{context.strip()}...",
                line,
            )
        )

    if outcome.problems:
        outcome.text = None
        return outcome

    body = "".join(pieces)
    outcome.text = _with_header_include(body, source_relpath)
    return outcome


def header_include_path(source_relpath: str) -> str:
    """The `#include` spelling that reaches the workdir-root header.

    Quoted includes resolve relative to the INCLUDING file's directory, and
    the canonicalization path writes unit sources one directory down
    (`<unit>/<unit>.c`) while the registry-less merge path writes them flat.
    Both are handled by counting directories, not by guessing.
    """
    depth = len([part for part in source_relpath.replace("\\", "/").split("/")[:-1] if part])
    return "../" * depth + HEADER_FILENAME


def _with_header_include(text: str, source_relpath: str) -> str:
    include = f'#include "{header_include_path(source_relpath)}"\n'
    if text.startswith("﻿"):
        return "﻿" + include + text[1:]
    return include + text


def lower_window(sources: Iterable[tuple[str, str, str]]) -> WgpipeLowering:
    """Lower a whole window.

    `sources` is an iterable of (unit_name, source_relpath, source_text).
    """
    plan = WgpipeLowering()
    for unit, relpath, text in sources:
        plan.units.append(lower_source(unit, relpath, text))
    return plan


def lowering_evidence(plan: WgpipeLowering) -> dict[str, object]:
    """The gate-ledger record. Structural only: no behavioural claim.

    A lowered store is a store the host CAN now receive. Whether the frame it
    contributes to is right is the GX host's own (currently synthetic)
    question -- see docs/gx-hle-host.md section 1.
    """
    by_width: dict[str, int] = {}
    by_address: dict[str, int] = {}
    units: list[dict[str, object]] = []
    for unit in plan.units:
        if not unit.stores:
            continue
        widths: dict[str, int] = {}
        for store in unit.stores:
            key = f"u{store.width * 8}"
            widths[key] = widths.get(key, 0) + 1
            by_width[key] = by_width.get(key, 0) + 1
            addr = f"0x{store.address:08x}"
            by_address[addr] = by_address.get(addr, 0) + 1
        units.append(
            {
                "unit": unit.unit,
                "source": unit.source_relpath,
                "stores": len(unit.stores),
                "by_width": dict(sorted(widths.items())),
            }
        )
    return {
        "abi_version": WGPIPE_ABI_VERSION,
        "header_sha256": HEADER_SHA256,
        "imports": list(WGPIPE_IMPORTS),
        "stores": plan.store_count,
        "by_width": dict(sorted(by_width.items())),
        "by_address": dict(sorted(by_address.items())),
        "units": units,
        # Structural lowering evidence only. This makes no behavioural claim
        # and never raises a unit's verification tier.
        "behavior_claim": None,
    }
