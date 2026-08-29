"""port_c_evidence.py -- static evidence index over a staged unit's verbatim C.

WHY THIS EXISTS
---------------
`port_trace_verify.refresh_plans` emits capture-plan SKELETONS with empty
reads/writes; the typed read/write sets that make a capture meaningful were
hand-authored, one unit at a time, by reading the verbatim C
(research/tools/dolphin-trace/README.md, "Authoring a new plan"). That does not
scale to 1,396 units, so `port_plan_derive` asks the local model to do the
derivation -- and an LLM-derived plan must NEVER be trusted blind.

This module is the trust anchor. It reads the same verbatim C the model reads
and extracts, WITHOUT any model, the set of memory accesses the C can possibly
perform: which parameter-relative offsets are stored to, which are loaded from,
which are merely handed to a callee as an interior pointer (direction unknown),
and which absolute ROM addresses the function names. Every entry in a derived
plan is then checked against this index:

  * an entry naming an offset/address the C never mentions is a HALLUCINATION;
  * a direct store off an entry parameter that the plan does NOT declare is an
    UNDER-DECLARATION (a write set that misses a store makes the oracle spec
    silently under-check, which is worse than refusing).

Deliberately conservative and syntactic. It works on Ghidra's decompiler output
shape (`*(float *)(param_1 + 0x184)`, `FLOAT_80438744`, `&DAT_8030316c + iVar3`),
not on arbitrary C, and it reports what it could not classify rather than
guessing. Every ambiguity resolves in the direction of "flag it", never
"assume it is fine".

Python only (owner rule); pure stdlib.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Iterable

# --------------------------------------------------------------- type widths

# Ghidra decompiler scalar spellings -> byte width. `undefined` with no digit is
# 1 byte in Ghidra's model. Anything absent from this table is reported as an
# unknown-width access rather than guessed.
_WIDTHS: dict[str, int] = {
    "bool": 1, "char": 1, "uchar": 1, "byte": 1, "sbyte": 1, "int8_t": 1,
    "uint8_t": 1, "undefined": 1, "undefined1": 1,
    "short": 2, "ushort": 2, "word": 2, "int16_t": 2, "uint16_t": 2,
    "undefined2": 2,
    "int": 4, "uint": 4, "long": 4, "ulong": 4, "dword": 4, "float": 4,
    "int32_t": 4, "uint32_t": 4, "undefined4": 4, "code": 4,
    "longlong": 8, "ulonglong": 8, "double": 8, "qword": 8, "int64_t": 8,
    "uint64_t": 8, "undefined8": 8,
}

# A ROM global Ghidra names after its address: FLOAT_80438744, DAT_8030316c,
# _DAT_80303148, DOUBLE_80438748, PTR_8043_1234 ... The address is the trailing
# 8 hex digits of a MEM1/ROM address (0x8xxxxxxx).
# The `PTR_FUN_80305240` / `PTR_LAB_...` spellings are Ghidra's name for a
# pointer-to-code global: still a DATA address (the ROM dispatch table
# FUN_800c4838 indexes), so the optional FUN_/LAB_ infix must be allowed or the
# table read looks ungrounded.
_GLOBAL_SYM = re.compile(
    r"\b_?(?:DAT|FLOAT|DOUBLE|UINT|INT|SHORT|USHORT|BYTE|WORD|DWORD|QWORD|PTR|LONG|ULONG|BOOL|CHAR|UNK)"
    r"_(?:FUN_|LAB_)?((?:8|9)[0-9a-fA-F]{7})\b"
)

# `*(<type> *)` -- the head of the decompiler's universal typed access. The base
# expression that follows is read with a BALANCED-paren scan, not a regex: a
# pointer chase nests (`*(char *)(*(int *)(param_1 + 0x90) + 0x18)`) and a
# paren-free regex silently drops exactly the accesses that matter most.
_TYPED_DEREF_HEAD = re.compile(
    r"\*\s*\(\s*([A-Za-z_][A-Za-z0-9_ ]*?)\s*\*+\s*\)\s*"
)
# `*(<type> *)<simple-ident>` -- deref of a bare parameter/local, offset 0.
_TYPED_DEREF_BARE = re.compile(
    r"\*\s*\(\s*([A-Za-z_][A-Za-z0-9_ ]*?)\s*\*\s*\)\s*([A-Za-z_][A-Za-z0-9_]*)\b"
)
# `(<type> *)(param_1 + 0x20)` NOT preceded by `*` -- an interior pointer handed
# to a callee. Direction unknown: the callee may read it, write it, or both.
_PTR_CAST_HEAD = re.compile(
    r"(?<![*\w])\(\s*([A-Za-z_][A-Za-z0-9_ ]*?)\s*\*+\s*\)\s*"
)


def _balanced(source: str, start: int) -> tuple[str, int] | None:
    """Read the parenthesised group starting at `start` ('(' expected).
    Returns (inner text, index just past the closing paren)."""
    if start >= len(source) or source[start] != "(":
        return None
    depth = 0
    for index in range(start, len(source)):
        char = source[index]
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return source[start + 1:index], index + 1
        elif char == ";":
            return None
    return None
# `param_3 + 0x14` / `param_3` inside a base expression.
_PARAM_OFFSET = re.compile(r"\bparam_(\d+)\s*\+\s*(0x[0-9a-fA-F]+|\d+)")
_PARAM_BARE = re.compile(r"\bparam_(\d+)\b")
_HEX_LITERAL = re.compile(r"\b0x[0-9a-fA-F]+\b")
_CALL = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(")

# Identifiers that are never memory bases in decompiler output.
_KEYWORDS = {
    "if", "else", "while", "for", "return", "switch", "case", "do", "break",
    "continue", "sizeof", "goto", "default", "SQRT", "ABS", "CONCAT44",
    "CONCAT31", "CONCAT22", "NAN", "SUB84", "SUB41",
}


def width_of(type_name: str) -> int | None:
    """Byte width of a decompiler scalar type spelling, or None if unknown."""
    key = " ".join(type_name.split())
    return _WIDTHS.get(key) or _WIDTHS.get(key.replace(" ", ""))


# ------------------------------------------------------------------ accesses


@dataclass(frozen=True)
class Access:
    """One statically observed memory access.

    kind      "param"    base is an entry parameter (rebasable, capturable)
              "absolute" base is a ROM global named after its address
              "chase"    base is a pointer LOADED from a param (`[p+a]+b`)
              "local"    base is a decompiler local (an allocator return, a
                         stack buffer, ...) -- NOT addressable from entry regs
    param     1-based parameter index for "param"/"chase", else None
    offset    constant offset off that base
    addr      absolute address for "absolute", else None
    width     access width in bytes, or None when the cast type is unknown
    direction "write" (lvalue of an assignment), "read" (rvalue), or
              "ptr" (interior pointer passed to a callee -- unknown direction)
    line      1-based line number inside the function body
    text      the source line, stripped -- the citation a derived entry must match
    depth     brace nesting inside the function body: 0 = unconditional (runs on
              every call), >0 = inside an if/loop. Only an unconditional store
              can excuse a later read from being declared.
    """

    kind: str
    param: int | None
    offset: int
    addr: int | None
    width: int | None
    direction: str
    line: int
    text: str
    depth: int = 0

    def key(self) -> tuple[Any, ...]:
        return (self.kind, self.param, self.offset, self.addr)


@dataclass
class FunctionEvidence:
    """Everything the static pass could establish about one function's C."""

    name: str
    body: str
    lines: list[str] = field(default_factory=list)
    accesses: list[Access] = field(default_factory=list)
    callees: set[str] = field(default_factory=set)
    globals_named: set[int] = field(default_factory=set)
    hex_literals: set[int] = field(default_factory=set)
    params: list[str] = field(default_factory=list)
    unclassified: list[str] = field(default_factory=list)

    # ---- queries used by the validator -------------------------------------

    def param_offsets(self, direction: str | None = None) -> set[tuple[int, int]]:
        return {
            (a.param, a.offset)
            for a in self.accesses
            if a.kind == "param" and a.param is not None
            and (direction is None or a.direction == direction)
        }

    def chase_offsets(self) -> set[tuple[int, int]]:
        return {
            (a.param, a.offset) for a in self.accesses
            if a.kind == "chase" and a.param is not None
        }

    def absolute_addrs(self) -> set[int]:
        return {a.addr for a in self.accesses if a.kind == "absolute" and a.addr is not None}

    def direct_param_writes(self) -> list[Access]:
        """Stores whose base is an entry parameter -- the accesses a plan's write
        set MUST cover (or explicitly excuse)."""
        return [a for a in self.accesses
                if a.kind == "param" and a.direction == "write" and a.param is not None]

    def direct_param_reads(self) -> list[Access]:
        return [a for a in self.accesses
                if a.kind == "param" and a.direction == "read" and a.param is not None]

    def unconditional_writes(self) -> list[Access]:
        """Stores that run on EVERY call (brace depth 0). A read of memory such a
        store already filled does not need to be seeded from the console -- the
        gold plan for FUN_800c4308 omits the +0x180 read for exactly this
        reason, because the function writes +0x180 unconditionally first."""
        return [a for a in self.accesses
                if a.kind == "param" and a.direction == "write"
                and a.param is not None and a.depth == 0]

    def has_local_base_writes(self) -> bool:
        return any(a.kind == "local" and a.direction == "write" for a in self.accesses)

    def cite(self, line_no: int) -> str:
        if 1 <= line_no <= len(self.lines):
            return self.lines[line_no - 1].strip()
        return ""


# ------------------------------------------------------------ body extraction

# The staged unit.c carries one marker line per function, emitted by the
# extraction stage: `// ==== 800c42bc  FUN_800c42bc ====`.
_UNIT_MARKER = re.compile(r"^//\s*====\s*([0-9a-fA-F]{6,8})\s+(\S+)\s*====\s*$")


def split_unit_functions(unit_c: str) -> dict[str, str]:
    """Split a staged unit.c into {function name: body text}.

    Bodies run from the marker line to the next marker (or to the next VERBATIM
    banner / end of file), so each body contains exactly one function's C plus
    its own banner comments.
    """
    lines = unit_c.splitlines()
    starts: list[tuple[int, str]] = []
    for index, line in enumerate(lines):
        match = _UNIT_MARKER.match(line.strip())
        if match:
            starts.append((index, match.group(2)))
    bodies: dict[str, str] = {}
    for position, (index, name) in enumerate(starts):
        end = starts[position + 1][0] if position + 1 < len(starts) else len(lines)
        # drop the trailing VERBATIM banner that belongs to the NEXT function
        chunk = lines[index:end]
        while chunk and chunk[-1].strip().startswith("/* ==== VERBATIM"):
            chunk.pop()
        bodies[name] = "\n".join(chunk).rstrip() + "\n"
    return bodies


# --------------------------------------------------------------- the analyser


def _strip_comments(text: str) -> str:
    """Blank out comments while preserving line count and column-ish layout."""
    out = re.sub(r"/\*.*?\*/", lambda m: re.sub(r"[^\n]", " ", m.group(0)), text, flags=re.S)
    out = re.sub(r"//[^\n]*", lambda m: " " * len(m.group(0)), out)
    return out


def _is_assignment_target(source: str, end: int) -> bool:
    """True when the expression ending at `end` is the LHS of a plain `=`.

    Rejects `==`, `<=`, `>=`, `!=` and compound assignments are treated as BOTH
    (handled by the caller adding a read).
    """
    tail = source[end:]
    match = re.match(r"\s*([-+*/%&|^]?=)(?!=)", tail)
    if not match:
        return False
    # `<=` / `>=` / `!=` have their operator char BEFORE the '='; our regex only
    # matches arithmetic compounds, so guard the comparison forms explicitly.
    return not re.match(r"\s*[=<>!]=", tail)


def _is_compound_assignment(source: str, end: int) -> bool:
    return bool(re.match(r"\s*[-+*/%&|^]=(?!=)", source[end:]))


def _line_of(source: str, index: int) -> int:
    return source.count("\n", 0, index) + 1


# MEM1 / ROM address window. Ghidra prints a compiled-in table base reached via
# a signed register offset as a NEGATIVE literal: `(float *)(iVar3 + -0x7fcfceb8)`
# is the 0x44-strided table at 0x80303148. Any literal whose 32-bit two's
# complement value lands in this window is an absolute address, not arithmetic.
_MEM1_LO, _MEM1_HI = 0x80000000, 0x81800000


def _int(token: str) -> int:
    """Parse a decompiler integer literal. `int(x, 0)` REJECTS leading-zero
    decimals ('0071128'), which Ghidra does emit -- that raised a ValueError
    that aborted a whole-corpus survey run."""
    text = token.strip()
    if text[:2].lower() in ("0x", "-0"):
        pass
    if text.lower().startswith("0x"):
        return int(text, 16)
    if text.startswith("-0x") or text.startswith("-0X"):
        return -int(text[3:], 16)
    return int(text, 10)


def _mem1_literal(expr: str) -> int | None:
    for match in re.finditer(r"(-?)\s*(0x[0-9a-fA-F]+|\d{6,})", expr):
        value = _int(match.group(2))
        if match.group(1) == "-":
            value = (-value) & 0xFFFFFFFF
        if _MEM1_LO <= value < _MEM1_HI:
            return value
    return None


# `uVar4 = *(uint *)(param_1 + 200);` -- the decompiler routinely hoists a
# pointer field into a local and derefs the LOCAL afterwards, so a purely
# syntactic pass would see `uVar4 + 100` as an unaddressable local and miss a
# real pointer chase the plan must declare. One substitution pass fixes that.
_LOCAL_PTR_ASSIGN = re.compile(
    r"\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*\*\s*\(\s*[A-Za-z_][A-Za-z0-9_ ]*?\s*\*\s*\)"
    r"\s*\(\s*param_(\d+)\s*\+\s*(0x[0-9a-fA-F]+|\d+)\s*\)\s*;"
)
_LOCAL_PTR_ASSIGN_BARE = re.compile(
    r"\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*\*\s*\(\s*[A-Za-z_][A-Za-z0-9_ ]*?\s*\*\s*\)"
    r"\s*param_(\d+)\s*;"
)


def _chase_locals(source: str) -> dict[str, tuple[int, int]]:
    """{local name: (param index, offset)} for locals holding a loaded pointer.

    A local reassigned anywhere else is dropped: a single static value is the
    only case this pass can honestly claim.
    """
    found: dict[str, tuple[int, int]] = {}
    for match in _LOCAL_PTR_ASSIGN.finditer(source):
        found.setdefault(match.group(1),
                         (int(match.group(2)), _int(match.group(3))))
    for match in _LOCAL_PTR_ASSIGN_BARE.finditer(source):
        found.setdefault(match.group(1), (int(match.group(2)), 0))
    # drop any local assigned more than once (ambiguous provenance)
    for name in list(found):
        assigns = len(re.findall(rf"\b{re.escape(name)}\s*=(?!=)", source))
        if assigns > 1:
            del found[name]
    return found


def _classify_base(base: str, chase_locals: dict[str, tuple[int, int]] | None = None
                   ) -> tuple[str, int | None, int, int | None] | None:
    """(kind, param, offset, addr) for a deref base expression, or None.

    Handles, in order of specificity:
      `*(int *)(param_1 + 0xc8) + 0x64`   -> chase off param_1 at 0x64
      `uVar4 + 100` where uVar4 = [param_1+200]  -> chase off param_1 at 0x64
      `param_1 + 0x184`                   -> param 1, offset 0x184
      `param_1`                           -> param 1, offset 0
      `&DAT_8030316c + iVar3`             -> absolute 0x8030316c
      `iVar3 + -0x7fcfceb8`               -> absolute 0x80303148 (strided table)
      `iVar3 + 0x20`                      -> local (not entry-addressable)
    """
    expr = " ".join(base.split())
    chase_locals = chase_locals or {}

    # pointer chase: a typed deref of a param inside the base expression
    chase = re.search(
        r"\*\s*\(\s*[A-Za-z_][A-Za-z0-9_ ]*?\s*\*\s*\)\s*\(\s*param_(\d+)\s*\+\s*(0x[0-9a-fA-F]+|\d+)\s*\)",
        expr,
    )
    if chase:
        tail = expr[chase.end():]
        offset_match = re.match(r"\s*\+\s*(0x[0-9a-fA-F]+|\d+)", tail)
        offset = int(offset_match.group(1), 0) if offset_match else 0
        return ("chase", int(chase.group(1)), offset, None)
    chase_bare = re.search(
        r"\*\s*\(\s*[A-Za-z_][A-Za-z0-9_ ]*?\s*\*\s*\)\s*param_(\d+)\b", expr
    )
    if chase_bare:
        tail = expr[chase_bare.end():]
        offset_match = re.match(r"\s*\+\s*(0x[0-9a-fA-F]+|\d+)", tail)
        offset = int(offset_match.group(1), 0) if offset_match else 0
        return ("chase", int(chase_bare.group(1)), offset, None)

    symbol = _GLOBAL_SYM.search(expr)
    if symbol:
        return ("absolute", None, 0, int(symbol.group(1), 16))

    # a local holding a previously loaded pointer, plus a constant offset
    for ident, (param, base_offset) in chase_locals.items():
        pattern = rf"^{re.escape(ident)}\s*(?:\+\s*(0x[0-9a-fA-F]+|\d+))?$"
        match = re.match(pattern, expr)
        if match:
            offset = _int(match.group(1)) if match.group(1) else 0
            return ("chase", param, offset, None)

    literal = _mem1_literal(expr)
    if literal is not None and not _PARAM_BARE.search(expr):
        return ("absolute", None, 0, literal)

    param_off = _PARAM_OFFSET.search(expr)
    if param_off:
        return ("param", int(param_off.group(1)), int(param_off.group(2), 0), None)

    param_bare = _PARAM_BARE.search(expr)
    if param_bare and not re.search(r"param_\d+\s*[-*/]", expr):
        return ("param", int(param_bare.group(1)), 0, None)

    if re.search(r"[A-Za-z_][A-Za-z0-9_]*", expr):
        return ("local", None, 0, None)
    return None


def analyse_function(name: str, body: str, params: Iterable[str] = ()) -> FunctionEvidence:
    """Build the static evidence index for one function body."""
    evidence = FunctionEvidence(name=name, body=body, lines=body.splitlines(),
                                params=list(params))
    source = _strip_comments(body)
    chase_locals = _chase_locals(source)

    for match in _GLOBAL_SYM.finditer(source):
        evidence.globals_named.add(int(match.group(1), 16))
    for match in _HEX_LITERAL.finditer(source):
        evidence.hex_literals.add(int(match.group(0), 16))
    for match in _CALL.finditer(source):
        callee = match.group(1)
        if callee not in _KEYWORDS and callee != name:
            evidence.callees.add(callee)

    consumed: list[tuple[int, int]] = []

    def record(kind: str, param: int | None, offset: int, addr: int | None,
               width: int | None, direction: str, index: int) -> None:
        line = _line_of(source, index)
        # brace depth relative to the function body ('{' of the function itself
        # is depth 0's opener, so subtract it)
        depth = max(0, source.count("{", 0, index) - source.count("}", 0, index) - 1)
        evidence.accesses.append(Access(kind, param, offset, addr, width,
                                        direction, line, evidence.cite(line), depth))

    for match in _TYPED_DEREF_HEAD.finditer(source):
        group = _balanced(source, match.end())
        if group is None:
            continue
        base, end = group
        consumed.append((match.start(), end))
        width = width_of(match.group(1))
        classified = _classify_base(base, chase_locals)
        if classified is None:
            evidence.unclassified.append(source[match.start():end])
            continue
        kind, param, offset, addr = classified
        write = _is_assignment_target(source, end)
        record(kind, param, offset, addr, width,
               "write" if write else "read", match.start())
        if write and _is_compound_assignment(source, end):
            record(kind, param, offset, addr, width, "read", match.start())

    for match in _TYPED_DEREF_BARE.finditer(source):
        if any(s <= match.start() < e for s, e in consumed):
            continue
        ident = match.group(2)
        if ident in _KEYWORDS:
            continue
        width = width_of(match.group(1))
        classified = _classify_base(ident, chase_locals)
        if classified is None:
            continue
        kind, param, offset, addr = classified
        write = _is_assignment_target(source, match.end())
        record(kind, param, offset, addr, width,
               "write" if write else "read", match.start())

    # `*param_3 = 0;` / `param_3[4]` -- an UNCAST deref of a pointer parameter.
    # Ghidra emits this whenever the parameter already has a pointer type, and
    # missing it hides a real store (zz_00c4704_'s failure-path `*param_3 = 0`
    # is the whole capturable write set of that function).
    # Scanned only INSIDE the body: `undefined1 *param_9` in the signature is a
    # DECLARATION, not a dereference, and counting it as a load made every
    # pointer-argument function look under-declared.
    body_start = source.find("{")
    declaration = re.compile(r"[A-Za-z0-9_]\s*$")
    for match in re.finditer(r"\*\s*param_(\d+)\b", source):
        if match.start() < body_start or any(s <= match.start() < e for s, e in consumed):
            continue
        if declaration.search(source[:match.start()]):
            continue  # preceded by a type token -> a declaration
        write = _is_assignment_target(source, match.end())
        record("param", int(match.group(1)), 0, None, None,
               "write" if write else "read", match.start())
    for match in re.finditer(r"\bparam_(\d+)\s*\[\s*(0x[0-9a-fA-F]+|\d+)\s*\]", source):
        if match.start() < body_start or any(s <= match.start() < e for s, e in consumed):
            continue
        write = _is_assignment_target(source, match.end())
        record("param", int(match.group(1)), _int(match.group(2)), None, None,
               "write" if write else "read", match.start())

    for match in _PTR_CAST_HEAD.finditer(source):
        if any(s <= match.start() < e for s, e in consumed):
            continue
        group = _balanced(source, match.end())
        if group is None:
            continue
        base, _end = group
        classified = _classify_base(base, chase_locals)
        if classified is None:
            continue
        kind, param, offset, addr = classified
        record(kind, param, offset, addr, width_of(match.group(1)), "ptr", match.start())

    # Bare `SYMBOL_8043xxxx` uses with no cast (e.g. `fVar3 = FLOAT_80438744;`)
    # are real 4/8-byte ROM constant loads; the symbol prefix carries the width.
    prefix_width = {"FLOAT": 4, "DOUBLE": 8, "UINT": 4, "INT": 4, "SHORT": 2,
                    "USHORT": 2, "BYTE": 1, "WORD": 2, "DWORD": 4, "QWORD": 8,
                    "PTR": 4, "LONG": 4, "ULONG": 4, "BOOL": 1, "CHAR": 1}
    # The optional _FUN/_LAB infix keeps `PTR_FUN_80305240` (a pointer-to-code
    # DATA global -- the ROM dispatch table) while the guard below drops a bare
    # `FUN_800c42bc`, which is a FUNCTION symbol: naming it is a call or a
    # declaration, never a memory access. Without that guard every function's
    # own name registered as a ROM constant read at its own entry address, and
    # a derived plan could have "grounded" an entry on it.
    for match in re.finditer(
        r"\b_?([A-Z]+(?:_FUN|_LAB)?)_((?:8|9)[0-9a-fA-F]{7})\b", source
    ):
        prefix = match.group(1)
        if prefix in ("FUN", "LAB"):
            continue
        addr = int(match.group(2), 16)
        if any(a.kind == "absolute" and a.addr == addr for a in evidence.accesses):
            continue
        write = _is_assignment_target(source, match.end())
        record("absolute", None, 0, addr, prefix_width.get(prefix.split("_")[0]),
               "write" if write else "read", match.start())

    return evidence


def analyse_unit(unit_c: str, registry: dict[str, dict[str, Any]] | None = None
                 ) -> dict[str, FunctionEvidence]:
    """Evidence index for every function in a staged unit.c."""
    registry = registry or {}
    out: dict[str, FunctionEvidence] = {}
    for name, body in split_unit_functions(unit_c).items():
        entry = registry.get(name) or {}
        out[name] = analyse_function(name, body, entry.get("params") or [])
    return out
