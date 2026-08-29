"""port_plan_derive.py -- LLM-derived capture plans, validated against the C.

THE BOTTLENECK THIS REMOVES
---------------------------
A dolphin-trace capture is only as good as its plan's TYPED read/write sets, and
`port_trace_verify.refresh_plans` emits only a skeleton with empty sets. The one
unit that got real sets (auto-c0020-007, 8 exports) was hand-authored line by
line from the verbatim C; the result was excellent (815 cases, 789 byte-exact,
0 unexplained) and completely unscalable across 1,396 units.

Deriving a read/write set from verbatim decompiled C is the same kind of reading
the port pipeline's local model already does when it repairs a compile. So this
module asks it -- and then refuses to believe it.

THE TRUST MODEL (three layers, all fail-closed)
-----------------------------------------------
1. CITATION. The prompt shows the C with numbered lines and forces one `line`
   field per declared entry. The cited line must exist AND must itself name the
   offset or address the entry claims, so a citation cannot be satisfied by
   pointing anywhere plausible. (A verbatim `evidence` line is still accepted,
   and is what the first version asked for -- but reply length turned out to be
   the binding constraint on this rig, and a line number costs a couple of
   tokens where a copied source line costs sixty.) Unjustifiable entries are
   the failure mode this is designed against.

2. STATIC GROUNDING (`port_c_evidence`). Every address expression is parsed and
   checked against an index built from the same C by a model-free syntactic
   pass: the offset or ROM address it names must actually be accessed there, in
   a compatible direction. An entry naming memory the C never touches is a
   HALLUCINATION and is reported as one.

3. COVERAGE. The reverse direction, which matters more. Every direct store the
   C performs off an entry parameter must be covered by the declared write set,
   and every direct load by the read set. A plan that MISSES a store is worse
   than a wrong one: the generated spec would compare fewer bytes and pass
   everything. Under-declaration is a refusal.

A plan that fails any layer is emitted as a REFUSAL record with its reasons --
never written over a hand-authored plan, never silently downgraded to a
skeleton.

GPU / serving rules: one request at a time through the shared server at :8888,
the same `CustomAPIClient` and sampling profile the compile-fix loop uses. This
module never starts, restarts, or reconfigures the model server, and never
touches the rig supervisor's lease.

Python only (owner rule); stdlib + the existing OGhidra client.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from src.port_c_evidence import (
    FunctionEvidence,
    analyse_function,
    split_unit_functions,
    width_of,
)
from src.port_trace_verify import (
    ORACLE_REGISTRY_RELPATH,
    PLANS_RELPATH,
    load_registry_functions,
    plan_args,
    plan_ret,
)

STAGING_RELPATH = "research/decomp/port-units-staging"

DERIVED_BY = "port_plan_derive LLM derivation v1"

# capture_oracle.py's own guard, duplicated so a plan is rejected HERE rather
# than at capture time on a live emulator boot.
EXPR_TOKEN = re.compile(r"^[\sr0-9a-fA-Fx+\-*&|()<>\[\]]+$")

# Widths the capture tool and the harness codec can both handle. Vector/matrix
# spans are multiples of 4 and are listed explicitly so a nonsense width (say 3
# or 7) is a malformed entry rather than a capture-time crash.
_LEGAL_WIDTHS = {1, 2, 4, 8, 12, 16, 24, 32, 48, 64}

_MEM1_LO, _MEM1_HI = 0x80000000, 0x81800000


# ---------------------------------------------------------------- validation


@dataclass
class EntryVerdict:
    side: str            # "read" | "write"
    entry_id: str
    status: str          # grounded | grounded_ptr | grounded_chase |
                         # ungrounded | ungrounded_rom_const | malformed |
                         # citation_missing
    detail: str = ""

    @property
    def ok(self) -> bool:
        return self.status.startswith("grounded")


@dataclass
class PlanValidation:
    fn: str
    entries: list[EntryVerdict] = field(default_factory=list)
    undeclared_writes: list[str] = field(default_factory=list)
    undeclared_reads: list[str] = field(default_factory=list)
    unacknowledged_local_writes: bool = False
    errors: list[str] = field(default_factory=list)

    @property
    def hallucinated(self) -> list[EntryVerdict]:
        return [e for e in self.entries if not e.ok]

    @property
    def verdict(self) -> str:
        """`validated` | `flagged` | `refused`.

        validated -- every entry grounded and every C-observed direct access
                     covered: safe to capture from, and eligible for spec
                     generation.
        flagged   -- entries are grounded but something needs a human eye (a
                     ROM constant this unit's C does not name, an allocator's
                     stores the capture cannot address). The plan is written,
                     the spec is NOT.
        refused   -- a hallucinated/malformed entry, or an under-declared
                     read/write set. Nothing is written.
        """
        if self.errors or any(
            e.status in ("ungrounded", "malformed", "citation_missing")
            for e in self.entries
        ):
            return "refused"
        if self.undeclared_writes or self.undeclared_reads:
            return "refused"
        if self.unacknowledged_local_writes or any(
            e.status == "ungrounded_rom_const" for e in self.entries
        ):
            return "flagged"
        return "validated"

    def reasons(self) -> list[str]:
        out = list(self.errors)
        for entry in self.entries:
            if not entry.ok:
                out.append(f"{self.fn}.{entry.side}[{entry.entry_id}]: "
                           f"{entry.status} -- {entry.detail}")
        for offset in self.undeclared_writes:
            out.append(f"{self.fn}: store at {offset} is not in the write set "
                       f"(under-declared write set: the spec would under-check)")
        for offset in self.undeclared_reads:
            out.append(f"{self.fn}: load at {offset} is not in the read set "
                       f"(the replay would read sentinel-poisoned memory)")
        if self.unacknowledged_local_writes:
            out.append(f"{self.fn}: stores through a non-parameter base "
                       f"(allocator return / stack) are not acknowledged in "
                       f"uncapturable_writes")
        return out


def _reg_to_param(plan: dict[str, Any],
                  registry_entry: dict[str, Any] | None = None) -> dict[str, int]:
    """{'r3': 1, 'r5': 9, ...} -- which parameter each argument register holds.

    The mapping is NOT r3->param_1 in general: FPR-passed doubles consume no
    GPR (FUN_800c4468 lands param_9 in r5), and 64-bit ints take a GPR pair.

    The REGISTRY is the authority when available, deliberately: deriving the
    mapping from the plan's own `args` would let a model rename its way out of
    validation. The plan's arg list is only a fallback, and a hand-authored plan
    that names its arguments semantically ("actor", "self", "owner") rather than
    param_N falls back further to positional order -- which is why the registry
    path is preferred.
    """
    if registry_entry is not None:
        args, _ = plan_args(registry_entry.get("params") or [])
        mapping: dict[str, int] = {}
        for arg in args:
            match = re.match(r"param_(\d+)", str(arg.get("name") or ""))
            if match:
                mapping[str(arg["reg"])] = int(match.group(1))
        if mapping:
            return mapping
    mapping = {}
    plan_arg_list = plan.get("args") or []
    for index, arg in enumerate(plan_arg_list, start=1):
        match = re.match(r"param_(\d+)", str(arg.get("name") or ""))
        mapping[str(arg.get("reg"))] = int(match.group(1)) if match else index
    return mapping


@dataclass
class ParsedAddr:
    """What an address expression claims, structurally."""

    form: str                       # "direct" | "chase" | "absolute" |
                                    # "absolute_strided" | "register"
    param: int | None = None
    offset: int = 0
    base_addr: int | None = None
    inner_loads: list[tuple[int, int]] = field(default_factory=list)
    error: str = ""


_INNER_LOAD = re.compile(r"\[\s*(r\d+)\s*(?:\+\s*(0x[0-9a-fA-F]+|\d+))?\s*\]")


def parse_addr(expr: str, reg_param: dict[str, int]) -> ParsedAddr:
    """Structure of a plan address expression, in the capture tool's grammar."""
    text = " ".join(str(expr).split())
    if not text:
        return ParsedAddr("", error="empty address expression")
    if not EXPR_TOKEN.match(text):
        return ParsedAddr("", error=f"illegal characters for capture_oracle: {text!r}")

    inner: list[tuple[int, int]] = []
    unknown: list[str] = []

    def swallow(match: re.Match[str]) -> str:
        reg = match.group(1)
        offset = int(match.group(2), 0) if match.group(2) else 0
        param = reg_param.get(reg)
        if param is None:
            unknown.append(reg)
            return " INNER "
        inner.append((param, offset))
        return f" INNER{len(inner) - 1} "

    outer = _INNER_LOAD.sub(swallow, text)
    if unknown:
        return ParsedAddr("", inner_loads=inner,
                          error=f"register(s) {sorted(set(unknown))} are not "
                                f"declared arguments of this function")

    for reg in re.findall(r"\br\d+\b", outer):
        if reg not in reg_param:
            return ParsedAddr("", inner_loads=inner,
                              error=f"register {reg} is not a declared argument")

    # absolute (possibly strided by an inner load): a MEM1 literal is the base
    literals = [int(tok, 0) for tok in re.findall(r"0x[0-9a-fA-F]+", outer)]
    mem1 = [value for value in literals if _MEM1_LO <= value < _MEM1_HI]
    if mem1:
        return ParsedAddr("absolute_strided" if inner else "absolute",
                          base_addr=mem1[0], inner_loads=inner)

    # chase: the outer expression is INNERn (+ constant)
    chase = re.match(r"^\s*INNER(\d+)\s*(?:\+\s*(0x[0-9a-fA-F]+|\d+))?\s*$", outer)
    if chase:
        param, base_offset = inner[int(chase.group(1))]
        offset = int(chase.group(2), 0) if chase.group(2) else 0
        return ParsedAddr("chase", param=param, offset=offset,
                          inner_loads=[(param, base_offset)])

    direct = re.match(r"^\s*(r\d+)\s*(?:\+\s*(0x[0-9a-fA-F]+|\d+))?\s*$", outer)
    if direct:
        return ParsedAddr("direct", param=reg_param[direct.group(1)],
                          offset=int(direct.group(2), 0) if direct.group(2) else 0,
                          inner_loads=inner)

    return ParsedAddr("", inner_loads=inner,
                      error=f"address expression shape not recognised: {text!r}")


def _normalise(text: str) -> str:
    return re.sub(r"\s+", " ", str(text or "")).strip()


def _citation_ok(entry: dict[str, Any], evidence: FunctionEvidence,
                 parsed: "ParsedAddr | None" = None) -> bool:
    """Is this entry's citation real?

    Two accepted forms, and the cheap one is also the stricter one:

    ``line``  a 1-based line number into the C block the prompt showed. The
              cited line must EXIST and must itself mention what the entry
              claims -- the offset (hex or decimal) or the ROM address. A number
              costs a couple of tokens where a copied source line costs ~60, and
              on this rig reply length is the binding constraint: the model's
              plan for a 44-line function stopped mid-``writes`` at 2.3 KB.

    ``evidence``  the source line copied verbatim, checked by containment. Kept
              because it needs no line numbering and reads well in the stored
              plan.
    """
    number = entry.get("line")
    if isinstance(number, str) and number.strip().lstrip("Ll").isdigit():
        number = int(number.strip().lstrip("Ll"))
    if isinstance(number, int):
        if not (1 <= number <= len(evidence.lines)):
            return False
        text = evidence.lines[number - 1]
        if parsed is None:
            return bool(text.strip())
        return _line_mentions(text, parsed)

    want = _normalise(entry.get("evidence", ""))
    if not want:
        return False
    return want in _normalise(evidence.body)


def _line_mentions(text: str, parsed: "ParsedAddr") -> bool:
    """Does this source line actually name what the entry claims?"""
    if parsed.form in ("absolute", "absolute_strided") and parsed.base_addr is not None:
        tail = f"{parsed.base_addr:08x}"
        return tail.lower() in text.lower() or _has_number(text, parsed.base_addr)
    if parsed.offset == 0:
        return "param_" in text or "*" in text
    return _has_number(text, parsed.offset)


def _has_number(text: str, value: int) -> bool:
    """The value written as Ghidra writes it: hex, decimal, or negative-MEM1."""
    forms = {f"0x{value:x}", f"0x{value:X}", str(value)}
    if value >= _MEM1_LO:
        forms.add(f"-0x{((1 << 32) - value):x}")
    lowered = text.lower()
    return any(form.lower() in lowered for form in forms)


def _covers(entries: list[dict[str, Any]], reg_param: dict[str, int],
            param: int, offset: int, width: int) -> bool:
    """True when some declared entry's byte range covers [offset, offset+width)
    on the same parameter. Range-based on purpose: the hand-authored gold plan
    coalesces the adjacent stores at +0x58/+0x5c into one 8-byte entry."""
    for entry in entries:
        parsed = parse_addr(entry.get("addr", ""), reg_param)
        if parsed.form != "direct" or parsed.param != param:
            continue
        entry_width = int(entry.get("width") or 0)
        if parsed.offset <= offset and offset + width <= parsed.offset + entry_width:
            return True
    return False


def _shadows_a_write(writes: list[dict[str, Any]], reg_param: dict[str, int],
                     param: int | None, offset: int, width: int) -> bool:
    """True when [offset, offset+width) lies inside a declared write on `param`."""
    for entry in writes:
        parsed = parse_addr(entry.get("addr", ""), reg_param)
        if parsed.form != "direct" or parsed.param != param:
            continue
        entry_width = int(entry.get("width") or 0)
        if parsed.offset <= offset and offset + width <= parsed.offset + entry_width:
            return True
    return False


def write_pre_state_gaps(plan: dict[str, Any], reg_param: dict[str, int],
                         evidence: FunctionEvidence | None = None) -> list[str]:
    """Declared writes whose PRE-state the read set does not cover.

    A generated spec cannot be emitted with any of these outstanding: on a call
    that takes a branch which does not store, the replay would compare its
    poisoned arena byte against the console's untouched pre-value and report a
    divergence that is the spec's fault, not the unit's.
    """
    gaps: list[str] = []
    reads = list(plan.get("reads") or [])
    unconditional = evidence.unconditional_writes() if evidence else []
    for entry in plan.get("writes") or []:
        parsed = parse_addr(entry.get("addr", ""), reg_param)
        if parsed.form != "direct":
            continue
        width = int(entry.get("width") or 0)
        if _covers(reads, reg_param, parsed.param, parsed.offset, width):
            continue
        # A store that runs on EVERY call overwrites whatever was there, so its
        # pre-state is never compared and never needs seeding.
        if any(store.param == parsed.param
               and store.offset <= parsed.offset
               and parsed.offset + width <= store.offset + (store.width or 1)
               for store in unconditional):
            continue
        gaps.append(f"param_{parsed.param}+{parsed.offset:#x} (w{width})")
    return gaps


def validate_plan(plan: dict[str, Any], evidence: FunctionEvidence,
                  registry_entry: dict[str, Any] | None = None,
                  *, require_citations: bool = True) -> PlanValidation:
    """Check a plan against the static evidence index. Fail-closed.

    `require_citations` is the derived-plan contract: every entry must carry the
    source line it came from. It is switched OFF when auditing the pre-existing
    HAND-authored plans, which predate the citation requirement -- their read/
    write sets are still checked in full, only the paper trail is waived.
    """
    result = PlanValidation(fn=str(plan.get("fn") or evidence.name))
    reg_param = _reg_to_param(plan, registry_entry)
    reads = list(plan.get("reads") or [])
    writes = list(plan.get("writes") or [])

    if not reg_param and (reads or writes):
        result.errors.append("plan declares no argument registers but has a "
                             "non-empty read/write set")

    seen_ids: set[str] = set()
    param_accesses = {
        (a.param, a.offset, a.direction) for a in evidence.accesses
        if a.kind == "param" and a.param is not None
    }
    chase_accesses = {
        (a.param, a.offset) for a in evidence.accesses
        if a.kind == "chase" and a.param is not None
    }
    absolute_accesses = evidence.absolute_addrs()

    for side, entries in (("read", reads), ("write", writes)):
        for entry in entries:
            entry_id = str(entry.get("id") or "")
            verdict = lambda status, detail="": EntryVerdict(  # noqa: E731
                side, entry_id or "<no id>", status, detail)

            if not entry_id or not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", entry_id):
                result.entries.append(verdict("malformed", "id is missing or not an identifier"))
                continue
            if entry_id in seen_ids:
                result.entries.append(verdict("malformed", "duplicate entry id"))
                continue
            seen_ids.add(entry_id)

            width = entry.get("width")
            if not isinstance(width, int) or width not in _LEGAL_WIDTHS:
                result.entries.append(verdict("malformed", f"width {width!r} is not capturable"))
                continue

            # The address is parsed BEFORE the citation is judged, because a
            # line-number citation is checked against what the entry claims:
            # the cited line has to mention that offset or address itself.
            parsed = parse_addr(entry.get("addr", ""), reg_param)
            if parsed.error:
                result.entries.append(verdict("malformed", parsed.error))
                continue

            if require_citations and not _citation_ok(entry, evidence, parsed):
                cited = entry.get("line", _normalise(entry.get("evidence")))
                result.entries.append(verdict(
                    "citation_missing",
                    f"citation {str(cited)[:90]!r} does not point at a line of "
                    f"{evidence.name}'s C that mentions {entry.get('addr')!r}"))
                continue

            # every inner load must itself be a real load in the C
            bad_inner = [
                f"[param_{p}+{o:#x}]" for p, o in parsed.inner_loads
                if (p, o, "read") not in param_accesses
                and (p, o, "ptr") not in param_accesses
            ]
            if bad_inner:
                result.entries.append(verdict(
                    "ungrounded",
                    f"pointer chase through {', '.join(bad_inner)}, which the C never loads"))
                continue

            if parsed.form in ("absolute", "absolute_strided"):
                if parsed.base_addr in absolute_accesses:
                    result.entries.append(verdict("grounded",
                                                  f"ROM address {parsed.base_addr:#x} named by the C"))
                else:
                    result.entries.append(verdict(
                        "ungrounded_rom_const",
                        f"ROM address {parsed.base_addr:#x} is a plausible constant but "
                        f"this function's C never names it (a callee's constant, or "
                        f"invented) -- needs a human"))
                continue

            if parsed.form == "chase":
                if (parsed.param, parsed.offset) in chase_accesses:
                    result.entries.append(verdict("grounded_chase"))
                else:
                    result.entries.append(verdict(
                        "ungrounded",
                        f"no load at [param_{parsed.param}]+{parsed.offset:#x} in the C"))
                continue

            # direct parameter access
            want = "write" if side == "write" else "read"
            # A read entry that exactly shadows a declared write is the
            # write's PRE-STATE, and it is not optional. The C may store to an
            # offset only on some branches (`if (...) { *(p+0x170) = 1; }`);
            # on the branches that do not store, the console's post-state at
            # that offset is its PRE-state -- which the replay can only know if
            # the capture recorded it. Without this entry the arena still holds
            # the poison byte there and every non-storing case reports a false
            # divergence. Grounded by the write it shadows, not by a load.
            if side == "read" and _shadows_a_write(
                    writes, reg_param, parsed.param, parsed.offset, width):
                result.entries.append(verdict(
                    "grounded_write_pre",
                    "pre-state of a declared write (needed for the branches "
                    "that do not store)"))
                continue
            if (parsed.param, parsed.offset, want) in param_accesses:
                result.entries.append(verdict("grounded"))
            elif (parsed.param, parsed.offset, "ptr") in param_accesses:
                result.entries.append(verdict(
                    "grounded_ptr",
                    "justified only as an interior pointer handed to a callee "
                    "(direction is the callee's, not the unit's)"))
            elif (parsed.param, parsed.offset, "read" if want == "write" else "write") \
                    in param_accesses:
                result.entries.append(verdict(
                    "ungrounded",
                    f"param_{parsed.param}+{parsed.offset:#x} is accessed by the C, but "
                    f"only as a {'read' if want == 'write' else 'write'} -- declared as a {want}"))
            else:
                result.entries.append(verdict(
                    "ungrounded",
                    f"the C never accesses param_{parsed.param}+{parsed.offset:#x}"))

    # ---- coverage: the direction that protects against under-checking -------
    for access in evidence.direct_param_writes():
        width = access.width or 1
        if not _covers(writes, reg_param, access.param, access.offset, width):
            result.undeclared_writes.append(
                f"param_{access.param}+{access.offset:#x} (w{width}, line {access.line})")
    unconditional = evidence.unconditional_writes()
    for access in evidence.direct_param_reads():
        width = access.width or 1
        if _covers(reads, reg_param, access.param, access.offset, width):
            continue
        # A load of memory this function ALREADY stored to unconditionally,
        # earlier in the body, does not need to be seeded from the console: the
        # replay's own earlier store supplies it. This is why the gold plan for
        # FUN_800c4308 declares +0x180 as a write and not as a read.
        if any(
            store.param == access.param
            and store.line < access.line
            and store.offset <= access.offset
            and access.offset + width <= store.offset + (store.width or 1)
            for store in unconditional
        ):
            continue
        result.undeclared_reads.append(
            f"param_{access.param}+{access.offset:#x} (w{width}, line {access.line})")

    if evidence.has_local_base_writes() and not plan.get("uncapturable_writes"):
        result.unacknowledged_local_writes = True

    return result


# ------------------------------------------------------------------- prompting

SYSTEM_PROMPT = (
    "You derive MEMORY ACCESS SETS from Ghidra-decompiled GameCube PowerPC C. "
    "You are precise, literal, and you never invent an offset. Every entry you "
    "emit must be readable off ONE line of the C you were given. If the C does "
    "not show it, you do not declare it. You reply with ONE json code block and "
    "nothing else."
)

# One complete worked example. Small on purpose: it shows the schema, the
# citation requirement, the ROM-constant form and the read/write split without
# spending prompt budget the 27B model needs for the target function.
_GOLD_C = """void FUN_800c42bc(int param_1)

{
  float fVar1;
  float fVar2;
  float fVar3;

  fVar3 = FLOAT_80438744;
  fVar2 = *(float *)(param_1 + 0x184) - *(float *)(param_1 + 0x44);
  fVar1 = fVar2 / FLOAT_8043875c;
  *(float *)(param_1 + 0x184) = fVar2;
  *(float *)(param_1 + 0x60) = fVar1;
  if (fVar1 <= fVar3) {
    zz_00c42a8_(param_1);
  }
  return;
}"""

_GOLD_JSON = """{
  "reads": [
    {"id": "a184_pre", "addr": "r3+0x184", "width": 4, "line": 9},
    {"id": "a44", "addr": "r3+0x44", "width": 4, "line": 9},
    {"id": "f_8744", "addr": "0x80438744", "width": 4, "line": 8},
    {"id": "f_875c", "addr": "0x8043875c", "width": 4, "line": 10}
  ],
  "writes": [
    {"id": "w184", "addr": "r3+0x184", "width": 4, "line": 11},
    {"id": "w60", "addr": "r3+0x60", "width": 4, "line": 12}
  ],
  "uncapturable_writes": [],
  "callee_owned": ["zz_00c42a8_ is an external ROM callee; anything it stores is not this function's write set"],
  "note": "Per-frame decrement of the remaining-distance field and the derived frames-to-arrival estimate."
}"""

RULES = """RULES (each one exists because breaking it produced a wrong capture):

1. ADDRESSES ARE REGISTER EXPRESSIONS. Use the argument registers listed for
   this function, never `param_N`. Allowed: hex literals, r0-r31, + - * & | << >>
   parentheses, and `[e]` meaning "the big-endian 32-bit word loaded from
   address e". Nothing else -- no C, no casts, no symbol names.
2. WIDTH IS THE CAST'S WIDTH. byte/undefined1/char = 1, ushort/undefined2 = 2,
   int/uint/float/undefined4 = 4, double/undefined8 = 8. A pointer handed to a
   vector helper (PSVECAdd, PSVECSubtract, PSVECNormalize, PSQUATScale,
   PSVECSquareDistance) spans a vec3 = 12 bytes; a 3x4 matrix = 48 bytes.
3. ROM GLOBALS CARRY THEIR ADDRESS IN THEIR NAME. `FLOAT_80438744` is the
   4-byte float at 0x80438744; `DOUBLE_80438748` is the 8-byte double at
   0x80438748; `DAT_8030316c` is at 0x8030316c. Declare them as absolute
   addresses.
4. A NEGATIVE MEM1 LITERAL IS A TABLE BASE. `(float *)(iVar3 + -0x7fcfceb8)` is
   address 0x80303148 (two's complement). If an index local was computed like
   `iVar3 = (uint)*(byte *)(param_1 + 0x11) * 0x44`, write the strided form:
   "0x80303148 + ((([r3+0x11]) >> 24) * 0x44)". The `>> 24` is REQUIRED: `[e]`
   loads a big-endian word, so a byte at offset 0x11 is that word's top byte.
5. OFFSETS MAY BE DECIMAL. `*(uint *)(param_1 + 200)` is offset 0xc8.
6. A LOCAL HOLDING A LOADED POINTER IS A CHASE. If `uVar4 = *(uint *)(param_1 +
   200);` and later `*(undefined4 *)(uVar4 + 100)`, that read is
   "[r3+0xc8]+0x64". Mark it "optional": true, because the pointer can be null
   on some calls.
7. DECLARE EVERY DIRECT STORE. If the C stores to `param_1 + X`, it MUST be in
   `writes`. A missing store makes the verification compare fewer bytes and
   pass everything -- the worst possible outcome.
8. DO NOT DECLARE WHAT A CALLEE OWNS. Memory that only an external `zz_*`
   callee writes is not this function's write set. Say so in `callee_owned`.
9. STORES THROUGH A LOCAL POINTER ARE NOT CAPTURABLE. If the base is an
   allocator's return value or a stack buffer rather than an argument register,
   list it as text in `uncapturable_writes` -- never as a `writes` entry.
10. EVERY entry needs a `line` field: the NUMBER of the source line it comes
    from, as numbered in the C below. The line you name must itself contain
    that offset or that address, or the entry is discarded. Give the number
    only -- never copy the line text.
11. BE COMPLETE, AND BE BRIEF. Emit every entry and nothing else: no prose, no
    quoted source, no commentary between entries. A reply that runs out of room
    before the `writes` array is closed is thrown away in full, so spend the
    space on entries."""


def _numbered(text: str) -> str:
    """The C as the prompt shows it: one 1-based number per line, so an entry
    can cite a line by NUMBER instead of copying it."""
    return "\n".join(f"{index:4d}  {line}"
                     for index, line in enumerate(text.splitlines(), 1))


def build_prompt(fn: str, body: str, args: list[dict[str, str]],
                 prototype: str, unsampled: list[str]) -> str:
    reg_lines = "\n".join(
        f"  {arg['reg']} = {arg['name']}" for arg in args) or "  (none)"
    skipped = "\n".join(f"  {item}" for item in unsampled) or "  (none)"
    return (
        f"{RULES}\n\n"
        f"SCHEMA -- reply with exactly this JSON shape:\n"
        f"```json\n{_GOLD_JSON}\n```\n\n"
        f"That example is the correct answer for this function (the `line` "
        f"numbers above refer to these numbers):\n"
        f"```c\n{_numbered(_GOLD_C)}\n```\n\n"
        f"=== NOW DO THIS FUNCTION ===\n\n"
        f"Prototype: {prototype}\n"
        f"Argument registers (use THESE, not param_N):\n{reg_lines}\n"
        f"Arguments the capture tool cannot sample (ignore them):\n{skipped}\n\n"
        f"```c\n{_numbered(body)}\n```\n\n"
        f"Derive the typed read set and write set for {fn}. Reply with ONE json "
        f"code block in the schema above and no other text."
    )


JSON_BLOCK = re.compile(r"```(?:json)?\s*\n(.*?)```", re.S)


def parse_reply(reply: str) -> tuple[dict[str, Any] | None, str]:
    """(payload, shape-description-on-failure) from a model reply."""
    text = reply or ""
    candidates = JSON_BLOCK.findall(text)
    if not candidates:
        # an unclosed fence is common and recoverable (same lesson as
        # port_wasm_units._compile_fix)
        opened = re.search(r"```(?:json)?[ \t]*\n", text)
        if opened and text.count("```") == 1:
            candidates = [text[opened.end():]]
        else:
            stripped = text.strip()
            if stripped.startswith("{"):
                candidates = [stripped]
    for candidate in candidates:
        try:
            payload = json.loads(candidate)
        except json.JSONDecodeError:
            # tolerate a trailing comma / truncated tail by trimming to the last }
            end = candidate.rfind("}")
            if end < 0:
                continue
            try:
                payload = json.loads(candidate[: end + 1])
            except json.JSONDecodeError:
                continue
        if isinstance(payload, dict):
            return payload, ""
    body = text.strip()
    return None, (f"len={len(body)} fences={body.count('```')} "
                  f"head={body[:200]!r}" if body else "empty reply")


# ------------------------------------------------------------- plan assembly


def assemble_plan(unit: str, fn: str, registry_entry: dict[str, Any],
                  payload: dict[str, Any]) -> dict[str, Any]:
    """A capture plan in exactly the shape capture_oracle.py consumes."""
    args, skipped = plan_args(registry_entry.get("params") or [])
    params = ", ".join(registry_entry.get("params") or []) or "void"
    chunk = registry_entry.get("chunk_file", "")
    line_range = registry_entry.get("line_range") or []
    where = (f"  /* {Path(chunk).name} {line_range[0]}-{line_range[1]}, staged unit.c */"
             if chunk and len(line_range) == 2 else "")

    def clean(entries: Any) -> list[dict[str, Any]]:
        out = []
        for entry in entries or []:
            if not isinstance(entry, dict):
                continue
            item: dict[str, Any] = {
                "id": entry.get("id"),
                "addr": entry.get("addr"),
                "width": entry.get("width"),
            }
            if entry.get("optional"):
                item["optional"] = True
            # the citation is kept IN the plan: it is the audit trail that makes
            # a machine-derived plan reviewable at a glance
            if entry.get("evidence"):
                item["evidence"] = _normalise(entry["evidence"])
            if entry.get("line") is not None:
                item["line"] = entry["line"]
            out.append(item)
        return out

    plan: dict[str, Any] = {
        "unit": unit,
        "fn": fn,
        "addr": registry_entry["address"],
        "prototype": f"{registry_entry.get('return_type', 'void')} {fn}({params}){where}",
        "derived_by": DERIVED_BY,
        "note": _normalise(payload.get("note", "")) or
                "LLM-derived read/write sets, statically validated against the "
                "unit's verbatim C (src/port_plan_derive.py).",
        "args": args,
        "reads": clean(payload.get("reads")),
        "ret": plan_ret(registry_entry),
        "writes": clean(payload.get("writes")),
    }
    if skipped:
        plan["unsampled_args"] = skipped
    if payload.get("uncapturable_writes"):
        plan["uncapturable_writes"] = [
            _normalise(item) for item in payload["uncapturable_writes"]
            if isinstance(item, str)
        ]
    if payload.get("callee_owned"):
        plan["callee_owned"] = [
            _normalise(item) for item in payload["callee_owned"]
            if isinstance(item, str)
        ]
    return plan


# ------------------------------------------------------------------- the run


@dataclass
class DerivationResult:
    unit: str
    fn: str
    verdict: str                  # validated | flagged | refused | error
    plan: dict[str, Any] | None = None
    validation: PlanValidation | None = None
    reasons: list[str] = field(default_factory=list)
    raw_reply: str = ""
    attempts: int = 0


class PlanDeriver:
    """Derive + validate capture plans for a staged unit's exports."""

    def __init__(self, repo_root: Path, llm: Any = None, max_tokens: int = 3072,
                 attempts: int = 2) -> None:
        self.repo_root = Path(repo_root)
        self._llm = llm
        self.max_tokens = max_tokens
        self.attempts = attempts
        self._registry: dict[str, dict[str, Any]] | None = None

    # -- inputs ------------------------------------------------------------

    def registry(self) -> dict[str, dict[str, Any]]:
        if self._registry is None:
            self._registry = load_registry_functions(self.repo_root)
        return self._registry

    def unit_c(self, unit: str) -> str:
        return (self.repo_root / STAGING_RELPATH / unit / "unit.c").read_text(
            encoding="utf-8", errors="replace")

    def bodies(self, unit: str) -> dict[str, str]:
        return split_unit_functions(self.unit_c(unit))

    # -- model -------------------------------------------------------------

    def llm(self) -> Any:
        if self._llm is None:
            from src.config import get_config
            from src.custom_api_client import CustomAPIClient

            self._llm = CustomAPIClient(get_config().custom_api)
        return self._llm

    def _ask(self, prompt: str, phase: str) -> str:
        import os

        disable_thinking = os.getenv("OGHIDRA_PORT_DISABLE_THINKING", "1").lower() \
            not in ("0", "false", "no")
        # SAMPLING IS NOT THE COMPILE-FIX PROFILE, and that difference is
        # load-bearing. Measured on this rig 2026-08-29: with the compile-fix
        # profile's presence_penalty=1.5, the model emitted two complete plan
        # entries and then stopped mid-JSON with finish_reason="stop" after 519
        # seconds. A presence penalty punishes tokens that have already appeared
        # -- which for this task is every structural key ("id", "addr", "width",
        # "evidence") that MUST repeat once per entry. It reads as a truncation
        # bug and is actually the sampler doing what it was told. Structured
        # extraction wants no presence penalty and a low temperature; prose C
        # repair wants the opposite.
        kwargs: dict[str, Any] = {
            "temperature": float(os.getenv("OGHIDRA_PLAN_DERIVE_TEMPERATURE", "0.2")),
            "top_p": float(os.getenv("OGHIDRA_PLAN_DERIVE_TOP_P", "0.9")),
            "top_k": int(os.getenv("OGHIDRA_PLAN_DERIVE_TOP_K", "20")),
            "presence_penalty": float(
                os.getenv("OGHIDRA_PLAN_DERIVE_PRESENCE_PENALTY", "0.0")),
        }
        if disable_thinking:
            kwargs["chat_template_kwargs"] = {"enable_thinking": False}
        return self.llm().generate(
            prompt=prompt,
            system_prompt=SYSTEM_PROMPT + (" /no_think" if disable_thinking else ""),
            max_tokens=self.max_tokens,
            phase=phase,
            # stream for the same two reasons as the compile-fix loop: mid-request
            # liveness telemetry, and a read timeout that is time-between-bytes.
            stream_callback=lambda _t, _e: None,
            **kwargs,
        )

    # -- one export --------------------------------------------------------

    def derive_function(self, unit: str, fn: str, body: str) -> DerivationResult:
        entry = self.registry().get(fn)
        if entry is None:
            return DerivationResult(unit, fn, "error",
                                    reasons=[f"{fn} is absent from the oracle registry"])
        args, skipped = plan_args(entry.get("params") or [])
        params = ", ".join(entry.get("params") or []) or "void"
        prototype = f"{entry.get('return_type', 'void')} {fn}({params})"
        evidence = analyse_function(fn, body, entry.get("params") or [])
        prompt = build_prompt(fn, body, args, prototype, skipped)

        last: DerivationResult | None = None
        for attempt in range(1, self.attempts + 1):
            try:
                reply = self._ask(prompt, f"plan_derive:{unit}:{fn}")
            except Exception as exc:  # transport / server-side failure
                last = DerivationResult(unit, fn, "error", attempts=attempt,
                                        reasons=[f"model call failed: {exc}"])
                continue
            payload, shape = parse_reply(reply)
            if payload is None:
                last = DerivationResult(unit, fn, "error", attempts=attempt,
                                        raw_reply=reply,
                                        reasons=[f"no usable json block ({shape})"])
                continue
            plan = assemble_plan(unit, fn, entry, payload)
            validation = validate_plan(plan, evidence, entry)
            result = DerivationResult(unit, fn, validation.verdict, plan, validation,
                                      validation.reasons(), reply, attempt)
            if validation.verdict in ("validated", "flagged"):
                return result
            last = result
        return last or DerivationResult(unit, fn, "error",
                                        reasons=["no attempt produced a reply"])

    def derive_unit(self, unit: str, only: list[str] | None = None
                    ) -> list[DerivationResult]:
        out: list[DerivationResult] = []
        for fn, body in self.bodies(unit).items():
            if only and fn not in only:
                continue
            out.append(self.derive_function(unit, fn, body))
        return out


# --------------------------------------------------- model-free derivation

# An indexed ROM table (`*(float *)(&DAT_8030316c + iVar3)`): the row the
# console read depends on a runtime index, so the plan needs a strided address
# expression AND the index's provenance. That is derivation, not extraction --
# the static path refuses it and leaves the function to the model.
_INDEXED_GLOBAL = re.compile(
    r"[&(]\s*_?[A-Z]+_(?:8|9)[0-9a-fA-F]{7}\s*\)?\s*(?:\+\s*[A-Za-z_]|\[)"
)


def derive_plan_statically(unit: str, fn: str, registry_entry: dict[str, Any],
                           evidence: FunctionEvidence
                           ) -> tuple[dict[str, Any] | None, str]:
    """A capture plan built from the static index alone -- no model.

    Worth having for one reason the corpus survey makes plain: the exports whose
    SPEC can be generated (no callees at all) are exactly the exports whose plan
    the static pass already determines completely -- every access is a direct,
    typed, parameter-relative load or store with the cast width right there in
    the source. Asking a model to restate that adds a hallucination surface and
    no information.

    Returns (plan, "") or (None, reason). The refusals are the cases where real
    derivation is needed: an indexed ROM table, a pointer chase whose object
    layout has to be reasoned about, or a store through a non-argument base.
    """
    if real_callee_names(evidence):
        return None, "function calls out; widths of callee-passed buffers need derivation"
    if evidence.indirect_calls:
        return None, "dispatches through a ROM function-pointer table (the replay traps)"
    if _INDEXED_GLOBAL.search(evidence.body):
        return None, "reads a runtime-indexed ROM table (needs a strided address expression)"
    if evidence.has_local_base_writes():
        return None, "stores through a non-argument base the capture cannot address"

    args, skipped = plan_args(registry_entry.get("params") or [])
    param_reg = {}
    for arg in args:
        match = re.match(r"param_(\d+)", str(arg.get("name") or ""))
        if match:
            param_reg.setdefault(int(match.group(1)), arg["reg"])

    reads: list[dict[str, Any]] = []
    writes: list[dict[str, Any]] = []
    seen: set[tuple] = set()
    unconditional = evidence.unconditional_writes()

    for access in evidence.direct_param_writes():
        reg = param_reg.get(access.param)
        if reg is None:
            return None, f"param_{access.param} is not in an argument register"
        key = ("w", access.param, access.offset)
        if key in seen:
            continue
        seen.add(key)
        writes.append({
            "id": f"w{access.param}_{access.offset:x}",
            "addr": f"{reg}+0x{access.offset:x}" if access.offset else reg,
            "width": access.width or 4,
            "evidence": _normalise(access.text),
        })

    # Every declared write also needs its PRE-state read, so a branch that does
    # not store leaves the replay comparing the console's real prior bytes
    # instead of arena poison.
    for entry in list(writes):
        parsed_param = int(entry["id"].split("_")[0][1:])
        offset = int(entry["addr"].split("+")[-1], 16) if "+" in entry["addr"] else 0
        key = ("r", parsed_param, offset)
        if key in seen:
            continue
        seen.add(key)
        reads.append({
            "id": f"pre{parsed_param}_{offset:x}",
            "addr": entry["addr"],
            "width": entry["width"],
            "evidence": entry["evidence"],
        })

    for access in evidence.direct_param_reads():
        reg = param_reg.get(access.param)
        if reg is None:
            return None, f"param_{access.param} is not in an argument register"
        width = access.width or 4
        if any(store.param == access.param and store.line < access.line
               and store.offset <= access.offset
               and access.offset + width <= store.offset + (store.width or 1)
               for store in unconditional):
            continue  # supplied by the function's own earlier unconditional store
        key = ("r", access.param, access.offset)
        if key in seen:
            continue
        seen.add(key)
        reads.append({
            "id": f"r{access.param}_{access.offset:x}",
            "addr": f"{reg}+0x{access.offset:x}" if access.offset else reg,
            "width": width,
            "evidence": _normalise(access.text),
        })

    for access in evidence.accesses:
        if access.kind != "absolute" or access.direction != "read":
            continue
        key = ("a", access.addr)
        if key in seen:
            continue
        seen.add(key)
        if not access.width:
            return None, f"ROM constant {access.addr:#x} has no width in the C"
        reads.append({
            "id": f"c_{access.addr:08x}",
            "addr": f"0x{access.addr:08x}",
            "width": access.width,
            "evidence": _normalise(access.text),
        })

    if not writes:
        return None, "no capturable store: a spec built on this would compare nothing"

    payload = {
        "reads": reads, "writes": writes,
        "note": (f"Read/write sets extracted STATICALLY from the verbatim C by "
                 f"src/port_c_evidence.py -- no model involved. Every entry is a "
                 f"direct, typed, argument-relative access with its cast width "
                 f"taken from the source line cited in each entry."),
    }
    return assemble_plan(unit, fn, registry_entry, payload), ""


def real_callee_names(evidence: FunctionEvidence) -> set[str]:
    from src.port_spec_emit import real_callees

    return real_callees(evidence)


def plan_output_path(repo_root: Path, unit: str, fn: str) -> Path:
    return Path(repo_root) / PLANS_RELPATH / f"{unit}.{fn}.json"


def write_plan(repo_root: Path, result: DerivationResult, *,
               overwrite_authored: bool = False) -> tuple[bool, str]:
    """Write a derived plan. A hand-authored plan (no generated/derived marker)
    is NEVER overwritten -- authored sets are strictly richer."""
    if result.plan is None or result.verdict not in ("validated", "flagged"):
        return False, f"not written ({result.verdict})"
    path = plan_output_path(repo_root, result.unit, result.fn)
    if path.is_file() and not overwrite_authored:
        try:
            existing = json.loads(path.read_text(encoding="utf-8-sig"))
        except (json.JSONDecodeError, OSError):
            existing = None
        if isinstance(existing, dict) and not (
            existing.get("generated_by") or existing.get("derived_by")
        ):
            return False, "hand-authored plan kept"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(result.plan, indent=2) + "\n",
                    encoding="utf-8", newline="\n")
    return True, str(path)
