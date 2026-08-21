"""Continuous assembly gate (design section 2.13 [V4-11], tranche T2b).

Every mechanism in the compile-fix loop keeps units *individually* green;
until this gate nothing ever linked two of them together -- G1's first
executable evidence sat behind a future assembly workstream. This module makes
composition continuous: on every green, the last N green/staged units are
linked in ONE emcc invocation (merged headers, shared flat arena, deduplicated
externs) and the result is instantiation-smoke-tested under node. The gate
passes iff the link produces a loadable wasm -- no behaviour is asserted;
behaviour stays the oracle tier's job.

Two roles, one mechanism (design section 2.13):
  1. The interim G1 metric: "progress toward a buildable game" is the largest
     N this gate has passed, not a count of individually-green units whose
     mutual composability is conjecture.
  2. The empirical conflict detector the T2c registry's tier ladder depends
     on: harvest-time comparison catches disagreements units wrote down; the
     merge + the linker catch the ones they didn't.

Merge precedence (section 2.11 [V4-5], applied registry-less): with no
registry there are no authoritative entries yet, so EVERY divergence between
two units' declarations of the same symbol is a contested conflict and fails
the merge loudly rather than picking a winner silently. Identical
(whitespace/comment-normalized) declarations keep exactly one copy.

On failure the gate pages (events emitted by the caller) and files conflict
records against the implicated symbols in a tracked ledger
(research/decomp/data/assembly-gate.json) -- the cross-unit reconciliation
report of section 3, generated as a by-product instead of by archaeology.

This module is deliberately import-light (only src.port_chunk_workflow for
atomic JSON I/O): src/port_wasm_units.py imports it, never the reverse, and
every emcc/node dependency is injected as a runner callable so the whole gate
is testable offline.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from src.port_chunk_workflow import atomic_write_json, utc_now

# Rolling window size: link the last N green/staged units on every green.
# Env-tunable without a code change; read at call time so tests can vary it.
DEFAULT_ASSEMBLY_N = 5


def assembly_window_size() -> int:
    try:
        return max(2, int(os.getenv("OGHIDRA_PORT_ASSEMBLY_N", str(DEFAULT_ASSEMBLY_N))))
    except ValueError:
        return DEFAULT_ASSEMBLY_N


GATE_LEDGER_SCHEMA = 1

# Conflict classes. The first two are the empirically expected classes for the
# current unit population (see docs/t2b-backfill-report.md):
#   - undefined8_fork: the PoC seed typedefs undefined8 as double (fp-trick
#     units) while the generator seed + SYSTEM_PROMPT mandate unsigned long
#     long; CONCAT44 forks with it (union bit-cast vs integer shift).
#   - collision_stub: two units disagree about the same callee/function --
#     divergent extern stub signatures, or the same function defined in more
#     than one unit.c.
CLASS_UNDEFINED8_FORK = "undefined8_fork"
CLASS_COLLISION_STUB = "collision_stub"
CLASS_DAT_DIVERGENCE = "dat_width_divergence"
CLASS_DECL_DIVERGENCE = "declaration_divergence"
CLASS_LINK_FAILURE = "link_failure"
CLASS_INSTANTIATION_FAILURE = "instantiation_failure"

# Statements that look like `name (...) {` but are control flow, not
# function definitions.
_C_KEYWORDS = {
    "if", "while", "for", "switch", "return", "do", "else", "sizeof",
    "defined", "union", "struct", "enum",
}

_COMMENT = re.compile(r"/\*.*?\*/|//[^\n]*", re.S)


def strip_comments(text: str) -> str:
    """Remove C comments, preserving line structure for the chunker."""
    return _COMMENT.sub(
        lambda m: "\n" * m.group(0).count("\n") if "\n" in m.group(0) else " ",
        text or "",
    )


def _logical_lines(text: str) -> list[str]:
    """Join backslash-continued lines (multi-line #define bodies)."""
    out: list[str] = []
    buffer = ""
    for line in text.split("\n"):
        stripped = line.rstrip()
        if stripped.endswith("\\"):
            buffer += stripped[:-1] + " "
            continue
        out.append(buffer + line)
        buffer = ""
    if buffer:
        out.append(buffer)
    return out


@dataclass
class HeaderChunk:
    """One declaration-level piece of a unit header."""

    kind: str  # macro | typedef | function_decl | function_def | var_decl |
    #            include | conditional | directive
    symbol: str | None
    text: str

    @property
    def normalized(self) -> str:
        return " ".join(self.text.split())


_GUARD_OPEN = re.compile(r"#\s*ifndef\s+([A-Za-z_]\w*)\s*$")
_DEFINE = re.compile(r"#\s*define\s+([A-Za-z_]\w*)")
# An include guard's #define is object-like and EMPTY (`#define GNT4_SHIM_H`,
# nothing after the name). A function-like or valued define under a leading
# `#ifndef X` is the conditional-definition idiom, not a guard -- misreading
# it as a guard silently DELETES the definition from the merge (review R1
# sub-bug).
_GUARD_DEFINE = re.compile(r"#\s*define\s+([A-Za-z_]\w*)\s*$")
# Line-anchored: every macro DEFINED anywhere inside a conditional block.
_DEFINE_IN_BLOCK = re.compile(r"^\s*#\s*define\s+([A-Za-z_]\w*)", re.M)
_TYPEDEF_PAREN = re.compile(r"\(\s*\**\s*([A-Za-z_]\w*)\s*\)")


def _typedef_symbol(text: str) -> str | None:
    body = " ".join(text.split()).rstrip(";")
    if "(" in body:
        match = _TYPEDEF_PAREN.search(body)
        if match:
            return match.group(1)
    identifiers = re.findall(r"[A-Za-z_]\w*", body.split("[")[0])
    return identifiers[-1] if len(identifiers) > 1 else None


def _c_chunk_symbol(text: str) -> tuple[str, str | None]:
    """Classify one brace/semicolon-terminated C chunk -> (kind, symbol)."""
    flat = " ".join(text.split())
    if flat.startswith("typedef"):
        return "typedef", _typedef_symbol(flat)
    paren = flat.find("(")
    brace = flat.find("{")
    if paren != -1 and (brace == -1 or paren < brace):
        head_ids = re.findall(r"[A-Za-z_]\w*", flat[:paren])
        symbol = head_ids[-1] if head_ids else None
        return ("function_def" if brace != -1 else "function_decl"), symbol
    body = flat.rstrip(";").split("=")[0]
    identifiers = re.findall(r"[A-Za-z_]\w*", body.split("[")[0])
    return "var_decl", identifiers[-1] if identifiers else None


def parse_header_chunks(text: str) -> list[HeaderChunk]:
    """Split a unit's gnt4_shim.h into declaration-level chunks.

    The outer include guard (``#ifndef X`` immediately followed by an
    object-like EMPTY ``#define X``, and its matching ``#endif``) is dropped
    -- the merged header carries its own guard. A function-like or valued
    define after ``#ifndef X`` is a conditional definition, never a guard.
    Inner conditional blocks are kept whole as single chunks. Note the generated headers legitimately carry content
    AFTER the guard's #endif (the auto-generated tail), so parsing continues
    past it.
    """
    lines = _logical_lines(strip_comments(text))
    chunks: list[HeaderChunk] = []
    guard_macro: str | None = None
    guard_depth = 0  # >0 while inside the outer guard's conditional scope
    index = 0
    while index < len(lines):
        line = lines[index]
        stripped = line.strip()
        if not stripped:
            index += 1
            continue
        if stripped.startswith("#"):
            guard_open = _GUARD_OPEN.match(stripped)
            if guard_macro is None and guard_open is not None:
                # Peek: an immediately-following #define of the same macro
                # makes this the include guard, not a real conditional.
                peek = index + 1
                while peek < len(lines) and not lines[peek].strip():
                    peek += 1
                if peek < len(lines):
                    define = _GUARD_DEFINE.match(lines[peek].strip())
                    if define and define.group(1) == guard_open.group(1):
                        guard_macro = guard_open.group(1)
                        guard_depth = 1
                        index = peek + 1
                        continue
            if re.match(r"#\s*(if|ifdef|ifndef)\b", stripped):
                if guard_depth > 0:
                    guard_depth += 1
                # A real conditional block: keep it whole.
                depth = 1
                block = [line]
                index += 1
                while index < len(lines) and depth > 0:
                    inner = lines[index].strip()
                    if re.match(r"#\s*(if|ifdef|ifndef)\b", inner):
                        depth += 1
                    elif re.match(r"#\s*endif\b", inner):
                        depth -= 1
                        if guard_depth > 0:
                            guard_depth -= 1
                    block.append(lines[index])
                    index += 1
                chunks.append(
                    HeaderChunk(kind="conditional", symbol=None, text="\n".join(block))
                )
                continue
            if re.match(r"#\s*endif\b", stripped):
                if guard_depth > 0:
                    guard_depth -= 1
                    index += 1
                    continue  # the guard's own #endif: dropped
                index += 1
                continue  # stray #endif: structurally meaningless post-strip
            if re.match(r"#\s*pragma\s+once\b", stripped):
                index += 1
                continue
            define = _DEFINE.match(stripped)
            if define:
                chunks.append(
                    HeaderChunk(kind="macro", symbol=define.group(1), text=line.strip())
                )
                index += 1
                continue
            if re.match(r"#\s*include\b", stripped):
                chunks.append(
                    HeaderChunk(kind="include", symbol=stripped, text=stripped)
                )
                index += 1
                continue
            chunks.append(HeaderChunk(kind="directive", symbol=None, text=stripped))
            index += 1
            continue
        # C chunk: accumulate until braces balance AND the chunk terminates
        # with ';' or a closing '}' at depth 0.
        block: list[str] = []
        depth = 0
        saw_any = False
        while index < len(lines):
            current = lines[index]
            block.append(current)
            depth += current.count("{") - current.count("}")
            saw_any = saw_any or bool(current.strip())
            tail = current.strip()
            index += 1
            if depth <= 0 and saw_any and (tail.endswith(";") or tail.endswith("}")):
                break
        text_block = "\n".join(block).strip()
        if text_block:
            kind, symbol = _c_chunk_symbol(text_block)
            chunks.append(HeaderChunk(kind=kind, symbol=symbol, text=text_block))
    return chunks


# ---------------------------------------------------------------------------
# Merge


def classify_conflict(symbol: str, kind: str, variants: list[str]) -> str:
    """Mechanical conflict classing -- names the failure family, decides
    nothing (resolution stays a human/registry decision)."""
    if symbol == "undefined8":
        return CLASS_UNDEFINED8_FORK
    has_double = ["double" in variant for variant in variants]
    if symbol in ("CONCAT44", "CONCAT44_INT") and any(has_double) and not all(has_double):
        # CONCAT44's union-double vs integer-shift split is downstream of the
        # undefined8 typedef fork, not an independent disagreement.
        return CLASS_UNDEFINED8_FORK
    if kind in ("function_decl", "function_def"):
        return CLASS_COLLISION_STUB
    if re.match(r"(PTR_|DAT_|FLOAT_|DOUBLE_|UNK_)", symbol or ""):
        return CLASS_DAT_DIVERGENCE
    return CLASS_DECL_DIVERGENCE


def _conflict_record(
    symbol: str | None,
    conflict_class: str,
    units: list[str],
    variants: dict[str, str],
    detail: str,
) -> dict[str, Any]:
    return {
        "symbol": symbol,
        "class": conflict_class,
        "units": sorted(units),
        "variants": {unit: text[:400] for unit, text in variants.items()},
        "detail": detail[:600],
    }


@dataclass
class MergeResult:
    merged_text: str | None
    conflicts: list[dict[str, Any]] = field(default_factory=list)


def merge_headers(headers: list[tuple[str, str]]) -> MergeResult:
    """Merge N unit headers into one, section 2.11 precedence, registry-less.

    ``headers`` is ``[(unit_name, header_text), ...]``. Identical normalized
    declarations of a symbol dedup to one copy; divergent declarations are
    contested conflicts and fail the merge loudly (no silent winner).

    Macros defined INSIDE inner conditional blocks (``#ifndef GC_U8`` /
    ``#define GC_U8(...)`` / ``#endif``) get the same treatment: identical
    blocks dedup, but two units guarding divergent definitions of the same
    macro -- or one guarding and one defining it bare -- refuse the merge
    loudly. Before this check (review R1), both blocks were emitted and the
    first unit's definition silently won at preprocess time.
    """
    # symbol key -> first-seen chunk; variants tracked for conflict records.
    order: list[str] = []
    canonical: dict[str, HeaderChunk] = {}
    variants: dict[str, dict[str, str]] = {}  # key -> {normalized: first unit}
    unit_by_variant: dict[str, dict[str, list[str]]] = {}
    kinds: dict[str, str] = {}
    anonymous: list[HeaderChunk] = []
    seen_anonymous: set[str] = set()
    # macro name -> {normalized block text: original block text} for defines
    # living inside conditional chunks; the divergence check below treats them
    # exactly like keyed symbols.
    guarded_defines: dict[str, dict[str, str]] = {}
    guarded_units: dict[str, dict[str, list[str]]] = {}

    for unit_name, text in headers:
        for chunk in parse_header_chunks(text):
            if chunk.symbol is None or chunk.kind == "include":
                key = chunk.normalized
                if chunk.kind == "conditional":
                    for macro in _DEFINE_IN_BLOCK.findall(chunk.text):
                        guarded_defines.setdefault(macro, {}).setdefault(
                            key, chunk.text
                        )
                        guarded_units.setdefault(macro, {}).setdefault(
                            key, []
                        ).append(unit_name)
                if key not in seen_anonymous:
                    seen_anonymous.add(key)
                    anonymous.append(chunk)
                continue
            key = f"{chunk.kind}:{chunk.symbol}"
            if key not in canonical:
                canonical[key] = chunk
                kinds[key] = chunk.kind
                order.append(key)
                variants[key] = {}
                unit_by_variant[key] = {}
            # Function declarations compare by PROTOTYPE (extern keyword,
            # parameter names and punctuation spacing are churn, not meaning);
            # everything else compares by whitespace-collapsed text.
            comparison = (
                _declaration_normal(chunk.text)
                if chunk.kind == "function_decl"
                else chunk.normalized
            )
            variants[key].setdefault(comparison, chunk.text)
            unit_by_variant[key].setdefault(comparison, []).append(unit_name)

    conflicts: list[dict[str, Any]] = []
    for key in order:
        if len(variants[key]) <= 1:
            continue
        kind, _, symbol = key.partition(":")
        implicated: list[str] = []
        variant_by_unit: dict[str, str] = {}
        for normalized, units in unit_by_variant[key].items():
            implicated.extend(units)
            for unit in units:
                variant_by_unit.setdefault(unit, normalized)
        conflict_class = classify_conflict(symbol, kind, list(variants[key]))
        conflicts.append(
            _conflict_record(
                symbol,
                conflict_class,
                implicated,
                variant_by_unit,
                f"{len(variants[key])} divergent {kind} declarations of {symbol}",
            )
        )
    # Guarded-define divergence (review R1): a macro #define'd inside inner
    # conditional blocks conflicts loudly when (a) two units guard divergent
    # definitions of it, or (b) it is ALSO defined as a plain (unguarded)
    # macro chunk -- in either case emitting the variants would hand the
    # preprocessor a silent first-wins pick.
    for macro in sorted(guarded_defines):
        block_variants = guarded_defines[macro]
        plain_key = f"macro:{macro}"
        if len(block_variants) <= 1 and plain_key not in variants:
            continue
        implicated: list[str] = []
        variant_by_unit: dict[str, str] = {}
        for normalized, units in guarded_units[macro].items():
            implicated.extend(units)
            for unit in units:
                variant_by_unit.setdefault(unit, block_variants[normalized])
        if plain_key in variants:
            for normalized, units in unit_by_variant[plain_key].items():
                implicated.extend(units)
                for unit in units:
                    variant_by_unit.setdefault(unit, normalized)
        conflicts.append(
            _conflict_record(
                macro,
                classify_conflict(macro, "macro", list(block_variants)),
                sorted(set(implicated)),
                variant_by_unit,
                f"{macro} is #define'd inside {len(block_variants)} divergent "
                "conditional block(s)"
                + (" and as a plain macro" if plain_key in variants else "")
                + "; emitting them would let the first definition win "
                "silently at preprocess time",
            )
        )
    if conflicts:
        return MergeResult(merged_text=None, conflicts=conflicts)

    lines = [
        "/* gnt4_shim.h -- MERGED by the continuous assembly gate",
        " * (src/port_assembly_gate.py, design section 2.13). Generated; do not edit.",
        f" * units: {', '.join(name for name, _ in headers)}",
        " */",
        "#ifndef GNT4_ASSEMBLY_MERGE_H",
        "#define GNT4_ASSEMBLY_MERGE_H",
        "",
    ]
    for chunk in anonymous:
        if chunk.kind == "include":
            lines.append(chunk.text)
    lines.append("")
    for key in order:
        lines.append(canonical[key].text)
    for chunk in anonymous:
        if chunk.kind != "include":
            lines.append(chunk.text)
    lines.append("")
    lines.append("#endif /* GNT4_ASSEMBLY_MERGE_H */")
    return MergeResult(merged_text="\n".join(lines) + "\n", conflicts=[])


# ---------------------------------------------------------------------------
# Cross-unit duplicate-definition prescan (collision stubs the merge cannot
# see: definitions live in the verbatim unit.c files, which are uneditable).

_DEF_SITE = re.compile(r"\b([A-Za-z_]\w*)\s*\(([^;{}]*)\)\s*\{")


def scan_function_definitions(unit_c_text: str) -> set[str]:
    """Names of functions DEFINED (not merely declared) in one unit.c."""
    names: set[str] = set()
    text = strip_comments(unit_c_text)
    for match in _DEF_SITE.finditer(text):
        name = match.group(1)
        if name in _C_KEYWORDS:
            continue
        names.add(name)
    return names


def duplicate_definition_conflicts(
    units: list[tuple[str, str]],
) -> list[dict[str, Any]]:
    """Same function defined in two unit.c files => a collision the single
    link invocation cannot resolve (unit.c is verbatim and uneditable)."""
    owners: dict[str, list[str]] = {}
    for unit_name, text in units:
        for symbol in scan_function_definitions(text):
            owners.setdefault(symbol, []).append(unit_name)
    conflicts = []
    for symbol, unit_names in sorted(owners.items()):
        if len(unit_names) < 2:
            continue
        conflicts.append(
            _conflict_record(
                symbol,
                CLASS_COLLISION_STUB,
                unit_names,
                {unit: f"defines {symbol}" for unit in unit_names},
                f"{symbol} is DEFINED in {len(unit_names)} units; "
                "one link invocation would see duplicate symbols",
            )
        )
    return conflicts


# ---------------------------------------------------------------------------
# Header-extern vs unit.c-prelude prototype cross-check. The merge only sees
# headers, but each unit.c carries its own auto-generated prototype prelude
# (before the first VERBATIM marker). Under a merged header, unit B's TU sees
# BOTH the merged header's extern for a symbol and its own prelude prototype
# -- a divergent pair is a hard 'conflicting types' compile error the
# per-unit builds could never surface (each unit only ever saw its own
# header). Found empirically on the first backfill sweep: auto-c0000-004's
# header says `extern int zz_0006fb4_();` while auto-c0000-006's prelude says
# `void zz_0006fb4_(undefined8, ...)`.

# Prefix WITHOUT the colon: D5-transformed blocks carry the renamed
# "/* ==== VERBATIM+D5:" marker (docs/d5-idiom-fix-design.md D5-3a), and the
# prelude split must recognize both spellings.
VERBATIM_MARKER = "/* ==== VERBATIM"


def prelude_region(unit_c_text: str) -> str:
    """Everything before the first verbatim block: the #include + the
    auto-generated prototype prelude. The verbatim bodies never move, so this
    split is mechanical."""
    return (unit_c_text or "").split(VERBATIM_MARKER)[0]


# C type-ish tokens that are never a parameter NAME: a trailing one of these
# is part of the type, not a dropped identifier.
_TYPE_TOKENS = {
    "void", "int", "char", "short", "long", "float", "double", "unsigned",
    "signed", "bool", "uint", "ushort", "ulong", "ulonglong", "longlong",
    "byte", "undefined", "undefined1", "undefined2", "undefined4",
    "undefined8", "code", "size_t", "...",
}


def _strip_parameter_names(declaration: str) -> str:
    """`double f(float *v)` and `double f(float *a)` are the SAME prototype;
    parameter names are not part of a C function type and must not manufacture
    conflicts. Purely lexical: drop a trailing identifier from each top-level
    parameter when it follows other tokens and is not itself a type token."""
    match = re.match(r"^(.*?\()(.*)(\)\s*;?\s*)$", declaration, re.S)
    if not match:
        return declaration
    head, params, tail = match.groups()
    depth = 0
    pieces: list[str] = []
    current = ""
    for char in params:
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
        if char == "," and depth == 0:
            pieces.append(current)
            current = ""
        else:
            current += char
    pieces.append(current)
    cleaned: list[str] = []
    for piece in pieces:
        tokens = re.findall(r"[A-Za-z_]\w*|\*|\.\.\.|\[|\]", piece)
        if (
            len(tokens) > 1
            and re.fullmatch(r"[A-Za-z_]\w*", tokens[-1])
            and tokens[-1] not in _TYPE_TOKENS
        ):
            tokens = tokens[:-1]
        cleaned.append(" ".join(tokens))
    return head + ",".join(cleaned) + tail


def _declaration_normal(text: str) -> str:
    flat = " ".join(text.split())
    if flat.startswith("extern "):
        flat = flat[len("extern "):]
    flat = _strip_parameter_names(flat)
    # Spacing around punctuation is churn, never meaning: `(int a, int b)`
    # and `(int a,int b)` must compare equal.
    return re.sub(r"\s*([^\w\s])\s*", r"\1", flat)


def _function_declarations(text: str) -> dict[str, str]:
    """symbol -> normalized declaration, for every function_decl chunk."""
    declarations: dict[str, str] = {}
    for chunk in parse_header_chunks(text):
        if chunk.kind == "function_decl" and chunk.symbol:
            declarations.setdefault(chunk.symbol, _declaration_normal(chunk.text))
    return declarations


def header_prelude_conflicts(
    headers: list[tuple[str, str]], sources: list[tuple[str, str]]
) -> list[dict[str, Any]]:
    """Symbols declared in one unit's HEADER and another unit's PRELUDE with
    divergent signatures: a 'conflicting types' error in the merged TU set."""
    header_decls: dict[str, dict[str, str]] = {}
    for unit_name, text in headers:
        for symbol, normal in _function_declarations(text).items():
            header_decls.setdefault(symbol, {})[unit_name] = normal
    prelude_decls: dict[str, dict[str, str]] = {}
    for unit_name, text in sources:
        for symbol, normal in _function_declarations(prelude_region(text)).items():
            prelude_decls.setdefault(symbol, {})[unit_name] = normal
    conflicts: list[dict[str, Any]] = []
    for symbol in sorted(set(header_decls) & set(prelude_decls)):
        implicated: dict[str, str] = {}
        for header_unit, header_normal in header_decls[symbol].items():
            for prelude_unit, prelude_normal in prelude_decls[symbol].items():
                if header_unit == prelude_unit:
                    continue  # the unit's own green build already proved these
                if header_normal != prelude_normal:
                    implicated[header_unit] = f"header: {header_normal}"
                    implicated[prelude_unit] = f"prelude: {prelude_normal}"
        if implicated:
            conflicts.append(
                _conflict_record(
                    symbol,
                    CLASS_COLLISION_STUB,
                    list(implicated),
                    implicated,
                    f"header extern vs unit.c prelude prototype diverge for {symbol}; "
                    "under a merged header this is a conflicting-types compile error",
                )
            )
    return conflicts


# ---------------------------------------------------------------------------
# Link-diagnostic parsing (the empirical detector: conflicts units did NOT
# write down, named by the compiler/linker).

_LINK_PATTERNS = [
    (re.compile(r"duplicate symbol:\s*([A-Za-z_]\w*)"), CLASS_COLLISION_STUB),
    (re.compile(r"function signature mismatch:\s*([A-Za-z_]\w*)"), CLASS_COLLISION_STUB),
    (re.compile(r"undefined symbol:\s*([A-Za-z_]\w*)"), CLASS_LINK_FAILURE),
]


def conflicts_from_link_error(error_text: str, units: list[str]) -> list[dict[str, Any]]:
    conflicts: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for line in (error_text or "").splitlines():
        for pattern, conflict_class in _LINK_PATTERNS:
            match = pattern.search(line)
            if not match:
                continue
            key = (conflict_class, match.group(1))
            if key in seen:
                continue
            seen.add(key)
            conflicts.append(
                _conflict_record(
                    match.group(1), conflict_class, units, {}, line.strip()
                )
            )
    if not conflicts:
        conflicts.append(
            _conflict_record(
                None,
                CLASS_LINK_FAILURE,
                units,
                {},
                (error_text or "").strip()[-600:] or "link failed with no diagnostics",
            )
        )
    return conflicts


# ---------------------------------------------------------------------------
# Unit artifact selection

REQUIRED_ARTIFACTS = ("unit.c", "gnt4_shim.h", "provenance.json")


@dataclass
class UnitArtifact:
    name: str
    directory: Path
    generated_at: str
    exports: list[str]
    allowed_extra_imports: list[str]
    tier: str


def load_unit_artifact(directory: Path) -> UnitArtifact | None:
    for artifact in REQUIRED_ARTIFACTS:
        if not (directory / artifact).is_file():
            return None
    try:
        provenance = json.loads(
            (directory / "provenance.json").read_text(encoding="utf-8-sig")
        )
    except (json.JSONDecodeError, OSError):
        return None
    return UnitArtifact(
        name=str(provenance.get("unit") or directory.name),
        directory=directory,
        generated_at=str(provenance.get("generated_at") or ""),
        exports=[str(e) for e in provenance.get("exported_functions") or []],
        allowed_extra_imports=[
            str(e) for e in provenance.get("allowed_extra_imports") or []
        ],
        tier=str(provenance.get("tier") or "unknown"),
    )


def select_recent_green_units(
    roots: list[Path], n: int | None
) -> list[UnitArtifact]:
    """The last N green/staged unit artifacts across the given roots, oldest
    first (stable link order), recency by provenance generated_at. n=None
    selects everything (the backfill sweep).

    ``roots`` is in AUTHORITY ORDER: when the same unit name appears in more
    than one root -- the scheduled T3 scenario where an artifact has been
    promoted from staging to the verified root but the staging copy still
    exists -- the EARLIEST root wins, regardless of which copy is newer. The
    caller passes the verified root (``port-units``) before staging, so the
    verified artifact always shadows its staging twin. Without this dedup
    (review R2) both copies were selected, the gate wrote ``{name}.c`` twice
    (newer silently overwriting older), and the composition compiled one
    unit's code twice while the other's was silently absent."""
    artifacts: list[UnitArtifact] = []
    seen_names: set[str] = set()
    for root in roots:
        if not root.is_dir():
            continue
        for directory in sorted(root.iterdir()):
            if not directory.is_dir():
                continue
            artifact = load_unit_artifact(directory)
            if artifact is None or artifact.name in seen_names:
                continue
            seen_names.add(artifact.name)
            artifacts.append(artifact)
    artifacts.sort(key=lambda a: (a.generated_at, a.name))
    if n is not None and n > 0:
        artifacts = artifacts[-n:]
    return artifacts


# ---------------------------------------------------------------------------
# Gate orchestration

SMOKE_JS = r"""// assembly-gate instantiation smoke (design section 2.13): the gate
// passes iff the linked module LOADS. No behaviour is asserted -- that is
// the oracle tier's job. Imports are stubbed mechanically.
const fs = require('fs');
const bytes = fs.readFileSync(process.argv[2]);
const mod = new WebAssembly.Module(bytes);
const imports = {};
for (const imp of WebAssembly.Module.imports(mod)) {
  imports[imp.module] = imports[imp.module] || {};
  if (imp.kind === 'function') imports[imp.module][imp.name] = () => 0;
  else if (imp.kind === 'memory')
    imports[imp.module][imp.name] = new WebAssembly.Memory({ initial: 1 });
  else if (imp.kind === 'global') imports[imp.module][imp.name] = 0;
  else if (imp.kind === 'table')
    imports[imp.module][imp.name] =
      new WebAssembly.Table({ element: 'anyfunc', initial: 1 });
}
const instance = new WebAssembly.Instance(mod, imports);
// NOTE: runs as CommonJS (.cjs), where `exports` is a wrapper identifier.
const exportCount = WebAssembly.Module.exports(mod).length;
console.log('ASSEMBLY_SMOKE_OK exports=' + exportCount);
"""

ASSEMBLY_WASM = "assembly.wasm"

# Identifier shape emcc's -sEXPORTED_FUNCTIONS accepts (mirrors the driver).
_C_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def run_assembly_gate(
    units: list[UnitArtifact],
    workdir: Path,
    link_runner: Callable[[Path, list[str], list[str], list[str]], tuple[bool, str]],
    smoke_runner: Callable[[Path], tuple[bool, str]] | None = None,
) -> dict[str, Any]:
    """Run one N-unit assembly-gate pass. Pure orchestration: emcc and node
    arrive as injected runners.

    link_runner(workdir, c_file_names, exports, allowed_extra) -> (ok, error)
    smoke_runner(wasm_path) -> (ok, log)
    """
    names = [unit.name for unit in units]
    result: dict[str, Any] = {
        "n": len(units),
        "units": names,
        "checked_at": utc_now(),
        "conflicts": [],
        "passed": False,
        "stage": "merge",
        "detail": "",
    }
    # Defense in depth behind select_recent_green_units' name dedup: the gate
    # writes {name}.c per unit, so a duplicate name would silently overwrite
    # one unit's code with another's. Refuse loudly instead (review R2).
    duplicate_names = sorted({name for name in names if names.count(name) > 1})
    if duplicate_names:
        result["stage"] = "select"
        result["conflicts"] = [
            _conflict_record(
                name,
                CLASS_COLLISION_STUB,
                [
                    f"{unit.name} ({unit.directory})"
                    for unit in units
                    if unit.name == name
                ],
                {},
                f"unit name {name} selected more than once; compiling it "
                "twice would silently drop one artifact's code",
            )
            for name in duplicate_names
        ]
        result["detail"] = (
            "selection contains duplicate unit name(s): "
            + ", ".join(duplicate_names)
        )
        return result
    headers = [
        (unit.name, (unit.directory / "gnt4_shim.h").read_text(encoding="utf-8-sig"))
        for unit in units
    ]
    sources = [
        (unit.name, (unit.directory / "unit.c").read_text(encoding="utf-8-sig"))
        for unit in units
    ]
    merge = merge_headers(headers)
    conflicts = list(merge.conflicts)
    conflicted_symbols = {c.get("symbol") for c in conflicts}
    conflicts.extend(
        c
        for c in header_prelude_conflicts(headers, sources)
        if c.get("symbol") not in conflicted_symbols
    )
    conflicts.extend(duplicate_definition_conflicts(sources))
    if conflicts:
        result["conflicts"] = conflicts
        result["detail"] = (
            f"header merge refused: {len(conflicts)} contested conflict(s); "
            "no silent winner is picked (section 2.11 precedence)"
        )
        return result

    workdir.mkdir(parents=True, exist_ok=True)
    assert merge.merged_text is not None
    (workdir / "gnt4_shim.h").write_text(
        merge.merged_text, encoding="utf-8", newline="\n"
    )
    c_files: list[str] = []
    for unit, (_, source) in zip(units, sources):
        file_name = f"{unit.name}.c"
        # The unit.c bytes are copied VERBATIM -- the gate never edits a unit.
        (workdir / file_name).write_text(source, encoding="utf-8", newline="\n")
        c_files.append(file_name)

    exports = sorted(
        {
            export
            for unit in units
            for export in unit.exports
            if _C_IDENTIFIER.fullmatch(export)
        }
    )
    allowed_extra = sorted(
        {extra for unit in units for extra in unit.allowed_extra_imports}
    )
    result["stage"] = "link"
    ok, error_text = link_runner(workdir, c_files, exports, allowed_extra)
    if not ok:
        result["conflicts"] = conflicts_from_link_error(error_text, names)
        result["detail"] = (error_text or "").strip()[-1200:]
        return result

    if smoke_runner is not None:
        result["stage"] = "smoke"
        ok, log = smoke_runner(workdir / ASSEMBLY_WASM)
        if not ok:
            result["conflicts"] = [
                _conflict_record(
                    None,
                    CLASS_INSTANTIATION_FAILURE,
                    names,
                    {},
                    (log or "").strip()[-600:] or "instantiation failed silently",
                )
            ]
            result["detail"] = (log or "").strip()[-1200:]
            return result

    result["stage"] = "pass"
    result["passed"] = True
    result["detail"] = f"{len(units)} unit(s) linked and instantiated together"
    return result


# ---------------------------------------------------------------------------
# Ledger: the conflict records + the interim G1 metric (largest N passed).


def _conflict_key(conflict: dict[str, Any]) -> str:
    return "|".join(
        [
            str(conflict.get("class")),
            str(conflict.get("symbol")),
            ",".join(conflict.get("units") or []),
        ]
    )


def record_gate_result(ledger_path: Path, result: dict[str, Any]) -> dict[str, Any]:
    """Fold one gate result into the tracked assembly ledger. Returns the
    updated ledger payload."""
    try:
        ledger = json.loads(ledger_path.read_text(encoding="utf-8-sig"))
        if ledger.get("schema") != GATE_LEDGER_SCHEMA:
            ledger = None
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        ledger = None
    if not isinstance(ledger, dict):
        ledger = {
            "schema": GATE_LEDGER_SCHEMA,
            "created_at": utc_now(),
            "largest_n_passed": 0,
            "runs_total": 0,
            "conflicts": {},
        }
    ledger["runs_total"] = int(ledger.get("runs_total", 0)) + 1
    if result.get("passed"):
        ledger["largest_n_passed"] = max(
            int(ledger.get("largest_n_passed", 0)), int(result.get("n", 0))
        )
    conflicts = ledger.setdefault("conflicts", {})
    now = utc_now()
    for conflict in result.get("conflicts") or []:
        key = _conflict_key(conflict)
        entry = conflicts.get(key)
        if entry is None:
            entry = dict(conflict)
            entry["first_seen"] = now
            entry["times_seen"] = 0
            conflicts[key] = entry
        entry["times_seen"] = int(entry.get("times_seen", 0)) + 1
        entry["last_seen"] = now
    ledger["last_run"] = {
        "checked_at": result.get("checked_at"),
        "n": result.get("n"),
        "units": result.get("units"),
        "passed": result.get("passed"),
        "stage": result.get("stage"),
        "conflict_count": len(result.get("conflicts") or []),
        "detail": (result.get("detail") or "")[:600],
    }
    ledger["updated_at"] = now
    ledger_path.parent.mkdir(parents=True, exist_ok=True)
    atomic_write_json(ledger_path, ledger)
    return ledger
