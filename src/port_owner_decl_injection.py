"""Owner (oracle-registry) prototype injection for zz_*/FUN_* symbols.

Units repeatedly fail the assembly gate with ``owner_variant_abi_incompatible``
because the compile-fix model INVENTS ``zz_*``/``FUN_*`` prototypes from the
call-site rendering (the endemic Ghidra register-class fork: a call site
renders a first parameter as ``double`` where the corpus-anchored owner says
``undefined8``).  The owner registry (oracle-registry.json, validated against
corpus bytes at gate load) is the authority the gate enforces at
canonicalization -- but nothing feeds those prototypes into the unit's header
seed, so the model can only guess, and the gate then contests the guess.

This module is the surgical, generator-side fix, the exact shape of the
``gnt4_*`` SDK seed sync (src/port_sdk_decl_injection.py): whenever a unit is
(re)attempted the unit's header seed is synchronised with the OWNER prototypes
for the ``zz_*``/``FUN_*`` symbols the unit's verbatim unit.c references.

Contract (mirrors the SDK sync):

- referenced + absent from the per-unit seed  -> injected (appended inside
  the include guard under a one-line banner)
- referenced + present but DIVERGENT          -> superseded in place (the
  owner line replaces the per-unit line)
- referenced + present and IDENTICAL (modulo  -> untouched
  parameter names / whitespace / ``extern``)
- NOT referenced by the unit                  -> never added, never touched
- owner unit IS this unit (own definitions)   -> excluded
- symbol DEFINED in this unit's unit.c        -> excluded
- ``gnt4_*``                                  -> excluded (SDK sync owns those)
- re-running the pass is a no-op (idempotent: no duplicates, no rewrites)
- the on-disk seed write is atomic (temp file + ``os.replace``) and only
  happens when the pass actually changed something

SCOPE GUARD (design): this feeds INFORMATION into the prompt seed; it creates
NO new authority.  The gate's canonicalization/contest machinery is untouched
-- if the model rewrites the declaration back, the gate still contests it
exactly as today.  Prototypes are reconstructed with the gate's OWN registry
validator and declaration reconstructor (``_validate_registry`` +
``_registry_declaration`` from src/port_assembly_abi), i.e. the same schema-1
data ``load_owner_snapshot`` validates against the corpus at gate load, spelled
the same way -- without the pinned-Clang corpus walk, which would be far too
heavy for a per-attempt seed pass and would make the sync silently inert on
hosts without the parser.

Token impact per prompt is proportional to the number of ``zz_*``/``FUN_*``
symbols the unit references (typically a handful of one-line declarations),
never to the size of the registry.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import Mapping

from src.port_assembly_abi import (
    AssemblyAbiError,
    _parse_json,
    _registry_declaration,
    _validate_registry,
)
from src.port_assembly_gate import (
    _declaration_normal,
    parse_header_chunks,
    strip_comments,
)
from src.port_sdk_decl_injection import (
    _atomic_write_text,
    _supersede_declaration,
)

__all__ = [
    "OwnerDeclInjection",
    "OwnerPrototype",
    "inject_owner_declarations",
    "load_owner_prototypes",
    "referenced_owner_symbols",
    "sync_owner_declarations",
    "unit_defined_symbols",
]

# The endemic-fork surface this pass exists for: Ghidra label/address names.
# gnt4_* is deliberately NOT matched -- the SDK sync owns that seam.
_OWNER_TOKEN = re.compile(r"\b(?:zz_|FUN_)\w+")

OWNER_DECL_BANNER = (
    "/* ---- owner prototypes "
    "(auto-injected from oracle-registry.json) ---- */"
)
_SUPERSEDE_MARK = "/* OWNER PROTOTYPE (oracle-registry.json): do not alter */"


def referenced_owner_symbols(unit_c_text: str) -> set[str]:
    """Every ``zz_*``/``FUN_*`` token the unit's verbatim .c references.

    Comments are stripped first: a symbol mentioned only in a comment is not
    a reference, and injecting for it would violate the never-touch-what-the-
    unit-does-not-use rule."""
    return set(_OWNER_TOKEN.findall(strip_comments(unit_c_text or "")))


@dataclass(frozen=True)
class OwnerPrototype:
    """One owner-registry prototype: the unit that DEFINES the symbol, and the
    declaration line reconstructed by the gate's own ``_registry_declaration``
    (validated at gate load to parse identically to the corpus definition)."""

    symbol: str
    owner_unit: str
    declaration: str  # e.g. "void zz_0006fb4_(undefined8 param_1,...);"


_PROTOTYPE_CACHE: dict[
    tuple[str, int, int], Mapping[str, OwnerPrototype]
] = {}


def load_owner_prototypes(registry_path: Path) -> Mapping[str, OwnerPrototype]:
    """symbol -> OwnerPrototype for every ``zz_*``/``FUN_*`` function record
    in the oracle registry.

    The registry is parsed with the gate's own JSON parser and validated with
    the gate's own whole-registry schema-1 validator (``_validate_registry``)
    -- format drift the gate would refuse is refused here too, so this pass
    can never inject a spelling the gate would not recognise.  Records whose
    declaration schema 1 cannot reconstruct (unrepresentable return
    declarators) are skipped: the gate itself refuses to bind them, so there
    is no canon spelling to feed.

    Loading + validating ~11k records is pure Python but not free, so the
    result is cached per (path, mtime_ns, size); the cache never outlives a
    changed registry file.  Any parse/validation/IO fault raises to the
    caller (the driver degrades to the unsynced seed and emits an event)."""
    resolved = Path(registry_path)
    stat = resolved.stat()
    key = (str(resolved), stat.st_mtime_ns, stat.st_size)
    cached = _PROTOTYPE_CACHE.get(key)
    if cached is not None:
        return cached
    registry = _validate_registry(_parse_json(resolved.read_bytes()))
    prototypes: dict[str, OwnerPrototype] = {}
    for record in registry["functions"]:
        name = record["name"]
        if not _OWNER_TOKEN.fullmatch(name):
            continue
        try:
            declaration = _registry_declaration(record).decode("utf-8")
        except AssemblyAbiError:
            continue  # no schema-1 spelling exists; the gate skips it too
        prototypes[name] = OwnerPrototype(
            symbol=name,
            owner_unit=record["unit"],
            declaration=declaration,
        )
    frozen: Mapping[str, OwnerPrototype] = MappingProxyType(prototypes)
    _PROTOTYPE_CACHE.clear()  # one registry per process; never grow unbounded
    _PROTOTYPE_CACHE[key] = frozen
    return frozen


def unit_defined_symbols(unit_c_text: str, candidates: set[str]) -> set[str]:
    """The subset of ``candidates`` that unit.c DEFINES (a parameter list
    followed by a ``{`` body).  Comment-stripped; a call site (no ``{`` after
    the closing paren) is never a definition."""
    stripped = strip_comments(unit_c_text or "")
    defined: set[str] = set()
    for symbol in candidates:
        for match in re.finditer(rf"\b{re.escape(symbol)}\s*\(", stripped):
            depth = 1
            index = match.end()
            while index < len(stripped) and depth > 0:
                char = stripped[index]
                if char == "(":
                    depth += 1
                elif char == ")":
                    depth -= 1
                index += 1
            if depth != 0:
                continue
            while index < len(stripped) and stripped[index] in " \t\r\n":
                index += 1
            if index < len(stripped) and stripped[index] == "{":
                defined.add(symbol)
                break
    return defined


@dataclass
class OwnerDeclInjection:
    """Outcome of one owner-prototype pass over one unit's header seed."""

    header_text: str
    injected: list[str] = field(default_factory=list)  # referenced + absent
    superseded: list[str] = field(default_factory=list)  # referenced + divergent
    unresolved: list[str] = field(default_factory=list)  # divergent, line not found
    changed: bool = False
    write_error: str | None = None  # seed persist failed; header_text still synced


def inject_owner_declarations(
    header_text: str,
    unit_c_text: str,
    prototypes: Mapping[str, OwnerPrototype],
    *,
    unit_name: str,
) -> OwnerDeclInjection:
    """Pure injection pass: returns the (possibly rewritten) header text and
    what happened per symbol.  See the module docstring for the contract."""
    result = OwnerDeclInjection(header_text=header_text)
    referenced = referenced_owner_symbols(unit_c_text)
    relevant = sorted(
        symbol
        for symbol in referenced & set(prototypes)
        if prototypes[symbol].owner_unit != unit_name
    )
    if not relevant:
        return result
    defined_here = unit_defined_symbols(unit_c_text, set(relevant))
    relevant = [symbol for symbol in relevant if symbol not in defined_here]
    if not relevant:
        return result

    existing: dict[str, str] = {}
    for chunk in parse_header_chunks(header_text or ""):
        if chunk.kind == "function_decl" and chunk.symbol:
            existing.setdefault(chunk.symbol, _declaration_normal(chunk.text))

    lines = (header_text or "").splitlines()
    to_append: list[str] = []
    for symbol in relevant:
        owner_line = f"extern {prototypes[symbol].declaration}"
        if symbol in existing:
            if existing[symbol] == _declaration_normal(owner_line):
                continue  # identical modulo names/spacing/extern: untouched
            if _supersede_declaration(
                lines, symbol, f"{owner_line}  {_SUPERSEDE_MARK}"
            ):
                result.superseded.append(symbol)
            else:
                # Declared somewhere the line scan cannot safely splice (an
                # inner conditional block, a comment-mangled line).  Adding a
                # second, conflicting declaration would guarantee a compile
                # error, so record it for the caller to surface instead.
                result.unresolved.append(symbol)
        else:
            to_append.append(owner_line)
            result.injected.append(symbol)

    if to_append:
        block = ["", OWNER_DECL_BANNER, *to_append]
        # Inside the include guard: insert before a trailing #endif when the
        # last non-blank line is one (same placement rule as the SDK sync).
        insert_at = len(lines)
        for i in range(len(lines) - 1, -1, -1):
            stripped = lines[i].strip()
            if not stripped:
                continue
            if re.match(r"#\s*endif\b", stripped):
                insert_at = i
            break
        lines[insert_at:insert_at] = block

    if result.injected or result.superseded:
        result.changed = True
        result.header_text = "\n".join(lines) + (
            "\n" if (header_text or "").endswith("\n") else ""
        )
    return result


def sync_owner_declarations(
    header_seed_path: Path,
    unit_c_text: str,
    registry_path: Path,
    *,
    unit_name: str,
    header_text: str | None = None,
) -> OwnerDeclInjection:
    """File-level pass for the driver's attempt path: inject, and when the
    pass changed the header, persist it back to the per-unit seed atomically
    so every later read of the seed (targeted rounds, registry fallback,
    replays) sees the owner prototypes.

    A missing/unreadable/invalid registry raises to the caller (the driver
    degrades to the unsynced seed and emits an event -- warmth is optional,
    correctness is not).  A failed WRITE does NOT raise: the in-memory
    ``header_text`` is already synced and this attempt should still benefit,
    so the fault is recorded on ``result.write_error`` for the caller to
    surface."""
    if header_text is None:
        header_text = header_seed_path.read_text(encoding="utf-8")
    prototypes = load_owner_prototypes(registry_path)
    result = inject_owner_declarations(
        header_text, unit_c_text, prototypes, unit_name=unit_name
    )
    if result.changed:
        try:
            _atomic_write_text(header_seed_path, result.header_text)
        except OSError as error:
            result.write_error = str(error)
    return result
