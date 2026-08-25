"""Canonical SDK declaration injection (v2/v3 port design, step 1).

The main seed (``gnt4_shim_seed.h``) carries the corpus-validated canonical
``gnt4_*`` SDK declarations, but every existing unit reads a PER-UNIT header
seed snapshotted before those declarations landed, so the canon was inert for
the whole live queue: units kept inventing their own signatures and the N=5
assembly link failed with ``collision_stub``.

The failed alternative -- bulk-rewriting all per-unit seeds with all 68
declarations -- added ~1400 tokens to every prompt and blew the serving
context ceiling.  This module is the surgical, generator-side fix: whenever a
unit is (re)attempted the driver synchronises that unit's header seed with
ONLY the canonical declarations for ``gnt4_*`` symbols the unit's verbatim
unit.c actually references.

Contract:

- referenced + absent from the per-unit seed  -> injected (appended inside
  the include guard under a one-line banner)
- referenced + present but DIVERGENT          -> superseded in place (the
  canonical line replaces the per-unit line)
- referenced + present and IDENTICAL (modulo  -> untouched
  parameter names / whitespace / ``extern``)
- NOT referenced by the unit                  -> never added, never touched
- re-running the pass is a no-op (idempotent: no duplicates, no rewrites)
- the on-disk seed write is atomic (temp file + ``os.replace``) and only
  happens when the pass actually changed something

Token impact per prompt is proportional to the number of ``gnt4_*`` symbols
the unit references (typically 0-3 declarations), not to the size of the
canon.
"""

from __future__ import annotations

import os
import re
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from src.port_assembly_gate import (
    _declaration_normal,
    parse_header_chunks,
    strip_comments,
)

__all__ = [
    "SdkDeclInjection",
    "canonical_sdk_declarations",
    "inject_sdk_declarations",
    "referenced_gnt4_symbols",
    "sync_sdk_declarations",
]

_GNT4_TOKEN = re.compile(r"\bgnt4_\w+")

SDK_DECL_BANNER = (
    "/* ---- canonical SDK declarations "
    "(auto-injected from gnt4_shim_seed.h) ---- */"
)
_SUPERSEDE_MARK = "/* CANONICAL SDK (gnt4_shim_seed.h): do not alter */"


def referenced_gnt4_symbols(unit_c_text: str) -> set[str]:
    """Every ``gnt4_*`` token the unit's verbatim .c actually references.

    Comments are stripped first: a symbol mentioned only in a comment is not
    a reference, and injecting for it would violate the never-touch-what-the-
    unit-does-not-use rule."""
    return set(_GNT4_TOKEN.findall(strip_comments(unit_c_text or "")))


def canonical_sdk_declarations(canonical_seed_text: str) -> dict[str, str]:
    """symbol -> single-line declaration text for every ``gnt4_*`` function
    declaration in the canonical seed.  First declaration wins (the canon
    must not carry duplicates; if it ever does, the earlier line is the one
    the corpus was validated against)."""
    declarations: dict[str, str] = {}
    for chunk in parse_header_chunks(canonical_seed_text or ""):
        if (
            chunk.kind == "function_decl"
            and chunk.symbol
            and chunk.symbol.startswith("gnt4_")
        ):
            text = " ".join(chunk.text.split())
            if not text.endswith(";"):
                text += ";"
            declarations.setdefault(chunk.symbol, text)
    return declarations


@dataclass
class SdkDeclInjection:
    """Outcome of one injection pass over one unit's header seed."""

    header_text: str
    injected: list[str] = field(default_factory=list)  # referenced + absent
    superseded: list[str] = field(default_factory=list)  # referenced + divergent
    unresolved: list[str] = field(default_factory=list)  # divergent, line not found
    changed: bool = False
    write_error: str | None = None  # seed persist failed; header_text still synced


def _decl_start(symbol: str) -> re.Pattern[str]:
    # A declaration line: optional `extern`, at least one type token, then the
    # symbol immediately followed by `(`.  `#define` lines never match (they
    # start with `#`); call sites cannot appear at declaration level in a
    # header the seed generator wrote.
    return re.compile(
        rf"^\s*(?:extern\s+)?[A-Za-z_][\w]*(?:[\s\*]+[\w\*]+)*[\s\*]+"
        rf"{re.escape(symbol)}\s*\("
    )


def _supersede_declaration(lines: list[str], symbol: str, replacement: str) -> bool:
    """Replace every single- or multi-line DECLARATION of ``symbol`` in the
    raw header lines with ``replacement`` (one line).  Returns True when at
    least one replacement happened.  Function DEFINITIONS (a ``{`` before the
    terminating ``;``) are never touched."""
    pattern = _decl_start(symbol)
    replaced = False
    index = 0
    while index < len(lines):
        stripped_line = strip_comments(lines[index])
        if not pattern.match(stripped_line):
            index += 1
            continue
        # Consume the logical declaration: through the line whose
        # comment-stripped content carries the terminating `;`.  A `{` first
        # means this is a definition, not a declaration -- skip it whole.
        end = index
        accumulated = stripped_line
        while ";" not in accumulated and "{" not in accumulated:
            end += 1
            if end >= len(lines):
                break
            accumulated += " " + strip_comments(lines[end])
        if "{" in accumulated.split(";")[0]:
            index = end + 1
            continue
        if ";" not in accumulated:
            index = end + 1
            continue
        lines[index : end + 1] = [replacement]
        replaced = True
        index += 1
    return replaced


def inject_sdk_declarations(
    header_text: str, unit_c_text: str, canonical_seed_text: str
) -> SdkDeclInjection:
    """Pure injection pass: returns the (possibly rewritten) header text and
    what happened per symbol.  See the module docstring for the contract."""
    result = SdkDeclInjection(header_text=header_text)
    canonical = canonical_sdk_declarations(canonical_seed_text)
    relevant = sorted(referenced_gnt4_symbols(unit_c_text) & set(canonical))
    if not relevant:
        return result

    existing: dict[str, str] = {}
    for chunk in parse_header_chunks(header_text or ""):
        if chunk.kind == "function_decl" and chunk.symbol:
            existing.setdefault(chunk.symbol, _declaration_normal(chunk.text))

    lines = (header_text or "").splitlines()
    to_append: list[str] = []
    for symbol in relevant:
        canon_text = canonical[symbol]
        if symbol in existing:
            if existing[symbol] == _declaration_normal(canon_text):
                continue  # identical modulo names/spacing: untouched
            if _supersede_declaration(
                lines, symbol, f"{canon_text}  {_SUPERSEDE_MARK}"
            ):
                result.superseded.append(symbol)
            else:
                # Declared somewhere the line scan cannot safely splice (an
                # inner conditional block, a comment-mangled line).  Adding a
                # second, conflicting declaration would guarantee a compile
                # error, so record it for the caller to surface instead.
                result.unresolved.append(symbol)
        else:
            to_append.append(canon_text)
            result.injected.append(symbol)

    if to_append:
        block = ["", SDK_DECL_BANNER, *to_append]
        # Inside the include guard: insert before a trailing #endif when the
        # last non-blank line is one (same placement rule as augment_seed).
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


def _atomic_write_text(path: Path, text: str) -> None:
    """Write ``text`` to ``path`` atomically: temp file in the same directory
    (same volume, so ``os.replace`` is a rename), then replace."""
    handle = tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        newline="\n",
        dir=str(path.parent),
        prefix=f".{path.name}.",
        suffix=".tmp",
        delete=False,
    )
    try:
        with handle:
            handle.write(text)
        os.replace(handle.name, path)
    except BaseException:
        try:
            os.unlink(handle.name)
        except OSError:
            pass
        raise


def sync_sdk_declarations(
    header_seed_path: Path,
    unit_c_text: str,
    canonical_seed_path: Path,
    *,
    header_text: str | None = None,
) -> SdkDeclInjection:
    """File-level pass for the driver's attempt path: inject, and when the
    pass changed the header, persist it back to the per-unit seed atomically
    so every later read of the seed (targeted rounds, registry fallback,
    replays) sees the canonical declarations.

    A missing/unreadable canonical seed raises to the caller (the driver
    degrades to the unsynced seed and emits an event -- warmth is optional,
    correctness is not).  A failed WRITE does NOT raise: the in-memory
    ``header_text`` is already synced and this attempt should still benefit,
    so the fault is recorded on ``result.write_error`` for the caller to
    surface."""
    if header_text is None:
        header_text = header_seed_path.read_text(encoding="utf-8")
    canonical_text = canonical_seed_path.read_text(encoding="utf-8")
    result = inject_sdk_declarations(header_text, unit_c_text, canonical_text)
    if result.changed:
        try:
            _atomic_write_text(header_seed_path, result.header_text)
        except OSError as error:
            result.write_error = str(error)
    return result
