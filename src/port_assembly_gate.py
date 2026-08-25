"""Continuous assembly gate (design section 2.13 [V4-11], tranche T2b).

Every mechanism in the compile-fix loop keeps units *individually* green;
until this gate nothing ever linked two of them together -- G1's first
executable evidence sat behind a future assembly workstream. This module makes
composition continuous: before publication, an explicit name+digest-bound
candidate and up to N-1 green/staged units are linked in ONE emcc invocation
(merged headers, shared flat arena, deduplicated externs) and the result is
instantiation-smoke-tested under node. The gate passes iff the link produces a
loadable wasm -- no behaviour is asserted; behaviour stays the oracle tier's
job.

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
records against the implicated symbols in a local evidence ledger
(research/decomp/data/assembly-gate.json) -- the cross-unit reconciliation
report of section 3, generated as a by-product instead of by archaeology.

This module is deliberately import-light (only src.port_chunk_workflow for
atomic JSON I/O): src/port_wasm_units.py imports it, never the reverse, and
every emcc/node dependency is injected as a runner callable so the whole gate
is testable offline.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from src.port_chunk_workflow import atomic_write_json, utc_now

from src.port_assembly_abi import (
    AssemblyAbiError,
    ToolIdentity,
    ToolWorld,
)

# The six tool roles ToolWorld requires, and where each lives under the repo
# root. `node` is discovered because emsdk pins its version in the directory
# name; hardcoding one silently breaks on the next emsdk bump.
_TOOL_RELPATHS: dict[str, str] = {
    "clang": "research/tools/emsdk/upstream/bin/clang.exe",
    "emcc": "research/tools/emsdk/upstream/emscripten/emcc.exe",
    "object-inspector": "research/tools/emsdk/upstream/bin/llvm-nm.exe",
    "wasm-ld": "research/tools/emsdk/upstream/bin/wasm-ld.exe",
}
_NODE_GLOB = "research/tools/emsdk/node/*/node.exe"
_EMSCRIPTEN_VERSION_RELPATH = "research/tools/emsdk/upstream/emscripten/emscripten-version.txt"


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def _tool_version_sha256(path: Path, version_argv: tuple[str, ...]) -> str:
    """Digest of the tool's own --version output.

    A toolchain upgrade that keeps the same file name must still move the
    world digest, so composition reds reopen. Failure to run the tool is a
    refusal, never a placeholder digest.
    """
    import subprocess

    try:
        completed = subprocess.run(
            [str(path), *version_argv],
            capture_output=True,
            timeout=120,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise AssemblyAbiError(
            _tool_world_refusal(f"cannot run {path.name} {' '.join(version_argv)}: {error}")
        ) from error
    if completed.returncode != 0:
        raise AssemblyAbiError(
            _tool_world_refusal(
                f"{path.name} {' '.join(version_argv)} exited {completed.returncode}"
            )
        )
    return hashlib.sha256(completed.stdout + completed.stderr).hexdigest()


def _tool_world_refusal(detail: str):
    from src.port_assembly_abi import AssemblyAbiRefusal

    return AssemblyAbiRefusal("tool_world_unresolvable", "tool-world", detail)


def resolve_node_executable(repo_root: Path) -> Path:
    """The single emsdk-pinned node. Zero or several is a refusal: picking one
    would bind the world to a tool the next run may not choose."""
    matches = sorted(repo_root.glob(_NODE_GLOB))
    if len(matches) != 1:
        raise AssemblyAbiError(
            _tool_world_refusal(
                f"expected exactly one emsdk node, found {len(matches)}: "
                + ", ".join(str(item) for item in matches[:4])
            )
        )
    return matches[0]


def build_tool_world(
    repo_root: Path,
    *,
    compile_argv: tuple[tuple[str, ...], ...],
    inspect_argv: tuple[tuple[str, ...], ...],
    link_argv: tuple[str, ...],
    instantiate_argv: tuple[str, ...],
    smoke_argv: tuple[str, ...],
    smoke_script: Path,
    environment: tuple[tuple[str, str], ...] = (),
) -> ToolWorld:
    """Build the production ToolWorld for one assembly composition.

    Every role is bound to a real absolute path, the file's own digest, and the
    digest of its `--version` output. `smoke-script` is a generated file rather
    than an executable, so its content digest serves as both identities -- it
    has no version to interrogate, and its bytes are what actually change.

    Any unresolvable tool refuses; the gate must never compose against a
    partially-identified toolchain.
    """
    root = Path(repo_root).resolve(strict=True)
    identities: list[ToolIdentity] = []
    for role, relpath in _TOOL_RELPATHS.items():
        path = (root / relpath).resolve()
        if not path.is_file():
            raise AssemblyAbiError(
                _tool_world_refusal(f"{role} is not a file at {path}")
            )
        if role == "emcc":
            # emcc.exe is a launcher that needs emsdk_env sourced, so
            # `emcc --version` exits 1 when run directly and cannot serve as
            # the version identity. emscripten pins its own release in
            # emscripten-version.txt, which is exactly what moves on an
            # upgrade -- and unlike sourcing emsdk it costs no subprocess.
            version_file = (root / _EMSCRIPTEN_VERSION_RELPATH).resolve()
            if not version_file.is_file():
                raise AssemblyAbiError(
                    _tool_world_refusal(f"emscripten version file missing at {version_file}")
                )
            version_digest = _sha256_file(version_file)
        else:
            version_digest = _tool_version_sha256(path, ("--version",))
        identities.append(
            ToolIdentity(role, str(path), _sha256_file(path), version_digest)
        )
    node = resolve_node_executable(root).resolve()
    identities.append(
        ToolIdentity("node", str(node), _sha256_file(node), _tool_version_sha256(node, ("--version",)))
    )
    script = Path(smoke_script).resolve()
    if not script.is_file():
        raise AssemblyAbiError(
            _tool_world_refusal(f"smoke-script is not a file at {script}")
        )
    script_digest = _sha256_file(script)
    identities.append(ToolIdentity("smoke-script", str(script), script_digest, script_digest))

    environment_sorted = tuple(sorted(environment, key=lambda item: item[0]))
    return ToolWorld(
        tuple(sorted(identities, key=lambda item: item.role)),
        compile_argv,
        inspect_argv,
        link_argv,
        instantiate_argv,
        smoke_argv,
        environment_sorted,
    )


# Every unit.c opens with `#include "gnt4_shim.h"` -- verified uniform across
# the staged corpus -- and canonicalization gives each unit its OWN derived
# header. So each translation unit compiles from its own directory, where that
# include resolves to its own header. The old single shared merged header
# cannot express per-unit canonicalization, and rewriting the include would
# edit a verbatim body, which section 3 forbids.
ASSEMBLY_OUTPUT = "assembly.wasm"

_EMCC_COMPILE_FLAGS: tuple[str, ...] = (
    "-O1",
    "-fno-strict-aliasing",
    "-Wno-implicit-function-declaration",
    "-Wno-int-conversion",
    "-Wno-deprecated-non-prototype",
    "-Wno-incompatible-pointer-types",
    "-Wno-pointer-sign",
    "-ferror-limit=0",
)


def bundle_relpaths(unit_name: str) -> tuple[str, str, str]:
    """(source, header, object) relpaths for one unit inside the attempt dir."""
    return (
        f"{unit_name}/unit.c",
        f"{unit_name}/gnt4_shim.h",
        f"{unit_name}/unit.o",
    )


def build_assembly_bundle(
    units: list[UnitArtifact],
    *,
    candidate_name: str,
    repo_root: Path,
    attempt: int,
    behavior_tier: str,
    smoke_script: Path,
    environment: tuple[tuple[str, str], ...] = (),
) -> "AssemblyBundle":
    """Adapt the gate's UnitArtifact window into one deep-module AssemblyBundle.

    Reads each unit's verbatim `unit.c` and its generated `gnt4_shim.h` and
    binds both by digest. Nothing is written and nothing is canonicalized here:
    this is purely the record the planner validates and plans against.

    `candidate_name` must name exactly one member of `units`; the deep module
    requires exactly one candidate role and derives the candidate/window
    bindings from the translation units when they are not supplied.
    """
    from src.port_assembly_abi import AssemblyBundle, BundleTranslationUnit

    if not units:
        raise AssemblyAbiError(
            _tool_world_refusal("assembly bundle requires at least one unit")
        )
    names = [unit.name for unit in units]
    if len(set(names)) != len(names):
        raise AssemblyAbiError(
            _tool_world_refusal("assembly bundle requires unique unit names")
        )
    if names.count(candidate_name) != 1:
        raise AssemblyAbiError(
            _tool_world_refusal(
                f"candidate {candidate_name!r} must appear exactly once in the window"
            )
        )

    emcc = (Path(repo_root) / _TOOL_RELPATHS["emcc"]).resolve()
    inspector = (Path(repo_root) / _TOOL_RELPATHS["object-inspector"]).resolve()

    translation_units: list[BundleTranslationUnit] = []
    compile_argv: list[tuple[str, ...]] = []
    inspect_argv: list[tuple[str, ...]] = []
    for ordinal, unit in enumerate(units):
        source_rel, header_rel, object_rel = bundle_relpaths(unit.name)
        try:
            source = (unit.directory / "unit.c").read_bytes()
            header = (unit.directory / "gnt4_shim.h").read_bytes()
        except OSError as error:
            raise AssemblyAbiError(
                _tool_world_refusal(f"cannot read {unit.name} artifact: {error}")
            ) from error
        unit_compile = (
            str(emcc),
            *_EMCC_COMPILE_FLAGS,
            "-c",
            source_rel,
            "-o",
            object_rel,
        )
        unit_inspect = (str(inspector), "--print-file-name", "--defined-only", object_rel)
        translation_units.append(
            BundleTranslationUnit(
                ordinal,
                unit.name,
                "candidate" if unit.name == candidate_name else "window",
                source_rel,
                source,
                hashlib.sha256(source).hexdigest(),
                header_rel,
                header,
                hashlib.sha256(header).hexdigest(),
                object_rel,
                unit_compile,
            )
        )
        compile_argv.append(unit_compile)
        inspect_argv.append(unit_inspect)

    objects = tuple(item.object_relpath for item in translation_units)
    world = build_tool_world(
        repo_root,
        compile_argv=tuple(compile_argv),
        inspect_argv=tuple(inspect_argv),
        link_argv=(str(emcc), "--no-entry", *objects, "-o", ASSEMBLY_OUTPUT),
        instantiate_argv=(str(resolve_node_executable(Path(repo_root))), "-e", "instantiate"),
        smoke_argv=(str(resolve_node_executable(Path(repo_root))), str(Path(smoke_script).resolve())),
        smoke_script=smoke_script,
        environment=environment,
    )
    return AssemblyBundle(
        candidate_name,
        attempt,
        behavior_tier,  # type: ignore[arg-type]
        tuple(translation_units),
        world,
    )


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
CLASS_CANONICALIZATION_REFUSED = "canonicalization_refused"
CLASS_LINK_FAILURE = "link_failure"
CLASS_INSTANTIATION_FAILURE = "instantiation_failure"
# G2/H3 dispatch companion (src/port_dispatch_companion.py): the window's
# address-keyed uniform-ABI table could not be derived, compiled, or linked.
# Always a loud refusal -- a window whose companion fails must never pass
# silently without its dispatch table (design V4 H3: misses are DEFINED
# behavior; an absent table is not).
CLASS_DISPATCH_COMPANION_FAILED = "dispatch_companion_failed"

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


def header_defines_external_functions(header_text: str) -> list[str]:
    """Non-static function definitions in a shim header.

    A shim header may legitimately carry `static inline` helpers -- the seed has
    two. A NON-static definition is different in kind: it creates a real symbol,
    silently replacing the ROM function of that name with whatever body it
    carries. The compile-fix model reaches for exactly this as a shortcut to
    make a unit link, e.g. `void FUN_801336a4(void) { }`.

    Returns the offending symbol names, sorted.
    """
    found: set[str] = set()
    for chunk in parse_header_chunks(header_text):
        if chunk.kind != "function_def" or chunk.symbol is None:
            continue
        head = strip_comments(chunk.text).lstrip()
        if head.startswith('static') and not (
            len(head) > 6 and (head[6].isalnum() or head[6] == '_')
        ):
            continue
            continue
        found.add(chunk.symbol)
    return sorted(found)


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
    lines = (error_text or "").splitlines()
    for index, line in enumerate(lines):
        for pattern, conflict_class in _LINK_PATTERNS:
            match = pattern.search(line)
            if not match:
                continue
            key = (conflict_class, match.group(1))
            if key in seen:
                continue
            seen.add(key)
            # wasm-ld attributes a signature/duplicate diagnostic on the
            # following ">>> defined as (f64, i32) -> void in unit_2.o" lines.
            # The ledger `detail` elsewhere keeps only the tail of stderr (the
            # echoed link command), so unless captured here the attribution is
            # lost and diagnosis needs a scratch link reproduction.
            detail = line.strip()
            for follow in lines[index + 1 : index + 7]:
                if not follow.lstrip().startswith(">>>"):
                    break
                detail += "\n" + follow.strip()
            conflicts.append(
                _conflict_record(
                    match.group(1), conflict_class, units, {}, detail
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
BACKFILL_REQUIRED_COMMITTED_FILES = frozenset(
    (*REQUIRED_ARTIFACTS, "unit.wasm")
)
BACKFILL_ALLOWED_IGNORED_EVIDENCE = frozenset({"oracle.log"})


@dataclass
class UnitArtifact:
    name: str
    directory: Path
    sha256: str
    generated_at: str
    exports: list[str]
    allowed_extra_imports: list[str]
    tier: str
    canonical: dict[str, Any] | None = None


@dataclass(frozen=True)
class CanonicalStateSnapshot:
    """One stable, digest-bound view of canonical unit eligibility."""

    path: Path
    sha256: str
    units: dict[str, dict[str, Any]]


ELIGIBLE_CANONICAL_TIERS = frozenset({"compile_only", "oracle_green"})
LegacyArtifactVerifier = Callable[
    [UnitArtifact, dict[str, Any]],
    tuple[dict[str, Any] | None, str | None],
]


def load_canonical_state_snapshot(
    state_path: Path, *, attempts: int = 3
) -> CanonicalStateSnapshot:
    """Read one stable schema-1 canonical state snapshot or fail closed."""
    last_error = "canonical state changed during read"
    for _ in range(max(1, attempts)):
        try:
            before = state_path.stat()
            payload = state_path.read_bytes()
            after = state_path.stat()
        except OSError as error:
            raise ValueError(f"canonical state unavailable: {error}") from error
        if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
            time.sleep(0)
            continue
        try:
            state = json.loads(payload.decode("utf-8-sig"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ValueError("canonical state is malformed") from error
        units = state.get("units") if isinstance(state, dict) else None
        if (
            not isinstance(state, dict)
            or state.get("state_schema") != 1
            or not isinstance(units, dict)
        ):
            raise ValueError("canonical state schema/units are invalid")
        if any(not isinstance(name, str) or not isinstance(record, dict)
               for name, record in units.items()):
            raise ValueError("canonical state contains an invalid unit record")
        return CanonicalStateSnapshot(
            path=state_path,
            sha256=hashlib.sha256(payload).hexdigest(),
            units=units,
        )
    raise ValueError(last_error)


def verify_canonical_state_snapshot(snapshot: CanonicalStateSnapshot) -> bool:
    """True only when a fresh stable read is byte-identical to ``snapshot``."""
    try:
        current = load_canonical_state_snapshot(snapshot.path)
    except ValueError:
        return False
    return current.sha256 == snapshot.sha256


def canonical_artifact_evidence(
    artifact: UnitArtifact,
    record: dict[str, Any] | None,
    *,
    required_tier: str | None,
    state_sha256: str,
    legacy_verifier: LegacyArtifactVerifier | None = None,
) -> tuple[dict[str, Any] | None, str | None]:
    """Return bound eligibility evidence, or one fail-closed exclusion reason."""
    if not isinstance(record, dict):
        return None, "missing-canonical-record"
    status = record.get("status")
    tier = record.get("tier")
    if status != "green":
        return None, f"canonical-status:{status or 'missing'}"
    if tier not in ELIGIBLE_CANONICAL_TIERS:
        return None, f"canonical-tier:{tier or 'missing'}"
    if required_tier is not None and tier != required_tier:
        return None, f"root-tier-mismatch:{tier}"
    if artifact.tier != tier:
        return None, f"artifact-tier-mismatch:{artifact.tier}"
    commit = record.get("commit")
    # Full 40-hex commit SHAs only: a short prefix is not proof-grade
    # identity (it can resolve to several objects, or to none).
    if not isinstance(commit, str) or re.fullmatch(r"[0-9a-f]{40}", commit, re.I) is None:
        return None, "canonical-commit-missing"
    if record.get("pushed") is not True:
        return None, "canonical-push-unconfirmed"
    bound_digest = record.get("candidate_sha256")
    if bound_digest is None:
        if legacy_verifier is None:
            return None, "canonical-artifact-digest-missing"
        binding, reason = legacy_verifier(artifact, record)
        if binding is None:
            return None, reason or "legacy-commit-tree-proof-failed"
        if (
            binding.get("binding") != "legacy-git-tree"
            or binding.get("artifact_sha256") != artifact.sha256
            or binding.get("commit") != commit
        ):
            return None, "legacy-commit-tree-proof-invalid"
        try:
            digest_after_proof = unit_artifact_sha256(artifact.directory)
        except OSError:
            return None, "legacy-artifact-raced"
        if digest_after_proof != artifact.sha256:
            return None, "legacy-artifact-raced"
    else:
        if (
            not isinstance(bound_digest, str)
            or re.fullmatch(r"[0-9a-f]{64}", bound_digest, re.I) is None
        ):
            return None, "canonical-artifact-digest-invalid"
        if bound_digest != artifact.sha256:
            return None, "canonical-artifact-digest-mismatch"
        binding = {
            "binding": "canonical-digest",
            "artifact_sha256": bound_digest,
            "commit": commit,
        }
    revoked = record.get("revoked")
    if revoked is not None and not isinstance(revoked, dict):
        return None, "canonical-revocation-malformed"
    if isinstance(revoked, dict) and revoked.get("previous_commit") == commit:
        return None, "current-lifecycle-revocation-contradiction"
    return {
        "name": artifact.name,
        "artifact_sha256": artifact.sha256,
        "status": status,
        "tier": tier,
        "commit": commit,
        "pushed": True,
        "promotion_transaction_id": record.get("promotion_transaction_id"),
        "promotion_transition_id": record.get("promotion_transition_id"),
        "state_sha256": state_sha256,
        "stale_revocation_ignored": isinstance(revoked, dict),
        "artifact_binding": binding,
    }, None


def unit_artifact_sha256(directory: Path) -> str:
    """Digest the complete artifact tree using framed relative paths/bytes.

    This binds not just C/header/provenance but also the wasm and oracle
    evidence that will be published after T2b. Symlinks are refused so the
    digest never depends on content outside the owned artifact directory.
    """
    digest = hashlib.sha256()
    for path in sorted(directory.rglob("*"), key=lambda item: item.as_posix()):
        if path.is_symlink():
            raise OSError(f"artifact tree contains a symlink: {path}")
        relative = path.relative_to(directory).as_posix().encode("utf-8")
        digest.update(len(relative).to_bytes(4, "big"))
        digest.update(relative)
        if path.is_dir():
            digest.update(b"D")
            continue
        if not path.is_file():
            raise OSError(f"artifact tree contains an unsupported entry: {path}")
        payload = path.read_bytes()
        digest.update(b"F")
        digest.update(len(payload).to_bytes(8, "big"))
        digest.update(payload)
    return digest.hexdigest()


def prove_legacy_artifact_commit_tree(
    artifact: UnitArtifact,
    record: dict[str, Any],
    *,
    repo_root: Path,
    git_runner: Callable[..., Any],
    publication_ref: str = "refs/remotes/origin/port-staging",
    publication_sha: str | None = None,
    required_committed_files: frozenset[str] | None = None,
    allowed_ignored_extras: frozenset[str] | None = None,
) -> tuple[dict[str, Any] | None, str | None]:
    """Prove a digest-less legacy artifact against its recorded product commit.

    The mutable worktree is never treated as authority. By default every file
    and directory must correspond exactly to ``commit:path``. The explicit
    digest-backfill maintenance path may provide a narrow ignored-evidence
    allowlist only to inventory and journal known historical evidence before
    sanctioning the complete raw directory digest.
    """
    commit = record.get("commit")
    if (
        not isinstance(commit, str)
        # Full 40-hex commit SHAs only -- the proof must name exactly one
        # object; abbreviated prefixes are refused.
        or re.fullmatch(r"[0-9a-f]{40}", commit, re.I) is None
    ):
        return None, "legacy-commit-invalid"
    try:
        repo = repo_root.resolve(strict=True)
        directory = artifact.directory.resolve(strict=True)
        relative = directory.relative_to(repo)
    except (OSError, ValueError):
        return None, "legacy-artifact-path-outside-repo"
    if artifact.directory.is_symlink() or not relative.parts:
        return None, "legacy-artifact-path-outside-repo"
    relative_text = relative.as_posix()
    reachability_target = publication_sha or publication_ref
    if publication_sha is not None and re.fullmatch(
        r"[0-9a-f]{40}|[0-9a-f]{64}", publication_sha, re.I
    ) is None:
        return None, "legacy-publication-sha-invalid"
    reachable = git_runner(
        "merge-base", "--is-ancestor", commit, reachability_target
    )
    if reachable.returncode != 0:
        return None, "legacy-commit-unreachable-from-publication-ref"
    tree = git_runner(
        "ls-tree", "-r", "-z", "--full-tree", commit, "--", relative_text
    )
    if tree.returncode != 0:
        return None, "legacy-commit-tree-unavailable"
    prefix = relative_text.rstrip("/") + "/"
    expected_files: dict[str, tuple[str, str]] = {}
    for entry in tree.stdout.split("\0"):
        if not entry:
            continue
        try:
            metadata, path = entry.split("\t", 1)
            mode, object_type, object_id = metadata.split(" ", 2)
        except ValueError:
            return None, "legacy-commit-tree-malformed"
        if (
            object_type != "blob"
            or mode not in {"100644", "100755"}
            or not path.startswith(prefix)
        ):
            return None, "legacy-commit-tree-unsupported-entry"
        local_name = path[len(prefix):]
        if not local_name or local_name in expected_files:
            return None, "legacy-commit-tree-malformed"
        expected_files[local_name] = (mode, object_id)
    if not expected_files:
        return None, "legacy-commit-path-missing"
    required = required_committed_files or frozenset()
    missing_required = sorted(required - set(expected_files))
    if missing_required:
        return None, "legacy-required-file-not-committed:" + missing_required[0]
    object_lengths = {len(object_id) for _mode, object_id in expected_files.values()}
    if object_lengths not in ({40}, {64}):
        return None, "legacy-commit-object-format-unsupported"
    expected_directories = {
        parent.as_posix()
        for name in expected_files
        for parent in Path(name).parents
        if parent != Path(".")
    }
    actual_files: set[str] = set()
    actual_directories: set[str] = set()
    file_inventory: list[dict[str, Any]] = []
    try:
        for path in artifact.directory.rglob("*"):
            if path.is_symlink():
                return None, "legacy-artifact-tree-unsupported-entry"
            name = path.relative_to(artifact.directory).as_posix()
            if path.is_dir():
                actual_directories.add(name)
                continue
            if not path.is_file():
                return None, "legacy-artifact-tree-unsupported-entry"
            actual_files.add(name)
            payload = path.read_bytes()
            file_inventory.append({
                "path": name,
                "size": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
            })
    except OSError:
        return None, "legacy-artifact-unreadable"
    extra_files = actual_files - set(expected_files)
    extra_directories = actual_directories - expected_directories
    if not set(expected_files).issubset(actual_files):
        return None, "legacy-artifact-commit-mismatch"
    ignore_evidence: list[dict[str, str]] = []
    if extra_directories:
        return None, "legacy-extra-directory-not-allowed:" + sorted(extra_directories)[0]
    if extra_files and allowed_ignored_extras is None:
        return None, "legacy-artifact-commit-mismatch"
    for name in sorted(extra_files):
        repo_path = f"{relative_text}/{name}"
        ignored = git_runner("check-ignore", "-v", "--", repo_path)
        is_ignored = ignored.returncode == 0 and bool(ignored.stdout.strip())
        if ignored.returncode not in {0, 1}:
            return None, "legacy-ignore-proof-unavailable:" + name
        if not is_ignored:
            return None, "legacy-extra-not-ignored:" + name
        if name not in (allowed_ignored_extras or frozenset()):
            return None, "legacy-ignored-extra-not-allowlisted:" + name
        ignore_evidence.append({
            "path": name,
            "repo_path": repo_path,
            "classification": "allowed-ignored-evidence",
            "allowlist_entry": name,
            "git_check_ignore": ignored.stdout.strip(),
        })
    try:
        digest_before = unit_artifact_sha256(artifact.directory)
    except OSError:
        return None, "legacy-artifact-unreadable"
    if digest_before != artifact.sha256:
        return None, "legacy-artifact-raced"
    # Git's clean filters are part of the repository's committed-byte model
    # (notably core.autocrlf on this Windows host). ``git diff`` proves the
    # worktree material maps exactly to the recorded tree without mistaking a
    # normal checkout representation for a substitution. The raw directory
    # digest above/below still binds the exact bytes compiled by the gate.
    diff = git_runner(
        "diff", "--no-ext-diff", "--quiet", commit, "--", relative_text
    )
    if diff.returncode == 1:
        return None, "legacy-artifact-commit-mismatch"
    if diff.returncode != 0:
        return None, "legacy-commit-tree-unavailable"
    try:
        digest_after = unit_artifact_sha256(artifact.directory)
    except OSError:
        return None, "legacy-artifact-unreadable"
    if digest_after != artifact.sha256:
        return None, "legacy-artifact-raced"
    tree_digest = hashlib.sha256()
    for name, (mode, object_id) in sorted(expected_files.items()):
        tree_digest.update(f"{mode} {object_id}\0{name}\0".encode("utf-8"))
    return {
        "binding": "legacy-git-tree",
        "artifact_sha256": artifact.sha256,
        "commit": commit,
        "publication_ref": publication_ref,
        "publication_sha": publication_sha or reachability_target,
        "path": relative_text,
        "tree_entry_count": len(expected_files),
        "tree_sha256": tree_digest.hexdigest(),
        "file_inventory": sorted(file_inventory, key=lambda item: item["path"]),
        "uncommitted_files": sorted(actual_files - set(expected_files)),
        "uncommitted_directories": sorted(
            actual_directories - expected_directories
        ),
        "ignored_extra_evidence": ignore_evidence,
        "required_committed_files": sorted(required),
    }, None


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
        sha256=unit_artifact_sha256(directory),
        generated_at=str(provenance.get("generated_at") or ""),
        exports=[str(e) for e in provenance.get("exported_functions") or []],
        allowed_extra_imports=[
            str(e) for e in provenance.get("allowed_extra_imports") or []
        ],
        tier=str(provenance.get("tier") or "unknown"),
    )


def select_recent_green_units(
    roots: list[Path],
    n: int | None,
    *,
    canonical_snapshot: CanonicalStateSnapshot,
    root_tiers: list[str | None] | None = None,
    legacy_verifier: LegacyArtifactVerifier | None = None,
) -> tuple[list[UnitArtifact], dict[str, str]]:
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
    if root_tiers is not None and len(root_tiers) != len(roots):
        raise ValueError("root_tiers must match roots")
    artifacts: list[UnitArtifact] = []
    excluded: dict[str, str] = {}
    seen_names: set[str] = set()
    for root_index, root in enumerate(roots):
        if not root.is_dir():
            continue
        for directory in sorted(root.iterdir()):
            if not directory.is_dir():
                continue
            artifact = load_unit_artifact(directory)
            if artifact is None or artifact.name in seen_names:
                continue
            seen_names.add(artifact.name)
            evidence, reason = canonical_artifact_evidence(
                artifact,
                canonical_snapshot.units.get(artifact.name),
                required_tier=(root_tiers[root_index] if root_tiers else None),
                state_sha256=canonical_snapshot.sha256,
                legacy_verifier=legacy_verifier,
            )
            if evidence is None:
                excluded[artifact.name] = reason or "ineligible"
                continue
            artifact.canonical = evidence
            artifacts.append(artifact)
    artifacts.sort(key=lambda a: (a.generated_at, a.name))
    if n is not None and n > 0:
        artifacts = artifacts[-n:]
    return artifacts, excluded


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
    *,
    candidate: UnitArtifact | None = None,
    selection_evidence: dict[str, Any] | None = None,
    canonicalization: "CanonicalizationRequest | None" = None,
    dispatch_companion: bool = False,
) -> dict[str, Any]:
    """Run one N-unit assembly-gate pass. Pure orchestration: emcc and node
    arrive as injected runners.

    link_runner(workdir, c_file_names, exports, allowed_extra) -> (ok, error)
    smoke_runner(wasm_path) -> (ok, log)

    ``dispatch_companion`` opts the window into the G2/H3 address-keyed
    uniform-ABI dispatch companion (src/port_dispatch_companion.py): an
    additional gate-derived translation unit in the same link, exporting
    __gf_dispatch and declaring the __gf_dispatch_miss host import. Default
    False keeps the live gate byte-identical until the driver deliberately
    opts in (the same introduction discipline as CanonicalizationRequest).
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
        "candidate": (
            {"name": candidate.name, "sha256": candidate.sha256}
            if candidate is not None
            else None
        ),
        "selection": selection_evidence,
    }
    if candidate is not None:
        matching = [unit for unit in units if unit.name == candidate.name]
        exact_match = (
            len(matching) == 1
            and matching[0].directory.resolve() == candidate.directory.resolve()
            and matching[0].sha256 == candidate.sha256
        )
        try:
            digest_now = unit_artifact_sha256(candidate.directory)
        except OSError as error:
            digest_now = f"unreadable:{error}"
        if not exact_match or digest_now != candidate.sha256:
            result["stage"] = "candidate-integrity"
            result["detail"] = (
                f"assembly selection did not bind exact candidate "
                f"{candidate.name}@{candidate.sha256}; observed "
                f"{digest_now} with {len(matching)} matching name(s)"
            )
            return result
    for unit in units:
        try:
            digest_now = unit_artifact_sha256(unit.directory)
        except OSError as error:
            digest_now = f"unreadable:{error}"
        if digest_now != unit.sha256:
            result["stage"] = "artifact-integrity"
            result["detail"] = (
                f"selected artifact {unit.name} changed before assembly: "
                f"expected {unit.sha256}, observed {digest_now}"
            )
            return result
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
    if canonicalization is not None:
        # Owner-derived canonicalization (spec section 3). Replaces the
        # registry-less textual merge entirely: each unit keeps its own header,
        # canonicalized against the unique verified owner definition, so the
        # linker sees one ABI per symbol instead of one per caller guess.
        canonical = _canonicalize_window(
            units, workdir, candidate, canonicalization, result
        )
        if canonical is None:
            return result
        c_files, canonical_evidence = canonical
        result["canonicalization"] = canonical_evidence
        return _link_and_smoke(
            result,
            units,
            names,
            workdir,
            c_files,
            link_runner,
            smoke_runner,
            candidate,
            dispatch_companion=dispatch_companion,
        )

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

    return _link_and_smoke(
        result,
        units,
        names,
        workdir,
        c_files,
        link_runner,
        smoke_runner,
        candidate,
        dispatch_companion=dispatch_companion,
    )


@dataclass(frozen=True)
class CanonicalizationRequest:
    """Everything owner-derived canonicalization needs, supplied by the driver.

    Passing this to run_assembly_gate opts one composition into spec section 3.
    Omitting it leaves the registry-less merge path byte-identical, so the live
    gate does not change behaviour until the driver deliberately supplies an
    owner snapshot.
    """

    repo_root: Path
    owner_snapshot: Any
    attempt: int
    behavior_tier: str
    smoke_script: Path
    environment: tuple[tuple[str, str], ...] = ()
    # The canonical SDK seed (gnt4_shim_seed.h). When set, the gate reads it
    # FRESH at gate time and unifies divergent gnt4_* declarations in the
    # derived headers to the seed's canon (or refuses loudly). None keeps
    # gnt4_* declarations passing through untouched, exactly as before.
    sdk_seed_path: Path | None = None


def _canonicalization_refusal(
    result: dict[str, Any],
    names: list[str],
    code: str,
    detail: str,
    symbol: str | None = None,
) -> None:
    result["stage"] = "canonicalize"
    result["conflicts"] = [
        _conflict_record(
            symbol, CLASS_CANONICALIZATION_REFUSED, names, {}, f"{code}: {detail}"[:600]
        )
    ]
    result["detail"] = f"{code}: {detail}"[:1200]


def _canonicalize_window(
    units: list[UnitArtifact],
    workdir: Path,
    candidate: UnitArtifact | None,
    request: CanonicalizationRequest,
    result: dict[str, Any],
) -> tuple[list[str], dict[str, Any]] | None:
    """Plan and materialize the owner-canonicalized bundle.

    Returns (c_files, evidence), or None with `result` populated by a contested
    refusal. Planning is whole-bundle and in memory; nothing is written until
    the plan succeeds, so a refusal leaves no partial canonical bundle.
    """
    from src.port_assembly_abi import CanonicalizationPlan, plan_canonicalization

    names = [unit.name for unit in units]
    candidate_name = candidate.name if candidate is not None else units[-1].name
    try:
        bundle = build_assembly_bundle(
            units,
            candidate_name=candidate_name,
            repo_root=request.repo_root,
            attempt=request.attempt,
            behavior_tier=request.behavior_tier,
            smoke_script=request.smoke_script,
            environment=request.environment,
        )
    except AssemblyAbiError as error:
        _canonicalization_refusal(
            result, names, error.refusal.code, error.refusal.detail
        )
        return None

    sdk_canon = None
    sdk_evidence: dict[str, Any] | None = None
    if request.sdk_seed_path is not None:
        # Read fresh every gate run: the seed is the owner authority for SDK
        # (gnt4_*) declarations, and a stale in-process copy would silently
        # re-create the divergence this pass exists to close. Fail closed --
        # a configured-but-unreadable seed must not degrade to the old
        # pass-through behaviour.
        try:
            seed_bytes = Path(request.sdk_seed_path).read_bytes()
        except OSError as error:
            _canonicalization_refusal(
                result,
                names,
                "sdk_canon_unavailable",
                f"cannot read SDK canon seed {request.sdk_seed_path}: {error}",
            )
            return None
        # Function-level import: port_sdk_decl_injection imports this module
        # at module level, so importing it at the top would be circular.
        from src.port_sdk_decl_injection import canonical_sdk_declarations

        seed_text = seed_bytes.decode("utf-8-sig", errors="replace")
        sdk_canon = canonical_sdk_declarations(seed_text)
        if not sdk_canon:
            # The driver rewrites this file, so torn/garbled/format-drifted
            # content is a real failure mode. A configured seed that parses to
            # ZERO declarations must not silently disable the SDK pass.
            _canonicalization_refusal(
                result,
                names,
                "sdk_canon_unavailable",
                f"configured SDK canon seed {request.sdk_seed_path} yielded "
                "no gnt4_* declarations",
            )
            return None
        sdk_evidence = {
            "seed_path": str(request.sdk_seed_path),
            "seed_sha256": hashlib.sha256(seed_bytes).hexdigest(),
            "declarations": len(sdk_canon),
        }

    plan = plan_canonicalization(bundle, request.owner_snapshot, sdk_canon=sdk_canon)
    if not isinstance(plan, CanonicalizationPlan):
        # Zero or several owners, an owner/catalog contradiction, or a
        # Clang-incompatible declaration variant. All are contested: the gate
        # stops before compile/link rather than picking a winner.
        _canonicalization_refusal(
            result, names, plan.code, plan.detail, getattr(plan, "symbol", None)
        )
        return None

    workdir.mkdir(parents=True, exist_ok=True)
    c_files: list[str] = []
    for item in plan.translation_units:
        source_path = workdir / item.source_relpath
        header_path = workdir / item.header_relpath
        source_path.parent.mkdir(parents=True, exist_ok=True)
        header_path.parent.mkdir(parents=True, exist_ok=True)
        source_path.write_bytes(item.derived_source)
        header_path.write_bytes(item.derived_header)
        c_files.append(item.source_relpath)

    evidence = {
        "receipt_sha256": plan.receipt.sha256,
        "derived_bundle_sha256": plan.receipt.derived_bundle_sha256,
        "registry_sha256": plan.receipt.registry_sha256,
        "tool_world_sha256": plan.receipt.tool_world_sha256,
        "owners": [item.public_dict() for item in plan.owner_bindings],
        # symbol -> 8-hex GC address, from the owner registry's address field.
        # The dispatch companion (G2/H3) uses this as its last-resort address
        # authority for renamed symbols whose final source lost its marker.
        "owner_addresses": {
            item.symbol: item.address for item in plan.owner_bindings
        },
        "compatibility_checks": [item.to_dict() for item in plan.compatibility_checks],
        "discarded_variants": [item.to_dict() for item in plan.discarded_variants],
        "sdk_canon": sdk_evidence,
        # Structural ABI evidence only. This makes no behavioural claim and
        # never raises a unit's verification tier.
        "behavior_claim": None,
    }
    return c_files, evidence


def _emit_dispatch_companion(
    result: dict[str, Any],
    units: list[UnitArtifact],
    names: list[str],
    workdir: Path,
    c_files: list[str],
) -> bool:
    """Derive + write the G2/H3 dispatch companion for this window.

    Reads the FINAL written sources (post-canonicalization when that path
    ran), derives one adapter thunk per (unit, exported symbol), and writes
    the frame-ABI header + companion translation unit into the workdir,
    appending the companion to ``c_files``. Any derivation problem populates
    ``result`` as a loud `dispatch_companion_failed` refusal and returns
    False -- a defined function is never silently skipped (it would become a
    wrong-behavior miss, not a defined one).
    """
    from src.port_dispatch_companion import (
        COMPANION_FILENAME,
        FRAME_HEADER_FILENAME,
        FRAME_HEADER_TEXT,
        companion_evidence,
        derive_window_signatures,
        emit_companion_source,
    )

    result["stage"] = "dispatch-companion"
    source_by_unit: dict[str, str] = {}
    for c_file in c_files:
        parts = Path(c_file).parts
        unit_name = parts[0] if len(parts) > 1 else Path(c_file).stem
        source_by_unit[unit_name] = c_file
    window: list[tuple[str, str, list[str]]] = []
    for unit in units:
        c_file = source_by_unit.get(unit.name)
        if c_file is None:
            result["conflicts"] = [
                _conflict_record(
                    None,
                    CLASS_DISPATCH_COMPANION_FAILED,
                    names,
                    {},
                    f"no written source maps to unit {unit.name}",
                )
            ]
            result["detail"] = (
                f"dispatch companion refused: no written source for {unit.name}"
            )
            return False
        try:
            source_text = (workdir / c_file).read_text(encoding="utf-8-sig")
        except OSError as error:
            result["conflicts"] = [
                _conflict_record(
                    None,
                    CLASS_DISPATCH_COMPANION_FAILED,
                    names,
                    {},
                    f"cannot read written source {c_file}: {error}",
                )
            ]
            result["detail"] = f"dispatch companion refused: unreadable {c_file}"
            return False
        window.append((unit.name, source_text, list(unit.exports)))
    canonicalization = result.get("canonicalization") or {}
    owner_addresses = canonicalization.get("owner_addresses") or {}
    derived = derive_window_signatures(window, owner_addresses)
    if derived.problems:
        result["conflicts"] = [
            _conflict_record(
                problem.symbol,
                CLASS_DISPATCH_COMPANION_FAILED,
                [problem.unit],
                {},
                f"{problem.code}: {problem.detail}",
            )
            for problem in derived.problems
        ]
        result["detail"] = (
            "dispatch companion refused: "
            f"{len(derived.problems)} underivable symbol(s); the address-keyed "
            "table must cover every defined function (design V4 H3)"
        )
        return False
    companion_text = emit_companion_source(derived.signatures)
    (workdir / FRAME_HEADER_FILENAME).write_text(
        FRAME_HEADER_TEXT, encoding="utf-8", newline="\n"
    )
    (workdir / COMPANION_FILENAME).write_text(
        companion_text, encoding="utf-8", newline="\n"
    )
    c_files.append(COMPANION_FILENAME)
    result["dispatch"] = companion_evidence(derived.signatures, companion_text)
    return True


def _link_and_smoke(
    result: dict[str, Any],
    units: list[UnitArtifact],
    names: list[str],
    workdir: Path,
    c_files: list[str],
    link_runner: Callable[[Path, list[str], list[str], list[str]], tuple[bool, str]],
    smoke_runner: Callable[[Path], tuple[bool, str]] | None,
    candidate: UnitArtifact | None,
    dispatch_companion: bool = False,
) -> dict[str, Any]:
    """Link, smoke, and re-verify artifact integrity.

    Shared by the registry-less merge path and the owner-derived
    canonicalization path so both compose under identical settings -- the gate
    must never pass under laxer conditions on one route than the other.
    """
    if dispatch_companion:
        # G2/H3: emit the address-keyed uniform-ABI dispatch companion as an
        # additional derived translation unit in the SAME link. Additive: the
        # existing merge/canonicalize/link semantics are untouched; companion
        # failure is its own loud refusal class.
        if not _emit_dispatch_companion(result, units, names, workdir, c_files):
            return result
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
    if dispatch_companion:
        from src.port_dispatch_companion import DISPATCH_EXPORT, MISS_IMPORT

        exports.append(DISPATCH_EXPORT)
        allowed_extra.append(MISS_IMPORT)
    result["stage"] = "link"
    ok, error_text = link_runner(workdir, c_files, exports, allowed_extra)
    if not ok:
        conflicts = conflicts_from_link_error(error_text, names)
        if dispatch_companion and "gf_dispatch_companion" in (error_text or ""):
            from src.port_dispatch_companion import COMPANION_FILENAME

            # The companion is gate-derived, so a compile/link diagnostic that
            # names it is a companion failure, not a unit conflict: file it
            # under the dispatch class so the refusal is attributable.
            conflicts.insert(
                0,
                _conflict_record(
                    None,
                    CLASS_DISPATCH_COMPANION_FAILED,
                    names,
                    {},
                    f"{COMPANION_FILENAME} implicated in link failure: "
                    + (error_text or "").strip()[-400:],
                ),
            )
        result["conflicts"] = conflicts
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

    for unit in units:
        try:
            digest_after = unit_artifact_sha256(unit.directory)
        except OSError as error:
            digest_after = f"unreadable:{error}"
        if digest_after != unit.sha256:
            result["stage"] = (
                "candidate-integrity"
                if candidate is not None and unit.name == candidate.name
                else "artifact-integrity"
            )
            result["detail"] = (
                f"selected artifact {unit.name} changed during assembly: expected "
                f"{unit.sha256}, observed {digest_after}"
            )
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


def read_gate_ledger(ledger_path: Path) -> dict[str, Any] | None:
    """Best-effort read of the tracked assembly ledger. Returns None for a
    missing, corrupt, or wrong-schema file (record_gate_result then rebuilds)."""
    try:
        ledger = json.loads(ledger_path.read_text(encoding="utf-8-sig"))
        if ledger.get("schema") != GATE_LEDGER_SCHEMA:
            return None
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return None
    return ledger if isinstance(ledger, dict) else None


_CONFLICT_CHURN_FIELDS = ("first_seen", "last_seen", "times_seen")


def gate_ledger_material(ledger: dict[str, Any] | None) -> dict[str, Any]:
    """The subset of the ledger whose change is worth a commit: conflict
    identity and the largest-N-passed G1 metric. Excludes the fields every
    run churns regardless of outcome (last_run, updated_at, runs_total) and
    the per-conflict recurrence bookkeeping (times_seen, first/last_seen) --
    a recurring already-filed conflict is not new information."""
    if not isinstance(ledger, dict):
        return {}
    conflicts: dict[str, Any] = {}
    for key, entry in (ledger.get("conflicts") or {}).items():
        if isinstance(entry, dict):
            conflicts[key] = {
                field: value
                for field, value in entry.items()
                if field not in _CONFLICT_CHURN_FIELDS
            }
        else:
            conflicts[key] = entry
    return {
        "largest_n_passed": int(ledger.get("largest_n_passed", 0)),
        "conflicts": conflicts,
    }


def record_gate_result(ledger_path: Path, result: dict[str, Any]) -> dict[str, Any]:
    """Fold one gate result into the tracked assembly ledger. Returns the
    updated ledger payload. NOTE: last_run/updated_at/runs_total change on
    EVERY call -- callers deciding whether the update deserves a commit must
    compare gate_ledger_material() views, not the raw payload."""
    ledger = read_gate_ledger(ledger_path)
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
        "candidate": result.get("candidate"),
    }
    ledger["updated_at"] = now
    ledger_path.parent.mkdir(parents=True, exist_ok=True)
    atomic_write_json(ledger_path, ledger)
    return ledger
