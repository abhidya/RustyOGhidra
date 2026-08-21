"""Knowledge registry, ADVISORY mode (design section 2.11, tranche T2c
[V4-1, V4-5, V4-6, V4-7, V4-8]).

All 1,396 queue units are extractions of ONE program sharing one flat address
space; before this module each re-derived typedefs, ``DAT_`` typings, and
prototypes from the same cold seed. The registry makes green-time decisions
reusable and, by the same stroke, becomes the assembly reconciliation ledger
(design section 3).

THE BINDING CONSTRAINT -- v3's registry FAILED adversarial review as an echo
chamber (finding F1, BLOCKING): a registry that instructs agreement measures
obedience, not correctness, and suppresses its own conflict detection. v4's
answer, implemented here:

  * ``compile_only`` entries are ADVISORY ONLY. They are injected as a
    COMMENTED block -- no active ``#define``, no do-not-alter rule, and no
    survival check of any kind. The unit derives its own typing with the hint
    in view; at harvest the independent derivation is compared against the
    advisory entry and disagreement is recorded as a conflict. Independent
    derivation IS the conflict detector.
  * Authoritative injection (active lines + do-not-alter rule + semantic
    survival check) is reserved for the ``oracle_green`` tier alone --
    entries established by behaviourally-verified units.
  * The registry NEVER settles, suppresses, or auto-resolves a conflict.
    Every disagreement is recorded in the losing-or-tied entry's
    ``conflicts[]`` and surfaced through events the caller emits; a
    same-tier contested symbol is not injected at all (presenting a
    coin-flip is worse than a cold start), and an oracle-green vs
    oracle-green disagreement pages the owner.
  * A deterministic 10% of units (by unit-name hash) receive NO injection --
    the F6 holdout; the agreement rate between holdout-derived typings and
    registry entries is the registry-correctness metric.

Harvest exclusions (what makes the tier ladder populatable without
poisoning, [V4-1]):

  * Seed-inherited content is never harvested: any active line already in
    the (augmented) seed the unit started from is not that unit's decision;
    harvesting it would launder the seed back into "evidence". Advisory
    lines are comments in the seed, so a unit that ADOPTS one has made it
    an active line of its own header -- that adoption is harvested as
    agreement evidence (the per-entry replication experiment, at zero extra
    calls).
  * Stub definitions for functions the unit calls but does not define are
    never harvested: a green unit necessarily stubs its callees, and those
    stubs are scaffolding assembly must replace, not knowledge to honour.
  * Definition-derived prototypes outrank call-site guesses: the prelude
    prototype of a function the unit DEFINES comes from Ghidra's own
    signature markers and is the arbiter for the three-way call-site
    disagreements the T2b backfill filed (docs/t2b-backfill-report.md,
    class 2 resolution 1 and 3). The losing call-site variant is recorded
    in ``conflicts[]``, never silently dropped -- arbitration decides what
    is PRESENTED, not what is remembered.

Import direction: src/port_wasm_units.py imports this module; this module
imports only src/port_assembly_gate.py (parsing/normalization helpers) and
src/port_chunk_workflow.py (atomic JSON I/O). Never the reverse.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from src.port_assembly_gate import (
    _C_KEYWORDS,
    _declaration_normal,
    _function_declarations,
    parse_header_chunks,
    prelude_region,
    scan_function_definitions,
    strip_comments,
)
from src.port_chunk_workflow import atomic_write_json, utc_now

REGISTRY_SCHEMA = 1
# In-repo, versioned by git AND by this monotonic counter (the counter is what
# section 2.8's world-changed gating compares; git history is the audit
# trail). The directory is wholesale-gitignored (GotYaForce .gitignore:63), so
# the path needs the negation exception shipped with this tranche [V4-8].
REGISTRY_RELPATH = (
    "research/decomp/generated/finish-game-port/knowledge-registry.json"
)

TIER_SEED = "seed"
TIER_COMPILE_ONLY = "compile_only"
TIER_ORACLE_GREEN = "oracle_green"
TIER_RANK = {TIER_SEED: 0, TIER_COMPILE_ONLY: 1, TIER_ORACLE_GREEN: 2}

KIND_DAT = "dat_typing"
KIND_PROTOTYPE = "prototype"
KIND_PSEUDO_OP = "pseudo_op"
KIND_TYPEDEF = "typedef"

_DAT_NAME = re.compile(r"^(?:PTR_)?DAT_[0-9a-fA-F]{8}$")
_DAT_OCCURRENCE = re.compile(r"\b(?:PTR_)?DAT_[0-9a-fA-F]{8}\b")
_PSEUDO_OP_NAME = re.compile(r"^(?:CONCAT|SUB|ZEXT|SEXT)\d{1,3}(?:_INT)?$")
_CALL_SITE = re.compile(r"\b([A-Za-z_]\w*)\s*\(")
_TYPEDEFISH = re.compile(
    r"\b(?:undefined\d?|byte|ushort|uint|ulong|ulonglong|longlong|code)\b"
)

# F6 holdout fraction, percent. Deterministic by unit-name hash so the
# assignment survives restarts and is auditable offline.
DEFAULT_HOLDOUT_PERCENT = 10


def holdout_percent() -> int:
    try:
        return max(
            0,
            min(
                100,
                int(
                    os.getenv(
                        "OGHIDRA_PORT_REGISTRY_HOLDOUT_PCT",
                        str(DEFAULT_HOLDOUT_PERCENT),
                    )
                ),
            ),
        )
    except ValueError:
        return DEFAULT_HOLDOUT_PERCENT


def is_holdout(unit_name: str) -> bool:
    """F6 [V4-1]: a deterministic slice of units receives no injection at
    all. Holdout units derive every typing independently; the agreement rate
    between their derivations and registry entries is the correctness
    metric an echo chamber cannot fake."""
    digest = hashlib.sha256(unit_name.encode("utf-8")).digest()
    return int.from_bytes(digest[:4], "big") % 100 < holdout_percent()


# ---------------------------------------------------------------------------
# Registry file


def empty_registry(program: str = "gnt4") -> dict[str, Any]:
    return {
        "registry_schema": REGISTRY_SCHEMA,
        "program": program,
        "version": 0,
        "updated_at": utc_now(),
        "entries": {},
    }


def load_registry(path: Path) -> dict[str, Any]:
    """Load the registry; a missing file is an empty version-0 registry.

    An UNREADABLE or foreign-schema file raises: silently replacing a
    corrupted registry with an empty one would reset the version counter and
    un-explain every recorded ``registry_version_used`` -- the caller must
    decide, loudly."""
    try:
        payload = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    except FileNotFoundError:
        return empty_registry()
    if (
        not isinstance(payload, dict)
        or payload.get("registry_schema") != REGISTRY_SCHEMA
        or not isinstance(payload.get("entries"), dict)
    ):
        raise ValueError(
            f"knowledge registry at {path} has an unexpected schema; refusing "
            "to silently replace it (the version counter explains past "
            "injections)"
        )
    return payload


def save_registry(path: Path, registry: dict[str, Any]) -> None:
    registry["updated_at"] = utc_now()
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    atomic_write_json(Path(path), registry)


def registry_version(registry: dict[str, Any]) -> int:
    try:
        return int(registry.get("version", 0))
    except (TypeError, ValueError):
        return 0


def _bump_version(registry: dict[str, Any]) -> int:
    registry["version"] = registry_version(registry) + 1
    return registry["version"]


def entry_key(kind: str, symbol: str) -> str:
    if kind == KIND_DAT:
        return f"dat:0x{symbol.split('DAT_')[-1].lower()}"
    if kind == KIND_PROTOTYPE:
        return f"fn:{symbol}"
    if kind == KIND_PSEUDO_OP:
        return f"macro:{symbol}"
    return f"typedef:{symbol}"


# ---------------------------------------------------------------------------
# Normalization ([V4-6]: semantic, not verbatim -- whitespace/comment
# insensitive token sequences; prototypes by normalized signature)


def _macro_normal(text: str) -> str:
    tokens = re.findall(r"[A-Za-z_]\w*|0[xX][0-9a-fA-F]+|\d+|[^\s\w]", strip_comments(text))
    return " ".join(tokens)


def normalized_form(kind: str, text: str) -> str:
    if kind == KIND_PROTOTYPE:
        return _declaration_normal(text)
    return _macro_normal(text)


# ---------------------------------------------------------------------------
# Unit symbol set (section 2.11 injection relevance = symbol/address
# intersection, nothing fuzzier)


def prelude_prototypes(prelude_text: str) -> dict[str, str]:
    """symbol -> normalized signature for every declaration in the unit's
    generated prelude (Ghidra's own signatures; they outrank injection)."""
    return _function_declarations(prelude_text or "")


def unit_symbol_set(unit_c_text: str, exports: list[str] | None = None) -> set[str]:
    """``DAT_<hex8>`` / ``PTR_DAT_<hex8>`` occurrences plus prelude, export
    and callee identifiers plus Ghidra typedef/pseudo-op tokens. Locals never
    make the set (they are call-shaped or DAT-shaped only if real)."""
    text = strip_comments(unit_c_text or "")
    symbols: set[str] = set(_DAT_OCCURRENCE.findall(text))
    symbols.update(exports or [])
    for match in _CALL_SITE.finditer(text):
        name = match.group(1)
        if name not in _C_KEYWORDS:
            symbols.add(name)
    symbols.update(_TYPEDEFISH.findall(text))
    symbols.update(_function_declarations(prelude_region(unit_c_text or "")))
    return symbols


# ---------------------------------------------------------------------------
# Harvest (mechanical, no LLM -- [V4-1])


@dataclass
class HarvestResult:
    added: list[str] = field(default_factory=list)
    agreed: list[str] = field(default_factory=list)
    new_conflicts: list[dict[str, Any]] = field(default_factory=list)
    changed: bool = False
    version: int = 0


def _seed_inherited(seed_text: str) -> set[tuple[str, str]]:
    """(bucket, normalized) pairs of every ACTIVE chunk in the augmented seed.
    Comments are stripped by the parser, so advisory-commented registry lines
    are NOT seed-inherited -- a unit that adopts one has made a decision."""
    inherited: set[tuple[str, str]] = set()
    for chunk in parse_header_chunks(seed_text or ""):
        if chunk.symbol is None:
            continue
        bucket = "decl" if chunk.kind == "function_decl" else chunk.kind
        normal = (
            _declaration_normal(chunk.text)
            if chunk.kind == "function_decl"
            else _macro_normal(chunk.text)
        )
        inherited.add((bucket, f"{chunk.symbol}|{normal}"))
    return inherited


def harvest_candidates(
    seed_text: str, header_text: str, unit_c_text: str
) -> list[dict[str, Any]]:
    """The unit's own decisions, mechanically extracted (design 2.11 harvest):
    diff the winning header against the unit's AUGMENTED seed; keep DAT
    typings, pseudo-op macros, typedefs and prototype declarations; exclude
    seed-inherited lines and callee stub definitions; add the
    definition-derived prelude prototypes of functions the unit defines."""
    inherited = _seed_inherited(seed_text)
    defined = scan_function_definitions(unit_c_text or "")
    candidates: list[dict[str, Any]] = []
    seen: set[str] = set()

    def push(kind: str, symbol: str, text: str, derivation: str | None = None) -> None:
        key = entry_key(kind, symbol)
        if key in seen:
            return
        seen.add(key)
        candidate: dict[str, Any] = {
            "kind": kind,
            "symbol": symbol,
            "text": " ".join(text.split()) if kind != KIND_PROTOTYPE else text.strip(),
            "normal": normalized_form(kind, text),
        }
        if derivation is not None:
            candidate["derivation"] = derivation
        candidates.append(candidate)

    for chunk in parse_header_chunks(header_text or ""):
        if chunk.symbol is None:
            continue
        if chunk.kind == "function_def":
            # Callee-stub exclusion [V4-1]: a definition living in the HEADER
            # is scaffolding the unit faked to link (real definitions live in
            # the verbatim unit.c) -- never knowledge.
            continue
        if chunk.kind == "macro":
            if _DAT_NAME.match(chunk.symbol):
                if ("macro", f"{chunk.symbol}|{_macro_normal(chunk.text)}") in inherited:
                    continue  # seed-inherited: not this unit's decision
                push(KIND_DAT, chunk.symbol, chunk.text)
            elif _PSEUDO_OP_NAME.match(chunk.symbol):
                if ("macro", f"{chunk.symbol}|{_macro_normal(chunk.text)}") in inherited:
                    continue
                push(KIND_PSEUDO_OP, chunk.symbol, chunk.text)
            continue
        if chunk.kind == "typedef":
            if ("typedef", f"{chunk.symbol}|{_macro_normal(chunk.text)}") in inherited:
                continue
            push(KIND_TYPEDEF, chunk.symbol, chunk.text)
            continue
        if chunk.kind == "function_decl":
            if chunk.symbol in defined:
                continue  # the prelude's definition-derived form wins below
            if ("decl", f"{chunk.symbol}|{_declaration_normal(chunk.text)}") in inherited:
                continue
            push(KIND_PROTOTYPE, chunk.symbol, chunk.text, derivation="call_site")
            continue
        if chunk.kind == "var_decl" and _DAT_NAME.match(chunk.symbol):
            # Review F1: a unit that re-expresses a DAT symbol as a VARIABLE
            # declaration (`extern unsigned short DAT_...;`) has made a typing
            # decision every bit as consequential as a macro -- and one that
            # diverges from the flat-memory absolute-address model. Harvesting
            # it lets the normal disagreement machinery detect macro-vs-
            # variable typing divergence instead of silently dropping it.
            if ("var_decl", f"{chunk.symbol}|{_macro_normal(chunk.text)}") in inherited:
                continue
            push(KIND_DAT, chunk.symbol, chunk.text, derivation="var_decl")
            continue

    # Definition-derived prototypes: the prelude prototype of a function the
    # unit DEFINES comes from Ghidra's own signature for the defining chunk --
    # the arbiter the T2b backfill's three-way disagreements need.
    prelude_decls = _function_declarations(prelude_region(unit_c_text or ""))
    for symbol in sorted(defined):
        normal = prelude_decls.get(symbol)
        if normal:
            candidate_key = entry_key(KIND_PROTOTYPE, symbol)
            if candidate_key in seen:
                # header re-declared a function the unit defines; the
                # definition-derived form replaces the header's copy.
                candidates[:] = [c for c in candidates if entry_key(c["kind"], c["symbol"]) != candidate_key]
                seen.discard(candidate_key)
            push(KIND_PROTOTYPE, symbol, normal + ";", derivation="definition")
    return candidates


def _conflict_entry(
    unit_name: str,
    losing_text: str,
    reason: str,
    *,
    tier: str,
    derivation: str | None = None,
) -> dict[str, Any]:
    record: dict[str, Any] = {
        "unit": unit_name,
        "text": losing_text[:400],
        "tier": tier,
        "reason": reason,
        "recorded_at": utc_now(),
    }
    if derivation is not None:
        record["derivation"] = derivation
    return record


def _has_conflict(entry: dict[str, Any], unit_name: str, normal: str) -> bool:
    for conflict in entry.get("conflicts") or []:
        if conflict.get("unit") == unit_name and conflict.get("normal") == normal:
            return True
    return False


def harvest_unit(
    registry: dict[str, Any],
    *,
    unit_name: str,
    tier: str,
    seed_text: str,
    header_text: str,
    unit_c_text: str,
    holdout: bool = False,
) -> HarvestResult:
    """Fold one green/staged unit's decisions into the registry.

    Agreement adds the unit as a source (advisory-injection agreement IS
    evidence -- the unit was free to disagree). Disagreement NEVER silently
    wins or loses: higher tier or definition-derivation decides what is
    PRESENTED; the other variant lands in ``conflicts[]``; a same-tier tie
    marks the entry contested (not injected at all) and is returned in
    ``new_conflicts`` for the caller to page/emit. Bumps ``version`` iff
    anything was added or changed."""
    if tier not in (TIER_COMPILE_ONLY, TIER_ORACLE_GREEN):
        raise ValueError(f"harvest tier must be compile_only|oracle_green, got {tier!r}")
    result = HarvestResult(version=registry_version(registry))
    entries = registry.setdefault("entries", {})
    touched_keys: set[str] = set()
    now = utc_now()
    for candidate in harvest_candidates(seed_text, header_text, unit_c_text):
        key = entry_key(candidate["kind"], candidate["symbol"])
        normal = candidate["normal"]
        derivation = candidate.get("derivation")
        entry = entries.get(key)
        if entry is None or entry.get("revoked"):
            entry = {
                "kind": candidate["kind"],
                "symbol": candidate["symbol"],
                "tier": tier,
                "source_units": [unit_name],
                "source_tiers": {unit_name: tier},
                "harvested_at": now,
                "contested": False,
                "conflicts": list((entry or {}).get("conflicts") or []),
            }
            if candidate["kind"] == KIND_DAT:
                entry["address"] = "0x" + candidate["symbol"].split("DAT_")[-1].lower()
            if candidate["kind"] in (KIND_DAT, KIND_PSEUDO_OP):
                entry["macro"] = candidate["text"]
            else:
                entry["declaration"] = candidate["text"]
            if derivation is not None:
                entry["derivation"] = derivation
            if holdout:
                entry.setdefault("holdout_sources", []).append(unit_name)
            entries[key] = entry
            result.added.append(key)
            touched_keys.add(key)
            continue
        presented_text = entry.get("macro") or entry.get("declaration") or ""
        presented_normal = normalized_form(entry.get("kind", candidate["kind"]), presented_text)
        if presented_normal == normal:
            # Agreement: independent replication (or holdout replication --
            # the F6 numerator). Recorded either way; never a conflict.
            if unit_name not in (entry.get("source_units") or []):
                entry.setdefault("source_units", []).append(unit_name)
                entry.setdefault("source_tiers", {})[unit_name] = tier
                if holdout:
                    entry.setdefault("holdout_sources", []).append(unit_name)
                # Review F3 tightening: agreement records EVIDENCE but never
                # raises tier. An oracle-verified unit that merely ADOPTED the
                # advisory hint would otherwise promote the entry to
                # oracle_green in one pass, bypassing [V4-7]'s
                # promotion-recompute -- the closest residual echo path. Tier
                # promotion happens only through promote_unit_entries.
                touched_keys.add(key)
            result.agreed.append(key)
            continue
        # Disagreement. Decide what is PRESENTED; record the rest. Never
        # silently drop either side, never un-record an existing conflict.
        old_tier = entry.get("tier", TIER_COMPILE_ONLY)
        old_derivation = entry.get("derivation")
        new_wins: bool
        arbiter: str
        if candidate["kind"] == KIND_PROTOTYPE and derivation != old_derivation and (
            derivation == "definition" or old_derivation == "definition"
        ):
            # The defining chunk is the arbiter (t2b-backfill class 2): a
            # definition-derived prototype outranks any call-site guess.
            new_wins = derivation == "definition"
            arbiter = "definition-derived prototype outranks call-site guess"
        elif TIER_RANK.get(tier, 0) != TIER_RANK.get(old_tier, 0):
            new_wins = TIER_RANK.get(tier, 0) > TIER_RANK.get(old_tier, 0)
            arbiter = "higher tier wins presentation"
        else:
            # Same tier, same derivation class: contested. Present neither
            # (a coin-flip hint is worse than a cold start), record both.
            entry["contested"] = True
            if not _has_conflict(entry, unit_name, normal):
                conflict = _conflict_entry(
                    unit_name,
                    candidate["text"],
                    "same-tier disagreement: symbol contested, injection disabled",
                    tier=tier,
                    derivation=derivation,
                )
                conflict["normal"] = normal
                entry.setdefault("conflicts", []).append(conflict)
                touched_keys.add(key)
                surfaced = {
                    "key": key,
                    "symbol": candidate["symbol"],
                    "kind": candidate["kind"],
                    "unit": unit_name,
                    "tier": tier,
                    "against_tier": old_tier,
                    "contested": True,
                    "green_green": tier == TIER_ORACLE_GREEN
                    and old_tier == TIER_ORACLE_GREEN,
                }
                result.new_conflicts.append(surfaced)
            continue
        if new_wins:
            losing = _conflict_entry(
                ", ".join(entry.get("source_units") or []) or "unknown",
                presented_text,
                f"superseded: {arbiter}",
                tier=old_tier,
                derivation=old_derivation,
            )
            losing["normal"] = presented_normal
            entry.setdefault("conflicts", []).append(losing)
            if candidate["kind"] in (KIND_DAT, KIND_PSEUDO_OP):
                entry["macro"] = candidate["text"]
                entry.pop("declaration", None)
            else:
                entry["declaration"] = candidate["text"]
                entry.pop("macro", None)
            entry["tier"] = tier
            entry["source_units"] = [unit_name]
            entry["source_tiers"] = {unit_name: tier}
            if derivation is not None:
                entry["derivation"] = derivation
            entry["harvested_at"] = now
            entry["contested"] = False
            # Review F4: supersede resets source_units/source_tiers, so the
            # holdout ledger must reset with them -- appending would leave
            # stale holdout attributions on an entry they no longer sourced.
            if holdout:
                entry["holdout_sources"] = [unit_name]
            else:
                entry.pop("holdout_sources", None)
            touched_keys.add(key)
        else:
            if not _has_conflict(entry, unit_name, normal):
                conflict = _conflict_entry(
                    unit_name,
                    candidate["text"],
                    f"outranked: {arbiter}",
                    tier=tier,
                    derivation=derivation,
                )
                conflict["normal"] = normal
                entry.setdefault("conflicts", []).append(conflict)
                touched_keys.add(key)
            else:
                continue
        surfaced = {
            "key": key,
            "symbol": candidate["symbol"],
            "kind": candidate["kind"],
            "unit": unit_name,
            "tier": tier,
            "against_tier": old_tier,
            "contested": False,
            "green_green": tier == TIER_ORACLE_GREEN and old_tier == TIER_ORACLE_GREEN,
        }
        result.new_conflicts.append(surfaced)
    if touched_keys:
        version = _bump_version(registry)
        for key in touched_keys:
            if key in entries:
                entries[key]["updated_version"] = version
        result.changed = True
        result.version = version
    return result


# ---------------------------------------------------------------------------
# Injection ([V4-1, V4-5]: seed/prelude-aware MERGE, tiered by trust)

AUTHORITATIVE_BANNER = (
    "/* ==== REGISTRY (authoritative): these lines were established by\n"
    "   behaviourally-verified units of this same program; do not alter\n"
    "   them -- adapt your other declarations instead. ==== */"
)
ADVISORY_BANNER = (
    "/* ==== REGISTRY (advisory): previous units of this program compiled with\n"
    "   the typings below. Verify each against THIS unit's use sites before\n"
    "   adopting it; you are free to disagree -- a reasoned disagreement is\n"
    "   wanted data. ==== */"
)


@dataclass
class AugmentResult:
    header_text: str
    authoritative: list[dict[str, Any]] = field(default_factory=list)
    advisory: list[dict[str, Any]] = field(default_factory=list)
    pending_conflicts: list[dict[str, Any]] = field(default_factory=list)
    skipped_contested: list[str] = field(default_factory=list)
    registry_changed: bool = False

    @property
    def injected_any(self) -> bool:
        return bool(self.authoritative or self.advisory)


def relevant_entries(
    registry: dict[str, Any], symbols: set[str]
) -> list[tuple[str, dict[str, Any]]]:
    """Relevance = symbol/address intersection, nothing fuzzier."""
    selected: list[tuple[str, dict[str, Any]]] = []
    for key, entry in sorted((registry.get("entries") or {}).items()):
        if entry.get("symbol") in symbols:
            selected.append((key, entry))
    return selected


def relevant_delta(
    registry: dict[str, Any], symbols: set[str], since_version: int
) -> list[str]:
    """Keys of entries touching the symbol set that were added or changed
    after ``since_version`` -- the per-unit registry component of the
    section-2.8 world-changed gate."""
    return [
        key
        for key, entry in relevant_entries(registry, symbols)
        if int(entry.get("updated_version", 0) or 0) > since_version
    ]


def _entry_line(entry: dict[str, Any]) -> str:
    return (entry.get("macro") or entry.get("declaration") or "").strip()


def _comment_safe(text: str) -> str:
    return text.replace("*/", "* /")


def _replace_in_seed(lines: list[str], entry: dict[str, Any]) -> bool:
    """[V4-5] merge, never append: if the seed already carries a line for the
    symbol, the authoritative entry replaces it IN PLACE -- duplicate macro
    definitions poison every fingerprint at best and fork semantics at
    worst. Returns True when a replacement happened."""
    symbol = entry.get("symbol") or ""
    kind = entry.get("kind")
    replacement = _entry_line(entry) + "  /* REGISTRY (authoritative): do not alter */"
    if kind in (KIND_DAT, KIND_PSEUDO_OP):
        pattern = re.compile(rf"^\s*#\s*define\s+{re.escape(symbol)}\b")
    elif kind == KIND_TYPEDEF:
        pattern = re.compile(rf"^\s*typedef\b.*\b{re.escape(symbol)}\s*(?:;|\[)")
    else:
        pattern = re.compile(rf"^\s*(?:extern\s+)?\w[\w\s\*]*\b{re.escape(symbol)}\s*\(.*;\s*$")
    replaced = False
    index = 0
    while index < len(lines):
        if pattern.match(lines[index]):
            # Review F2: replace the LOGICAL line -- a backslash-continued
            # #define spans several physical lines (every live seed carries
            # CONCAT44 in exactly this shape); replacing only the first line
            # would orphan the continuation as a stray expression and hand
            # the model a syntactically broken header.
            end = index
            while end < len(lines) and lines[end].rstrip().endswith("\\"):
                end += 1
            lines[index : end + 1] = [replacement]
            replaced = True
        index += 1
    return replaced


def augment_seed(
    registry: dict[str, Any],
    *,
    unit_name: str,
    seed_text: str,
    symbols: set[str],
    prelude_declarations: dict[str, str] | None = None,
) -> AugmentResult:
    """Assemble the unit's starting header from the seed plus the relevant
    registry entries (design 2.11 injection, [V4-1] tier semantics).

    - ``oracle_green`` entries inject authoritatively: active lines, seed
      lines for the same symbol replaced in place, do-not-alter rule.
    - ``compile_only`` entries inject as a COMMENTED advisory block only.
    - Contested/revoked entries are never injected (``skipped_contested``).
    - A prototype the unit's PRELUDE already declares is never injected: the
      prelude is Ghidra's own signature for this unit and outranks a sibling
      unit's compile-time guess. If the registry entry disagrees with the
      prelude the disagreement is recorded on the entry as a pending
      conflict -- data, surfaced; not an injection (``registry_changed``
      tells the caller to save + emit).

    Holdout units must not reach this function; the caller checks
    ``is_holdout`` first (F6)."""
    prelude_declarations = prelude_declarations or {}
    result = AugmentResult(header_text=seed_text)
    authoritative: list[dict[str, Any]] = []
    advisory: list[dict[str, Any]] = []
    changed = False
    for key, entry in relevant_entries(registry, symbols):
        if entry.get("revoked"):
            continue
        if entry.get("contested"):
            result.skipped_contested.append(key)
            continue
        tier = entry.get("tier", TIER_SEED)
        if tier not in (TIER_COMPILE_ONLY, TIER_ORACLE_GREEN):
            continue  # seed-tier entries ARE the seed; nothing to inject
        if not _entry_line(entry):
            continue
        if entry.get("kind") == KIND_PROTOTYPE and entry.get("symbol") in prelude_declarations:
            prelude_normal = prelude_declarations[entry.get("symbol")]
            entry_normal = _declaration_normal(_entry_line(entry))
            if prelude_normal != entry_normal:
                pending = {
                    "key": key,
                    "symbol": entry.get("symbol"),
                    "kind": KIND_PROTOTYPE,
                    "unit": unit_name,
                    "prelude": prelude_normal,
                    "registry": entry_normal,
                    "pending": True,
                }
                if not _has_conflict(entry, unit_name, prelude_normal):
                    conflict = _conflict_entry(
                        unit_name,
                        prelude_normal,
                        "prelude prototype disagrees with registry entry "
                        "(pending; prelude outranks injection)",
                        tier="prelude",
                        derivation="definition",
                    )
                    conflict["normal"] = prelude_normal
                    entry.setdefault("conflicts", []).append(conflict)
                    changed = True
                    result.pending_conflicts.append(pending)
            continue  # never injected either way: the prelude already declares it
        record = {
            "key": key,
            "symbol": entry.get("symbol"),
            "kind": entry.get("kind"),
            "tier": tier,
            "text": _entry_line(entry),
            "normal": normalized_form(entry.get("kind", KIND_PSEUDO_OP), _entry_line(entry)),
        }
        (authoritative if tier == TIER_ORACLE_GREEN else advisory).append(record)
    if changed:
        version = _bump_version(registry)
        for pending in result.pending_conflicts:
            entry = (registry.get("entries") or {}).get(pending["key"])
            if entry is not None:
                entry["updated_version"] = version
        result.registry_changed = True
    if not authoritative and not advisory:
        return result

    lines = seed_text.splitlines()
    appended: list[str] = []
    if authoritative:
        pending_append = []
        for record in authoritative:
            entry = (registry.get("entries") or {}).get(record["key"]) or record
            if not _replace_in_seed(lines, {**entry, "kind": record["kind"], "symbol": record["symbol"]}):
                pending_append.append(record["text"])
        appended.append("")
        appended.append(AUTHORITATIVE_BANNER)
        for text in pending_append:
            appended.append(text)
    if advisory:
        appended.append("")
        appended.append(ADVISORY_BANNER)
        for record in advisory:
            appended.append(f"/* {_comment_safe(record['text'])} */")
    # Insert before a trailing include-guard #endif so injected lines stay
    # inside the guard; otherwise append at the end.
    insert_at = len(lines)
    for index in range(len(lines) - 1, -1, -1):
        stripped = lines[index].strip()
        if not stripped:
            continue
        if re.match(r"#\s*endif\b", stripped):
            insert_at = index
        break
    lines[insert_at:insert_at] = appended
    result.header_text = "\n".join(lines) + ("\n" if seed_text.endswith("\n") else "")
    result.authoritative = authoritative
    result.advisory = advisory
    return result


# ---------------------------------------------------------------------------
# Survival check ([V4-6]: semantic, oracle-tier only)


def check_survival(
    authoritative: list[dict[str, Any]], header_text: str
) -> list[dict[str, Any]]:
    """Re-parse the applied header and compare normalized token sequences for
    the injected AUTHORITATIVE symbols only. Advisory entries are free to be
    ignored -- that is their point [V4-1] -- so they are never checked. A
    deviation does not abort anything (the header may still compile); the
    caller records it, and if the unit goes green with the deviation the
    harvest comparison turns it into a conflict record."""
    if not authoritative:
        return []
    found: dict[tuple[str, str], str] = {}
    for chunk in parse_header_chunks(header_text or ""):
        if chunk.symbol is None:
            continue
        if chunk.kind == "macro":
            found[("macro", chunk.symbol)] = _macro_normal(chunk.text)
        elif chunk.kind == "typedef":
            found[("typedef", chunk.symbol)] = _macro_normal(chunk.text)
        elif chunk.kind == "function_decl":
            found[("decl", chunk.symbol)] = _declaration_normal(chunk.text)
        elif chunk.kind == "var_decl":
            # Review F1: a macro re-expressed as a variable declaration
            # (`extern unsigned short DAT_...;`) is a deviation WITH a found
            # form -- record it so the eventual conflict carries the unit's
            # actual divergent typing instead of found=None.
            found[("var_decl", chunk.symbol)] = _macro_normal(chunk.text)
    deviations: list[dict[str, Any]] = []
    for record in authoritative:
        kind = record.get("kind")
        bucket = (
            "macro"
            if kind in (KIND_DAT, KIND_PSEUDO_OP)
            else ("typedef" if kind == KIND_TYPEDEF else "decl")
        )
        actual = found.get((bucket, record.get("symbol") or ""))
        if actual is None and bucket == "macro":
            actual = found.get(("var_decl", record.get("symbol") or ""))
        if actual != record.get("normal"):
            deviations.append(
                {
                    "key": record.get("key"),
                    "symbol": record.get("symbol"),
                    "kind": kind,
                    "expected": record.get("normal"),
                    "found": actual,
                }
            )
    return deviations


def record_surviving_deviations(
    registry: dict[str, Any],
    *,
    unit_name: str,
    tier: str,
    deviations: list[dict[str, Any]],
) -> HarvestResult:
    """[V4-6] promise, closed (review F1): a semantic mutation of an
    authoritative line that SURVIVES to green/staged becomes a conflict
    record at harvest. ``harvest_candidates`` catches re-expressions that
    still parse as macro/typedef/decl/DAT-var chunks; this catches the rest
    -- outright DELETION of the injected line, or any re-expression the
    harvest cannot see -- by folding the round-recorded deviations into the
    entry's ``conflicts[]``. Without this, later units keep receiving the
    possibly-wrong authoritative line with zero dissent on the record.

    Dedup is by (unit, normalized found form), same as every other conflict
    path, so a deviation the harvest already filed is not filed twice.
    Bumps ``version`` iff anything changed."""
    result = HarvestResult(version=registry_version(registry))
    entries = registry.get("entries") or {}
    touched: set[str] = set()
    for deviation in deviations or []:
        key = deviation.get("key")
        entry = entries.get(key) if key else None
        if entry is None or entry.get("revoked"):
            continue
        found = deviation.get("found")
        normal = found or ""
        if _has_conflict(entry, unit_name, normal):
            continue  # the harvest comparison already filed this one
        conflict = _conflict_entry(
            unit_name,
            found
            or "(authoritative line deleted or re-expressed beyond the "
            "parser's chunk kinds)",
            "authoritative injection did not survive: unit went green with "
            "a semantic deviation (design 2.11 [V4-6])",
            tier=tier,
        )
        conflict["normal"] = normal
        conflict["expected"] = deviation.get("expected")
        entry.setdefault("conflicts", []).append(conflict)
        green_green = (
            tier == TIER_ORACLE_GREEN and entry.get("tier") == TIER_ORACLE_GREEN
        )
        if green_green:
            entry["green_green"] = True
        touched.add(key)
        result.new_conflicts.append(
            {
                "key": key,
                "symbol": deviation.get("symbol"),
                "kind": deviation.get("kind"),
                "unit": unit_name,
                "tier": tier,
                "against_tier": entry.get("tier"),
                "contested": bool(entry.get("contested")),
                "green_green": green_green,
                "deviation": True,
            }
        )
    if touched:
        version = _bump_version(registry)
        for key in touched:
            entries[key]["updated_version"] = version
        result.changed = True
        result.version = version
    return result


# ---------------------------------------------------------------------------
# Re-tier / demote / revoke ([V4-7]: tiers move in both directions; every
# move bumps version so section-2.8 gating sees demotions like additions)


@dataclass
class RetierResult:
    promoted: list[str] = field(default_factory=list)
    demoted: list[str] = field(default_factory=list)
    revoked: list[str] = field(default_factory=list)
    green_green: list[str] = field(default_factory=list)
    reopened: list[str] = field(default_factory=list)
    changed: bool = False
    version: int = 0


def promote_unit_entries(registry: dict[str, Any], unit_name: str) -> RetierResult:
    """A staged unit passed its oracle: its harvested entries promote
    ``compile_only`` -> ``oracle_green``, and promotion RECOMPUTES conflicts:
    a same-tier-contested symbol may now have a winner (re-enabling
    injection); a collision with an existing ``oracle_green`` escalates to
    the green-green page instead of silently winning by recency."""
    result = RetierResult(version=registry_version(registry))
    entries = registry.get("entries") or {}
    touched: list[str] = []
    for key, entry in entries.items():
        sources = entry.get("source_units") or []
        if unit_name not in sources or entry.get("revoked"):
            continue
        entry.setdefault("source_tiers", {})[unit_name] = TIER_ORACLE_GREEN
        if entry.get("tier") == TIER_COMPILE_ONLY:
            entry["tier"] = TIER_ORACLE_GREEN
            result.promoted.append(key)
            touched.append(key)
        if entry.get("contested"):
            # Recompute: the promoted presentation now outranks compile-only
            # conflict variants -- unless one of them is itself oracle_green.
            conflicting_greens = [
                c
                for c in entry.get("conflicts") or []
                if c.get("tier") == TIER_ORACLE_GREEN and not c.get("tombstone")
            ]
            if conflicting_greens:
                entry["green_green"] = True
                result.green_green.append(key)
            else:
                entry["contested"] = False
                result.reopened.append(key)
            touched.append(key)
    if touched:
        version = _bump_version(registry)
        for key in set(touched):
            entries[key]["updated_version"] = version
        result.changed = True
        result.version = version
    return result


def revoke_unit_entries(registry: dict[str, Any], unit_name: str) -> RetierResult:
    """A failed oracle re-run on a staged unit (F5's scenario) downgrades or
    removes every entry sourced from it: down to ``compile_only`` where
    independent sources remain, otherwise revoked with a tombstone recorded
    in ``conflicts[]`` -- an entry that vanished without trace would
    un-explain past injections."""
    result = RetierResult(version=registry_version(registry))
    entries = registry.get("entries") or {}
    touched: list[str] = []
    for key, entry in entries.items():
        sources = entry.get("source_units") or []
        if unit_name not in sources or entry.get("revoked"):
            continue
        remaining = [unit for unit in sources if unit != unit_name]
        entry["source_units"] = remaining
        (entry.get("source_tiers") or {}).pop(unit_name, None)
        if remaining:
            ranks = [
                TIER_RANK.get(tier, 0)
                for unit, tier in (entry.get("source_tiers") or {}).items()
            ] or [TIER_RANK[TIER_COMPILE_ONLY]]
            demoted_tier = (
                TIER_ORACLE_GREEN
                if max(ranks) >= TIER_RANK[TIER_ORACLE_GREEN]
                else TIER_COMPILE_ONLY
            )
            if entry.get("tier") != demoted_tier:
                entry["tier"] = demoted_tier
                result.demoted.append(key)
        else:
            entry["revoked"] = True
            entry.setdefault("conflicts", []).append(
                {
                    "tombstone": True,
                    "unit": unit_name,
                    "text": _entry_line(entry)[:400],
                    "tier": entry.get("tier"),
                    "reason": "sole source failed its oracle re-run; entry revoked",
                    "recorded_at": utc_now(),
                }
            )
            result.revoked.append(key)
        touched.append(key)
    if touched:
        version = _bump_version(registry)
        for key in set(touched):
            entries[key]["updated_version"] = version
        result.changed = True
        result.version = version
    return result
