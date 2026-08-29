"""Borg-family liveness gating for ``verify-sweep`` candidate selection.

WHY THIS EXISTS (measured 2026-08-29, research/tools/dolphin-trace/scenarios/
README.md): 810 of the 818 exports across the 104 staged compile-only greens
are borg *family* code -- they only execute while that family's actor is
loaded and acting in the running game. The repo has exactly one battle
savestate, and in it only family ``0x800c04c0`` (pl0300 / pl030b) is live, so
exactly 5 of the 104 staged units are capturable there. Before this module the
sweep picked candidates by staleness alone and burned ~15 minutes per
unreachable unit rediscovering "the function never fires" -- in one run six
consecutive units, none of them one of the five reachable ones.

The gate answers two questions and refuses to guess at either:

  1. WHICH FAMILY GATES A UNIT (``FamilyIndex``).  Deterministic, from
     committed evidence, never from unit-id numbering:

       - ``research/decomp/data/family-state-machine-coverage.json`` records
         one ``constructorAddress`` per borg family (119 of them) together
         with that family's ROM members (pl0300, pl030b, ...). Those
         constructors are the family code-block roots.
       - Sorted, the constructors partition the DOL's borg-family text into
         contiguous per-family blocks: family F owns
         ``[F.constructorAddress, next_constructor)``. VALIDATED against the
         same artifact's own ``romEvidence``: of the 9024 ``boot.dol:0x...``
         code addresses those entries cite as evidence for a family, 9024
         fall inside that family's block and 0 fall outside.
       - A unit's exports resolve to addresses through
         ``research/decomp/data/oracle-registry.json`` (the same typing
         authority the capture plans use), falling back to the address
         encoded in Ghidra's own naming (``FUN_800c05bc`` -> 0x800c05bc,
         ``zz_00c05bc_`` -> 0x800c05bc) only when the registry has no entry.
       - The unit's gating family set is the set of blocks its export
         addresses land in. A unit whose exports land in no block (engine
         code below the first constructor) is NOT family-gated.

     WHY NOT CALL-GRAPH REACHABILITY: it was tried first and does not work
     here. Family action handlers are reached through per-actor function
     POINTER TABLES, not direct calls, so the evidence index records 0
     callers for most of them and forward reachability from a constructor
     root covers exactly one node (itself). Address-block ownership is the
     only relation the committed evidence actually supports.

     KNOWN BOUND: the LAST family block has no next constructor to close it,
     so addresses at or after the highest constructor are reported as
     UNDETERMINED rather than attributed to that family. No staged export is
     currently in that region. When a boundary anchor is measured, give the
     last block an explicit end instead of widening it by guess.

  2. WHICH FAMILIES ARE LIVE IN A SCENARIO (``scenario_live_families``).
     Data-driven from the scenario JSON's optional, additive
     ``live_families`` field (see SCENARIO_LIVENESS_FIELD for why this is not
     a scenario_schema bump), never inferred. Three distinct states:

       - ``live_families`` absent or null  -> UNKNOWN. The gate is DISABLED
         for that scenario and the sweep degrades to its pre-gate behaviour.
         Unknown must never look like "nothing is live", or the sweep would
         silently skip every real unit.
       - ``live_families: []``             -> MEASURED-EMPTY. No family is
         live; every family-gated unit is skipped.
       - ``live_families: ["0x...", ...]`` -> those families are live.

Fail-open is the rule throughout: anything this module cannot decide from
committed evidence leaves the unit selectable, so a missing artifact costs
capture time but never hides work.

Python only (owner rule); pure stdlib.
"""

from __future__ import annotations

import bisect
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping

# ---------------------------------------------------------------- repo layout

FAMILY_COVERAGE_RELPATH = "research/decomp/data/family-state-machine-coverage.json"
SCENARIOS_RELPATH = "research/tools/dolphin-trace/scenarios"

# The structured sweep skip reason for a unit whose gating family is absent
# from the scenario's live set. Reason strings the sweep records start with
# this token so the skip is greppable and never a silent drop.
FAMILY_NOT_LIVE = "family_not_live"

# ``live_families`` is an ADDITIVE, OPTIONAL scenario field, deliberately NOT
# a scenario_schema bump: capture_oracle.py::load_scenario hard-refuses any
# scenario whose ``scenario_schema`` is not exactly 1, so bumping it would
# break every capture. Unknown keys are ignored there, so schema 1 files carry
# the field safely; a file without it simply reads as UNKNOWN here.
SCENARIO_LIVENESS_FIELD = "live_families"
SCENARIO_LIVENESS_BASIS_FIELD = "live_families_basis"

_FUN_NAME = re.compile(r"^FUN_([0-9a-fA-F]{8})$")
_ZZ_NAME = re.compile(r"^zz_([0-9a-fA-F]{7})_$")


def _parse_address(text: Any) -> int | None:
    if isinstance(text, int):
        return text
    if not isinstance(text, str):
        return None
    stripped = text.strip()
    if not stripped:
        return None
    try:
        return int(stripped, 16)
    except ValueError:
        return None


def address_from_name(name: str) -> int | None:
    """The address Ghidra encoded into its own default names. ``FUN_800c05bc``
    carries the full address; ``zz_00c05bc_`` drops the leading ``8`` of the
    0x8xxxxxxx text address (verified against the evidence index:
    ``zz_0027adc_`` is 0x80027adc). Used ONLY as a fallback when the oracle
    registry has no entry for the export."""
    match = _FUN_NAME.match(name or "")
    if match:
        return int(match.group(1), 16)
    match = _ZZ_NAME.match(name or "")
    if match:
        return int("8" + match.group(1), 16)
    return None


def export_address(name: str, registry_fns: Mapping[str, Mapping[str, Any]]) -> int | None:
    """Registry address first (the committed typing authority), Ghidra's
    encoded name second, then honestly nothing."""
    entry = registry_fns.get(name) if registry_fns else None
    if isinstance(entry, Mapping):
        address = _parse_address(entry.get("address"))
        if address is not None:
            return address
    return address_from_name(name)


# ------------------------------------------------------------- family index

@dataclass(frozen=True)
class FamilyBlock:
    """One borg family's contiguous DOL text block."""

    family: str            # canonical constructor address, e.g. "0x800c04c0"
    start: int             # inclusive
    end: int | None        # exclusive; None == open/undetermined (last block)
    members: tuple[str, ...]

    def label(self) -> str:
        return f"{self.family}/{self.members[0]}" if self.members else self.family


@dataclass(frozen=True)
class UnitFamilies:
    """What the index could and could not decide about one unit's exports."""

    families: frozenset[str]
    undetermined: tuple[str, ...]   # export names with no decidable family

    @property
    def gated(self) -> bool:
        """A unit is family-gated only when EVERY export resolved into a
        family block. One undetermined export means some code in the unit may
        fire without any family loaded, so the unit stays selectable."""
        return bool(self.families) and not self.undetermined


class FamilyIndex:
    """Address -> borg family, from the committed family-state-machine
    coverage artifact. See the module docstring for the derivation."""

    def __init__(self, blocks: Iterable[FamilyBlock]):
        self.blocks: list[FamilyBlock] = sorted(blocks, key=lambda b: b.start)
        self._starts = [block.start for block in self.blocks]
        self.members_by_family = {block.family: block.members for block in self.blocks}

    @classmethod
    def load(cls, repo_root: Path) -> "FamilyIndex | None":
        """None when the coverage artifact is missing or unusable -- the
        caller must then leave the gate disabled rather than guess."""
        path = Path(repo_root) / FAMILY_COVERAGE_RELPATH
        try:
            payload = json.loads(path.read_text(encoding="utf-8-sig"))
        except (OSError, json.JSONDecodeError):
            return None
        families = payload.get("families")
        if not isinstance(families, list) or not families:
            return None
        raw: list[tuple[int, str, tuple[str, ...]]] = []
        for family in families:
            if not isinstance(family, dict):
                continue
            address = _parse_address(family.get("constructorAddress"))
            if address is None:
                continue
            members = tuple(
                str(member)
                for member in (family.get("members") or [])
                if isinstance(member, str)
            )
            raw.append((address, f"0x{address:08x}", members))
        if not raw:
            return None
        raw.sort()
        blocks: list[FamilyBlock] = []
        for index, (start, name, members) in enumerate(raw):
            # The block ends where the next family's constructor begins. The
            # last block has no such bound in committed evidence, so it stays
            # open and everything past it reads as undetermined.
            end = raw[index + 1][0] if index + 1 < len(raw) else None
            blocks.append(FamilyBlock(family=name, start=start, end=end, members=members))
        return cls(blocks)

    def family_for_address(self, address: int | None) -> str | None:
        if address is None:
            return None
        position = bisect.bisect_right(self._starts, address) - 1
        if position < 0:
            return None                       # engine code below every family
        block = self.blocks[position]
        if block.end is None or address >= block.end:
            return None                       # unbounded tail: undetermined
        return block.family

    def label(self, family: str) -> str:
        members = self.members_by_family.get(family) or ()
        return f"{family}/{members[0]}" if members else family

    def unit_families(
        self, exports: Iterable[str], registry_fns: Mapping[str, Mapping[str, Any]]
    ) -> UnitFamilies:
        found: set[str] = set()
        undetermined: list[str] = []
        for name in exports or ():
            family = self.family_for_address(export_address(name, registry_fns))
            if family is None:
                undetermined.append(name)
            else:
                found.add(family)
        return UnitFamilies(frozenset(found), tuple(undetermined))


# ---------------------------------------------------------- scenario liveness

@dataclass(frozen=True)
class ScenarioLiveness:
    """A scenario's declared live-family set. ``families is None`` means the
    scenario does not declare one -- UNKNOWN, and the gate stays off."""

    scenario: str
    families: frozenset[str] | None
    basis: str

    @property
    def known(self) -> bool:
        return self.families is not None


def _canonical_family(value: Any) -> str | None:
    address = _parse_address(value)
    return None if address is None else f"0x{address:08x}"


def scenario_live_families(repo_root: Path, scenario: str) -> ScenarioLiveness:
    """Read ``live_families`` out of a scenario JSON. Missing file, missing
    field, or an unparseable field all mean UNKNOWN (gate off) -- never
    'nothing is live'."""
    path = Path(repo_root) / SCENARIOS_RELPATH / f"{scenario}.json"
    try:
        payload = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError):
        return ScenarioLiveness(scenario, None, "scenario file missing or unreadable")
    if not isinstance(payload, dict):
        return ScenarioLiveness(scenario, None, "scenario file is not an object")
    if SCENARIO_LIVENESS_FIELD not in payload:
        return ScenarioLiveness(
            scenario, None,
            f"scenario declares no {SCENARIO_LIVENESS_FIELD} (schema "
            f"{payload.get('scenario_schema')})",
        )
    declared = payload.get(SCENARIO_LIVENESS_FIELD)
    basis = str(
        payload.get(SCENARIO_LIVENESS_BASIS_FIELD) or "declared by the scenario"
    )
    if declared is None:
        return ScenarioLiveness(scenario, None, basis)
    if not isinstance(declared, list):
        return ScenarioLiveness(
            scenario, None,
            f"{SCENARIO_LIVENESS_FIELD} is not a list; treating as unknown",
        )
    canonical = {_canonical_family(item) for item in declared}
    if None in canonical:
        return ScenarioLiveness(
            scenario, None,
            f"{SCENARIO_LIVENESS_FIELD} holds an unparseable family address; "
            "treating as unknown",
        )
    return ScenarioLiveness(scenario, frozenset(c for c in canonical if c), basis)


# ------------------------------------------------------------- gate decision

@dataclass(frozen=True)
class GateDecision:
    """Whether one unit may be attempted in one scenario, and why."""

    selectable: bool
    reason: str                      # FAMILY_NOT_LIVE or a not-gated reason
    families: tuple[str, ...]        # the unit's gating families (sorted)
    scenario: str

    def skip_reason(self, index: "FamilyIndex | None" = None) -> str:
        labels = ", ".join(
            (index.label(f) if index else f) for f in self.families
        ) or "none"
        return (
            f"{FAMILY_NOT_LIVE}: gating borg family {labels} is not live in "
            f"scenario {self.scenario}"
        )


def decide(
    unit_families: UnitFamilies, liveness: ScenarioLiveness
) -> GateDecision:
    families = tuple(sorted(unit_families.families))
    if not liveness.known:
        return GateDecision(True, "scenario_liveness_unknown", families, liveness.scenario)
    if not unit_families.families:
        return GateDecision(True, "no_gating_family", families, liveness.scenario)
    if unit_families.undetermined:
        # Part of the unit is not family code: it can fire without any family.
        return GateDecision(True, "family_partially_undetermined", families, liveness.scenario)
    if unit_families.families & (liveness.families or frozenset()):
        return GateDecision(True, "family_live", families, liveness.scenario)
    return GateDecision(False, FAMILY_NOT_LIVE, families, liveness.scenario)


def blocked_inventory_summary(
    blocked: Mapping[str, GateDecision], index: "FamilyIndex | None" = None
) -> str:
    """The one-line blocked inventory the sweep prints in NORMAL output:
    ``N units skipped across M absent families`` plus a compact per-family
    breakdown, biggest first."""
    if not blocked:
        return "family gate: 0 units skipped across 0 absent families"
    per_family: dict[str, int] = {}
    for decision in blocked.values():
        for family in decision.families:
            per_family[family] = per_family.get(family, 0) + 1
    breakdown = ", ".join(
        f"{index.label(family) if index else family} x{count}"
        for family, count in sorted(per_family.items(), key=lambda kv: (-kv[1], kv[0]))
    )
    return (
        f"family gate: {len(blocked)} units skipped across {len(per_family)} "
        f"absent families -- {breakdown}"
    )
