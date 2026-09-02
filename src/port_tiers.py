"""The driver's tier vocabulary: what a unit's ``tier`` field may say, which
tiers carry a behavioural claim, and how per-FUNCTION console evidence rolls
up into a per-UNIT verdict.

Why this module exists
----------------------
Four verification standards exist for wasm port units (docs/verification-status.md
section 1).  Until now the driver knew two of them -- ``compile_only`` and
``oracle_green``.  The two console-derived standards that actually produced
results, ``transcript_green`` and ``boundary_green``, existed only in
``tools/survey_plan_tiers.py`` (an offline surveyor) and in committed result
artifacts.  The driver could not record them, so passing console results moved
the ledger by exactly zero.

Two counters compounded that.  ``port_contract.queue_status`` and
``port_progress.classify_counts`` both classified a green record by asking
"is the tier ``compile_only``?" and routing *everything else* -- ``None``, a
typo, a future tier -- into ``green``.  That is fail-OPEN, and it is not
hypothetical: the live ledger carries two ``status=green, tier=None`` records
(``damage-core``, ``knockback-core``) that those counters already report as
verified while ``run-state.json``'s ``units_verified`` (a positive test) does
not.  Two files published by the same run disagree, and the looser one feeds
the README banner.

The discipline this module encodes
----------------------------------
1. **Allowlists, never negations.**  Every predicate here is a positive test
   against an explicit frozenset, following ``ELIGIBLE_CANONICAL_TIERS``
   (src/port_assembly_gate.py).  A tier string this module does not know is
   ``unknown`` -- never ``green``, never ``staged``, never verified.
2. **Weaker standards are never totalled with the stronger one**
   (claim-honesty rule 3).  ``VERIFIED_TIERS`` says "carries SOME behavioural
   claim"; it is not a single quantity.  ``WRITE_VERIFIED_TIERS`` is the only
   set that may be described as write-set verified.
3. **A mixed unit is reported mixed, never rounded up.**  The rollup below is
   the in-driver counterpart of the offline rule in
   ``tools/survey_plan_tiers.py`` ("a unit whose exports reach a MIX of tiers
   is reported as mixed, never rounded up to the stronger one").
4. **Partial coverage stays visibly partial.**  A unit with three passing
   exports out of eight reaches no tier at all, and the rollup says so with
   the covered/total counts and the uncovered export list.

Python only (owner rule); pure stdlib.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping

# --------------------------------------------------------------- tier strings

TIER_COMPILE_ONLY = "compile_only"
TIER_TRANSCRIPT_GREEN = "transcript_green"
TIER_BOUNDARY_GREEN = "boundary_green"
TIER_ORACLE_GREEN = "oracle_green"

#: Every tier string the driver is allowed to write into a unit record.
#: Anything outside this set is a defect, and every consumer here treats it as
#: unknown rather than guessing.
KNOWN_TIERS = frozenset(
    {
        TIER_COMPILE_ONLY,
        TIER_TRANSCRIPT_GREEN,
        TIER_BOUNDARY_GREEN,
        TIER_ORACLE_GREEN,
    }
)

#: Tiers that record INVENTORY -- the code built, and nothing was checked
#: about its behaviour (claim-honesty rule 1).
UNVERIFIED_TIERS = frozenset({TIER_COMPILE_ONLY})

#: Tiers that carry SOME console-derived behavioural claim.  This set is the
#: positive predicate the counters test; it is deliberately NOT a single
#: quantity, and a report that sums across it must name the tiers it summed
#: (claim-honesty rule 3).
VERIFIED_TIERS = frozenset(
    {TIER_TRANSCRIPT_GREEN, TIER_BOUNDARY_GREEN, TIER_ORACLE_GREEN}
)

#: The only tier in which the function's MEMORY WRITE SET was compared.
#: "Verified" without this qualifier must never be read as write-verified.
WRITE_VERIFIED_TIERS = frozenset({TIER_ORACLE_GREEN})

#: Sentinel for a unit whose exports are all verified but not all at one
#: standard.  It is a REPORT value, never a record value: it may not be
#: written into a unit's ``tier`` field and it is not in ``KNOWN_TIERS``.
TIER_MIXED = "mixed"

#: Which per-function result tiers SATISFY a unit rollup at a given tier.
#:
#: ``oracle_green`` is satisfied only by ``oracle_green``.  ``transcript_green``
#: is additionally satisfied by ``oracle_green``, following the combined
#: ranking ``tools/survey_plan_tiers.py`` already applies offline ("oracle_green
#: (a byte-exact write comparison) always outranks transcript_green") -- note
#: that this only ever rounds a unit DOWN to the weaker claim, never up.
#:
#: ``boundary_green`` is INCOMPARABLE with both.  docs/verification-status.md
#: section 1: it "is **not** ``oracle_green`` and never upgrades into one"; it
#: is the standard for a NONTERMINATING spine function and compares a callee
#: boundary over K iterations up to a cut, which no returning-function standard
#: subsumes and which subsumes neither of them.  So it satisfies only itself,
#: and a unit mixing it with anything else is ``mixed``.
TIER_SATISFIED_BY: Mapping[str, frozenset[str]] = {
    TIER_ORACLE_GREEN: frozenset({TIER_ORACLE_GREEN}),
    TIER_BOUNDARY_GREEN: frozenset({TIER_BOUNDARY_GREEN}),
    TIER_TRANSCRIPT_GREEN: frozenset({TIER_TRANSCRIPT_GREEN, TIER_ORACLE_GREEN}),
}

#: Report order, strongest first.  ``unit_tier_rollup`` names the STRONGEST
#: tier every export satisfies, so an all-``oracle_green`` unit reports
#: ``oracle_green`` rather than the weaker ``transcript_green`` it also meets.
TIER_REPORT_ORDER: tuple[str, ...] = (
    TIER_ORACLE_GREEN,
    TIER_BOUNDARY_GREEN,
    TIER_TRANSCRIPT_GREEN,
)


# ------------------------------------------------------------ tier predicates


def is_known_tier(tier: Any) -> bool:
    """True only for a tier string the driver may write.  ``None``, a typo and
    any future standard nobody taught this module all answer False."""
    return isinstance(tier, str) and tier in KNOWN_TIERS


def is_verified_tier(tier: Any) -> bool:
    """True only for a tier carrying a behavioural claim.  FAIL-CLOSED: the
    predicate is membership of an allowlist, never ``!= compile_only``."""
    return isinstance(tier, str) and tier in VERIFIED_TIERS


def is_unverified_tier(tier: Any) -> bool:
    """True only for a tier that is explicitly INVENTORY (``compile_only``).
    An unknown tier is not unverified inventory either -- it is unknown."""
    return isinstance(tier, str) and tier in UNVERIFIED_TIERS


def is_write_verified_tier(tier: Any) -> bool:
    """True only where the memory write set was compared byte-for-byte."""
    return isinstance(tier, str) and tier in WRITE_VERIFIED_TIERS


def classify_tier(tier: Any) -> str:
    """``'verified'`` | ``'staged'`` | ``'unknown'`` for one record's tier.

    This is the single decision the ledger counters make.  ``'unknown'`` is a
    real bucket, not a synonym for either of the others: a record the driver
    cannot classify must be visible as such, because silently calling it
    ``verified`` is the exact fail-open defect this module was written to
    remove, and silently calling it ``staged`` would hide a corrupt record.
    """
    if is_verified_tier(tier):
        return "verified"
    if is_unverified_tier(tier):
        return "staged"
    return "unknown"


#: The ledger bucket each classification lands in. Every counter that reports
#: green-status records -- port_contract.queue_status, port_progress
#: .classify_counts, and port_wasm_units' run-state writer -- indexes THIS map,
#: so the three files published by one run cannot drift apart again. That
#: drift is exactly what the defect was: two of them said 3 while the third
#: said 1, and the looser number fed the README banner.
COUNT_BUCKET: Mapping[str, str] = {
    "verified": "green",
    "staged": "staged",
    "unknown": "unknown_tier",
}


def count_bucket(tier: Any) -> str:
    """``'green'`` | ``'staged'`` | ``'unknown_tier'`` for one record's tier."""
    return COUNT_BUCKET[classify_tier(tier)]


# ---------------------------------------------------------- per-unit rollup


@dataclass(frozen=True)
class ExportResult:
    """One export's console-derived verdict, already admitted by the caller.

    ``tier`` must be a member of ``VERIFIED_TIERS``; anything else makes the
    result inadmissible and ``unit_tier_rollup`` refuses it rather than
    ignoring it.
    """

    export: str
    tier: str
    artifact: str = ""


@dataclass(frozen=True)
class UnitRollup:
    """The honest per-unit verdict.

    ``tier`` is a member of ``VERIFIED_TIERS`` only when EVERY export of the
    unit has a passing result at that tier or at one that satisfies it.  It is
    ``TIER_MIXED`` when every export is verified but at standards that do not
    reduce to one, and ``None`` whenever coverage is partial or any result is
    inadmissible.  ``covered``/``total`` are always populated so partial
    coverage stays visibly partial.
    """

    unit: str
    tier: str | None
    covered: int
    total: int
    per_export: dict[str, str] = field(default_factory=dict)
    uncovered: tuple[str, ...] = ()
    reasons: tuple[str, ...] = ()

    @property
    def full_coverage(self) -> bool:
        return self.total >= 1 and self.covered == self.total

    @property
    def promotable(self) -> bool:
        """A rollup may move a unit's ledger tier only when it names a real
        verified tier.  ``mixed`` and ``None`` never promote."""
        return is_verified_tier(self.tier)

    def summary(self) -> str:
        """One line for a journal/event, always naming the coverage."""
        if self.tier is None:
            return (
                f"{self.unit}: no unit tier "
                f"({self.covered}/{self.total} exports verified)"
            )
        return f"{self.unit}: {self.tier} ({self.covered}/{self.total} exports)"


def unit_tier_rollup(
    unit: str,
    exports: Iterable[str],
    results: Iterable[ExportResult],
) -> UnitRollup:
    """Aggregate per-FUNCTION results into a per-UNIT verdict, fail-closed.

    The rule, stated so it can be argued with:

    * Only exports named in ``exports`` count.  A result for a function the
      staged provenance does not export is inadmissible (it cannot be evidence
      about this artifact's surface) and is recorded as a refusal reason.
    * Only tiers in ``VERIFIED_TIERS`` count.  A result carrying
      ``compile_only`` or an unknown standard is inadmissible.
    * A unit reaches tier ``T`` only when EVERY export has a result whose tier
      is in ``TIER_SATISFIED_BY[T]``.  The strongest such ``T`` is reported.
    * Every export verified but no single ``T`` covers them -> ``TIER_MIXED``.
      Never the stronger of the two; never a total across them.
    * Any export without an admissible result -> tier ``None`` and the missing
      exports are listed.  Partial coverage is not a weak pass, it is no pass.
    * Two admissible results for the SAME export must agree on tier; a
      disagreement is a refusal, not a max().
    """
    export_list = [name for name in exports]
    export_set = set(export_list)
    reasons: list[str] = []
    per_export: dict[str, str] = {}

    for result in results:
        if not isinstance(result, ExportResult):
            reasons.append(f"{unit}: result is not an ExportResult")
            continue
        if result.export not in export_set:
            reasons.append(
                f"{unit}: result for {result.export!r} which the staged "
                "provenance does not export"
            )
            continue
        if not is_verified_tier(result.tier):
            reasons.append(
                f"{unit}: {result.export} carries tier {result.tier!r}, "
                "not a verified tier"
            )
            continue
        seen = per_export.get(result.export)
        if seen is not None and seen != result.tier:
            reasons.append(
                f"{unit}: {result.export} has conflicting results "
                f"({seen!r} and {result.tier!r}); refusing to pick one"
            )
            per_export.pop(result.export, None)
            export_set.discard(result.export)  # never re-admitted this pass
            continue
        per_export[result.export] = result.tier

    total = len(export_list)
    covered = sum(1 for name in export_list if name in per_export)
    uncovered = tuple(name for name in export_list if name not in per_export)

    if total < 1:
        return UnitRollup(
            unit, None, 0, 0, per_export, uncovered,
            tuple(reasons + [f"{unit}: no exports declared"]),
        )
    if covered != total:
        return UnitRollup(unit, None, covered, total, per_export, uncovered, tuple(reasons))

    tiers_present = set(per_export.values())
    for candidate in TIER_REPORT_ORDER:
        if tiers_present <= TIER_SATISFIED_BY[candidate]:
            return UnitRollup(
                unit, candidate, covered, total, per_export, uncovered, tuple(reasons)
            )
    return UnitRollup(
        unit,
        TIER_MIXED,
        covered,
        total,
        per_export,
        uncovered,
        tuple(
            reasons
            + [
                f"{unit}: exports span {sorted(tiers_present)}; reported mixed, "
                "never rounded up (claim-honesty rule 3)"
            ]
        ),
    )
