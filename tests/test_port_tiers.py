"""The driver's tier vocabulary and the per-unit rollup.

Two things are under test and they are different:

* the FAIL-CLOSED classification of one record's ``tier`` field -- the thing
  the ledger counters do, and the thing that was fail-OPEN; and
* the aggregation of per-FUNCTION console evidence into a per-UNIT verdict,
  which must demand full export coverage, must report a mixed unit as mixed,
  and must never round anything up.
"""

from __future__ import annotations

import pytest

from src.port_tiers import (
    KNOWN_TIERS,
    TIER_BOUNDARY_GREEN,
    TIER_COMPILE_ONLY,
    TIER_MIXED,
    TIER_ORACLE_GREEN,
    TIER_TRANSCRIPT_GREEN,
    UNVERIFIED_TIERS,
    VERIFIED_TIERS,
    WRITE_VERIFIED_TIERS,
    ExportResult,
    classify_tier,
    is_known_tier,
    is_unverified_tier,
    is_verified_tier,
    is_write_verified_tier,
    unit_tier_rollup,
)


# ------------------------------------------------------------- the vocabulary


def test_the_four_standards_are_the_whole_vocabulary():
    assert KNOWN_TIERS == {
        TIER_COMPILE_ONLY,
        TIER_TRANSCRIPT_GREEN,
        TIER_BOUNDARY_GREEN,
        TIER_ORACLE_GREEN,
    }
    # compile_only is inventory and the other three carry a claim; the two
    # sets partition the vocabulary with nothing left over and no overlap.
    assert VERIFIED_TIERS | UNVERIFIED_TIERS == KNOWN_TIERS
    assert not (VERIFIED_TIERS & UNVERIFIED_TIERS)


def test_only_oracle_green_is_write_verified():
    """claim-honesty rule 3: the weaker standards compare a callee boundary,
    never a write set, and must never be reported as oracle_green."""
    assert WRITE_VERIFIED_TIERS == {TIER_ORACLE_GREEN}
    assert is_write_verified_tier(TIER_ORACLE_GREEN)
    assert not is_write_verified_tier(TIER_TRANSCRIPT_GREEN)
    assert not is_write_verified_tier(TIER_BOUNDARY_GREEN)


def test_compile_only_is_never_verified():
    assert is_unverified_tier(TIER_COMPILE_ONLY)
    assert not is_verified_tier(TIER_COMPILE_ONLY)
    assert classify_tier(TIER_COMPILE_ONLY) == "staged"


@pytest.mark.parametrize(
    "tier",
    [
        None,
        "",
        "green",
        "oracle-green",          # hyphen typo
        "ORACLE_GREEN",          # case typo
        "transcript_green ",     # trailing space
        "spine_green",           # a tier that does not exist (trap 3)
        "gx_callstream_green",   # a real standard, but not a wasm-unit tier
        "mixed",                 # a REPORT value, never a record value
        42,
        object(),
    ],
)
def test_an_unknown_tier_is_never_green(tier):
    """THE regression test for the fail-open defect: every predicate is a
    positive allowlist test, so anything the driver does not know is
    ``unknown`` -- never verified, and never quietly counted as inventory."""
    assert classify_tier(tier) == "unknown"
    assert not is_verified_tier(tier)
    assert not is_unverified_tier(tier)
    assert not is_known_tier(tier)
    assert not is_write_verified_tier(tier)


def test_mixed_is_a_report_value_not_a_record_value():
    assert TIER_MIXED not in KNOWN_TIERS
    assert not is_verified_tier(TIER_MIXED)


# ------------------------------------------------------------ the aggregation


def _r(export: str, tier: str) -> ExportResult:
    return ExportResult(export=export, tier=tier)


def test_full_coverage_at_one_tier_reaches_that_tier():
    rollup = unit_tier_rollup(
        "u", ["a", "b"],
        [_r("a", TIER_TRANSCRIPT_GREEN), _r("b", TIER_TRANSCRIPT_GREEN)],
    )
    assert rollup.tier == TIER_TRANSCRIPT_GREEN
    assert rollup.full_coverage and rollup.promotable
    assert rollup.covered == rollup.total == 2


def test_partial_coverage_stays_visibly_partial():
    """Three of eight exports verified is three of eight, not a weak pass and
    not silence -- the shape of every unit with console evidence today."""
    exports = [f"e{n}" for n in range(8)]
    rollup = unit_tier_rollup(
        "u", exports, [_r("e0", TIER_TRANSCRIPT_GREEN),
                       _r("e1", TIER_TRANSCRIPT_GREEN),
                       _r("e2", TIER_TRANSCRIPT_GREEN)],
    )
    assert rollup.tier is None
    assert not rollup.promotable and not rollup.full_coverage
    assert (rollup.covered, rollup.total) == (3, 8)
    assert rollup.uncovered == ("e3", "e4", "e5", "e6", "e7")
    assert "3/8" in rollup.summary()


def test_all_oracle_green_reports_oracle_green_not_the_weaker_tier():
    rollup = unit_tier_rollup(
        "u", ["a", "b"], [_r("a", TIER_ORACLE_GREEN), _r("b", TIER_ORACLE_GREEN)]
    )
    assert rollup.tier == TIER_ORACLE_GREEN


def test_oracle_green_and_transcript_green_round_DOWN_to_transcript_green():
    """The only direction a rollup may move is toward the weaker claim. A unit
    with one write-verified export and one transcript-verified export is a
    transcript_green unit; calling it oracle_green would total a weaker
    standard into the stronger one (claim-honesty rule 3)."""
    rollup = unit_tier_rollup(
        "u", ["a", "b"], [_r("a", TIER_ORACLE_GREEN), _r("b", TIER_TRANSCRIPT_GREEN)]
    )
    assert rollup.tier == TIER_TRANSCRIPT_GREEN


def test_boundary_green_is_incomparable_so_a_mix_is_mixed():
    """boundary_green 'is not oracle_green and never upgrades into one'
    (docs/verification-status.md section 1). It satisfies only itself, so a
    unit spanning it and anything else is reported MIXED, never rounded."""
    rollup = unit_tier_rollup(
        "u", ["a", "b"], [_r("a", TIER_BOUNDARY_GREEN), _r("b", TIER_TRANSCRIPT_GREEN)]
    )
    assert rollup.tier == TIER_MIXED
    assert rollup.full_coverage        # coverage IS complete ...
    assert not rollup.promotable       # ... and it still does not promote
    assert any("mixed" in reason for reason in rollup.reasons)

    both_boundary = unit_tier_rollup(
        "u", ["a", "b"], [_r("a", TIER_BOUNDARY_GREEN), _r("b", TIER_BOUNDARY_GREEN)]
    )
    assert both_boundary.tier == TIER_BOUNDARY_GREEN


def test_a_compile_only_or_unknown_result_is_inadmissible():
    rollup = unit_tier_rollup(
        "u", ["a", "b"],
        [_r("a", TIER_TRANSCRIPT_GREEN), _r("b", TIER_COMPILE_ONLY)],
    )
    assert rollup.tier is None
    assert rollup.covered == 1
    assert any("not a verified tier" in reason for reason in rollup.reasons)

    unknown = unit_tier_rollup(
        "u", ["a"], [_r("a", "transcript_gren")]  # typo
    )
    assert unknown.tier is None and unknown.covered == 0


def test_a_result_for_a_function_the_unit_does_not_export_is_refused():
    rollup = unit_tier_rollup(
        "u", ["a"], [_r("a", TIER_TRANSCRIPT_GREEN), _r("stranger", TIER_ORACLE_GREEN)]
    )
    assert rollup.tier == TIER_TRANSCRIPT_GREEN   # the admissible one still counts
    assert any("does not export" in reason for reason in rollup.reasons)


def test_conflicting_results_for_one_export_refuse_rather_than_pick_a_winner():
    rollup = unit_tier_rollup(
        "u", ["a"], [_r("a", TIER_TRANSCRIPT_GREEN), _r("a", TIER_ORACLE_GREEN)]
    )
    assert rollup.tier is None
    assert rollup.covered == 0
    assert any("conflicting results" in reason for reason in rollup.reasons)


def test_a_unit_with_no_exports_and_no_results_never_passes_vacuously():
    """Zero of zero is not full coverage. A rollup that answered 'verified'
    here would be the vacuity the weaker standards were built to avoid."""
    rollup = unit_tier_rollup("u", [], [])
    assert rollup.tier is None
    assert not rollup.full_coverage and not rollup.promotable
    assert any("no exports declared" in reason for reason in rollup.reasons)


def test_no_results_at_all_is_no_tier():
    rollup = unit_tier_rollup("u", ["a", "b"], [])
    assert rollup.tier is None
    assert (rollup.covered, rollup.total) == (0, 2)
