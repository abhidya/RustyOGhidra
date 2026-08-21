"""Offline tests for the T2c knowledge registry (src/port_knowledge_registry.py)
and its driver touch points -- design section 2.11 [V4-1, V4-5, V4-6, V4-7,
V4-8], ADVISORY mode.

The heart of this file is the advisory-boundary suite: v3's registry FAILED
adversarial review as an echo chamber that suppressed its own conflict
detection, so these tests demonstrate the registry CANNOT override a unit's
independent derivation, CANNOT suppress a conflict, and never presents a
contested coin-flip.
"""

from __future__ import annotations

import json
import hashlib
import subprocess
from pathlib import Path

import pytest

from src.port_assembly_gate import (
    CLASS_COLLISION_STUB,
    CLASS_LINK_FAILURE,
    conflicts_from_link_error,
    record_gate_result,
)
from src.port_knowledge_registry import (
    REGISTRY_RELPATH,
    TIER_COMPILE_ONLY,
    TIER_ORACLE_GREEN,
    augment_seed,
    check_survival,
    empty_registry,
    fold_assembly_conflict_ledger,
    harvest_candidates,
    harvest_unit,
    is_holdout,
    load_registry,
    promote_unit_entries,
    registry_version,
    relevant_delta,
    revoke_unit_entries,
    save_registry,
    unit_symbol_set,
)

DAT_SYM = "DAT_802c44f8"
DAT_KEY = "dat:0x802c44f8"
MACRO_CHAR = "#define DAT_802c44f8 (*(unsigned char *)(unsigned int)0x802c44f8)"
MACRO_INT = "#define DAT_802c44f8 (*(unsigned int *)(unsigned int)0x802c44f8)"
MACRO_SHORT = "#define DAT_802c44f8 (*(unsigned short *)(unsigned int)0x802c44f8)"

SEED = "/* seed */\ntypedef unsigned long long undefined8;\n"

UNIT_C = (
    '#include "gnt4_shim.h"\n\n'
    "int zz_use_(int a);\n\n"
    "/* ==== VERBATIM: chunk.c 1-4 ==== */\n"
    "int zz_use_(int a)\n{\n  return a + (int)DAT_802c44f8;\n}\n"
)


def _entry(
    tier: str = TIER_COMPILE_ONLY,
    macro: str = MACRO_INT,
    unit: str = "unit-earlier",
    **extra,
):
    entry = {
        "kind": "dat_typing",
        "symbol": DAT_SYM,
        "address": "0x802c44f8",
        "macro": macro,
        "tier": tier,
        "source_units": [unit],
        "source_tiers": {unit: tier},
        "contested": False,
        "conflicts": [],
        "updated_version": 1,
    }
    entry.update(extra)
    return entry


def _registry_with(entry) -> dict:
    registry = empty_registry()
    registry["version"] = 1
    registry["entries"][DAT_KEY] = entry
    return registry


def _assembly_ledger_bytes(records: dict[str, dict]) -> bytes:
    return (
        json.dumps(
            {
                "schema": 1,
                "created_at": "2026-08-21T00:00:00Z",
                "updated_at": "2026-08-21T00:01:00Z",
                "largest_n_passed": 5,
                "runs_total": 1,
                "conflicts": records,
            },
            sort_keys=True,
            indent=2,
        )
        + "\n"
    ).encode("utf-8")


def _synthetic_41_conflict_ledger() -> bytes:
    """Public, synthetic census with the historical T2b cardinality.

    The shapes exercise every assembly-only evidence family without copying
    byte-exact game candidates into a public fixture.
    """
    variants = {
        "undefined8": {
            "unit-a": "typedef double undefined8;",
            "unit-b": "typedef unsigned long long undefined8;",
        },
        "CONCAT44": {
            "unit-a": "#define CONCAT44(a,b) double_form(a,b)",
            "unit-b": "#define CONCAT44(a,b) integer_form(a,b)",
        },
        "DAT_804361fc": {
            "unit-a": "#define DAT_804361fc GC_U8(0x804361fc)",
            "unit-b": "#define DAT_804361fc GC_IPTR(0x804361fc)",
        },
        "zz_00f0104_": {
            "unit-a": "int zz_00f0104_();",
            "unit-b": "void zz_00f0104_(int,int,int);",
        },
        "zz_00076d0_": {},
    }
    for index in range(36):
        symbol = f"zz_synthetic_{index:02d}_"
        variants[symbol] = {
            "unit-a": f"int {symbol}();",
            "unit-b": f"void {symbol}(int);",
        }
    records = {}
    for index, (symbol, unit_variants) in enumerate(variants.items()):
        conflict_class = (
            "undefined8_fork"
            if symbol in {"undefined8", "CONCAT44"}
            else "dat_width_divergence"
            if symbol.startswith("DAT_")
            else "collision_stub"
        )
        units = ["unit-a", "unit-b"]
        records[f"source-ledger-key-{index:02d}"] = {
            "symbol": symbol,
            "class": conflict_class,
            "units": units,
            "variants": unit_variants,
            "detail": (
                f"synthetic unresolved link reference: {symbol}"
                if not unit_variants
                else f"synthetic divergent declarations: {symbol}"
            ),
            "first_seen": "2026-08-21T00:00:00Z",
            "last_seen": "2026-08-21T00:01:00Z",
            "times_seen": 2,
        }
    assert len(records) == 41
    return _assembly_ledger_bytes(records)


# ---------------------------------------------------- T2b -> T2c evidence fold


def test_assembly_conflict_fold_imports_41_symbols_without_a_silent_winner():
    registry = empty_registry()
    ledger_bytes = _synthetic_41_conflict_ledger()
    digest = hashlib.sha256(ledger_bytes).hexdigest()

    result = fold_assembly_conflict_ledger(registry, ledger_bytes)

    assert result.changed is True
    assert result.imported == 41
    assert result.ledger_sha256 == digest
    assert registry_version(registry) == 1
    assert len(registry["entries"]) == 41
    conflict_ids = set()
    for entry in registry["entries"].values():
        assert entry["assembly_only"] is True
        assert entry["behavioral_authority"] is False
        assert entry["contested"] is True
        assert "macro" not in entry and "declaration" not in entry
        assert len(entry["assembly_conflicts"]) == 1
        evidence = entry["assembly_conflicts"][0]
        assert evidence["ledger_sha256"] == digest
        assert evidence["evidence_domain"] == "assembly"
        assert evidence["injectable"] is False
        assert evidence["first_seen"] == "2026-08-21T00:00:00Z"
        assert evidence["last_seen"] == "2026-08-21T00:01:00Z"
        conflict_ids.add(evidence["conflict_id"])
    assert len(conflict_ids) == 41

    for symbol in (
        "undefined8",
        "CONCAT44",
        "DAT_804361fc",
        "zz_00f0104_",
        "zz_00076d0_",
    ):
        augmented = augment_seed(
            registry, unit_name="later-unit", seed_text=SEED, symbols={symbol}
        )
        assert augmented.injected_any is False
        assert augmented.skipped_contested

    link_only = registry["entries"]["fn:zz_00076d0_"]["assembly_conflicts"][0]
    assert link_only["variants"] == {}
    assert link_only["resolution"] == "unresolved"


def test_assembly_conflict_fold_is_byte_and_version_idempotent():
    registry = empty_registry()
    ledger_bytes = _synthetic_41_conflict_ledger()
    first = fold_assembly_conflict_ledger(registry, ledger_bytes)
    first_bytes = json.dumps(registry, sort_keys=True, indent=2).encode("utf-8")
    first_version = registry_version(registry)

    second = fold_assembly_conflict_ledger(registry, ledger_bytes)

    assert first.changed is True
    assert second.changed is False
    assert second.imported == 0
    assert registry_version(registry) == first_version
    assert json.dumps(registry, sort_keys=True, indent=2).encode("utf-8") == first_bytes


def test_assembly_conflict_fold_ignores_recurrence_only_ledger_churn():
    registry = empty_registry()
    ledger_bytes = _synthetic_41_conflict_ledger()
    fold_assembly_conflict_ledger(registry, ledger_bytes)
    first_bytes = json.dumps(registry, sort_keys=True, indent=2).encode("utf-8")
    first_version = registry_version(registry)
    churned = json.loads(ledger_bytes)
    churned["updated_at"] = "2026-08-21T02:00:00Z"
    churned["runs_total"] = 99
    for conflict in churned["conflicts"].values():
        conflict["last_seen"] = "2026-08-21T02:00:00Z"
        conflict["times_seen"] = 99
    churned_bytes = (json.dumps(churned, sort_keys=True, indent=2) + "\n").encode()

    result = fold_assembly_conflict_ledger(registry, churned_bytes)

    assert result.changed is False
    assert registry_version(registry) == first_version
    assert json.dumps(registry, sort_keys=True, indent=2).encode("utf-8") == first_bytes


def test_assembly_conflict_fold_rejects_malformed_snapshot_atomically():
    registry = _registry_with(_entry())
    before = json.dumps(registry, sort_keys=True)
    malformed = _assembly_ledger_bytes(
        {
            "a-valid": {
                "symbol": "zz_valid_",
                "class": "collision_stub",
                "units": ["unit-a", "unit-b"],
                "variants": {
                    "unit-a": "int zz_valid_();",
                    "unit-b": "void zz_valid_(int);",
                },
                "detail": "valid fixture before malformed record",
                "first_seen": "2026-08-21T00:00:00Z",
                "last_seen": "2026-08-21T00:01:00Z",
                "times_seen": 1,
            },
            "z-invalid": {"symbol": "zz_invalid_", "class": "collision_stub"},
        }
    )

    with pytest.raises(ValueError, match="nonempty units"):
        fold_assembly_conflict_ledger(registry, malformed)

    assert json.dumps(registry, sort_keys=True) == before


def test_assembly_only_fold_does_not_reopen_source_retry_delta():
    registry = empty_registry()
    fold_assembly_conflict_ledger(registry, _synthetic_41_conflict_ledger())

    assert relevant_delta(registry, {"zz_00f0104_"}, since_version=0) == []
    assert relevant_delta(registry, {"zz_00076d0_"}, since_version=0) == []


def test_assembly_fold_preserves_revocation_tombstone_and_existing_tier():
    entry = _entry(
        tier=TIER_ORACLE_GREEN,
        revoked=True,
        contested=False,
        conflicts=[
            {
                "unit": "unit-earlier",
                "tombstone": True,
                "reason": "oracle re-run failed",
            }
        ],
    )
    registry = _registry_with(entry)
    ledger = _assembly_ledger_bytes(
        {
            "dat-conflict": {
                "symbol": DAT_SYM,
                "class": "dat_width_divergence",
                "units": ["unit-a", "unit-b"],
                "variants": {"unit-a": MACRO_CHAR, "unit-b": MACRO_INT},
                "detail": "synthetic divergence",
                "first_seen": "2026-08-21T00:00:00Z",
                "last_seen": "2026-08-21T00:01:00Z",
                "times_seen": 1,
            }
        }
    )

    fold_assembly_conflict_ledger(registry, ledger)

    imported = registry["entries"][DAT_KEY]
    assert imported["revoked"] is True
    assert imported["tier"] == TIER_ORACLE_GREEN
    assert imported["macro"] == MACRO_INT
    assert imported["source_units"] == ["unit-earlier"]
    assert imported["conflicts"] == entry["conflicts"]
    assert imported["assembly_conflicts"]
    assert augment_seed(
        registry, unit_name="later-unit", seed_text=SEED, symbols={DAT_SYM}
    ).injected_any is False

    harvest_unit(
        registry,
        unit_name="fresh-source",
        tier=TIER_COMPILE_ONLY,
        seed_text=SEED,
        header_text=SEED + MACRO_CHAR + "\n",
        unit_c_text=UNIT_C,
    )
    assert registry["entries"][DAT_KEY]["assembly_conflicts"]


def _harvest_definition_over_assembly_conflict(tier: str) -> dict:
    registry = empty_registry()
    fold_assembly_conflict_ledger(
        registry,
        _assembly_ledger_bytes(
            {
                "definition-conflict": {
                    "symbol": "zz_demo_",
                    "class": CLASS_COLLISION_STUB,
                    "units": ["caller-a", "caller-b"],
                    "variants": {
                        "caller-a": "int zz_demo_();",
                        "caller-b": "void zz_demo_(int);",
                    },
                    "detail": "synthetic declaration disagreement",
                    "first_seen": "2026-08-21T00:00:00Z",
                    "last_seen": "2026-08-21T00:01:00Z",
                    "times_seen": 1,
                }
            }
        ),
    )
    harvest_unit(
        registry,
        unit_name="owner",
        tier=tier,
        seed_text="",
        header_text="",
        unit_c_text=(
            "void zz_demo_(int a);\n\n"
            "/* ==== VERBATIM ==== */\n"
            "void zz_demo_(int a) { (void)a; }\n"
        ),
    )
    return registry


def test_compile_definition_normalizes_assembly_only_entry_to_mixed_contested():
    registry = _harvest_definition_over_assembly_conflict(TIER_COMPILE_ONLY)
    entry = registry["entries"]["fn:zz_demo_"]
    assert entry["assembly_only"] is False
    assert entry["behavioral_authority"] is False
    assert entry["tier"] == TIER_COMPILE_ONLY
    assert entry["source_units"] == ["owner"]
    assert entry["source_tiers"] == {"owner": TIER_COMPILE_ONLY}
    assert entry["contested"] is True
    assert entry["assembly_conflicts"][0]["behavioral_authority"] is False
    assert augment_seed(
        registry, unit_name="later", seed_text=SEED, symbols={"zz_demo_"}
    ).injected_any is False


def test_oracle_definition_normalizes_mixed_source_authority_but_not_assembly():
    registry = _harvest_definition_over_assembly_conflict(TIER_ORACLE_GREEN)
    entry = registry["entries"]["fn:zz_demo_"]
    assert entry["assembly_only"] is False
    assert entry["behavioral_authority"] is True
    assert entry["tier"] == TIER_ORACLE_GREEN
    assert entry["source_units"] == ["owner"]
    assert entry["source_tiers"] == {"owner": TIER_ORACLE_GREEN}
    assert entry["contested"] is True
    assert entry["assembly_conflicts"][0]["behavioral_authority"] is False
    assert augment_seed(
        registry, unit_name="later", seed_text=SEED, symbols={"zz_demo_"}
    ).injected_any is False


def test_unattributed_producer_link_failure_does_not_block_named_import(tmp_path):
    units = ["unit-a", "unit-b"]
    conflicts = conflicts_from_link_error("linker exited without a symbol", units)
    conflicts += conflicts_from_link_error(
        "wasm-ld: error: function signature mismatch: zz_ok_", units
    )
    assert conflicts[0]["symbol"] is None
    ledger_path = tmp_path / "assembly-gate.json"
    record_gate_result(
        ledger_path,
        {
            "passed": False,
            "n": 2,
            "units": units,
            "checked_at": "2026-08-21T00:00:00Z",
            "stage": "link",
            "detail": "synthetic link failure",
            "conflicts": conflicts,
        },
    )
    registry = empty_registry()

    result = fold_assembly_conflict_ledger(registry, ledger_path.read_bytes())

    assert result.imported == 2
    assert "fn:zz_ok_" in registry["entries"]
    unattributed = registry["assembly_unattributed_conflicts"]
    assert len(unattributed) == 1
    assert unattributed[0]["class"] == CLASS_LINK_FAILURE
    assert unattributed[0]["symbol"] is None
    assert unattributed[0]["injectable"] is False
    assert unattributed[0]["resolution"] == "unresolved"


@pytest.mark.parametrize(
    ("patch", "message"),
    [
        ({"class": "not-a-gate-class"}, "unknown class"),
        ({"units": []}, "nonempty units"),
        ({"units": ["unit-a", "unit-a"]}, "unique units"),
        (
            {"variants": {"ghost-unit": "int zz_bad_();"}},
            "variant units",
        ),
        ({"first_seen": 123}, "first_seen.*ISO"),
        ({"last_seen": "not-a-timestamp"}, "last_seen.*ISO"),
        ({"times_seen": -7}, "nonnegative times_seen"),
    ],
)
def test_assembly_conflict_fold_rejects_adversarial_provenance_atomically(
    patch, message
):
    conflict = {
        "symbol": "zz_bad_",
        "class": CLASS_COLLISION_STUB,
        "units": ["unit-a", "unit-b"],
        "variants": {
            "unit-a": "int zz_bad_();",
            "unit-b": "void zz_bad_(int);",
        },
        "detail": "synthetic disagreement",
        "first_seen": "2026-08-21T00:00:00Z",
        "last_seen": "2026-08-21T00:01:00Z",
        "times_seen": 1,
    }
    conflict.update(patch)
    registry = _registry_with(_entry())
    before = json.dumps(registry, sort_keys=True)

    with pytest.raises(ValueError, match=message):
        fold_assembly_conflict_ledger(
            registry, _assembly_ledger_bytes({"adversarial": conflict})
        )

    assert json.dumps(registry, sort_keys=True) == before


def test_new_definition_harvest_emits_one_semicolon():
    candidates = harvest_candidates(
        SEED,
        SEED,
        '#include "gnt4_shim.h"\n\nint zz_defined_(int a);\n\n'
        "/* ==== VERBATIM ==== */\nint zz_defined_(int a) { return a; }\n",
    )
    definition = next(c for c in candidates if c["symbol"] == "zz_defined_")
    assert definition["text"].endswith(";")
    assert not definition["text"].endswith(";;")


# ---------------------------------------------------------------- injection


def test_advisory_entry_injects_as_comment_only():
    """[V4-1] BLOCKING-finding fix: compile_only knowledge is a HINT. No
    active #define, no do-not-alter rule -- the unit stays free to derive its
    own typing."""
    result = augment_seed(
        _registry_with(_entry()),
        unit_name="unit-a",
        seed_text=SEED,
        symbols={DAT_SYM},
    )
    header = result.header_text
    assert result.advisory and not result.authoritative
    # the macro appears ONLY inside a comment
    assert f"/* {MACRO_INT} */" in header
    assert "\n" + MACRO_INT not in header.replace(f"/* {MACRO_INT} */", "")
    assert "advisory" in header
    assert "free to disagree" in header
    # the do-not-alter rule is reserved for the oracle tier
    assert "do not alter" not in header


def test_authoritative_entry_replaces_seed_line_in_place():
    """[V4-5] merge, never append: a seed line for the same symbol is
    replaced, so no symbol appears twice in the assembled header."""
    seed = SEED + MACRO_CHAR + "\n"
    result = augment_seed(
        _registry_with(_entry(tier=TIER_ORACLE_GREEN, macro=MACRO_INT)),
        unit_name="unit-a",
        seed_text=seed,
        symbols={DAT_SYM},
    )
    header = result.header_text
    assert result.authoritative
    assert MACRO_INT in header
    assert MACRO_CHAR not in header  # replaced, not duplicated
    assert header.count(f"#define {DAT_SYM}") == 1
    assert "do not alter" in header


def test_contested_entry_is_never_injected_even_advisorily():
    """Presenting a coin-flip is worse than a cold start: a contested symbol
    is withheld entirely."""
    result = augment_seed(
        _registry_with(_entry(contested=True)),
        unit_name="unit-a",
        seed_text=SEED,
        symbols={DAT_SYM},
    )
    assert result.header_text == SEED
    assert result.skipped_contested == [DAT_KEY]
    assert not result.injected_any


def test_revoked_entry_is_never_injected():
    result = augment_seed(
        _registry_with(_entry(revoked=True)),
        unit_name="unit-a",
        seed_text=SEED,
        symbols={DAT_SYM},
    )
    assert result.header_text == SEED
    assert not result.injected_any


def test_irrelevant_entry_is_not_injected():
    """Relevance = symbol intersection, nothing fuzzier."""
    result = augment_seed(
        _registry_with(_entry()),
        unit_name="unit-a",
        seed_text=SEED,
        symbols={"DAT_deadbeef", "zz_other_"},
    )
    assert result.header_text == SEED


def test_prelude_declared_prototype_is_not_injected_and_files_pending_conflict():
    """[V4-5] the prelude is Ghidra's own signature for this unit and
    outranks a sibling unit's compile-time guess; the disagreement is
    recorded as data, never as an injection."""
    registry = empty_registry()
    registry["version"] = 1
    registry["entries"]["fn:zz_callee_"] = {
        "kind": "prototype",
        "symbol": "zz_callee_",
        "declaration": "int zz_callee_(int);",
        "tier": TIER_COMPILE_ONLY,
        "source_units": ["unit-earlier"],
        "source_tiers": {"unit-earlier": TIER_COMPILE_ONLY},
        "contested": False,
        "conflicts": [],
        "updated_version": 1,
    }
    result = augment_seed(
        registry,
        unit_name="unit-a",
        seed_text=SEED,
        symbols={"zz_callee_"},
        prelude_declarations={"zz_callee_": "void zz_callee_(int,int);"},
    )
    assert result.header_text == SEED  # nothing injected
    assert result.registry_changed
    assert result.pending_conflicts and result.pending_conflicts[0]["symbol"] == "zz_callee_"
    entry = registry["entries"]["fn:zz_callee_"]
    assert entry["conflicts"] and entry["conflicts"][0]["tier"] == "prelude"
    # the entry itself was NOT rewritten: recorded, not auto-resolved
    assert entry["declaration"] == "int zz_callee_(int);"
    assert registry_version(registry) == 2
    # recording the same disagreement again neither duplicates nor re-bumps
    again = augment_seed(
        registry,
        unit_name="unit-a",
        seed_text=SEED,
        symbols={"zz_callee_"},
        prelude_declarations={"zz_callee_": "void zz_callee_(int,int);"},
    )
    assert not again.registry_changed
    assert len(entry["conflicts"]) == 1


def test_holdout_is_deterministic_and_near_ten_percent(monkeypatch):
    monkeypatch.delenv("OGHIDRA_PORT_REGISTRY_HOLDOUT_PCT", raising=False)
    names = [f"auto-c{i:04d}-{j:03d}" for i in range(80) for j in range(25)]
    first = [is_holdout(name) for name in names]
    assert first == [is_holdout(name) for name in names]  # deterministic
    fraction = sum(first) / len(first)
    assert 0.05 < fraction < 0.15


# ------------------------------------------------------------------ harvest


def test_harvest_takes_unit_decisions_and_applies_both_exclusions():
    """[V4-1]: seed-inherited lines and callee stub definitions are never
    harvested; the unit's own DAT/pseudo-op/typedef/prototype decisions are."""
    seed = SEED + "#define CONCAT44(hi,lo) (((unsigned long long)(unsigned int)(hi) << 32) | (unsigned int)(lo))\n"
    header = (
        seed
        + MACRO_CHAR + "\n"
        + "typedef unsigned char byte;\n"
        + "extern double zz_callee_(short);\n"
        + "int zz_stub_(int a, int b) { return 0; }\n"  # callee stub definition
    )
    registry = empty_registry()
    result = harvest_unit(
        registry,
        unit_name="unit-a",
        tier=TIER_COMPILE_ONLY,
        seed_text=seed,
        header_text=header,
        unit_c_text=UNIT_C,
    )
    assert result.changed and registry_version(registry) == 1
    entries = registry["entries"]
    assert DAT_KEY in entries  # the unit's decision
    assert "typedef:byte" in entries
    assert "fn:zz_callee_" in entries
    assert entries["fn:zz_callee_"]["derivation"] == "call_site"
    # exclusions:
    assert "typedef:undefined8" not in entries  # seed-inherited
    assert "macro:CONCAT44" not in entries  # seed-inherited pseudo-op
    assert "fn:zz_stub_" not in entries  # callee stub definition


def test_harvest_agreement_adds_source_without_conflict():
    registry = _registry_with(_entry(macro=MACRO_CHAR))
    result = harvest_unit(
        registry,
        unit_name="unit-b",
        tier=TIER_COMPILE_ONLY,
        seed_text=SEED,
        header_text=SEED + MACRO_CHAR + "\n",
        unit_c_text=UNIT_C,
    )
    entry = registry["entries"][DAT_KEY]
    assert "unit-b" in entry["source_units"]
    assert not result.new_conflicts and not entry["conflicts"]
    # re-harvesting the same unit changes nothing (no fake version churn)
    again = harvest_unit(
        registry,
        unit_name="unit-b",
        tier=TIER_COMPILE_ONLY,
        seed_text=SEED,
        header_text=SEED + MACRO_CHAR + "\n",
        unit_c_text=UNIT_C,
    )
    assert not again.changed


def test_definition_derived_prototype_is_the_arbiter():
    """t2b-backfill class 2: the defining chunk's prelude prototype outranks
    every call-site guess -- it wins the PRESENTED slot, and the losing
    variant is recorded, never dropped."""
    registry = empty_registry()
    registry["version"] = 1
    registry["entries"]["fn:zz_0006fb4_"] = {
        "kind": "prototype",
        "symbol": "zz_0006fb4_",
        "declaration": "int zz_0006fb4_();",
        "tier": TIER_COMPILE_ONLY,
        "derivation": "call_site",
        "source_units": ["auto-c0001-010"],
        "source_tiers": {"auto-c0001-010": TIER_COMPILE_ONLY},
        "contested": False,
        "conflicts": [],
        "updated_version": 1,
    }
    defining_unit_c = (
        '#include "gnt4_shim.h"\n\n'
        "void zz_0006fb4_(int a, short *b);\n\n"
        "/* ==== VERBATIM: chunk.c 1-4 ==== */\n"
        "void zz_0006fb4_(int a, short *b)\n{\n  *b = (short)a;\n}\n"
    )
    result = harvest_unit(
        registry,
        unit_name="unit-defining",
        tier=TIER_COMPILE_ONLY,
        seed_text=SEED,
        header_text=SEED,
        unit_c_text=defining_unit_c,
    )
    entry = registry["entries"]["fn:zz_0006fb4_"]
    assert entry["derivation"] == "definition"
    assert "void" in entry["declaration"]
    assert entry["source_units"] == ["unit-defining"]
    assert entry["conflicts"] and "int zz_0006fb4_" in entry["conflicts"][0]["text"]
    assert result.new_conflicts and not result.new_conflicts[0]["contested"]
    # ...and a later call-site guess cannot displace the definition
    later = harvest_unit(
        registry,
        unit_name="unit-caller",
        tier=TIER_COMPILE_ONLY,
        seed_text=SEED,
        header_text=SEED + "extern undefined8 zz_0006fb4_(int, int);\n",
        unit_c_text=UNIT_C.replace("zz_use_", "zz_x_"),
    )
    assert registry["entries"]["fn:zz_0006fb4_"]["derivation"] == "definition"
    assert "void" in registry["entries"]["fn:zz_0006fb4_"]["declaration"]
    assert later.new_conflicts  # the disagreement is still on the record


# ------------------------------------ the advisory boundary (echo-chamber F1)


def test_registry_cannot_override_or_suppress_a_conflict():
    """THE binding T2c constraint: an advisory entry is a hint, not a law.

    A unit that independently derives a DIFFERENT typing (with the advisory
    hint in view) must (a) keep its own derivation -- augment gave it only a
    comment to disagree with; (b) have the disagreement RECORDED as a
    conflict; (c) render the symbol contested so neither variant is
    presented again; and (d) leave the original entry text un-flipped -- no
    silent winner in either direction."""
    registry = _registry_with(_entry(macro=MACRO_INT))
    # (a) injection cannot force anything: the seed gains only a comment
    augmented = augment_seed(
        registry, unit_name="unit-b", seed_text=SEED, symbols={DAT_SYM}
    )
    active_lines = [
        line
        for line in augmented.header_text.splitlines()
        if line.strip().startswith("#define")
    ]
    assert active_lines == []  # no active define was imposed
    # the unit derives MACRO_CHAR instead; harvest compares independently
    result = harvest_unit(
        registry,
        unit_name="unit-b",
        tier=TIER_COMPILE_ONLY,
        seed_text=augmented.header_text,
        header_text=augmented.header_text + "\n" + MACRO_CHAR + "\n",
        unit_c_text=UNIT_C,
    )
    entry = registry["entries"][DAT_KEY]
    # (b) conflict recorded and surfaced
    assert result.new_conflicts and result.new_conflicts[0]["symbol"] == DAT_SYM
    assert entry["conflicts"] and entry["conflicts"][0]["unit"] == "unit-b"
    # (c) contested: withheld from every later unit
    assert entry["contested"] is True
    assert (
        augment_seed(
            registry, unit_name="unit-c", seed_text=SEED, symbols={DAT_SYM}
        ).header_text
        == SEED
    )
    # (d) no silent winner: the presented text did not flip to the newcomer
    assert entry["macro"] == MACRO_INT


def test_adopting_an_advisory_hint_counts_as_agreement_evidence():
    """Advisory lines are comments in the seed, so a unit that ADOPTS one has
    made an active-line decision of its own -- harvested as agreement (the
    zero-extra-cost replication experiment)."""
    registry = _registry_with(_entry(macro=MACRO_INT))
    augmented = augment_seed(
        registry, unit_name="unit-b", seed_text=SEED, symbols={DAT_SYM}
    )
    result = harvest_unit(
        registry,
        unit_name="unit-b",
        tier=TIER_COMPILE_ONLY,
        seed_text=augmented.header_text,
        header_text=augmented.header_text + "\n" + MACRO_INT + "\n",
        unit_c_text=UNIT_C,
    )
    entry = registry["entries"][DAT_KEY]
    assert "unit-b" in entry["source_units"]
    assert not result.new_conflicts


def test_authoritative_injection_is_not_laundered_into_agreement():
    """A unit that keeps an injected AUTHORITATIVE line unchanged made no
    decision about it: the line is seed-inherited and must not add the unit
    as an agreeing source [V4-1]."""
    registry = _registry_with(_entry(tier=TIER_ORACLE_GREEN, macro=MACRO_INT))
    augmented = augment_seed(
        registry, unit_name="unit-b", seed_text=SEED, symbols={DAT_SYM}
    )
    assert MACRO_INT in augmented.header_text  # actively injected
    result = harvest_unit(
        registry,
        unit_name="unit-b",
        tier=TIER_COMPILE_ONLY,
        seed_text=augmented.header_text,
        header_text=augmented.header_text,  # kept verbatim
        unit_c_text=UNIT_C,
    )
    entry = registry["entries"][DAT_KEY]
    assert "unit-b" not in entry["source_units"]
    assert DAT_KEY not in result.agreed and DAT_KEY not in result.added
    # (the unit's own defined-function prototype still harvests -- that IS
    # its decision; only the untouched injected line is excluded)
    assert result.added == ["fn:zz_use_"]


def test_lower_tier_disagreement_is_recorded_but_never_wins():
    registry = _registry_with(_entry(tier=TIER_ORACLE_GREEN, macro=MACRO_INT))
    result = harvest_unit(
        registry,
        unit_name="unit-b",
        tier=TIER_COMPILE_ONLY,
        seed_text=SEED,
        header_text=SEED + MACRO_CHAR + "\n",
        unit_c_text=UNIT_C,
    )
    entry = registry["entries"][DAT_KEY]
    assert entry["macro"] == MACRO_INT  # presentation unchanged
    assert entry["tier"] == TIER_ORACLE_GREEN
    assert not entry["contested"]  # higher tier still injectable
    assert entry["conflicts"] and entry["conflicts"][0]["unit"] == "unit-b"
    assert result.new_conflicts and not result.new_conflicts[0]["green_green"]


def test_green_green_disagreement_pages_instead_of_winning_by_recency():
    registry = _registry_with(_entry(tier=TIER_ORACLE_GREEN, macro=MACRO_INT))
    result = harvest_unit(
        registry,
        unit_name="unit-b",
        tier=TIER_ORACLE_GREEN,
        seed_text=SEED,
        header_text=SEED + MACRO_CHAR + "\n",
        unit_c_text=UNIT_C,
    )
    entry = registry["entries"][DAT_KEY]
    assert result.new_conflicts and result.new_conflicts[0]["green_green"]
    assert entry["contested"] is True  # neither variant presented
    assert entry["macro"] == MACRO_INT  # and neither silently replaced


# ------------------------------------------------- survival check ([V4-6])


def test_survival_check_is_semantic_and_oracle_tier_only():
    authoritative = [
        {
            "key": DAT_KEY,
            "symbol": DAT_SYM,
            "kind": "dat_typing",
            "text": MACRO_INT,
            "normal": "# define DAT_802c44f8 ( * ( unsigned int * ) ( unsigned int ) 0x802c44f8 )".replace("# define", "# define"),
        }
    ]
    # normalize expected the same way the module does
    from src.port_knowledge_registry import normalized_form

    authoritative[0]["normal"] = normalized_form("dat_typing", MACRO_INT)
    # cosmetic churn (spacing + comment) is NOT a deviation
    cosmetic = SEED + "#define  DAT_802c44f8   (*(unsigned int *)(unsigned int)0x802c44f8) /* kept */\n"
    assert check_survival(authoritative, cosmetic) == []
    # a semantic mutation IS a deviation, even though the prefix survived
    mutated = SEED + MACRO_SHORT + "\n"
    deviations = check_survival(authoritative, mutated)
    assert deviations and deviations[0]["symbol"] == DAT_SYM
    # dropping the line entirely is a deviation too
    assert check_survival(authoritative, SEED)
    # advisory entries are never checked: the API only accepts the
    # authoritative list, and an empty list checks nothing
    assert check_survival([], mutated) == []


# ------------------------------------------- re-tier / demote / revoke [V4-7]


def test_promotion_recomputes_conflicts_and_escalates_green_green():
    registry = _registry_with(
        _entry(
            unit="unit-b",
            macro=MACRO_INT,
            contested=True,
            conflicts=[
                {
                    "unit": "unit-c",
                    "text": MACRO_CHAR,
                    "tier": TIER_COMPILE_ONLY,
                    "normal": "x",
                    "reason": "same-tier disagreement",
                }
            ],
        )
    )
    result = promote_unit_entries(registry, "unit-b")
    entry = registry["entries"][DAT_KEY]
    assert DAT_KEY in result.promoted
    assert entry["tier"] == TIER_ORACLE_GREEN
    assert entry["contested"] is False  # the tie now has a winner
    assert DAT_KEY in result.reopened
    assert registry_version(registry) == 2
    # but a conflicting variant that is itself oracle_green escalates
    registry2 = _registry_with(
        _entry(
            unit="unit-b",
            macro=MACRO_INT,
            contested=True,
            conflicts=[
                {
                    "unit": "unit-c",
                    "text": MACRO_CHAR,
                    "tier": TIER_ORACLE_GREEN,
                    "normal": "x",
                    "reason": "disagreement",
                }
            ],
        )
    )
    result2 = promote_unit_entries(registry2, "unit-b")
    assert DAT_KEY in result2.green_green
    assert registry2["entries"][DAT_KEY]["contested"] is True  # still withheld


def test_revocation_demotes_or_tombstones_never_vanishes():
    # sole source -> revoked with tombstone
    registry = _registry_with(_entry(unit="unit-b", tier=TIER_ORACLE_GREEN))
    result = revoke_unit_entries(registry, "unit-b")
    entry = registry["entries"][DAT_KEY]
    assert DAT_KEY in result.revoked
    assert entry["revoked"] is True
    assert any(c.get("tombstone") for c in entry["conflicts"])
    assert registry_version(registry) == 2
    # independent sources remain -> demoted, not removed
    shared = _entry(unit="unit-b", tier=TIER_ORACLE_GREEN)
    shared["source_units"] = ["unit-b", "unit-c"]
    shared["source_tiers"] = {
        "unit-b": TIER_ORACLE_GREEN,
        "unit-c": TIER_COMPILE_ONLY,
    }
    registry2 = _registry_with(shared)
    result2 = revoke_unit_entries(registry2, "unit-b")
    entry2 = registry2["entries"][DAT_KEY]
    assert DAT_KEY in result2.demoted
    assert entry2["tier"] == TIER_COMPILE_ONLY
    assert entry2["source_units"] == ["unit-c"]
    assert not entry2.get("revoked")


# ------------------------------------------------- misc mechanics


def test_relevant_delta_filters_by_symbol_and_version():
    registry = _registry_with(_entry(updated_version=3))
    registry["entries"]["fn:zz_other_"] = {
        "kind": "prototype",
        "symbol": "zz_other_",
        "declaration": "void zz_other_(void);",
        "tier": TIER_COMPILE_ONLY,
        "source_units": ["u"],
        "contested": False,
        "conflicts": [],
        "updated_version": 5,
    }
    assert relevant_delta(registry, {DAT_SYM}, 2) == [DAT_KEY]
    assert relevant_delta(registry, {DAT_SYM}, 3) == []
    assert relevant_delta(registry, {"zz_other_"}, 3) == ["fn:zz_other_"]
    assert relevant_delta(registry, {"unrelated"}, 0) == []


def test_unit_symbol_set_catches_dat_callee_export_and_typedefs():
    symbols = unit_symbol_set(UNIT_C, exports=["zz_use_"])
    assert DAT_SYM in symbols
    assert "zz_use_" in symbols
    assert "uVar1" not in symbols


def test_load_registry_missing_is_empty_and_roundtrips(tmp_path):
    path = tmp_path / "knowledge-registry.json"
    registry = load_registry(path)
    assert registry_version(registry) == 0
    registry["entries"][DAT_KEY] = _entry()
    registry["version"] = 7
    save_registry(path, registry)
    assert registry_version(load_registry(path)) == 7
    path.write_text("{\"registry_schema\": 99}", encoding="utf-8")
    with pytest.raises(ValueError):
        load_registry(path)


# --------------------------------------------- [V4-8] path trackability


def test_registry_path_is_trackable_in_gotyaforce():
    """Design [V4-8]: the registry lives inside a wholesale-gitignored
    directory; without the negation exception 'versioned by git' is false as
    written. git check-ignore must REJECT (exit non-zero for) the path."""
    from src.port_run_controller import find_gotyaforce_root

    try:
        root = find_gotyaforce_root()
    except Exception:  # noqa: BLE001
        pytest.skip("GotYaForce root not locatable in this environment")
    if not (root / ".git").exists():
        pytest.skip("GotYaForce root is not a git checkout")
    completed = subprocess.run(
        ["git", "-C", str(root), "check-ignore", "-q", REGISTRY_RELPATH],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert completed.returncode != 0, (
        f"{REGISTRY_RELPATH} is gitignored; the [V4-8] negation exception is "
        "missing from the GotYaForce .gitignore"
    )
    # and the wholesale rule still holds for its siblings
    sibling = subprocess.run(
        [
            "git", "-C", str(root), "check-ignore", "-q",
            "research/decomp/generated/finish-game-port/wasm-units-state.json",
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert sibling.returncode == 0, "the wholesale ignore rule was lost"


# ===========================================================================
# Driver touch points (src/port_wasm_units.py, T2c section 9)

from src.port_driver import EXIT_NO_WORK, EXIT_PROGRESSED  # noqa: E402
from src.port_wasm_units import PROMPT_VERSION, WasmUnitDriver  # noqa: E402


def _completed(rc: int = 0, stdout: str = "") -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(
        args=["git"], returncode=rc, stdout=stdout, stderr=""
    )


def _write_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    (repo / "research/decomp/ghidra-export").mkdir(parents=True)
    (repo / "research/decomp/generated/finish-game-port").mkdir(parents=True)
    (repo / "research/decomp/poc").mkdir(parents=True)
    chunk = repo / "research/decomp/ghidra-export/chunk_9999.c"
    chunk.write_text(
        "// line1\nint zz_test_(int a)\n{\n  return a + (int)DAT_802c44f8;\n}\n// tail\n",
        encoding="utf-8",
    )
    (repo / "research/decomp/poc/seed.h").write_text(SEED, encoding="utf-8")
    queue = {
        "queue_schema": 1,
        "units": [
            {
                "name": "unit-a",
                "extractions": [
                    {
                        "file": "research/decomp/ghidra-export/chunk_9999.c",
                        "start": 2,
                        "end": 5,
                    }
                ],
                "prelude": ["int zz_test_(int a);"],
                "exported_functions": ["zz_test_"],
                "header_seed": "research/decomp/poc/seed.h",
                "oracle": {
                    "command": ["node", "fake.mjs"],
                    "cwd": "research/decomp/poc",
                    "env": {},
                    "success_patterns": ["PASS"],
                },
            }
        ],
    }
    (repo / "research/decomp/generated/finish-game-port/wasm-units.json").write_text(
        json.dumps(queue), encoding="utf-8"
    )
    return repo


class _FakeJournal:
    """Deterministic durable journal used by driver-integration fixtures."""

    def __init__(self):
        self.checkpoints = []

    def checkpoint(self, **kwargs):
        transition = kwargs.get("transition")
        transition_id = (
            transition.extra.get("transition_id")
            if transition is not None and isinstance(transition.extra, dict)
            else None
        )
        if transition_id and any(
            item.get("transition") is not None
            and item["transition"].extra.get("transition_id") == transition_id
            for item in self.checkpoints
        ):
            return {
                "recorded": True,
                "committed": True,
                "pushed": True,
                "idempotent": True,
            }
        self.checkpoints.append(kwargs)
        return {"recorded": True, "committed": True, "pushed": True}

    def authoritative_transition_receipt(self, transition_id):
        records = [
            item["transition"].to_record("", "")
            for item in self.checkpoints
            if item.get("transition") is not None
            and item["transition"].extra.get("transition_id") == transition_id
        ]
        return {
            "authoritative": True,
            "remote": bool(records),
            "remote_records": records,
        }

    def push_is_pending(self):
        return False

    def flush_pending_push(self):
        pass


def _driver(repo: Path, **kwargs) -> WasmUnitDriver:
    defaults = dict(
        repo_root=repo,
        build_runner=lambda workdir, exports, extra=None: (True, ""),
        oracle_runner=lambda unit, wasm: (True, "1/1", "PASS log"),
        git_runner=lambda *args: _completed(0, "abc123\n"),
        journal=_FakeJournal(),
    )
    defaults.update(kwargs)
    return WasmUnitDriver(**defaults)


def _registry_file(repo: Path) -> Path:
    return repo / REGISTRY_RELPATH


def _events(repo: Path) -> list[dict]:
    path = repo / "research/decomp/generated/finish-game-port/events.jsonl"
    return [
        json.loads(line) for line in path.read_text().splitlines() if line.strip()
    ]


class _HeaderLLM:
    default_model = "fake-27b"

    def __init__(self, header_body: str):
        self.header_body = header_body

    def generate(self, **_kwargs):
        return "```c\n" + self.header_body + "\n```"


def test_driver_folds_assembly_evidence_through_registry_co_commit(
    tmp_path, monkeypatch
):
    """The pure fold is consumed only inside the lock-taking green path;
    its registry mutation rides the existing artifact/journal transaction."""
    monkeypatch.delenv("OGHIDRA_PORT_LIVENESS_PATH", raising=False)
    monkeypatch.setenv("OGHIDRA_PORT_REGISTRY_HOLDOUT_PCT", "0")
    repo = _write_repo(tmp_path)
    queue_path = repo / "research/decomp/generated/finish-game-port/wasm-units.json"
    queue = json.loads(queue_path.read_text())
    queue["units"][0]["oracle"] = {"type": "compile_only"}
    queue_path.write_text(json.dumps(queue), encoding="utf-8")
    ledger_path = repo / "research/decomp/data/assembly-gate.json"
    ledger_path.parent.mkdir(parents=True)
    ledger_path.write_bytes(
        _assembly_ledger_bytes(
            {
                "link-only": {
                    "symbol": "zz_00076d0_",
                    "class": "collision_stub",
                    "units": ["unit-a", "unit-b"],
                    "variants": {},
                    "detail": "synthetic function signature mismatch",
                    "first_seen": "2026-08-21T00:00:00Z",
                    "last_seen": "2026-08-21T00:01:00Z",
                    "times_seen": 1,
                }
            }
        )
    )
    git_calls = []

    def fake_git(*args):
        git_calls.append(args)
        return _completed(0, "abc123\n")

    def successful_build(workdir, exports, extra=None):
        (workdir / "unit.wasm").write_bytes(b"\x00asm")
        return True, ""

    driver = _driver(repo, build_runner=successful_build, git_runner=fake_git)
    assert driver.run() == EXIT_NO_WORK

    registry = load_registry(_registry_file(repo))
    imported = registry["entries"]["fn:zz_00076d0_"]
    assert imported["assembly_only"] is True
    assert imported["assembly_conflicts"][0]["variants"] == {}
    assert any(
        event.get("kind") == "registry_assembly_conflicts_imported"
        for event in _events(repo)
    )
    assert any(
        args[0] == "add" and REGISTRY_RELPATH in args for args in git_calls
    )


def test_green_unit_harvests_and_co_commits_the_registry(tmp_path, monkeypatch):
    """T2c section 9: step 5 calls harvest(), and the registry rides the
    unit's own artifact commit (one push, G3-preserving); step 2 records
    registry_version_used and the per-attempt prompt version."""
    monkeypatch.delenv("OGHIDRA_PORT_LIVENESS_PATH", raising=False)
    monkeypatch.setenv("OGHIDRA_PORT_REGISTRY_HOLDOUT_PCT", "0")
    repo = _write_repo(tmp_path)
    git_calls = []

    def fake_git(*args):
        git_calls.append(args)
        if args[0] in {"rev-parse", "ls-remote"}:
            return _completed(0, "deadbeef\n")
        return _completed(0)

    builds = []

    def flaky_build(workdir, exports, extra=None):
        builds.append((workdir / "gnt4_shim.h").read_text())
        if len(builds) == 1:
            return False, "error: use of undeclared identifier 'DAT_802c44f8'"
        (workdir / "unit.wasm").write_bytes(b"\x00asm")
        return True, ""

    driver = _driver(
        repo,
        git_runner=fake_git,
        build_runner=flaky_build,
        llm=_HeaderLLM(SEED + MACRO_CHAR),
    )
    assert driver.run() == EXIT_NO_WORK
    registry = load_registry(_registry_file(repo))
    assert registry_version(registry) == 1
    entry = registry["entries"][DAT_KEY]
    assert entry["tier"] == TIER_ORACLE_GREEN  # oracle passed
    assert entry["source_units"] == ["unit-a"]
    add_calls = [args for args in git_calls if args[0] == "add"]
    commit_calls = [args for args in git_calls if args[0] == "commit"]
    assert any(REGISTRY_RELPATH in args for args in add_calls)
    assert any(REGISTRY_RELPATH in args for args in commit_calls)
    state = json.loads(
        (
            repo / "research/decomp/generated/finish-game-port/wasm-units-state.json"
        ).read_text()
    )
    record = state["units"]["unit-a"]
    assert record["registry_version_used"] == 0
    assert record["registry_holdout"] is False
    assert record["prompt_version"] == PROMPT_VERSION
    assert DAT_SYM in record["symbol_set"]


def test_advisory_boundary_in_the_driver(tmp_path, monkeypatch):
    """End to end: an advisory entry reaches the model as a COMMENT only; the
    unit's independent (disagreeing) derivation goes green untouched; the
    disagreement is filed as a registry_conflict event and the entry becomes
    contested -- the registry never overrode or suppressed anything."""
    monkeypatch.delenv("OGHIDRA_PORT_LIVENESS_PATH", raising=False)
    monkeypatch.setenv("OGHIDRA_PORT_REGISTRY_HOLDOUT_PCT", "0")
    repo = _write_repo(tmp_path)
    # compile_only tier: a same-tier disagreement is the contested case (an
    # oracle-green unit would legitimately outrank the compile-only hint).
    queue_path = repo / "research/decomp/generated/finish-game-port/wasm-units.json"
    queue = json.loads(queue_path.read_text())
    queue["units"][0]["oracle"] = {"type": "compile_only"}
    queue_path.write_text(json.dumps(queue), encoding="utf-8")
    save_registry(_registry_file(repo), _registry_with(_entry(macro=MACRO_INT)))

    builds = []

    def flaky_build(workdir, exports, extra=None):
        builds.append((workdir / "gnt4_shim.h").read_text())
        if len(builds) == 1:
            return False, "error: use of undeclared identifier 'DAT_802c44f8'"
        (workdir / "unit.wasm").write_bytes(b"\x00asm")
        return True, ""

    driver = _driver(
        repo,
        build_runner=flaky_build,
        llm=_HeaderLLM(SEED + MACRO_CHAR),  # disagrees with the advisory hint
    )
    assert driver.run() == EXIT_NO_WORK
    # the model saw the hint as a comment, never as an active define
    assert "/* " + MACRO_INT + " */" in builds[0]
    assert not any(
        line.strip().startswith("#define DAT_802c44f8")
        for line in builds[0].splitlines()
    )
    # the unit's own derivation survived into the artifact
    artifact_header = (
        repo / "research/decomp/port-units-staging/unit-a/gnt4_shim.h"
    ).read_text()
    assert MACRO_CHAR in artifact_header
    # the disagreement is data: conflict filed, symbol contested, no winner
    registry = load_registry(_registry_file(repo))
    entry = registry["entries"][DAT_KEY]
    assert entry["contested"] is True
    assert entry["macro"] == MACRO_INT  # not flipped by the newcomer either
    assert entry["conflicts"] and entry["conflicts"][0]["unit"] == "unit-a"
    kinds = [event.get("kind") for event in _events(repo)]
    assert "registry_injected" in kinds
    assert "registry_conflict" in kinds


def test_holdout_unit_starts_cold_and_is_recorded(tmp_path, monkeypatch):
    """F6 [V4-1]: a holdout unit receives NO injection -- it derives every
    typing independently, which is what makes the agreement rate a
    correctness metric an echo chamber cannot fake."""
    monkeypatch.delenv("OGHIDRA_PORT_LIVENESS_PATH", raising=False)
    monkeypatch.setenv("OGHIDRA_PORT_REGISTRY_HOLDOUT_PCT", "100")
    repo = _write_repo(tmp_path)
    save_registry(_registry_file(repo), _registry_with(_entry(macro=MACRO_INT)))
    builds = []

    def capture_build(workdir, exports, extra=None):
        builds.append((workdir / "gnt4_shim.h").read_text())
        (workdir / "unit.wasm").write_bytes(b"\x00asm")
        return True, ""

    driver = _driver(repo, build_runner=capture_build)
    assert driver.run() == EXIT_NO_WORK
    assert builds[0] == SEED  # cold seed, untouched
    state = json.loads(
        (
            repo / "research/decomp/generated/finish-game-port/wasm-units-state.json"
        ).read_text()
    )
    assert state["units"]["unit-a"]["registry_holdout"] is True


def test_authoritative_mutation_emits_registry_deviation(tmp_path, monkeypatch):
    """[V4-6]: a semantic mutation of an injected oracle_green line does not
    abort the round -- it is recorded as a registry_deviation event, and the
    green harvest turns it into a conflict record."""
    monkeypatch.delenv("OGHIDRA_PORT_LIVENESS_PATH", raising=False)
    monkeypatch.setenv("OGHIDRA_PORT_REGISTRY_HOLDOUT_PCT", "0")
    repo = _write_repo(tmp_path)
    save_registry(
        _registry_file(repo),
        _registry_with(_entry(tier=TIER_ORACLE_GREEN, macro=MACRO_INT)),
    )
    builds = []

    def flaky_build(workdir, exports, extra=None):
        builds.append((workdir / "gnt4_shim.h").read_text())
        if len(builds) == 1:
            return False, "error: something"
        (workdir / "unit.wasm").write_bytes(b"\x00asm")
        return True, ""

    driver = _driver(
        repo,
        build_runner=flaky_build,
        llm=_HeaderLLM(SEED + MACRO_SHORT),  # mutates the authoritative line
    )
    assert driver.run() == EXIT_NO_WORK  # still green: deviation never aborts
    assert MACRO_INT in builds[0]  # the authoritative line WAS injected
    events = _events(repo)
    deviations = [e for e in events if e.get("kind") == "registry_deviation"]
    assert deviations and deviations[0]["symbol"] == DAT_SYM
    # green-with-deviation became a conflict at harvest
    registry = load_registry(_registry_file(repo))
    assert registry["entries"][DAT_KEY]["conflicts"]


def test_registry_delta_reopens_only_reds_it_touches(tmp_path, monkeypatch):
    """Section 2.8 (T2c refinement): a registry version bump re-opens a red
    ONLY when entries touching its recorded symbol set changed; an unrelated
    bump leaves it zero-delta (no forbidden same-input retry)."""
    monkeypatch.delenv("OGHIDRA_PORT_LIVENESS_PATH", raising=False)
    monkeypatch.setenv("OGHIDRA_PORT_REGISTRY_HOLDOUT_PCT", "0")
    repo = _write_repo(tmp_path)

    class ProseLLM:
        default_model = "fake"

        def generate(self, **_kwargs):
            return "no fence"

    red_driver = _driver(
        repo,
        build_runner=lambda workdir, exports, extra=None: (False, "error: bad"),
        llm=ProseLLM(),
    )
    assert red_driver.run() == EXIT_PROGRESSED
    state_path = (
        repo / "research/decomp/generated/finish-game-port/wasm-units-state.json"
    )
    record = json.loads(state_path.read_text())["units"]["unit-a"]
    assert record["status"] == "red_retryable"
    assert DAT_SYM in record["symbol_set"]

    # An UNRELATED registry bump: still zero-delta, still skipped.
    unrelated = empty_registry()
    unrelated["version"] = 1
    other = _entry(updated_version=1)
    other["symbol"] = "DAT_deadbeef"
    unrelated["entries"]["dat:0xdeadbeef"] = other
    save_registry(_registry_file(repo), unrelated)
    second = _driver(repo)
    state = json.loads(state_path.read_text())
    assert second._next_unit([{"name": "unit-a"}], state, set()) is None

    # A bump whose entry TOUCHES the unit's symbols: schedulable again.
    touching = empty_registry()
    touching["version"] = 1
    touching["entries"][DAT_KEY] = _entry(updated_version=1)
    save_registry(_registry_file(repo), touching)
    third = _driver(repo)
    state = json.loads(state_path.read_text())
    picked = third._next_unit([{"name": "unit-a"}], state, set())
    assert picked is not None and picked["name"] == "unit-a"


# ===========================================================================
# 2026-08-20 T2c adversarial-review regressions (F1-F4)

from src.port_knowledge_registry import record_surviving_deviations  # noqa: E402


def test_f1_surviving_deletion_becomes_conflict_at_harvest():
    """Review F1, deletion shape: the model DELETES the injected authoritative
    macro outright. check_survival fires (found=None); harvest_candidates sees
    no chunk for the symbol, so harvest alone files nothing -- the fold-in
    must turn the surviving deviation into a conflict record, or later units
    keep receiving the possibly-wrong line with zero recorded dissent."""
    registry = _registry_with(_entry(tier=TIER_ORACLE_GREEN, macro=MACRO_INT))
    augmented = augment_seed(
        registry, unit_name="unit-b", seed_text=SEED, symbols={DAT_SYM}
    )
    assert MACRO_INT in augmented.header_text  # actively injected
    final_header = SEED  # the macro is gone entirely
    deviations = check_survival(augmented.authoritative, final_header)
    assert deviations and deviations[0]["found"] is None
    harvest = harvest_unit(
        registry,
        unit_name="unit-b",
        tier=TIER_COMPILE_ONLY,
        seed_text=augmented.header_text,
        header_text=final_header,
        unit_c_text=UNIT_C,
    )
    assert DAT_KEY not in [c.get("key") for c in harvest.new_conflicts]
    version_before = registry_version(registry)
    fold = record_surviving_deviations(
        registry, unit_name="unit-b", tier=TIER_COMPILE_ONLY, deviations=deviations
    )
    entry = registry["entries"][DAT_KEY]
    assert fold.changed and fold.new_conflicts
    assert fold.new_conflicts[0]["deviation"] is True
    assert fold.new_conflicts[0]["key"] == DAT_KEY
    unit_b_conflicts = [c for c in entry["conflicts"] if c.get("unit") == "unit-b"]
    assert len(unit_b_conflicts) == 1
    assert registry_version(registry) > version_before  # gating sees it
    assert entry["macro"] == MACRO_INT  # presentation untouched: dissent, no flip
    # idempotent: re-folding the same deviation files nothing new
    again = record_surviving_deviations(
        registry, unit_name="unit-b", tier=TIER_COMPILE_ONLY, deviations=deviations
    )
    assert not again.changed
    assert len([c for c in entry["conflicts"] if c.get("unit") == "unit-b"]) == 1


def test_f1_var_decl_re_expression_is_detected_by_harvest():
    """Review F1, re-expression shape: the model re-expresses the DAT symbol
    as a variable declaration (`extern unsigned short DAT_...;`) -- the
    parser's var_decl kind. Harvest must now catch macro-vs-variable typing
    divergence generally, and check_survival must report the found form
    instead of found=None."""
    registry = _registry_with(_entry(tier=TIER_ORACLE_GREEN, macro=MACRO_INT))
    augmented = augment_seed(
        registry, unit_name="unit-b", seed_text=SEED, symbols={DAT_SYM}
    )
    var_decl = "extern unsigned short DAT_802c44f8;"
    final_header = SEED + var_decl + "\n"
    deviations = check_survival(augmented.authoritative, final_header)
    assert deviations and deviations[0]["found"] is not None
    assert "extern" in deviations[0]["found"]
    harvest = harvest_unit(
        registry,
        unit_name="unit-b",
        tier=TIER_COMPILE_ONLY,
        seed_text=augmented.header_text,
        header_text=final_header,
        unit_c_text=UNIT_C,
    )
    entry = registry["entries"][DAT_KEY]
    # the harvest itself files the divergence now (var_decl chunk harvested)
    assert any(c.get("unit") == "unit-b" for c in entry["conflicts"])
    assert harvest.new_conflicts and harvest.new_conflicts[0]["key"] == DAT_KEY
    assert entry["macro"] == MACRO_INT  # oracle_green presentation unchanged
    # the fold-in dedups against the harvest-filed conflict: no double record
    record_surviving_deviations(
        registry, unit_name="unit-b", tier=TIER_COMPILE_ONLY, deviations=deviations
    )
    assert len([c for c in entry["conflicts"] if c.get("unit") == "unit-b"]) == 1


def test_f1_driver_folds_surviving_deletion_into_conflicts(tmp_path, monkeypatch):
    """Review F1 end-to-end: unit goes green having DELETED the authoritative
    line; step 5b must file the conflict and emit a registry_conflict event
    (deviation=True) -- before the fix the deviation event fired and then
    nothing reached the ledger."""
    monkeypatch.delenv("OGHIDRA_PORT_LIVENESS_PATH", raising=False)
    monkeypatch.setenv("OGHIDRA_PORT_REGISTRY_HOLDOUT_PCT", "0")
    repo = _write_repo(tmp_path)
    save_registry(
        _registry_file(repo),
        _registry_with(_entry(tier=TIER_ORACLE_GREEN, macro=MACRO_INT)),
    )
    builds = []

    def flaky_build(workdir, exports, extra=None):
        builds.append((workdir / "gnt4_shim.h").read_text())
        if len(builds) == 1:
            return False, "error: something"
        (workdir / "unit.wasm").write_bytes(b"\x00asm")
        return True, ""

    driver = _driver(
        repo,
        build_runner=flaky_build,
        llm=_HeaderLLM(SEED),  # deletes the authoritative line entirely
    )
    assert driver.run() == EXIT_NO_WORK  # deviation never costs the green
    assert MACRO_INT in builds[0]  # it WAS injected
    assert MACRO_INT not in builds[1]  # and then deleted
    events = _events(repo)
    assert any(e.get("kind") == "registry_deviation" for e in events)
    conflicts = [e for e in events if e.get("kind") == "registry_conflict"]
    assert any(e.get("deviation") for e in conflicts)
    registry = load_registry(_registry_file(repo))
    entry = registry["entries"][DAT_KEY]
    assert any(c.get("unit") == "unit-a" for c in entry["conflicts"])


def test_f2_replace_in_seed_consumes_backslash_continuations():
    """Review F2: every live seed carries `#define CONCAT44(hi, lo) \\` with
    its body on the next physical line. Replacing only the first physical
    line orphans the continuation as a stray expression -- the augmented
    header must stay syntactically whole (one macro chunk, no orphan)."""
    seed = (
        SEED
        + "#define CONCAT44(hi, lo) \\\n"
        + "  (((unsigned long long)(unsigned int)(hi) << 32) | (unsigned int)(lo))\n"
        + "int zz_tail_marker_(void);\n"
    )
    registry = empty_registry()
    registry["version"] = 1
    registry["entries"]["macro:CONCAT44"] = {
        "kind": "pseudo_op",
        "symbol": "CONCAT44",
        "macro": (
            "#define CONCAT44(hi,lo) (((unsigned long long)(unsigned int)(hi)"
            " << 32) | (unsigned int)(lo))"
        ),
        "tier": TIER_ORACLE_GREEN,
        "source_units": ["unit-earlier"],
        "source_tiers": {"unit-earlier": TIER_ORACLE_GREEN},
        "contested": False,
        "conflicts": [],
        "updated_version": 1,
    }
    result = augment_seed(
        registry, unit_name="unit-a", seed_text=seed, symbols={"CONCAT44"}
    )
    header = result.header_text
    assert result.authoritative
    # no dangling continuation and no orphaned macro body as a stray expression
    assert not any(line.rstrip().endswith("\\") for line in header.splitlines())
    orphans = [
        line
        for line in header.splitlines()
        if line.lstrip().startswith("(((unsigned long long)")
    ]
    assert orphans == []
    defines = [
        line
        for line in header.splitlines()
        if line.strip().startswith("#define CONCAT44")
    ]
    assert len(defines) == 1 and "<< 32" in defines[0]
    # the parser agrees the header is whole: exactly one CONCAT44 macro chunk,
    # and the old body did not survive as a var_decl/directive orphan chunk
    from src.port_assembly_gate import parse_header_chunks

    chunks = parse_header_chunks(header)
    concat = [c for c in chunks if c.symbol == "CONCAT44"]
    assert len(concat) == 1 and concat[0].kind == "macro"
    assert not any("<< 32" in c.text for c in chunks if c.symbol != "CONCAT44")
    # the tail of the seed survived the splice
    assert any(c.symbol == "zz_tail_marker_" for c in chunks)


def test_f3_adoption_agreement_never_raises_tier():
    """Review F3: one oracle-verified unit ADOPTING the advisory hint must
    not promote the entry to oracle_green (do-not-alter law after a single
    pass would bypass [V4-7]'s promotion-recompute). Agreement records
    evidence; only the explicit promote path moves the tier."""
    registry = _registry_with(_entry(macro=MACRO_INT))  # compile_only
    augmented = augment_seed(
        registry, unit_name="unit-b", seed_text=SEED, symbols={DAT_SYM}
    )
    result = harvest_unit(
        registry,
        unit_name="unit-b",
        tier=TIER_ORACLE_GREEN,
        seed_text=augmented.header_text,
        header_text=augmented.header_text + "\n" + MACRO_INT + "\n",
        unit_c_text=UNIT_C,
    )
    entry = registry["entries"][DAT_KEY]
    assert DAT_KEY in result.agreed
    assert "unit-b" in entry["source_units"]  # evidence recorded
    assert entry["source_tiers"]["unit-b"] == TIER_ORACLE_GREEN
    assert entry["tier"] == TIER_COMPILE_ONLY  # tier NOT raised by adoption
    # the explicit promote path still works, with its conflict recompute
    promoted = promote_unit_entries(registry, "unit-b")
    assert DAT_KEY in promoted.promoted
    assert entry["tier"] == TIER_ORACLE_GREEN


def test_f4_supersede_resets_holdout_sources():
    """Review F4: the new_wins branch resets source_units/source_tiers; the
    holdout ledger must reset with them, not accumulate stale attributions."""
    registry = _registry_with(
        _entry(macro=MACRO_INT, holdout_sources=["unit-earlier"])
    )
    harvest_unit(
        registry,
        unit_name="unit-green",
        tier=TIER_ORACLE_GREEN,
        seed_text=SEED,
        header_text=SEED + MACRO_CHAR + "\n",
        unit_c_text=UNIT_C,
    )
    entry = registry["entries"][DAT_KEY]
    assert entry["source_units"] == ["unit-green"]
    assert "holdout_sources" not in entry  # stale ledger cleared with the reset
    # a HOLDOUT superseder is attributed fresh, not appended after the stale one
    registry2 = _registry_with(
        _entry(macro=MACRO_INT, holdout_sources=["unit-earlier"])
    )
    harvest_unit(
        registry2,
        unit_name="unit-holdout",
        tier=TIER_ORACLE_GREEN,
        seed_text=SEED,
        header_text=SEED + MACRO_CHAR + "\n",
        unit_c_text=UNIT_C,
        holdout=True,
    )
    assert registry2["entries"][DAT_KEY]["holdout_sources"] == ["unit-holdout"]
