"""Tests for the owner (oracle-registry) prototype injection pass.

Synthetic fixtures are shaped exactly like the live seeds (outer include
guard, Ghidra typedefs, single-line ``extern`` declarations); the synthetic
registry is built to satisfy the gate's own ``_validate_registry`` so the
loader is exercised through the same validator the gate trusts.  One
integration-shaped test runs against the REAL product registry.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from src import port_owner_decl_injection as odi
from src.port_assembly_abi import AssemblyAbiError, _registry_declaration

REAL_PRODUCT_ROOT = Path(r"D:\GotYaForce")
REAL_REGISTRY = REAL_PRODUCT_ROOT / "research/decomp/data/oracle-registry.json"


# ------------------------------------------------------------ registry fixture


def _function_record(
    name: str,
    address: str,
    unit: str,
    return_type: str,
    params: list[str],
    line_start: int = 1,
    loc: int = 4,
) -> dict:
    return {
        "name": name,
        "address": address,
        "unit": unit,
        "chunk_file": "research/decomp/ghidra-export/chunk_9999.c",
        "line_range": [line_start, line_start + loc - 1],
        "loc": loc,
        "return_type": return_type,
        "params": params,
        "returns_value": return_type.strip() not in {"void", "code"},
        "has_pointer_args": any("*" in p or "[" in p for p in params),
        "external_callees": {"count": 0, "list": []},
        "global_refs": [],
        "ts_citations": [],
        "citation_grade": None,
        "citation_scan_skipped": None,
        "structural_class": "C",
        "gap_alignment": None,
    }


def _registry_fixture(functions: list[dict]) -> dict:
    functions = sorted(functions, key=lambda item: (item["address"], item["name"]))
    units = {item["unit"] for item in functions}
    buckets = ("differential_vs_ts", "state_diff", "citations_no_family", "trace_only")
    return {
        "oracle_registry_schema": 1,
        "meta": {
            "generated_by": "tests/test_port_owner_decl_injection.py",
            "inputs": {
                "queue": "research/decomp/generated/finish-game-port/wasm-units.json",
                "skipped": "research/decomp/generated/finish-game-port/wasm-units-skipped.json",
                "chunk_index": "research/decomp/ghidra-export/_index.tsv",
                "family_coverage": "research/decomp/data/family-state-machine-coverage.json",
            },
            "conventions": {
                "address": "synthetic",
                "structural_class": "synthetic",
                "citation_grade": "synthetic",
                "gap_alignment": "synthetic",
                "ranked_units_sort": "synthetic",
                "oracle_able_units": "synthetic",
            },
        },
        "summary": {
            "functions_total": len(functions),
            "units_total": len(units),
            "excluded_total": 0,
            "excluded_reasons": {},
            "structural_class_counts": {"C": len(functions)},
            "citation_grade_counts": {"none": len(functions)},
            "class_by_citation_grade": {"C": {"none": len(functions)}},
            "gap_aligned_functions": 0,
            "gap_aligned_functions_partial_family": 0,
            "fully_gap_aligned_units": 0,
            "fully_gap_aligned_unit_names": [],
            "oracle_able_units": {bucket: 0 for bucket in buckets},
            "oracle_able_unit_names": {bucket: [] for bucket in buckets},
            "anomalies": [],
        },
        "ranked_units": [],
        "functions": functions,
        "excluded": [],
    }


FIXTURE_FUNCTIONS = [
    # The endemic register-class fork target: owner says undefined8 first.
    _function_record(
        "zz_0006fb4_", "0x80006fb4", "auto-c0000-005", "void",
        ["undefined8 param_1", "double param_2"],
    ),
    # Identical in the unit seed already.
    _function_record(
        "FUN_80031634", "0x80031634", "auto-c0001-000", "uint",
        ["int param_1"],
    ),
    # Absent from the unit seed: injected.
    _function_record(
        "zz_00a1110_", "0x800a1110", "auto-c0002-000", "int", ["void"],
    ),
    # Never referenced by the unit: never added.
    _function_record(
        "zz_00b2220_", "0x800b2220", "auto-c0003-000", "void", ["void"],
    ),
    # Owned by the unit under test itself: excluded.
    _function_record(
        "zz_00c3330_", "0x800c3330", "auto-c0029-012", "void", ["int param_1"],
    ),
    # Registered to ANOTHER unit but textually defined inside this unit's
    # unit.c (drift): excluded by the definition scan.
    _function_record(
        "zz_00d4440_", "0x800d4440", "auto-c0004-000", "void", ["void"],
    ),
    # Not a zz_/FUN_ name: filtered out of the prototype map entirely.
    _function_record(
        "__check_pad9", "0x800e5550", "auto-c0005-000", "uint",
        ["undefined8 param_1"],
    ),
]

UNIT_NAME = "auto-c0029-012"

UNIT_SEED = """\
#ifndef GNT4_SHIM_H
#define GNT4_SHIM_H

typedef unsigned long long undefined8;
typedef unsigned int uint;

extern void zz_0006fb4_(double param_1, double param_2);
extern uint FUN_80031634(int x);

#endif /* GNT4_SHIM_H */
"""

# References: zz_0006fb4_ (divergent: double vs undefined8 first param),
# FUN_80031634 (identical modulo parameter name), zz_00a1110_ (absent),
# zz_00c3330_ (owner is this unit), zz_00d4440_ (defined right here),
# gnt4_helper (SDK seam -- never this pass's business).
# Never references zz_00b2220_ or __check_pad9.
UNIT_C = """\
void zz_00d4440_(void) { return; }

void zz_00c3330_(int param_1) {
  zz_0006fb4_((undefined8)param_1, 1.0);
  uint r = FUN_80031634(param_1);
  int s = zz_00a1110_();
  zz_00d4440_();
  gnt4_helper(r, s);
}
"""


@pytest.fixture()
def registry_path(tmp_path):
    path = tmp_path / "oracle-registry.json"
    path.write_text(
        json.dumps(_registry_fixture(FIXTURE_FUNCTIONS)), encoding="utf-8", newline="\n"
    )
    return path


def _prototypes(registry_path):
    return odi.load_owner_prototypes(registry_path)


# ---------------------------------------------------------------- reference scan


def test_referenced_symbols_found():
    assert odi.referenced_owner_symbols(UNIT_C) == {
        "zz_0006fb4_",
        "FUN_80031634",
        "zz_00a1110_",
        "zz_00c3330_",
        "zz_00d4440_",
    }


def test_comment_only_mention_is_not_a_reference():
    text = "/* calls zz_0006fb4_ indirectly */\nint f(void) { return 0; }\n"
    assert odi.referenced_owner_symbols(text) == set()


def test_gnt4_symbols_are_never_this_pass_business():
    text = "void f(void) { gnt4_PSVECMag_bl(0); }\n"
    assert odi.referenced_owner_symbols(text) == set()


def test_unit_defined_symbols_scan():
    defined = odi.unit_defined_symbols(
        UNIT_C, {"zz_00d4440_", "zz_00c3330_", "zz_0006fb4_", "zz_00a1110_"}
    )
    assert defined == {"zz_00d4440_", "zz_00c3330_"}


# ---------------------------------------------------------------- registry load


def test_load_owner_prototypes_spellings_match_the_gate(registry_path):
    prototypes = _prototypes(registry_path)
    assert set(prototypes) == {
        "zz_0006fb4_", "FUN_80031634", "zz_00a1110_", "zz_00b2220_",
        "zz_00c3330_", "zz_00d4440_",
    }  # __check_pad9 filtered: not a zz_/FUN_ name
    record = next(
        item for item in FIXTURE_FUNCTIONS if item["name"] == "zz_0006fb4_"
    )
    assert prototypes["zz_0006fb4_"].declaration == (
        _registry_declaration(record).decode("utf-8")
    )
    assert prototypes["zz_0006fb4_"].owner_unit == "auto-c0000-005"


def test_load_owner_prototypes_is_cached_per_file_state(registry_path):
    first = _prototypes(registry_path)
    assert _prototypes(registry_path) is first


def test_invalid_registry_raises(tmp_path):
    path = tmp_path / "oracle-registry.json"
    path.write_text('{"oracle_registry_schema": 2}', encoding="utf-8")
    with pytest.raises(AssemblyAbiError):
        odi.load_owner_prototypes(path)


def test_missing_registry_raises(tmp_path):
    with pytest.raises(OSError):
        odi.load_owner_prototypes(tmp_path / "missing.json")


# ---------------------------------------------------------------- core contract


def test_referenced_absent_is_injected(registry_path):
    result = odi.inject_owner_declarations(
        UNIT_SEED, UNIT_C, _prototypes(registry_path), unit_name=UNIT_NAME
    )
    assert result.changed
    assert result.injected == ["zz_00a1110_"]
    assert "extern int zz_00a1110_(void);" in result.header_text
    assert odi.OWNER_DECL_BANNER in result.header_text
    # Injected inside the include guard: before the trailing #endif.
    lines = result.header_text.splitlines()
    decl_at = next(i for i, l in enumerate(lines) if "zz_00a1110_" in l)
    endif_at = max(i for i, l in enumerate(lines) if l.strip().startswith("#endif"))
    assert decl_at < endif_at


def test_referenced_divergent_is_superseded_in_place(registry_path):
    result = odi.inject_owner_declarations(
        UNIT_SEED, UNIT_C, _prototypes(registry_path), unit_name=UNIT_NAME
    )
    assert result.superseded == ["zz_0006fb4_"]
    # The register-class fork is gone; the owner line appears exactly once.
    assert "zz_0006fb4_(double" not in result.header_text
    assert (
        result.header_text.count(
            "extern void zz_0006fb4_(undefined8 param_1,double param_2);"
        )
        == 1
    )
    # In place, not appended: above the appended banner block.
    lines = result.header_text.splitlines()
    fork_at = next(i for i, l in enumerate(lines) if "zz_0006fb4_" in l)
    banner_at = next(i for i, l in enumerate(lines) if l == odi.OWNER_DECL_BANNER)
    assert fork_at < banner_at


def test_referenced_identical_untouched(registry_path):
    # FUN_80031634 differs only in the parameter name: byte-for-byte survival.
    result = odi.inject_owner_declarations(
        UNIT_SEED, UNIT_C, _prototypes(registry_path), unit_name=UNIT_NAME
    )
    assert "extern uint FUN_80031634(int x);" in result.header_text
    assert "FUN_80031634" not in result.superseded
    assert "FUN_80031634" not in result.injected


def test_unreferenced_never_added(registry_path):
    result = odi.inject_owner_declarations(
        UNIT_SEED, UNIT_C, _prototypes(registry_path), unit_name=UNIT_NAME
    )
    assert "zz_00b2220_" not in result.header_text
    assert "__check_pad9" not in result.header_text


def test_own_definitions_are_excluded(registry_path):
    # zz_00c3330_ is registered TO this unit; zz_00d4440_ is registered to
    # another unit but textually defined in this unit.c.  Neither may gain a
    # seed declaration from this pass.
    result = odi.inject_owner_declarations(
        UNIT_SEED, UNIT_C, _prototypes(registry_path), unit_name=UNIT_NAME
    )
    assert "zz_00c3330_" not in result.header_text
    assert "zz_00d4440_" not in result.header_text
    assert "zz_00c3330_" not in result.injected + result.superseded
    assert "zz_00d4440_" not in result.injected + result.superseded


def test_no_relevant_symbols_is_a_noop(registry_path):
    unit_c = "int f(void) { return 1; }\n"
    result = odi.inject_owner_declarations(
        UNIT_SEED, unit_c, _prototypes(registry_path), unit_name=UNIT_NAME
    )
    assert not result.changed
    assert result.header_text == UNIT_SEED


def test_rerun_is_idempotent(registry_path):
    prototypes = _prototypes(registry_path)
    first = odi.inject_owner_declarations(
        UNIT_SEED, UNIT_C, prototypes, unit_name=UNIT_NAME
    )
    assert first.changed
    second = odi.inject_owner_declarations(
        first.header_text, UNIT_C, prototypes, unit_name=UNIT_NAME
    )
    assert not second.changed
    assert second.header_text == first.header_text
    assert second.injected == [] and second.superseded == []
    assert first.header_text.count("zz_00a1110_") == 1


def test_multiline_divergent_declaration_superseded(registry_path):
    header = (
        "#ifndef GNT4_SHIM_H\n#define GNT4_SHIM_H\n"
        "extern void zz_0006fb4_(\n"
        "    double param_1,\n"
        "    double param_2);\n"
        "#endif /* GNT4_SHIM_H */\n"
    )
    unit_c = "void f(void) { zz_0006fb4_(0, 1.0); }\n"
    result = odi.inject_owner_declarations(
        header, unit_c, _prototypes(registry_path), unit_name=UNIT_NAME
    )
    assert result.superseded == ["zz_0006fb4_"]
    assert "double param_1,\n" not in result.header_text
    assert (
        "extern void zz_0006fb4_(undefined8 param_1,double param_2);"
        in result.header_text
    )


def test_unspliceable_divergence_reported_not_duplicated(registry_path):
    header = (
        "#ifndef GNT4_SHIM_H\n#define GNT4_SHIM_H\n"
        "extern void /* torn\n"
        "comment */ zz_0006fb4_(double param_1);\n"
        "#endif /* GNT4_SHIM_H */\n"
    )
    unit_c = "void f(void) { zz_0006fb4_(0, 1.0); }\n"
    result = odi.inject_owner_declarations(
        header, unit_c, _prototypes(registry_path), unit_name=UNIT_NAME
    )
    assert result.unresolved == ["zz_0006fb4_"]
    assert not result.changed
    assert "undefined8" not in result.header_text


def test_definition_body_in_header_never_superseded(registry_path):
    header = (
        "#ifndef GNT4_SHIM_H\n#define GNT4_SHIM_H\n"
        "static int zz_00a1110_(void) { return 0; }\n"
        "#endif /* GNT4_SHIM_H */\n"
    )
    unit_c = "int f(void) { return zz_00a1110_(); }\n"
    result = odi.inject_owner_declarations(
        header, unit_c, _prototypes(registry_path), unit_name=UNIT_NAME
    )
    assert "static int zz_00a1110_(void) { return 0; }" in result.header_text
    assert "zz_00a1110_" not in result.superseded


# ---------------------------------------------------------------- file-level sync


def _write_seed(tmp_path):
    seed = tmp_path / "auto-c0029-012.h"
    seed.write_text(UNIT_SEED, encoding="utf-8", newline="\n")
    return seed


def test_sync_writes_seed_atomically(tmp_path, registry_path):
    seed = _write_seed(tmp_path)
    result = odi.sync_owner_declarations(
        seed, UNIT_C, registry_path, unit_name=UNIT_NAME
    )
    assert result.changed and result.write_error is None
    on_disk = seed.read_text(encoding="utf-8")
    assert on_disk == result.header_text
    assert "extern int zz_00a1110_(void);" in on_disk
    assert [p.name for p in tmp_path.glob("*.tmp")] == []


def test_sync_noop_does_not_rewrite_file(tmp_path, registry_path, monkeypatch):
    seed = _write_seed(tmp_path)
    odi.sync_owner_declarations(seed, UNIT_C, registry_path, unit_name=UNIT_NAME)

    calls = []
    original = odi._atomic_write_text

    def counting(path, text):
        calls.append(path)
        return original(path, text)

    monkeypatch.setattr(odi, "_atomic_write_text", counting)
    second = odi.sync_owner_declarations(
        seed, UNIT_C, registry_path, unit_name=UNIT_NAME
    )
    assert not second.changed
    assert calls == []  # idempotent re-run: the file is never touched


def test_sync_write_failure_degrades_but_keeps_memory_sync(
    tmp_path, registry_path, monkeypatch
):
    seed = _write_seed(tmp_path)

    def failing_replace(src, dst):
        raise OSError("locked by AV scan")

    import src.port_sdk_decl_injection as sdi

    monkeypatch.setattr(sdi.os, "replace", failing_replace)
    result = odi.sync_owner_declarations(
        seed, UNIT_C, registry_path, unit_name=UNIT_NAME
    )
    assert result.changed
    assert result.write_error and "locked" in result.write_error
    # In-memory header is synced for this attempt...
    assert "extern int zz_00a1110_(void);" in result.header_text
    # ...but the seed file is untouched and no temp file lingers.
    assert seed.read_text(encoding="utf-8") == UNIT_SEED
    assert [p.name for p in tmp_path.glob("*.tmp")] == []


def test_sync_missing_registry_raises(tmp_path):
    seed = _write_seed(tmp_path)
    with pytest.raises(OSError):
        odi.sync_owner_declarations(
            seed, UNIT_C, tmp_path / "missing.json", unit_name=UNIT_NAME
        )
    assert seed.read_text(encoding="utf-8") == UNIT_SEED


def test_sync_accepts_preread_header_text(tmp_path, registry_path):
    seed = _write_seed(tmp_path)
    result = odi.sync_owner_declarations(
        seed, UNIT_C, registry_path, unit_name=UNIT_NAME, header_text=UNIT_SEED
    )
    assert result.changed
    assert seed.read_text(encoding="utf-8") == result.header_text


# ------------------------------------------------------- real-registry integration


@pytest.mark.skipif(
    not REAL_REGISTRY.is_file()
    or json.loads(REAL_REGISTRY.read_text(encoding="utf-8-sig")).get(
        "oracle_registry_schema"
    )
    != 1,
    reason="the schema-1 product registry is not present in this checkout",
)
def test_real_registry_supersedes_the_zz_0006fb4_register_class_fork():
    """auto-c0029-012's live failure shape: the compile-fix model rendered
    zz_0006fb4_'s first parameter as ``double`` from the call site, where the
    corpus-anchored owner (auto-c0000-005) says ``undefined8`` -- and the gate
    then refused with owner_variant_abi_incompatible.  Against the REAL
    registry the pass must supersede the fork with the owner prototype."""
    prototypes = odi.load_owner_prototypes(REAL_REGISTRY)
    owner = prototypes["zz_0006fb4_"]
    assert owner.owner_unit != "auto-c0029-012"
    assert owner.declaration.startswith("void zz_0006fb4_(undefined8 param_1,")

    wrong = (
        "#ifndef GNT4_SHIM_H\n#define GNT4_SHIM_H\n"
        "extern void zz_0006fb4_(double param_1,double param_2,double param_3,"
        "double param_4,double param_5,double param_6,double param_7,"
        "double param_8,int param_9,int param_10,int param_11,"
        "undefined4 param_12,undefined4 param_13,undefined4 param_14,"
        "undefined4 param_15,undefined4 param_16);\n"
        "#endif /* GNT4_SHIM_H */\n"
    )
    unit_c = "void f(void) { zz_0006fb4_(0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0); }\n"
    result = odi.inject_owner_declarations(
        wrong, unit_c, prototypes, unit_name="auto-c0029-012"
    )
    assert result.superseded == ["zz_0006fb4_"]
    superseded_line = next(
        line
        for line in result.header_text.splitlines()
        if "zz_0006fb4_" in line
    )
    # The superseded line IS the owner prototype (plus the extern spelling and
    # the do-not-alter marker).
    assert superseded_line.startswith(f"extern {owner.declaration}")
    assert "double param_1" not in result.header_text
