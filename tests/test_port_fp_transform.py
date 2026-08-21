"""Offline tests for the D5 idiom-fix transform (src/port_fp_transform.py)
and its materialization seam (docs/d5-idiom-fix-design.md D5-3a/D5-4/D5-7)."""

from __future__ import annotations

import hashlib
import inspect
import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from src.port_assembly_gate import prelude_region
from src.port_fp_transform import (
    CURRENT,
    comma_operand_sites,
    HELPER_DEFINITION,
    HELPER_NAME,
    RESTAMP,
    STALE,
    TRANSFORM_NAME,
    TRANSFORM_VERSION,
    census_text,
    dataflow_residual_risk,
    transform_record,
    ensure_bitcast_helper,
    restamp_in_place,
    rewrite_fp_reinterpret,
    scan_sites,
    transform_staleness,
)
from src.port_wasm_units import extract_verbatim, materialize_unit_c

GOTYAFORCE_ROOT = Path(r"D:\GotYaForce")


def T(text: str) -> str:
    return rewrite_fp_reinterpret(text)[0]


# ---------------------------------------------------------------- grammar G
# One golden in/out pair per variant (D5-7 gate item 1).


def test_v1_signed_xor_inside_lo():
    src = (
        "dVar3 = (double)(float)((double)CONCAT44(0x43300000,"
        "(int)sVar1 ^ 0x80000000) - DOUBLE_80439e88);"
    )
    out, sites = rewrite_fp_reinterpret(src)
    assert sites == 1
    assert out == (
        "dVar3 = (double)(float)(__gnt4_bitcast_f64(CONCAT44(0x43300000,"
        "(int)sVar1 ^ 0x80000000)) - DOUBLE_80439e88);"
    )


def test_v2_xor_outside_on_the_u64():
    src = "dVar1 = (double)(CONCAT44(0x43300000, uVar2) ^ 0x80000000);"
    out, sites = rewrite_fp_reinterpret(src)
    assert sites == 1
    assert out == (
        "dVar1 = __gnt4_bitcast_f64(CONCAT44(0x43300000, uVar2)"
        " ^ 0x80000000);"
    )


def test_v3_unsigned_subtract_adjacent():
    src = "dVar1 = (double)CONCAT44(0x43300000, uVar2) - DOUBLE_80436fb0;"
    out, sites = rewrite_fp_reinterpret(src)
    assert sites == 1
    assert out == (
        "dVar1 = __gnt4_bitcast_f64(CONCAT44(0x43300000, uVar2))"
        " - DOUBLE_80436fb0;"
    )


def test_v4_subtraction_textually_deferred():
    src = (
        "  dVar5 = (double)CONCAT44(0x43300000, uVar2);\n"
        "  dVar6 = dVar5 - DOUBLE_80436fb0;\n"
    )
    out, sites = rewrite_fp_reinterpret(src)
    assert sites == 1
    assert out == (
        "  dVar5 = __gnt4_bitcast_f64(CONCAT44(0x43300000, uVar2));\n"
        "  dVar6 = dVar5 - DOUBLE_80436fb0;\n"
    )


def test_v5_non_magic_high_word():
    src = (
        "dVar1 = (double)CONCAT44(local_18._4_4_ & 0x7fffffff |"
        " local_10 & 0x80000000, local_14);"
    )
    out, sites = rewrite_fp_reinterpret(src)
    assert sites == 1
    assert out.startswith("dVar1 = __gnt4_bitcast_f64(CONCAT44(")
    assert "(double)" not in out


def test_wrapped_cast_split_across_lines_preserves_line_count():
    # The fleet shape single-line grep misses: "(\n double)CONCAT44".
    src = (
        "  dVar1 = (\n"
        "          double)CONCAT44(0x43300000,\n"
        "                          uVar2) - DOUBLE_80436fb0;\n"
    )
    out, sites = rewrite_fp_reinterpret(src)
    assert sites == 1
    assert out.count("\n") == src.count("\n")  # line-by-line traceability
    assert HELPER_NAME in out
    assert "double)" not in out.replace("__gnt4_bitcast_f64", "")


def test_multiline_args_kept_verbatim_inside_the_helper():
    src = (
        "x = (double)CONCAT44(0x43300000,\n"
        "                     (int)*(short *)(param_9 + 0x1af8) ^ 0x80000000)\n"
        "    - DOUBLE_80439e88;"
    )
    out, sites = rewrite_fp_reinterpret(src)
    assert sites == 1
    assert "(int)*(short *)(param_9 + 0x1af8) ^ 0x80000000" in out
    assert out.count("\n") == src.count("\n")


def test_idempotence():
    src = (
        "a = (double)CONCAT44(0x43300000, x ^ 0x80000000) - M;\n"
        "b = (double)(CONCAT44(0x43300000, y) ^ 0x80000000);\n"
    )
    once, sites = rewrite_fp_reinterpret(src)
    twice, more = rewrite_fp_reinterpret(once)
    assert sites == 2
    assert more == 0
    assert twice == once


def test_identity_on_site_free_text():
    src = (
        "uVar1 = CONCAT44(a, b) ^ c;\n"          # integer cohort: untouched
        "uVar2 = CONCAT44(a, b) >> 0x20;\n"
        "dVar3 = (double)uVar9;\n"                # cast, but no CONCAT44
        "dVar4 = (double)(float)iVar5;\n"
        "int double_trouble = 3;\n"
    )
    out, sites = rewrite_fp_reinterpret(src)
    assert sites == 0
    assert out == src  # byte-identical: the migration's identity predicate


def test_leftmost_primary_exclusion_for_outer_promotions():
    # (double)(<expr>) where the leftmost primary is NOT the call: an
    # arithmetic promotion the transform must never touch.
    for src in (
        "d = (double)(x + CONCAT44(a, b));",
        "d = (double)((CONCAT44(a, b)));",  # more than one paren skipped
        "d = (double)(float)CONCAT44(a, b);",  # inner cast, not the call
        "d = (double)(-CONCAT44(a, b));",
    ):
        out, sites = rewrite_fp_reinterpret(src)
        assert sites == 0, src
        assert out == src


def test_comments_and_strings_pass_through_untouched():
    # F-D5-3: the scanner is comment/string-aware.
    src = (
        "/* (double)CONCAT44(0x43300000, x) - M */\n"
        "// (double)CONCAT44(1, 2)\n"
        "const char *s = \"(double)CONCAT44(1, 2)\";\n"
        "char q = '\"';\n"
        "real = (double)CONCAT44(0x43300000, x) - M;\n"
    )
    out, sites = rewrite_fp_reinterpret(src)
    assert sites == 1
    assert "/* (double)CONCAT44(0x43300000, x) - M */" in out
    assert "\"(double)CONCAT44(1, 2)\"" in out
    assert "real = __gnt4_bitcast_f64(CONCAT44(0x43300000, x)) - M;" in out


def test_nested_site_inside_an_operand_is_rewritten():
    # One exists in chunk_0061.c; the fixpoint catches it.
    src = "d = (double)CONCAT44(a, (int)((double)CONCAT44(h, l) - M));"
    out, sites = rewrite_fp_reinterpret(src)
    assert sites == 2
    assert "(double)" not in out
    assert len(scan_sites(src)) == 2  # census counts nested sites too


def test_comment_between_cast_and_call():
    src = "d = (double) /* lfd */ CONCAT44(a, b);"
    out, sites = rewrite_fp_reinterpret(src)
    assert sites == 1
    assert HELPER_NAME in out


def test_newline_between_cast_and_operand_preserves_line_count():
    # Review M2: the gap between the cast's ')' and the operand start.
    for src in (
        "d = (double)\nCONCAT44(a, b) - M;",
        "d = (double)\n(CONCAT44(a, b) ^ K);",
        "d = (\ndouble)\nCONCAT44(a, b) - M;",
    ):
        out, sites = rewrite_fp_reinterpret(src)
        assert sites == 1, src
        assert out.count("\n") == src.count("\n"), src


def test_comma_operand_is_refused_and_flagged():
    # Review M3: (double)(CONCAT44(a,b), other) casts `other` -- a rewrite
    # would change semantics. Refused; flagged residual-risk style.
    src = "d = (double)(CONCAT44(a, b), other);"
    out, sites = rewrite_fp_reinterpret(src)
    assert sites == 0
    assert out == src
    assert comma_operand_sites(src) == 1
    counts = census_text(src)
    assert counts["comma_operand_sites"] == 1
    assert counts["double_cast_sites"] == 0
    # And it lands in the transform record's residual-risk stamp.
    _blocks, record = transform_record([src])
    assert record["sites"] == 0
    assert record["d5_residual_risk"] == 1


# ------------------------------------------------------------ F-D5-2 guard


def test_dataflow_residual_risk_fires_on_separated_shape():
    text = (
        "u = CONCAT44(0x43300000, x);\n"
        "later = (double)u - M;\n"
    )
    assert dataflow_residual_risk(text) == 1


def test_dataflow_residual_risk_zero_on_clean_and_transformed_text():
    clean = "u = CONCAT44(a, b) ^ c;\nd = (double)other;\n"
    assert dataflow_residual_risk(clean) == 0
    transformed = T("d = (double)CONCAT44(0x43300000, x) - M;")
    assert dataflow_residual_risk(transformed) == 0


# ------------------------------------------------------- staleness (D5-4 R2)


def _provenance(version: int, sha: str) -> dict:
    return {
        "transform": {
            "name": TRANSFORM_NAME,
            "version": version,
            "sites": 1,
            "transformed_sha256": sha,
        }
    }


def test_staleness_no_transform_key_is_stale_when_non_identity():
    assert transform_staleness({}, "abc") == STALE
    assert transform_staleness(None, "abc") == STALE
    assert transform_staleness({"transform": {"name": "other"}}, "x") == STALE
    assert (
        transform_staleness({"extracted_sha256": "old"}, "different") == STALE
    )


def test_staleness_pre_d5_identity_artifact_is_restamp_with_added_block():
    # Review M1 / D5-6 identity carve-out: a pre-D5 SITE-FREE artifact
    # (knockback-core, collision-core) has extracted == current transformed
    # output; its verdict stands and restamp ADDS the identity block.
    prov = {
        "extracted_sha256": "same",
        "extractions": [{"file": "x", "start": 1, "end": 2}, {"file": "y", "start": 3, "end": 4}],
    }
    assert transform_staleness(prov, "same") == RESTAMP
    restamp_in_place(prov)
    block = prov["transform"]
    assert block["name"] == TRANSFORM_NAME
    assert block["version"] == TRANSFORM_VERSION
    assert block["sites"] == 0
    assert block["sites_per_block"] == [0, 0]
    assert block["transformed_sha256"] == "same"
    assert transform_staleness(prov, "same") == CURRENT


def test_staleness_current_version_is_current():
    assert transform_staleness(_provenance(TRANSFORM_VERSION, "abc"), "zzz") == CURRENT


def test_staleness_future_version_is_stale_not_trusted():
    # Review M4 nit: a rolled-back driver must never trust a future-grammar
    # artifact silently.
    assert (
        transform_staleness(_provenance(TRANSFORM_VERSION + 1, "abc"), "abc")
        == STALE
    )


def test_staleness_old_version_matching_output_is_restamp_in_place():
    prov = _provenance(TRANSFORM_VERSION - 1, "same")
    assert transform_staleness(prov, "same") == RESTAMP
    restamp_in_place(prov)
    assert prov["transform"]["version"] == TRANSFORM_VERSION
    assert transform_staleness(prov, "same") == CURRENT


def test_staleness_old_version_differing_output_is_stale():
    assert transform_staleness(_provenance(TRANSFORM_VERSION - 1, "old"), "new") == STALE


# ----------------------------------------------------------- helper ensure


def test_ensure_bitcast_helper_appends_once_and_is_idempotent():
    header = "/* seed */\ntypedef unsigned long long undefined8;\n"
    ensured = ensure_bitcast_helper(header)
    assert HELPER_DEFINITION.strip() in ensured
    assert ensure_bitcast_helper(ensured) == ensured


def test_seed_header_carries_the_exact_helper_definition():
    seed = (
        GOTYAFORCE_ROOT
        / "research/decomp/generated/finish-game-port/gnt4_shim_seed.h"
    )
    if not seed.is_file():
        pytest.skip("GotYaForce seed header not present on this machine")
    text = seed.read_text(encoding="utf-8")
    # Byte-identical to the module constant so the assembly merge dedups the
    # seed-inherited copy against ensure_bitcast_helper()'s appended copy.
    assert HELPER_DEFINITION.strip() in text
    # And ensure() recognizes it (no double append).
    assert ensure_bitcast_helper(text) == text


def test_helper_name_is_collision_free_in_the_export():
    export = GOTYAFORCE_ROOT / "research/decomp/ghidra-export"
    if not export.is_dir():
        pytest.skip("ghidra-export not present on this machine")
    for chunk in sorted(export.glob("chunk_*.c")):
        assert HELPER_NAME not in chunk.read_text(
            encoding="utf-8", errors="replace"
        ), f"{HELPER_NAME} collides in {chunk.name}"


# --------------------------------------------------------------- census


def test_census_categories_on_synthetic_text():
    text = (
        "a = (double)CONCAT44(0x43300000, x ^ 0x80000000) - M;\n"
        "b = (double)(CONCAT44(0x43300000, y) ^ 0x80000000);\n"
        "c = (double)CONCAT44(hi_expr, lo);\n"
        "i = CONCAT44(p, q) ^ r;\n"
        "s = SUB84(d, 0);\n"
        "u = CONCAT44(0x43300000, z);\n"
        "later = (double)u;\n"
    )
    counts = census_text(text)
    assert counts["concat44_calls"] == 5
    assert counts["double_cast_sites"] == 3
    assert counts["xor_outside_sites"] == 1
    assert counts["non_magic_hi_sites"] == 1
    assert counts["other_cast_sites"] == 0
    assert counts["dataflow_separated"] == 1
    assert counts["sub84_calls"] == 1


def test_census_other_cast_falsifier_scan():
    counts = census_text("f = (float)CONCAT44(a, b);")
    assert counts["other_cast_sites"] == 1
    assert counts["double_cast_sites"] == 0


# ------------------------------------------- gate 2: permanent residual census


def _staged_unit_cs() -> list[Path]:
    trees = [
        GOTYAFORCE_ROOT / "research/decomp/port-units-staging",
        GOTYAFORCE_ROOT / "research/decomp/port-units",
    ]
    files: list[Path] = []
    for tree in trees:
        if tree.is_dir():
            files.extend(sorted(tree.glob("*/unit.c")))
    return files


def test_gate2_zero_double_on_concat44_in_any_transformed_output():
    """D5-7 gate item 2 (permanent): the transform leaves ZERO
    (double)-on-CONCAT44 sites in the transformed form of every built unit.c
    in both staged trees. Pre-migration artifacts on disk may still carry
    sites; their TRANSFORMED output must not -- and any artifact whose
    provenance already carries a transform block must be residual-free on
    disk as built."""
    files = _staged_unit_cs()
    if not files:
        pytest.skip("staged trees not present on this machine")
    for unit_c in files:
        text = unit_c.read_text(encoding="utf-8", errors="replace")
        transformed, _sites = rewrite_fp_reinterpret(text)
        assert len(scan_sites(transformed)) == 0, f"residual site in {unit_c}"
        provenance_path = unit_c.parent / "provenance.json"
        if provenance_path.is_file():
            provenance = json.loads(
                provenance_path.read_text(encoding="utf-8-sig")
            )
            if isinstance(provenance.get("transform"), dict):
                assert len(scan_sites(text)) == 0, (
                    f"{unit_c} carries transform provenance but still has "
                    "(double)CONCAT44 sites on disk"
                )


# ------------------------------------------------- materialization seam


def _write_repo(tmp_path: Path, chunk_body: str) -> Path:
    repo = tmp_path / "repo"
    (repo / "research/decomp/ghidra-export").mkdir(parents=True)
    (repo / "research/decomp/poc").mkdir(parents=True)
    chunk = repo / "research/decomp/ghidra-export/chunk_7777.c"
    chunk.write_text(chunk_body, encoding="utf-8")
    (repo / "research/decomp/poc/seed.h").write_text(
        "/* seed header */\n", encoding="utf-8"
    )
    return repo


IDIOM_BODY = (
    "// head\n"
    "void zz_fp_(int x)\n"
    "{\n"
    "  double d = (double)CONCAT44(0x43300000, x ^ 0x80000000) - M;\n"
    "  use(d);\n"
    "}\n"
    "// mid\n"
    "int zz_int_(int a)\n"
    "{\n"
    "  return a + 1;\n"
    "}\n"
)


def _unit(extractions: list[dict]) -> dict:
    return {
        "name": "unit-t",
        "extractions": extractions,
        "prelude": ["void zz_fp_(int x);"],
        "exported_functions": ["zz_fp_"],
        "header_seed": "research/decomp/poc/seed.h",
    }


def test_materialize_zero_site_unit_is_byte_identical_with_identity_stamp(tmp_path):
    repo = _write_repo(tmp_path, IDIOM_BODY)
    spec = [{"file": "research/decomp/ghidra-export/chunk_7777.c", "start": 8, "end": 11}]
    materialized = materialize_unit_c(repo, _unit(spec))
    legacy_verbatim, legacy_records = extract_verbatim(repo, spec)
    legacy_unit_c = (
        "#include \"gnt4_shim.h\"\n\nvoid zz_fp_(int x);\n\n" + legacy_verbatim
    )
    assert materialized.unit_c == legacy_unit_c  # transform is identity
    assert materialized.verbatim == legacy_verbatim
    assert materialized.extraction_records == legacy_records
    assert materialized.transform["name"] == TRANSFORM_NAME
    assert materialized.transform["version"] == TRANSFORM_VERSION
    assert materialized.transform["sites"] == 0
    assert materialized.transform["sites_per_block"] == [0]
    # Identity re-stamp semantics: transformed == extracted, so a migration
    # census stamps the artifact in place -- no revocation, no rebuild.
    assert (
        materialized.transform["transformed_sha256"]
        == materialized.extracted_sha256
    )
    assert transform_staleness(
        {"transform": materialized.transform},
        materialized.transform["transformed_sha256"],
    ) == CURRENT
    assert "VERBATIM+D5" not in materialized.unit_c  # marker keeps VERBATIM:


def test_materialize_transformed_unit_records_both_hashes(tmp_path):
    repo = _write_repo(tmp_path, IDIOM_BODY)
    specs = [
        {"file": "research/decomp/ghidra-export/chunk_7777.c", "start": 2, "end": 6},
        {"file": "research/decomp/ghidra-export/chunk_7777.c", "start": 8, "end": 11},
    ]
    materialized = materialize_unit_c(repo, _unit(specs))
    raw_verbatim, raw_records = extract_verbatim(repo, specs)
    # Pre-transform provenance is untouched: per-block hashes match the raw
    # export slices exactly as extract_verbatim records them.
    assert materialized.extraction_records == raw_records
    assert materialized.extracted_sha256 == hashlib.sha256(
        raw_verbatim.encode("utf-8")
    ).hexdigest()
    # Post-transform: the site is rewritten, the transformed hash differs,
    # per-block site counts localize the rewrite.
    assert materialized.transform["sites"] == 1
    assert materialized.transform["sites_per_block"] == [1, 0]
    assert (
        materialized.transform["transformed_sha256"]
        != materialized.extracted_sha256
    )
    assert HELPER_NAME in materialized.unit_c
    assert "(double)CONCAT44" not in materialized.unit_c
    assert materialized.transform["d5_residual_risk"] == 0
    # Line count identical to the untransformed materialization.
    assert materialized.unit_c.count("\n") == (
        "#include \"gnt4_shim.h\"\n\nvoid zz_fp_(int x);\n\n" + raw_verbatim
    ).count("\n")
    # Marker rename: only the block the transform changed claims +D5.
    assert "/* ==== VERBATIM+D5: " in materialized.verbatim
    assert materialized.verbatim.count("/* ==== VERBATIM+D5: ") == 1
    assert materialized.verbatim.count("/* ==== VERBATIM: ") == 1


def test_prelude_region_splits_on_both_marker_spellings():
    plain = "#include \"gnt4_shim.h\"\nint a;\n/* ==== VERBATIM: x 1-2 ==== */\nbody\n"
    renamed = "#include \"gnt4_shim.h\"\nint a;\n/* ==== VERBATIM+D5: x 1-2 ==== */\nbody\n"
    assert prelude_region(plain) == prelude_region(renamed)
    assert "body" not in prelude_region(renamed)


def test_extract_verbatim_is_called_only_through_the_materialization_seam():
    """F-D5-6: transform-version drift between the build, diagnosis, and F4
    replay paths is killed structurally -- extract_verbatim has exactly one
    caller, materialize_unit_c."""
    import src.port_wasm_units as module

    source = inspect.getsource(module)
    calls = re.findall(r"extract_verbatim\(", source)
    # one def + one call (inside materialize_unit_c)
    assert len(calls) == 2, (
        "extract_verbatim must only be called by materialize_unit_c; "
        f"found {len(calls) - 1} call site(s)"
    )
    assert "extract_verbatim(" in inspect.getsource(module.materialize_unit_c)


# ------------------------------------------------- driver-level provenance


def _completed(rc: int = 0, stdout: str = "") -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(
        args=["git"], returncode=rc, stdout=stdout, stderr=""
    )


def test_green_unit_provenance_carries_the_transform_block(tmp_path, monkeypatch):
    from src.port_wasm_units import WasmUnitDriver

    monkeypatch.delenv("OGHIDRA_PORT_LIVENESS_PATH", raising=False)
    repo = _write_repo(tmp_path, IDIOM_BODY)
    (repo / "research/decomp/generated/finish-game-port").mkdir(parents=True)
    queue = {
        "queue_schema": 1,
        "units": [
            {
                **_unit(
                    [
                        {
                            "file": "research/decomp/ghidra-export/chunk_7777.c",
                            "start": 2,
                            "end": 6,
                        }
                    ]
                ),
                "name": "unit-fp",
                "oracle": {
                    "command": ["node", "fake.mjs"],
                    "cwd": "research/decomp/poc",
                    "env": {"POC_WASM": "{wasm}"},
                    "success_patterns": ["PASS"],
                },
            }
        ],
    }
    (repo / "research/decomp/generated/finish-game-port/wasm-units.json").write_text(
        json.dumps(queue), encoding="utf-8"
    )

    seen = {}

    def fake_build(workdir, exports, extra=None):
        seen["unit_c"] = (workdir / "unit.c").read_text(encoding="utf-8")
        seen["header"] = (workdir / "gnt4_shim.h").read_text(encoding="utf-8")
        (workdir / "unit.wasm").write_bytes(b"\x00asm")
        return True, ""

    driver = WasmUnitDriver(
        repo_root=repo,
        build_runner=fake_build,
        oracle_runner=lambda unit, wasm: (True, "1/1", "PASS log"),
        git_runner=lambda *args: _completed(0, "abc123\n"),
    )
    driver.run()

    # The built unit went through the transform, and the header gained the
    # seed-tier helper deterministically (snapshot header lacked it).
    assert HELPER_NAME in seen["unit_c"]
    assert "(double)CONCAT44" not in seen["unit_c"]
    assert HELPER_DEFINITION.strip() in seen["header"]

    provenance_path = (
        repo / "research/decomp/port-units/unit-fp/provenance.json"
    )
    assert provenance_path.is_file()
    provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
    block = provenance["transform"]
    assert block["name"] == TRANSFORM_NAME
    assert block["version"] == TRANSFORM_VERSION
    assert block["sites"] == 1
    assert block["sites_per_block"] == [1]
    assert block["transformed_sha256"] != provenance["extracted_sha256"]
    assert block["d5_residual_risk"] == 0
    # Artifact unit.c matches the transformed hash chain: the +D5 marker.
    artifact = (
        repo / "research/decomp/port-units/unit-fp/unit.c"
    ).read_text(encoding="utf-8")
    assert "/* ==== VERBATIM+D5: " in artifact


def test_dataflow_residual_risk_blocks_the_unit(tmp_path, monkeypatch):
    from src.port_wasm_units import WasmUnitDriver

    monkeypatch.delenv("OGHIDRA_PORT_LIVENESS_PATH", raising=False)
    body = (
        "// head\n"
        "void zz_sep_(int x)\n"
        "{\n"
        "  unsigned long long u = CONCAT44(0x43300000, x);\n"
        "  use((double)u);\n"
        "}\n"
    )
    repo = _write_repo(tmp_path, body)
    (repo / "research/decomp/generated/finish-game-port").mkdir(parents=True)
    queue = {
        "queue_schema": 1,
        "units": [
            {
                "name": "unit-sep",
                "extractions": [
                    {
                        "file": "research/decomp/ghidra-export/chunk_7777.c",
                        "start": 2,
                        "end": 6,
                    }
                ],
                "prelude": [],
                "exported_functions": ["zz_sep_"],
                "header_seed": "research/decomp/poc/seed.h",
                "oracle": {"type": "compile_only"},
            }
        ],
    }
    (repo / "research/decomp/generated/finish-game-port/wasm-units.json").write_text(
        json.dumps(queue), encoding="utf-8"
    )
    built = []
    driver = WasmUnitDriver(
        repo_root=repo,
        build_runner=lambda workdir, exports, extra=None: built.append(1)
        or (True, ""),
        oracle_runner=lambda unit, wasm: (True, "1/1", "PASS"),
        git_runner=lambda *args: _completed(0, "abc123\n"),
    )
    driver.run()
    assert built == []  # F-D5-2/F-D5-B: paged and blocked, never silently built
    state = json.loads(
        (
            repo
            / "research/decomp/generated/finish-game-port/wasm-units-state.json"
        ).read_text(encoding="utf-8")
    )
    record = state["units"]["unit-sep"]
    assert record["status"] != "ported"
    assert "residual-risk" in record.get("error", "")


# ------------------------------------------------- D5-6 migration sweep


def _migration_repo(tmp_path: Path):
    repo = _write_repo(tmp_path, IDIOM_BODY)
    (repo / "research/decomp/generated/finish-game-port").mkdir(parents=True)
    staging = repo / "research/decomp/port-units-staging"

    def entry(name: str, start: int, end: int) -> dict:
        return {
            "name": name,
            "extractions": [
                {
                    "file": "research/decomp/ghidra-export/chunk_7777.c",
                    "start": start,
                    "end": end,
                }
            ],
            "prelude": [],
            "exported_functions": ["zz_fp_"],
            "header_seed": "research/decomp/poc/seed.h",
            "oracle": {"type": "compile_only"},
        }

    queue = {
        "queue_schema": 1,
        "units": [
            entry("unit-wrong", 2, 6),    # idiom site, pre-D5 green -> revoke
            entry("unit-clean", 8, 11),   # site-free, pre-D5 green -> stands
            entry("unit-current", 2, 6),  # already transform-stamped -> current
            entry("island-core", 8, 11),  # green, no staged dir -> skipped
            entry("unit-pending", 2, 6),  # never green -> untouched
        ],
    }
    (repo / "research/decomp/generated/finish-game-port/wasm-units.json").write_text(
        json.dumps(queue), encoding="utf-8"
    )

    def stage(name: str, provenance: dict) -> None:
        unit_dir = staging / name
        unit_dir.mkdir(parents=True)
        (unit_dir / "provenance.json").write_text(
            json.dumps(provenance), encoding="utf-8"
        )

    units = {unit["name"]: unit for unit in queue["units"]}
    wrong = materialize_unit_c(repo, units["unit-wrong"])
    clean = materialize_unit_c(repo, units["unit-clean"])
    current = materialize_unit_c(repo, units["unit-current"])
    # Pre-D5 provenance shape: extraction hashes only, NO transform block.
    stage("unit-wrong", {
        "unit": "unit-wrong",
        "extractions": wrong.extraction_records,
        "extracted_sha256": wrong.extracted_sha256,
        "tier": "compile_only",
    })
    stage("unit-clean", {
        "unit": "unit-clean",
        "extractions": clean.extraction_records,
        "extracted_sha256": clean.extracted_sha256,
        "tier": "compile_only",
    })
    stage("unit-current", {
        "unit": "unit-current",
        "extractions": current.extraction_records,
        "extracted_sha256": current.extracted_sha256,
        "transform": current.transform,
        "tier": "compile_only",
    })
    state = {
        "state_schema": 1,
        "units": {
            "unit-wrong": {"status": "green", "attempts": 1, "tier": "compile_only"},
            "unit-clean": {"status": "green", "attempts": 1, "tier": "compile_only"},
            "unit-current": {"status": "green", "attempts": 2, "tier": "compile_only"},
            "island-core": {"status": "green", "attempts": 1},
            "unit-pending": {"status": "pending", "attempts": 0},
        },
    }
    (repo / "research/decomp/generated/finish-game-port/wasm-units-state.json").write_text(
        json.dumps(state), encoding="utf-8"
    )
    return repo


def _migration_driver(repo: Path):
    from src.port_wasm_units import WasmUnitDriver

    return WasmUnitDriver(
        repo_root=repo,
        build_runner=lambda workdir, exports, extra=None: (True, ""),
        oracle_runner=lambda unit, wasm: (True, "1/1", "PASS"),
        git_runner=lambda *args: _completed(0, "abc123\n"),
    )


def test_d5_migrate_revokes_exactly_the_predicate_selection(tmp_path, monkeypatch):
    monkeypatch.delenv("OGHIDRA_PORT_LIVENESS_PATH", raising=False)
    repo = _migration_repo(tmp_path)
    report = _migration_driver(repo).d5_migrate()
    assert [row["unit"] for row in report["revoked"]] == ["unit-wrong"]
    assert report["revoked"][0]["sites"] == 1
    assert report["identity_stand"] == ["unit-clean"]
    assert report["current"] == ["unit-current"]
    assert [row["unit"] for row in report["skipped"]] == ["island-core"]
    assert report["backup"]  # state was backed up before the first edit
    state = json.loads(
        (
            repo
            / "research/decomp/generated/finish-game-port/wasm-units-state.json"
        ).read_text(encoding="utf-8")
    )
    units = state["units"]
    assert units["unit-wrong"]["status"] == "pending"  # requeued
    assert units["unit-wrong"]["revoked"]["via"] == "d5-migrate"
    assert units["unit-wrong"]["revoked"]["previous_tier"] == "compile_only"
    assert units["unit-clean"]["status"] == "green"    # identity carve-out
    assert units["unit-current"]["status"] == "green"
    assert units["island-core"]["status"] == "green"   # step 4: out of scope
    assert units["unit-pending"]["status"] == "pending"
    # The journal saw the revocation (events.jsonl carries verdict_revoked).
    events_path = (
        repo / "research/decomp/generated/finish-game-port/events.jsonl"
    )
    revoked_events = [
        json.loads(line)
        for line in events_path.read_text(encoding="utf-8").splitlines()
        if '"verdict_revoked"' in line
    ]
    assert [event.get("unit") for event in revoked_events] == ["unit-wrong"]
    # Idempotent: a second sweep finds nothing left to revoke.
    second = _migration_driver(repo).d5_migrate()
    assert second["revoked"] == []
    assert second["identity_stand"] == ["unit-clean"]


def test_d5_migrate_dry_run_changes_nothing(tmp_path, monkeypatch):
    monkeypatch.delenv("OGHIDRA_PORT_LIVENESS_PATH", raising=False)
    repo = _migration_repo(tmp_path)
    state_path = (
        repo / "research/decomp/generated/finish-game-port/wasm-units-state.json"
    )
    before = state_path.read_text(encoding="utf-8")
    report = _migration_driver(repo).d5_migrate(dry_run=True)
    assert [row["unit"] for row in report["revoked"]] == ["unit-wrong"]
    assert report["backup"] is None
    assert state_path.read_text(encoding="utf-8") == before
    events_path = (
        repo / "research/decomp/generated/finish-game-port/events.jsonl"
    )
    assert (
        not events_path.is_file()
        or '"verdict_revoked"' not in events_path.read_text(encoding="utf-8")
    )


# ----------------------------------------------------- gate 3 rehearsal


def _toolchain_present() -> bool:
    emsdk = GOTYAFORCE_ROOT / "research/tools/emsdk/emsdk_env.sh"
    if not emsdk.is_file():
        return False
    try:
        from src.port_wasm_units import resolve_node_exe

        resolve_node_exe()
    except FileNotFoundError:
        return False
    return shutil.which("bash") is not None or Path(
        r"C:\Program Files\Git\bin\bash.exe"
    ).is_file()


@pytest.mark.skipif(
    not (GOTYAFORCE_ROOT / "research/decomp/ghidra-export").is_dir()
    or not _toolchain_present(),
    reason="real repo + emsdk/node toolchain required (gate-3 rehearsal)",
)
def test_gate3_rehearsal_auto_c0035_002_probe_flips(tmp_path):
    """D5-7 gate item 3, rehearsed offline: rebuild auto-c0035-002 through
    the transform with the production emcc path and probe FUN_80131688.
    Inputs {100, 50, -200, 0} must store distinct, input-proportional values
    equal to the PPC-truncation reference (fctiwz truncates toward zero:
    0.96f * 100 -> 95, * 50 -> 47, * -200 -> -191, * 0 -> 0) -- and never
    the pre-fix saturation artifact -1."""
    from src.port_d5_probe import run_probe

    report = run_probe(GOTYAFORCE_ROOT, tmp_path / "d5-probe")
    assert report["ok"], report
    assert report["transform"]["sites"] == 3
    stored = {row["input"]: row["stored"] for row in report["results"]}
    assert stored == {100: 95, 50: 47, -200: -191, 0: 0}
