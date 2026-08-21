"""Offline tests for the continuous assembly gate (src/port_assembly_gate.py,
design section 2.13 [V4-11], tranche T2b)."""

from __future__ import annotations

import json
from pathlib import Path

from src.port_assembly_gate import (
    CLASS_COLLISION_STUB,
    CLASS_DAT_DIVERGENCE,
    CLASS_INSTANTIATION_FAILURE,
    CLASS_LINK_FAILURE,
    CLASS_UNDEFINED8_FORK,
    ASSEMBLY_WASM,
    HeaderChunk,
    conflicts_from_link_error,
    duplicate_definition_conflicts,
    load_unit_artifact,
    merge_headers,
    parse_header_chunks,
    record_gate_result,
    run_assembly_gate,
    scan_function_definitions,
    select_recent_green_units,
    strip_comments,
)

DOUBLE_HEADER = """\
#ifndef GNT4_SHIM_H
#define GNT4_SHIM_H
#include <stdbool.h>
typedef unsigned char undefined;
typedef double undefined8;
#define CONCAT44(hi, lo) \\
  (((union { unsigned long long u; double d; }){ \\
     .u = ((unsigned long long)(unsigned int)(hi) << 32) | (unsigned int)(lo) }).d)
#define GC_U8(a)   (*(unsigned char *)(unsigned int)(a))
#define DAT_80436238 GC_U8(0x80436238)
extern int zz_0066168_();
#endif /* GNT4_SHIM_H */
"""

INTEGER_HEADER = """\
#ifndef GNT4_SHIM_H
#define GNT4_SHIM_H
#include <stdbool.h>
typedef unsigned char undefined;
typedef unsigned long long  undefined8;   /* an INTEGER, never double */
#define CONCAT44(hi, lo) \\
  (((unsigned long long)(unsigned int)(hi) << 32) | (unsigned int)(lo))
#define GC_U8(a)   (*(unsigned char *)(unsigned int)(a))
#define DAT_80436238 GC_U8(0x80436238)
extern int zz_0066168_();
#endif /* GNT4_SHIM_H */
"""


# --------------------------------------------------------------------- parsing


def test_strip_comments_preserves_code():
    text = "int a; /* gone */\n// gone too\nint b;"
    stripped = strip_comments(text)
    assert "int a;" in stripped and "int b;" in stripped
    assert "gone" not in stripped


def test_parse_header_drops_the_guard_and_finds_symbols():
    chunks = parse_header_chunks(DOUBLE_HEADER)
    symbols = {c.symbol for c in chunks if c.symbol}
    assert "undefined8" in symbols
    assert "CONCAT44" in symbols
    assert "DAT_80436238" in symbols
    assert "zz_0066168_" in symbols
    # The include guard's macro never becomes a mergeable symbol.
    assert "GNT4_SHIM_H" not in symbols


def test_parse_header_survives_content_after_the_guard_endif():
    text = DOUBLE_HEADER + "\n/* auto tail */\n#define DAT_80430000 GC_U8(0x80430000)\n"
    chunks = parse_header_chunks(text)
    assert any(c.symbol == "DAT_80430000" for c in chunks)


def test_typedef_function_pointer_symbol():
    chunks = parse_header_chunks("typedef void (code)();\n")
    assert chunks[0].kind == "typedef"
    assert chunks[0].symbol == "code"


def test_static_inline_function_is_one_chunk():
    text = (
        "static inline unsigned countLeadingZeros(int x) {\n"
        "  return x == 0 ? 32u : (unsigned)__builtin_clz((unsigned)x);\n"
        "}\n"
    )
    chunks = parse_header_chunks(text)
    assert len(chunks) == 1
    assert chunks[0].kind == "function_def"
    assert chunks[0].symbol == "countLeadingZeros"


# ----------------------------------------------------------------------- merge


def test_identical_headers_merge_to_one_copy_per_symbol():
    result = merge_headers([("unit-a", DOUBLE_HEADER), ("unit-b", DOUBLE_HEADER)])
    assert result.conflicts == []
    assert result.merged_text is not None
    assert result.merged_text.count("typedef double undefined8;") == 1
    assert result.merged_text.count("DAT_80436238") == 1
    assert "#ifndef GNT4_ASSEMBLY_MERGE_H" in result.merged_text


def test_undefined8_fork_is_a_loud_conflict_never_a_silent_winner():
    result = merge_headers([("unit-a", DOUBLE_HEADER), ("unit-b", INTEGER_HEADER)])
    assert result.merged_text is None
    classes = {c["class"] for c in result.conflicts}
    assert classes == {CLASS_UNDEFINED8_FORK}
    fork = next(c for c in result.conflicts if c["symbol"] == "undefined8")
    assert fork["units"] == ["unit-a", "unit-b"]
    # CONCAT44's union-double vs integer split is classed with the fork.
    assert any(c["symbol"] == "CONCAT44" for c in result.conflicts)


def test_dat_width_divergence_class():
    a = "#define DAT_803b069c (*(short *)(unsigned int)0x803b069c)\n"
    b = "#define DAT_803b069c (*(unsigned char *)(unsigned int)0x803b069c)\n"
    result = merge_headers([("unit-a", a), ("unit-b", b)])
    assert result.merged_text is None
    assert result.conflicts[0]["class"] == CLASS_DAT_DIVERGENCE
    assert result.conflicts[0]["symbol"] == "DAT_803b069c"


def test_extern_stub_signature_mismatch_is_a_collision_stub():
    a = "extern int zz_004beb8_();\n"
    b = "extern void zz_004beb8_(int param_1, int param_2);\n"
    result = merge_headers([("unit-a", a), ("unit-b", b)])
    assert result.merged_text is None
    assert result.conflicts[0]["class"] == CLASS_COLLISION_STUB
    assert result.conflicts[0]["symbol"] == "zz_004beb8_"


def test_whitespace_and_comment_churn_do_not_conflict():
    a = "typedef unsigned int uint;\n#define GC_F32(a)  (*(float *)(unsigned int)(a))\n"
    b = (
        "typedef  unsigned   int  uint ;  /* model rewrote this line */\n"
        "#define GC_F32(a) (*(float *)(unsigned int)(a))\n"
    )
    result = merge_headers([("unit-a", a), ("unit-b", b)])
    # typedef spacing churn normalizes away except the ` ;` token split, which
    # IS a textual difference -- so compare the macro, which is whitespace-only.
    assert all(c["symbol"] != "GC_F32" for c in result.conflicts)


# ------------------------------------------------------- duplicate definitions


def test_scan_function_definitions_ignores_control_flow():
    text = (
        "void zz_00064d4_(void)\n\n{\n"
        "  if (x) {\n    while( true ) {\n      break;\n    }\n  }\n}\n"
    )
    assert scan_function_definitions(text) == {"zz_00064d4_"}


def test_duplicate_definitions_across_units_are_collision_stubs():
    a = "int zz_dup_(int a)\n{\n  return a;\n}\n"
    b = "int zz_dup_(int a)\n{\n  return a + 1;\n}\n"
    conflicts = duplicate_definition_conflicts([("unit-a", a), ("unit-b", b)])
    assert len(conflicts) == 1
    assert conflicts[0]["class"] == CLASS_COLLISION_STUB
    assert conflicts[0]["symbol"] == "zz_dup_"
    assert conflicts[0]["units"] == ["unit-a", "unit-b"]


# ----------------------------------------------------------- link diagnostics


def test_link_error_symbols_are_extracted_and_classed():
    error = (
        "wasm-ld: error: duplicate symbol: zz_dup_\n"
        "wasm-ld: error: unit-b.o: undefined symbol: zz_gone_\n"
    )
    conflicts = conflicts_from_link_error(error, ["unit-a", "unit-b"])
    by_symbol = {c["symbol"]: c["class"] for c in conflicts}
    assert by_symbol["zz_dup_"] == CLASS_COLLISION_STUB
    assert by_symbol["zz_gone_"] == CLASS_LINK_FAILURE


def test_unparseable_link_error_still_files_one_conflict():
    conflicts = conflicts_from_link_error("emcc: something exploded", ["u1", "u2"])
    assert len(conflicts) == 1
    assert conflicts[0]["class"] == CLASS_LINK_FAILURE
    assert conflicts[0]["symbol"] is None


# -------------------------------------------------------------- unit selection


def _write_artifact(
    root: Path, name: str, generated_at: str, header: str = DOUBLE_HEADER,
    unit_c: str = "int zz_x_(int a)\n{\n  return a;\n}\n",
    exports: list | None = None,
) -> Path:
    directory = root / name
    directory.mkdir(parents=True)
    (directory / "unit.c").write_text(unit_c, encoding="utf-8")
    (directory / "gnt4_shim.h").write_text(header, encoding="utf-8")
    (directory / "provenance.json").write_text(
        json.dumps(
            {
                "unit": name,
                "generated_at": generated_at,
                "exported_functions": exports or ["zz_x_"],
                "allowed_extra_imports": ["zz_ext_"],
                "tier": "compile_only",
            }
        ),
        encoding="utf-8",
    )
    return directory


def test_select_recent_green_units_orders_by_recency_and_caps_n(tmp_path):
    root = tmp_path / "port-units-staging"
    _write_artifact(root, "old", "2026-08-01T00:00:00Z")
    _write_artifact(root, "mid", "2026-08-10T00:00:00Z")
    _write_artifact(root, "new", "2026-08-20T00:00:00Z")
    (root / "broken").mkdir()  # no artifacts: skipped, never fatal
    picked = select_recent_green_units([root, tmp_path / "missing-root"], 2)
    assert [u.name for u in picked] == ["mid", "new"]
    everything = select_recent_green_units([root], None)
    assert [u.name for u in everything] == ["old", "mid", "new"]


def test_load_unit_artifact_requires_all_files(tmp_path):
    directory = tmp_path / "partial"
    directory.mkdir()
    (directory / "unit.c").write_text("int x;\n", encoding="utf-8")
    assert load_unit_artifact(directory) is None


# ----------------------------------------------------------------------- gate


def _units(tmp_path, headers_and_sources):
    root = tmp_path / "staging"
    units = []
    for index, (name, header, source) in enumerate(headers_and_sources):
        _write_artifact(
            root, name, f"2026-08-{10 + index:02d}T00:00:00Z",
            header=header, unit_c=source, exports=[f"fn_{index}"],
        )
    return select_recent_green_units([root], None)


def test_gate_pass_links_merged_workdir_and_smokes(tmp_path):
    units = _units(
        tmp_path,
        [
            ("unit-a", DOUBLE_HEADER, "int fn_0(int a)\n{\n  return a;\n}\n"),
            ("unit-b", DOUBLE_HEADER, "int fn_1(int a)\n{\n  return a + 1;\n}\n"),
        ],
    )
    calls = {}

    def fake_link(workdir, c_files, exports, allowed_extra):
        calls["c_files"] = c_files
        calls["exports"] = exports
        calls["allowed_extra"] = allowed_extra
        (workdir / ASSEMBLY_WASM).write_bytes(b"\x00asm")
        return True, ""

    def fake_smoke(wasm_path):
        calls["smoked"] = wasm_path.name
        return True, "ASSEMBLY_SMOKE_OK exports=2"

    workdir = tmp_path / "work"
    result = run_assembly_gate(units, workdir, fake_link, fake_smoke)
    assert result["passed"] is True
    assert result["stage"] == "pass"
    assert result["conflicts"] == []
    assert calls["c_files"] == ["unit-a.c", "unit-b.c"]
    assert calls["exports"] == ["fn_0", "fn_1"]
    assert calls["allowed_extra"] == ["zz_ext_"]
    assert calls["smoked"] == ASSEMBLY_WASM
    # The merged header replaced the per-unit ones; unit.c bytes are verbatim.
    merged = (workdir / "gnt4_shim.h").read_text()
    assert "GNT4_ASSEMBLY_MERGE_H" in merged
    assert (workdir / "unit-a.c").read_text() == "int fn_0(int a)\n{\n  return a;\n}\n"


def test_gate_merge_conflict_fails_before_any_link(tmp_path):
    units = _units(
        tmp_path,
        [
            ("unit-a", DOUBLE_HEADER, "int fn_0(void)\n{\n  return 0;\n}\n"),
            ("unit-b", INTEGER_HEADER, "int fn_1(void)\n{\n  return 1;\n}\n"),
        ],
    )
    linked = []
    result = run_assembly_gate(
        units, tmp_path / "work", lambda *a: linked.append(a) or (True, ""), None
    )
    assert result["passed"] is False
    assert result["stage"] == "merge"
    assert linked == []  # merge failed loudly; the link never ran
    assert {c["class"] for c in result["conflicts"]} == {CLASS_UNDEFINED8_FORK}


def test_gate_link_failure_files_conflicts(tmp_path):
    units = _units(
        tmp_path,
        [
            ("unit-a", DOUBLE_HEADER, "int fn_0(void)\n{\n  return 0;\n}\n"),
            ("unit-b", DOUBLE_HEADER, "int fn_1(void)\n{\n  return 1;\n}\n"),
        ],
    )
    result = run_assembly_gate(
        units,
        tmp_path / "work",
        lambda *a: (False, "wasm-ld: error: duplicate symbol: zz_dup_"),
        None,
    )
    assert result["passed"] is False
    assert result["stage"] == "link"
    assert result["conflicts"][0]["symbol"] == "zz_dup_"
    assert result["conflicts"][0]["class"] == CLASS_COLLISION_STUB


def test_gate_smoke_failure_is_an_instantiation_conflict(tmp_path):
    units = _units(
        tmp_path,
        [
            ("unit-a", DOUBLE_HEADER, "int fn_0(void)\n{\n  return 0;\n}\n"),
            ("unit-b", DOUBLE_HEADER, "int fn_1(void)\n{\n  return 1;\n}\n"),
        ],
    )

    def fake_link(workdir, c_files, exports, allowed_extra):
        (workdir / ASSEMBLY_WASM).write_bytes(b"\x00asm")
        return True, ""

    result = run_assembly_gate(
        units, tmp_path / "work", fake_link, lambda wasm: (False, "RangeError: oom")
    )
    assert result["passed"] is False
    assert result["stage"] == "smoke"
    assert result["conflicts"][0]["class"] == CLASS_INSTANTIATION_FAILURE


# ---------------------------------------------------------------------- ledger


def test_ledger_tracks_largest_n_and_dedups_conflicts(tmp_path):
    ledger_path = tmp_path / "assembly-gate.json"
    fail = {
        "n": 3,
        "units": ["a", "b", "c"],
        "checked_at": "2026-08-20T00:00:00Z",
        "passed": False,
        "stage": "merge",
        "detail": "merge refused",
        "conflicts": [
            {
                "symbol": "undefined8",
                "class": CLASS_UNDEFINED8_FORK,
                "units": ["a", "b"],
                "variants": {},
                "detail": "fork",
            }
        ],
    }
    record_gate_result(ledger_path, fail)
    record_gate_result(ledger_path, fail)
    ledger = json.loads(ledger_path.read_text())
    assert ledger["runs_total"] == 2
    assert ledger["largest_n_passed"] == 0
    assert len(ledger["conflicts"]) == 1
    only = next(iter(ledger["conflicts"].values()))
    assert only["times_seen"] == 2

    ok = dict(fail, passed=True, stage="pass", n=5, conflicts=[])
    record_gate_result(ledger_path, ok)
    ledger = json.loads(ledger_path.read_text())
    assert ledger["largest_n_passed"] == 5
    assert ledger["last_run"]["passed"] is True


def test_ledger_survives_a_corrupt_file(tmp_path):
    ledger_path = tmp_path / "assembly-gate.json"
    ledger_path.write_text("{not json", encoding="utf-8")
    record_gate_result(
        ledger_path,
        {"n": 2, "units": ["a", "b"], "checked_at": "x", "passed": True,
         "stage": "pass", "detail": "", "conflicts": []},
    )
    ledger = json.loads(ledger_path.read_text())
    assert ledger["largest_n_passed"] == 2


# ------------------------------------------- header vs prelude cross-check


def test_header_extern_vs_prelude_prototype_divergence_is_flagged():
    from src.port_assembly_gate import header_prelude_conflicts

    headers = [("unit-a", "extern int zz_0006fb4_();\n"), ("unit-b", "")]
    sources = [
        ("unit-a", "#include \"gnt4_shim.h\"\n\n/* ==== VERBATIM: x 1-2 ==== */\n"),
        (
            "unit-b",
            "#include \"gnt4_shim.h\"\n\n"
            "void zz_0006fb4_(int param_1, int param_2);\n\n"
            "/* ==== VERBATIM: x 1-2 ==== */\nvoid zz_0006fb4_(int a, int b) {}\n",
        ),
    ]
    conflicts = header_prelude_conflicts(headers, sources)
    assert len(conflicts) == 1
    assert conflicts[0]["symbol"] == "zz_0006fb4_"
    assert conflicts[0]["class"] == CLASS_COLLISION_STUB
    assert conflicts[0]["units"] == ["unit-a", "unit-b"]
    assert "header:" in conflicts[0]["variants"]["unit-a"]
    assert "prelude:" in conflicts[0]["variants"]["unit-b"]


def test_own_header_vs_own_prelude_is_never_a_conflict():
    from src.port_assembly_gate import header_prelude_conflicts

    headers = [("unit-a", "extern int zz_x_();\n")]
    sources = [
        (
            "unit-a",
            "#include \"gnt4_shim.h\"\n\nvoid zz_x_(int a);\n\n"
            "/* ==== VERBATIM: x 1-2 ==== */\n",
        )
    ]
    # The unit's own green build already proved this pair coexists.
    assert header_prelude_conflicts(headers, sources) == []


def test_matching_header_and_prelude_decls_do_not_conflict():
    from src.port_assembly_gate import header_prelude_conflicts

    headers = [("unit-a", "extern void zz_x_(int param_1);\n"), ("unit-b", "")]
    sources = [
        ("unit-a", "/* ==== VERBATIM: x 1-2 ==== */\n"),
        ("unit-b", "void zz_x_(int param_1);\n/* ==== VERBATIM: x 1-2 ==== */\n"),
    ]
    assert header_prelude_conflicts(headers, sources) == []


def test_prelude_scan_never_reads_verbatim_bodies():
    from src.port_assembly_gate import prelude_region

    text = (
        "#include \"gnt4_shim.h\"\n\nint zz_a_(int a);\n\n"
        "/* ==== VERBATIM: chunk.c 1-9 ==== */\nint zz_b_(int b);\n"
    )
    region = prelude_region(text)
    assert "zz_a_" in region and "zz_b_" not in region


def test_parameter_name_and_comma_spacing_churn_is_not_a_conflict():
    a = "extern double gnt4_PSVECMag_bl(float *v);\n"
    b = "extern double gnt4_PSVECMag_bl(float *a);\n"
    assert merge_headers([("unit-a", a), ("unit-b", b)]).conflicts == []

    from src.port_assembly_gate import header_prelude_conflicts

    headers = [("unit-a", "extern void fn_x(int param_1, int param_2);\n"), ("unit-b", "")]
    sources = [
        ("unit-a", "/* ==== VERBATIM: x 1-2 ==== */\n"),
        ("unit-b", "void fn_x(int param_1,int param_2);\n/* ==== VERBATIM: x 1-2 ==== */\n"),
    ]
    assert header_prelude_conflicts(headers, sources) == []


def test_return_type_divergence_is_still_a_conflict_after_normalization():
    a = "extern double gnt4_PSMTXConcat_bl(float *a, float *b, float *out);\n"
    b = "extern undefined8 gnt4_PSMTXConcat_bl(float *a, float *b, float *out);\n"
    result = merge_headers([("unit-a", a), ("unit-b", b)])
    assert result.conflicts and result.conflicts[0]["class"] == CLASS_COLLISION_STUB
