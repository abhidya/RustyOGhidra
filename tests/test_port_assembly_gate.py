"""Offline tests for the continuous assembly gate (src/port_assembly_gate.py,
design section 2.13 [V4-11], tranche T2b)."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from src.port_assembly_gate import (
    CLASS_COLLISION_STUB,
    CLASS_DAT_DIVERGENCE,
    CLASS_INSTANTIATION_FAILURE,
    CLASS_LINK_FAILURE,
    CLASS_UNDEFINED8_FORK,
    ASSEMBLY_WASM,
    HeaderChunk,
    load_canonical_state_snapshot,
    conflicts_from_link_error,
    duplicate_definition_conflicts,
    load_unit_artifact,
    merge_headers,
    parse_header_chunks,
    prove_legacy_artifact_commit_tree,
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


def test_link_error_captures_wasm_ld_attribution_lines():
    """wasm-ld names WHICH objects disagree on the '>>> defined as' lines.

    The one-line match alone filed 'function signature mismatch: <sym>' while
    the result `detail` kept only the tail of stderr (the echoed link
    command), so the per-object signatures needed a scratch reproduction to
    recover. They belong in the conflict record.
    """
    error = (
        "wasm-ld: error: function signature mismatch: gnt4_PSQUATScale_bl\n"
        ">>> defined as (f64, i32, i32) -> void in unit_2.o\n"
        ">>> defined as (f64, i32, i32) -> i64 in unit_4.o\n"
        "emcc: error: wasm-ld failed (returned 1)\n"
    )
    conflicts = conflicts_from_link_error(error, ["unit-a", "unit-b"])
    assert len(conflicts) == 1
    detail = conflicts[0]["detail"]
    assert conflicts[0]["symbol"] == "gnt4_PSQUATScale_bl"
    assert conflicts[0]["class"] == CLASS_COLLISION_STUB
    assert "(f64, i32, i32) -> void in unit_2.o" in detail
    assert "(f64, i32, i32) -> i64 in unit_4.o" in detail
    # The unrelated trailing emcc line is not attribution and stays out.
    assert "returned 1" not in detail


# -------------------------------------------------------------- unit selection


def _write_artifact(
    root: Path, name: str, generated_at: str, header: str = DOUBLE_HEADER,
    unit_c: str = "int zz_x_(int a)\n{\n  return a;\n}\n",
    exports: list | None = None,
    tier: str = "compile_only",
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
                "tier": tier,
            }
        ),
        encoding="utf-8",
    )
    return directory


def _canonical_snapshot(tmp_path: Path, records: dict[str, dict] | list[str]):
    if isinstance(records, list):
        records = {
            name: {
                "status": "green", "tier": "compile_only",
                "commit": f"deadbee{index:x}", "pushed": True,
            }
            for index, name in enumerate(records)
        }
    for name, record in records.items():
        if "candidate_sha256" in record:
            continue
        directories = sorted(
            path.parent
            for path in tmp_path.rglob("provenance.json")
            if path.parent.name == name
        )
        if directories:
            artifact = load_unit_artifact(directories[0])
            assert artifact is not None
            record["candidate_sha256"] = artifact.sha256
    path = tmp_path / "wasm-units-state.json"
    path.write_text(json.dumps({"state_schema": 1, "units": records}))
    return load_canonical_state_snapshot(path)


def _git(repo: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", *args], cwd=repo, capture_output=True, text=True, check=False
    )


def _legacy_commit_fixture(
    tmp_path: Path,
    *,
    name: str = "legacy",
    root_name: str = "research/decomp/port-units-staging",
    tier: str = "compile_only",
) -> tuple[Path, Path, dict, object]:
    repo = tmp_path / "repo"
    root = repo / root_name
    _write_artifact(root, name, "2026-08-01T00:00:00Z", tier=tier)
    assert _git(repo, "init").returncode == 0
    assert _git(repo, "config", "user.email", "port-test@example.invalid").returncode == 0
    assert _git(repo, "config", "user.name", "Port Test").returncode == 0
    assert _git(repo, "add", ".").returncode == 0
    assert _git(repo, "commit", "-m", "legacy artifact").returncode == 0
    commit = _git(repo, "rev-parse", "HEAD").stdout.strip()
    assert _git(
        repo, "update-ref", "refs/remotes/origin/port-staging", commit
    ).returncode == 0
    record = {
        "status": "green",
        "tier": tier,
        "commit": commit,
        "pushed": True,
    }
    state_path = repo / "state.json"
    state_path.write_text(json.dumps({
        "state_schema": 1, "units": {name: record}
    }), encoding="utf-8")
    snapshot = load_canonical_state_snapshot(state_path)
    return repo, root, record, snapshot


def _legacy_verifier(repo: Path):
    return lambda artifact, record: prove_legacy_artifact_commit_tree(
        artifact, record, repo_root=repo, git_runner=lambda *args: _git(repo, *args)
    )


def test_select_recent_green_units_orders_by_recency_and_caps_n(tmp_path):
    root = tmp_path / "port-units-staging"
    _write_artifact(root, "old", "2026-08-01T00:00:00Z")
    _write_artifact(root, "mid", "2026-08-10T00:00:00Z")
    _write_artifact(root, "new", "2026-08-20T00:00:00Z")
    (root / "broken").mkdir()  # no artifacts: skipped, never fatal
    snapshot = _canonical_snapshot(tmp_path, ["old", "mid", "new"])
    picked, excluded = select_recent_green_units(
        [root, tmp_path / "missing-root"], 2, canonical_snapshot=snapshot
    )
    assert [u.name for u in picked] == ["mid", "new"]
    assert excluded == {}
    everything, _ = select_recent_green_units(
        [root], None, canonical_snapshot=snapshot
    )
    assert [u.name for u in everything] == ["old", "mid", "new"]


def test_legacy_missing_digest_passes_only_with_exact_commit_tree(tmp_path):
    repo, root, _record, snapshot = _legacy_commit_fixture(tmp_path)

    picked, excluded = select_recent_green_units(
        [root], None, canonical_snapshot=snapshot,
        legacy_verifier=_legacy_verifier(repo),
    )

    assert [unit.name for unit in picked] == ["legacy"]
    binding = picked[0].canonical["artifact_binding"]
    assert binding["binding"] == "legacy-git-tree"
    assert binding["artifact_sha256"] == picked[0].sha256
    assert binding["commit"] == _git(repo, "rev-parse", "HEAD").stdout.strip()
    assert binding["path"] == "research/decomp/port-units-staging/legacy"
    assert binding["tree_entry_count"] == 3
    assert excluded == {}


def test_legacy_missing_digest_rejects_substituted_worktree_bytes(tmp_path):
    repo, root, _record, snapshot = _legacy_commit_fixture(tmp_path)
    (root / "legacy/unit.c").write_text("int substituted;\n", encoding="utf-8")

    picked, excluded = select_recent_green_units(
        [root], None, canonical_snapshot=snapshot,
        legacy_verifier=_legacy_verifier(repo),
    )

    assert picked == []
    assert excluded == {"legacy": "legacy-artifact-commit-mismatch"}


def test_legacy_missing_digest_rejects_unreachable_commit_and_missing_path(tmp_path):
    repo, root, record, _snapshot = _legacy_commit_fixture(tmp_path)
    state_path = repo / "state.json"
    record["commit"] = "f" * 40
    state_path.write_text(json.dumps({
        "state_schema": 1, "units": {"legacy": record}
    }), encoding="utf-8")
    unreachable = load_canonical_state_snapshot(state_path)
    picked, excluded = select_recent_green_units(
        [root], None, canonical_snapshot=unreachable,
        legacy_verifier=_legacy_verifier(repo),
    )
    assert picked == []
    assert excluded == {
        "legacy": "legacy-commit-unreachable-from-publication-ref"
    }

    missing_root = repo / "research/decomp/port-units-missing"
    _write_artifact(missing_root, "not-in-commit", "2026-08-02T00:00:00Z")
    record = {
        "status": "green", "tier": "compile_only",
        "commit": _git(repo, "rev-parse", "HEAD").stdout.strip(), "pushed": True,
    }
    state_path.write_text(json.dumps({
        "state_schema": 1, "units": {"not-in-commit": record}
    }), encoding="utf-8")
    missing_path = load_canonical_state_snapshot(state_path)
    picked, excluded = select_recent_green_units(
        [missing_root], None, canonical_snapshot=missing_path,
        legacy_verifier=_legacy_verifier(repo),
    )
    assert picked == []
    assert excluded == {"not-in-commit": "legacy-commit-path-missing"}


def test_legacy_proof_uses_publication_ref_when_head_diverged(tmp_path):
    repo, root, _record, snapshot = _legacy_commit_fixture(tmp_path)
    published = _git(
        repo, "rev-parse", "refs/remotes/origin/port-staging"
    ).stdout.strip()
    assert _git(repo, "checkout", "--orphan", "diverged").returncode == 0
    assert _git(repo, "commit", "--allow-empty", "-m", "diverged head").returncode == 0
    assert _git(repo, "merge-base", "--is-ancestor", published, "HEAD").returncode == 1

    picked, excluded = select_recent_green_units(
        [root], None, canonical_snapshot=snapshot,
        legacy_verifier=_legacy_verifier(repo),
    )

    assert [unit.name for unit in picked] == ["legacy"]
    assert picked[0].canonical["artifact_binding"]["publication_ref"] == (
        "refs/remotes/origin/port-staging"
    )
    assert excluded == {}


def test_legacy_proof_fails_if_local_publication_ref_is_missing(tmp_path):
    repo, root, _record, snapshot = _legacy_commit_fixture(tmp_path)
    assert _git(
        repo, "update-ref", "-d", "refs/remotes/origin/port-staging"
    ).returncode == 0

    picked, excluded = select_recent_green_units(
        [root], None, canonical_snapshot=snapshot,
        legacy_verifier=_legacy_verifier(repo),
    )

    assert picked == []
    assert excluded == {
        "legacy": "legacy-commit-unreachable-from-publication-ref"
    }


def test_legacy_commit_proof_detects_artifact_race(tmp_path):
    repo, root, _record, snapshot = _legacy_commit_fixture(tmp_path)
    raced = {"done": False}

    def racing_git(*args):
        result = _git(repo, *args)
        if args[0] == "diff" and not raced["done"]:
            raced["done"] = True
            (root / "legacy/unit.c").write_text("int raced;\n", encoding="utf-8")
        return result

    picked, excluded = select_recent_green_units(
        [root], None, canonical_snapshot=snapshot,
        legacy_verifier=lambda artifact, record: prove_legacy_artifact_commit_tree(
            artifact, record, repo_root=repo, git_runner=racing_git
        ),
    )

    assert picked == []
    assert excluded == {"legacy": "legacy-artifact-raced"}


def test_legacy_commit_proof_preserves_verified_root_precedence(tmp_path):
    repo, verified, record, _snapshot = _legacy_commit_fixture(
        tmp_path,
        name="auto-x",
        root_name="research/decomp/port-units",
        tier="oracle_green",
    )
    staging = repo / "research/decomp/port-units-staging"
    _write_artifact(
        staging, "auto-x", "2999-08-20T00:00:00Z",
        unit_c="int staged_substitute;\n", tier="oracle_green",
    )
    snapshot = load_canonical_state_snapshot(repo / "state.json")

    picked, excluded = select_recent_green_units(
        [verified, staging], None, canonical_snapshot=snapshot,
        root_tiers=["oracle_green", "compile_only"],
        legacy_verifier=_legacy_verifier(repo),
    )

    assert [unit.name for unit in picked] == ["auto-x"]
    assert picked[0].directory == verified / "auto-x"
    assert excluded == {}


def test_selection_uses_canonical_lifecycle_not_artifact_mtime(tmp_path):
    verified = tmp_path / "port-units"
    staging = tmp_path / "port-units-staging"
    _write_artifact(
        verified, "verified", "2026-08-01T00:00:00Z", tier="oracle_green"
    )
    _write_artifact(staging, "staged", "2026-08-02T00:00:00Z")
    statuses = {
        "pending": "pending",
        "retryable": "red_retryable",
        "failed": "failed",
        "structural": "structural_ineligible",
        "revoked": "green",
    }
    for index, name in enumerate(statuses, start=10):
        _write_artifact(staging, name, f"2999-08-{index:02d}T00:00:00Z")
    records = {
        "verified": {
            "status": "green", "tier": "oracle_green",
            "commit": "abc1234", "pushed": True,
        },
        "staged": {
            "status": "green", "tier": "compile_only",
            "commit": "abc1235", "pushed": True,
        },
    }
    for index, (name, status) in enumerate(statuses.items(), start=6):
        records[name] = {
            "status": status,
            "tier": "compile_only",
            "commit": f"abc123{index:x}",
            "pushed": True,
        }
    records["revoked"]["revoked"] = {
        "previous_commit": records["revoked"]["commit"],
        "reason": "current lifecycle revoked",
    }
    snapshot = _canonical_snapshot(tmp_path, records)

    picked, excluded = select_recent_green_units(
        [verified, staging], None, canonical_snapshot=snapshot,
        root_tiers=["oracle_green", "compile_only"],
    )

    assert [unit.name for unit in picked] == ["verified", "staged"]
    assert excluded == {
        "failed": "canonical-status:failed",
        "pending": "canonical-status:pending",
        "retryable": "canonical-status:red_retryable",
        "revoked": "current-lifecycle-revocation-contradiction",
        "structural": "canonical-status:structural_ineligible",
    }


def test_verified_root_shadow_is_fail_closed_before_name_dedup(tmp_path):
    verified = tmp_path / "port-units"
    staging = tmp_path / "port-units-staging"
    _write_artifact(verified, "auto-x", "2026-08-01T00:00:00Z")
    _write_artifact(staging, "auto-x", "2026-08-20T00:00:00Z")
    snapshot = _canonical_snapshot(tmp_path, {
        "auto-x": {
            "status": "green", "tier": "compile_only",
            "commit": "abc1234", "pushed": True,
        }
    })

    picked, excluded = select_recent_green_units(
        [verified, staging], None, canonical_snapshot=snapshot,
        root_tiers=["oracle_green", "compile_only"],
    )

    assert picked == []
    assert excluded == {"auto-x": "root-tier-mismatch:compile_only"}


def test_stale_revocation_from_prior_lifecycle_does_not_poison_green(tmp_path):
    root = tmp_path / "port-units-staging"
    directory = _write_artifact(root, "rebuilt", "2026-08-20T00:00:00Z")
    artifact = load_unit_artifact(directory)
    assert artifact is not None
    snapshot = _canonical_snapshot(tmp_path, {
        "rebuilt": {
            "status": "green", "tier": "compile_only",
            "commit": "bbb2222", "pushed": True,
            "candidate_sha256": artifact.sha256,
            "revoked": {"previous_commit": "aaa1111", "reason": "old verdict"},
        }
    })

    picked, excluded = select_recent_green_units(
        [root], None, canonical_snapshot=snapshot
    )

    assert [unit.name for unit in picked] == ["rebuilt"]
    assert picked[0].canonical["stale_revocation_ignored"] is True
    assert excluded == {}


def test_canonical_snapshot_rejects_non_object_state(tmp_path):
    path = tmp_path / "wasm-units-state.json"
    path.write_text("[]", encoding="utf-8")

    with pytest.raises(ValueError, match="schema/units"):
        load_canonical_state_snapshot(path)


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
    snapshot = _canonical_snapshot(
        tmp_path, [name for name, _header, _source in headers_and_sources]
    )
    return select_recent_green_units(
        [root], None, canonical_snapshot=snapshot
    )[0]


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


def test_gate_fails_if_explicit_candidate_digest_changes_during_link(tmp_path):
    units = _units(
        tmp_path,
        [
            ("unit-a", DOUBLE_HEADER, "int fn_0(void)\n{\n  return 0;\n}\n"),
            ("unit-b", DOUBLE_HEADER, "int fn_1(void)\n{\n  return 1;\n}\n"),
        ],
    )
    candidate = units[-1]
    expected = {"name": candidate.name, "sha256": candidate.sha256}

    def mutating_link(workdir, c_files, exports, allowed_extra):
        (workdir / ASSEMBLY_WASM).write_bytes(b"\x00asm")
        (candidate.directory / "unit.c").write_text(
            "int fn_1(void)\n{\n  return 999;\n}\n", encoding="utf-8"
        )
        return True, ""

    result = run_assembly_gate(
        units,
        tmp_path / "work",
        mutating_link,
        lambda wasm: (True, "ASSEMBLY_SMOKE_OK"),
        candidate=candidate,
    )
    assert result["passed"] is False
    assert result["stage"] == "candidate-integrity"
    assert result["candidate"] == expected
    assert expected["sha256"] in result["detail"]


def test_gate_fails_if_prior_artifact_digest_changes_during_link(tmp_path):
    units = _units(
        tmp_path,
        [
            ("unit-a", DOUBLE_HEADER, "int fn_0(void)\n{\n  return 0;\n}\n"),
            ("unit-b", DOUBLE_HEADER, "int fn_1(void)\n{\n  return 1;\n}\n"),
        ],
    )

    def mutating_link(workdir, c_files, exports, allowed_extra):
        (workdir / ASSEMBLY_WASM).write_bytes(b"\x00asm")
        (units[0].directory / "unit.c").write_text("int changed;\n")
        return True, ""

    result = run_assembly_gate(
        units, tmp_path / "work", mutating_link, lambda _path: (True, "ok")
    )

    assert result["passed"] is False
    assert result["stage"] == "artifact-integrity"
    assert "unit-a changed during assembly" in result["detail"]


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


# ---------------------------------------- guarded-macro divergence (review R1)
# Adversarial-review finding: an `#ifndef`-guarded `#define` lives inside an
# inner conditional block, which the merge treated as an anonymous chunk --
# divergent guarded definitions were BOTH emitted with zero conflicts filed,
# and the first unit's definition silently won at preprocess time.


def _guarded_header(gc_u8_body: str) -> str:
    return (
        "#ifndef GNT4_SHIM_H\n"
        "#define GNT4_SHIM_H\n"
        "#include <stdbool.h>\n"
        "typedef unsigned char undefined;\n"
        "#ifndef GC_U8\n"
        f"#define GC_U8(a) {gc_u8_body}\n"
        "#endif\n"
        "extern int zz_0066168_();\n"
        "#endif /* GNT4_SHIM_H */\n"
    )


def test_guarded_macro_divergence_is_a_loud_conflict_never_first_wins():
    """The review's exact repro: same inner `#ifndef GC_U8` guard, divergent
    bodies. Must refuse to merge loudly -- never emit both blocks and let the
    preprocessor pick the first unit's definition silently."""
    a = _guarded_header("(*(unsigned char *)(unsigned int)(a))")
    b = _guarded_header("(*(char *)(unsigned int)(a))")
    result = merge_headers([("unit-a", a), ("unit-b", b)])
    assert result.merged_text is None
    gc = [c for c in result.conflicts if c["symbol"] == "GC_U8"]
    assert gc, f"no GC_U8 conflict filed: {result.conflicts}"
    assert gc[0]["units"] == ["unit-a", "unit-b"]


def test_identical_guarded_macro_blocks_still_merge_to_one_copy():
    a = _guarded_header("(*(unsigned char *)(unsigned int)(a))")
    result = merge_headers([("unit-a", a), ("unit-b", a)])
    assert result.conflicts == []
    assert result.merged_text is not None
    assert result.merged_text.count("#define GC_U8(a)") == 1


def test_guarded_vs_plain_macro_definition_is_a_loud_conflict():
    """One unit guards its GC_U8, the other defines it bare: emitting both
    (guarded block + plain #define) is a redefinition whose winner depends on
    emission order -- refuse loudly instead."""
    a = _guarded_header("(*(unsigned char *)(unsigned int)(a))")
    b = (
        "#ifndef GNT4_SHIM_H\n#define GNT4_SHIM_H\n"
        "#define GC_U8(a) (*(char *)(unsigned int)(a))\n"
        "#endif /* GNT4_SHIM_H */\n"
    )
    result = merge_headers([("unit-a", a), ("unit-b", b)])
    assert result.merged_text is None
    assert any(c["symbol"] == "GC_U8" for c in result.conflicts)


def test_leading_function_like_guarded_define_is_not_an_include_guard():
    """Sub-bug: in a header with NO outer guard, a leading
    `#ifndef X / #define X(...)` conditional definition was misread as the
    include guard and the definition was silently DELETED from the merge.
    An include guard's #define is object-like and empty; anything else is a
    real conditional block whose content must survive."""
    text = (
        "#ifndef GC_U8\n"
        "#define GC_U8(a) (*(unsigned char *)(unsigned int)(a))\n"
        "#endif\n"
    )
    chunks = parse_header_chunks(text)
    assert any("#define GC_U8" in c.text for c in chunks), (
        "guarded GC_U8 definition was deleted by the include-guard heuristic"
    )
    # And the definition must reach the merged header, not vanish.
    result = merge_headers([("unit-a", text)])
    assert result.merged_text is not None
    assert "#define GC_U8(a)" in result.merged_text


def test_object_like_valued_leading_define_is_not_an_include_guard():
    text = "#ifndef GC_NULL\n#define GC_NULL 0\n#endif\nextern int zz_a_();\n"
    result = merge_headers([("unit-a", text)])
    assert result.merged_text is not None
    assert "#define GC_NULL 0" in result.merged_text


def test_real_empty_include_guard_is_still_dropped():
    chunks = parse_header_chunks(DOUBLE_HEADER)
    assert not any("GNT4_SHIM_H" in c.text for c in chunks)


# --------------------------------- cross-root name collision (review R2)
# Adversarial-review finding: the same unit name present in BOTH roots
# (scheduled once T3 moves artifacts from staging to port-units) was selected
# twice; run_assembly_gate writes {name}.c per unit, so the newer artifact
# silently overwrote the older and was compiled TWICE while the older's code
# was absent from the tested composition.


def test_same_unit_name_in_both_roots_dedups_and_verified_root_wins(tmp_path):
    verified = tmp_path / "port-units"
    staging = tmp_path / "port-units-staging"
    _write_artifact(
        verified, "auto-x", "2026-08-01T00:00:00Z",
        unit_c="int fn_v(void)\n{\n  return 1;\n}\n",
    )
    _write_artifact(
        staging, "auto-x", "2026-08-15T00:00:00Z",
        unit_c="int fn_s(void)\n{\n  return 2;\n}\n",
    )
    snapshot = _canonical_snapshot(tmp_path, ["auto-x"])
    picked, _ = select_recent_green_units(
        [verified, staging], None, canonical_snapshot=snapshot
    )
    assert [u.name for u in picked] == ["auto-x"]
    # Authority rule: the earlier root in the list (the caller passes the
    # verified root first) wins over its staging copy -- even a NEWER one.
    assert picked[0].directory == verified / "auto-x"


def test_cross_root_duplicate_never_reaches_the_gate_twice(tmp_path):
    verified = tmp_path / "port-units"
    staging = tmp_path / "port-units-staging"
    _write_artifact(
        verified, "auto-x", "2026-08-01T00:00:00Z",
        unit_c="int fn_v(void)\n{\n  return 1;\n}\n", exports=["fn_v"],
    )
    _write_artifact(
        staging, "auto-x", "2026-08-15T00:00:00Z",
        unit_c="int fn_s(void)\n{\n  return 2;\n}\n", exports=["fn_s"],
    )
    _write_artifact(
        staging, "auto-y", "2026-08-16T00:00:00Z",
        unit_c="int fn_y(void)\n{\n  return 3;\n}\n", exports=["fn_y"],
    )
    snapshot = _canonical_snapshot(tmp_path, ["auto-x", "auto-y"])
    units, _ = select_recent_green_units(
        [verified, staging], None, canonical_snapshot=snapshot
    )
    linked = {}

    def fake_link(workdir, c_files, exports, allowed_extra):
        linked["c_files"] = list(c_files)
        (workdir / ASSEMBLY_WASM).write_bytes(b"\x00asm")
        return True, ""

    result = run_assembly_gate(units, tmp_path / "work", fake_link, None)
    assert result["passed"] is True
    assert sorted(linked["c_files"]) == ["auto-x.c", "auto-y.c"]
    # The verified artifact's code is what got compiled, not the staging copy.
    assert (tmp_path / "work" / "auto-x.c").read_text() == (
        "int fn_v(void)\n{\n  return 1;\n}\n"
    )


def test_gate_refuses_duplicate_unit_names_loudly(tmp_path):
    """Defense in depth: if a duplicate-name selection ever reaches the gate,
    it must refuse loudly, never overwrite one unit's .c with another's."""
    root_a = tmp_path / "a"
    root_b = tmp_path / "b"
    _write_artifact(root_a, "auto-x", "2026-08-01T00:00:00Z")
    _write_artifact(root_b, "auto-x", "2026-08-15T00:00:00Z")
    units = [load_unit_artifact(root_a / "auto-x"), load_unit_artifact(root_b / "auto-x")]
    assert all(unit is not None for unit in units)
    assert len(units) == 2  # deliberately bypassing selection-time dedup
    linked = []
    result = run_assembly_gate(
        units, tmp_path / "work", lambda *a: linked.append(a) or (True, ""), None
    )
    assert result["passed"] is False
    assert result["stage"] == "select"
    assert linked == []
    assert result["conflicts"] and result["conflicts"][0]["symbol"] == "auto-x"


# --------------------------------------------------------------- tool world
#
# Task 3 needs a production ToolWorld: the deep module only shipped
# ToolWorld.synthetic(), which cannot bind a real composition to the toolchain
# that produced it.

REPO_ROOT = Path(__file__).resolve().parents[1]


def _discover_product_root() -> Path:
    """Walk up until the emsdk toolchain appears.

    The OGhidra checkout sits at <product>/research/tools/OGhidra, but review
    worktrees live at <product>/.tmp/<name>, so a fixed parents[n] index
    silently skips these tests in exactly the tree they are meant to guard.
    """
    probe = "research/tools/emsdk/upstream/bin/clang.exe"
    for candidate in (REPO_ROOT, *REPO_ROOT.parents):
        if (candidate / probe).is_file():
            return candidate
    return REPO_ROOT


PRODUCT_ROOT = _discover_product_root()


def _tool_world_kwargs(smoke_script: Path, **overrides):
    kwargs = dict(
        compile_argv=(("clang", "-c", "unit.c"),),
        inspect_argv=(("llvm-nm", "unit.o"),),
        link_argv=("wasm-ld", "-o", "assembly.wasm"),
        instantiate_argv=("node", "instantiate.cjs"),
        smoke_argv=("node", "assembly-smoke.cjs"),
        smoke_script=smoke_script,
    )
    kwargs.update(overrides)
    return kwargs


@pytest.fixture
def smoke_script(tmp_path: Path) -> Path:
    path = tmp_path / "assembly-smoke.cjs"
    path.write_text('console.log("smoke");\n', encoding="utf-8")
    return path


def _product_root_available() -> bool:
    from src.port_assembly_gate import _EMSCRIPTEN_VERSION_RELPATH, _TOOL_RELPATHS

    return all((PRODUCT_ROOT / rel).is_file() for rel in _TOOL_RELPATHS.values()) and (
        PRODUCT_ROOT / _EMSCRIPTEN_VERSION_RELPATH
    ).is_file()


requires_toolchain = pytest.mark.skipif(
    not _product_root_available(), reason="emsdk toolchain not present in this checkout"
)


@requires_toolchain
def test_tool_world_binds_every_role_to_the_real_toolchain(smoke_script: Path):
    from src.port_assembly_abi import _validate_tool_world
    from src.port_assembly_gate import build_tool_world

    world = build_tool_world(PRODUCT_ROOT, **_tool_world_kwargs(smoke_script))
    _validate_tool_world(world)
    assert tuple(item.role for item in world.identities) == (
        "clang",
        "emcc",
        "node",
        "object-inspector",
        "smoke-script",
        "wasm-ld",
    )
    for item in world.identities:
        assert Path(item.resolved_path).is_file()
        assert len(item.file_sha256) == 64 and len(item.version_sha256) == 64
    # emcc.exe cannot answer --version without emsdk_env, so its version
    # identity comes from emscripten-version.txt; it must NOT silently fall
    # back to the file digest, which would not move on an in-place upgrade.
    emcc = next(item for item in world.identities if item.role == "emcc")
    assert emcc.version_sha256 != emcc.file_sha256
    # The smoke script has no version to interrogate; both identities are its
    # own bytes, which is exactly what changes when it is regenerated.
    script = next(item for item in world.identities if item.role == "smoke-script")
    assert script.version_sha256 == script.file_sha256


@requires_toolchain
def test_tool_world_digest_moves_when_the_smoke_script_changes(smoke_script: Path):
    from src.port_assembly_gate import build_tool_world

    before = build_tool_world(PRODUCT_ROOT, **_tool_world_kwargs(smoke_script))
    smoke_script.write_text('console.log("smoke2");\n', encoding="utf-8")
    after = build_tool_world(PRODUCT_ROOT, **_tool_world_kwargs(smoke_script))
    assert before.tool_world_sha256 != after.tool_world_sha256


@requires_toolchain
def test_tool_world_sorts_environment_regardless_of_input_order(smoke_script: Path):
    from src.port_assembly_gate import build_tool_world

    world = build_tool_world(
        PRODUCT_ROOT,
        **_tool_world_kwargs(
            smoke_script, environment=(("PATH", "b" * 64), ("EMSDK", "a" * 64))
        ),
    )
    assert tuple(name for name, _ in world.environment) == ("EMSDK", "PATH")


def test_tool_world_refuses_a_missing_smoke_script(tmp_path: Path):
    from src.port_assembly_abi import AssemblyAbiError
    from src.port_assembly_gate import build_tool_world

    if not _product_root_available():
        pytest.skip("emsdk toolchain not present in this checkout")
    with pytest.raises(AssemblyAbiError) as caught:
        build_tool_world(
            PRODUCT_ROOT, **_tool_world_kwargs(tmp_path / "absent.cjs")
        )
    assert caught.value.refusal.code == "tool_world_unresolvable"


def test_tool_world_refuses_a_root_without_the_toolchain(tmp_path: Path, smoke_script: Path):
    from src.port_assembly_abi import AssemblyAbiError
    from src.port_assembly_gate import build_tool_world

    with pytest.raises(AssemblyAbiError) as caught:
        build_tool_world(tmp_path, **_tool_world_kwargs(smoke_script))
    assert caught.value.refusal.code == "tool_world_unresolvable"


@pytest.mark.parametrize("count", [0, 2])
def test_resolve_node_refuses_zero_or_several_pinned_nodes(tmp_path: Path, count: int):
    from src.port_assembly_abi import AssemblyAbiError
    from src.port_assembly_gate import resolve_node_executable

    for index in range(count):
        node_dir = tmp_path / "research/tools/emsdk/node" / f"2{index}.0.0_64bit"
        node_dir.mkdir(parents=True)
        (node_dir / "node.exe").write_bytes(b"stub")
    with pytest.raises(AssemblyAbiError) as caught:
        resolve_node_executable(tmp_path)
    assert caught.value.refusal.code == "tool_world_unresolvable"


# ----------------------------------------------------------- assembly bundle

STAGING_ROOT = PRODUCT_ROOT / "research/decomp/port-units-staging"


def _staged_unit(name: str):
    from src.port_assembly_gate import UnitArtifact

    directory = STAGING_ROOT / name
    provenance = json.loads((directory / "provenance.json").read_text(encoding="utf-8-sig"))
    return UnitArtifact(
        name,
        directory,
        "a" * 64,
        provenance.get("generated_at", ""),
        provenance.get("exported_functions") or [],
        provenance.get("allowed_extra_imports") or [],
        provenance.get("tier", "compile_only"),
    )


# The exact five-artifact window from the 2026-08-21 RCA, whose link failed
# with `wasm-ld: error: function signature mismatch: zz_00076d0_`.
RCA_C0035_WINDOW = (
    "auto-c0011-010",
    "auto-c0034-018",
    "auto-c0035-002",
    "auto-c0029-013",
    "auto-c0035-006",
)

requires_staging = pytest.mark.skipif(
    not all((STAGING_ROOT / name / "unit.c").is_file() for name in RCA_C0035_WINDOW),
    reason="staged RCA window not present in this checkout",
)


def _build(units, candidate_name: str, smoke_script: Path, **overrides):
    from src.port_assembly_gate import build_assembly_bundle

    kwargs = dict(
        candidate_name=candidate_name,
        repo_root=PRODUCT_ROOT,
        attempt=1,
        behavior_tier="compile_only",
        smoke_script=smoke_script,
    )
    kwargs.update(overrides)
    return build_assembly_bundle(units, **kwargs)


@requires_toolchain
@requires_staging
def test_bundle_from_the_rca_window_satisfies_the_deep_module(smoke_script: Path):
    from src.port_assembly_abi import _bundle_candidate, _bundle_window, _validate_bundle

    units = [_staged_unit(name) for name in RCA_C0035_WINDOW]
    bundle = _build(units, "auto-c0035-006", smoke_script)

    assert _validate_bundle(bundle) is None
    assert [item.ordinal for item in bundle.translation_units] == [0, 1, 2, 3, 4]
    roles = [item.role for item in bundle.translation_units]
    assert roles.count("candidate") == 1
    assert bundle.translation_units[-1].unit == "auto-c0035-006"
    assert bundle.translation_units[-1].role == "candidate"
    # Each unit compiles from its own directory so its verbatim
    # `#include "gnt4_shim.h"` resolves to its own derived header.
    for item in bundle.translation_units:
        assert item.source_relpath == f"{item.unit}/unit.c"
        assert item.header_relpath == f"{item.unit}/gnt4_shim.h"
        assert item.object_relpath == f"{item.unit}/unit.o"
    # The validator requires the world's compile argv to equal the plan's, in
    # order; a mismatch means the composition is not bound to its own compiles.
    assert bundle.tool_world.compile_argv == tuple(
        item.compile_argv for item in bundle.translation_units
    )
    assert len(bundle.tool_world.inspect_argv) == len(bundle.translation_units)
    assert _bundle_candidate(bundle).artifact_relpath == "auto-c0035-006/unit.c"
    assert len(_bundle_window(bundle)) == 5


@requires_toolchain
@requires_staging
def test_bundle_binds_the_exact_staged_bytes(smoke_script: Path):
    import hashlib

    units = [_staged_unit(name) for name in RCA_C0035_WINDOW]
    bundle = _build(units, "auto-c0035-006", smoke_script)
    for item in bundle.translation_units:
        on_disk = (STAGING_ROOT / item.unit / "unit.c").read_bytes()
        assert item.source == on_disk
        assert item.source_sha256 == hashlib.sha256(on_disk).hexdigest()


@requires_toolchain
@requires_staging
@pytest.mark.parametrize(
    ("mutation", "detail"),
    [
        ("empty", "at least one unit"),
        ("duplicate", "unique unit names"),
        ("absent_candidate", "exactly once"),
        # A repeated candidate is a repeated NAME, and the uniqueness check
        # runs first. Pinning that precedence keeps the refusal deterministic.
        ("repeated_candidate", "unique unit names"),
    ],
)
def test_bundle_refuses_malformed_windows(smoke_script: Path, mutation: str, detail: str):
    from src.port_assembly_abi import AssemblyAbiError

    units = [_staged_unit(name) for name in RCA_C0035_WINDOW]
    candidate = "auto-c0035-006"
    if mutation == "empty":
        units = []
    elif mutation == "duplicate":
        units = [*units, _staged_unit("auto-c0034-018")]
    elif mutation == "absent_candidate":
        candidate = "auto-c9999-999"
    else:
        units = [*units, _staged_unit("auto-c0035-006")]
    with pytest.raises(AssemblyAbiError) as caught:
        _build(units, candidate, smoke_script)
    assert caught.value.refusal.code == "tool_world_unresolvable"
    assert detail in caught.value.refusal.detail


@requires_toolchain
def test_bundle_refuses_an_unreadable_artifact(tmp_path: Path, smoke_script: Path):
    from src.port_assembly_abi import AssemblyAbiError
    from src.port_assembly_gate import UnitArtifact

    unit = UnitArtifact("auto-c0000-000", tmp_path / "absent", "a" * 64, "", [], [], "compile_only")
    with pytest.raises(AssemblyAbiError) as caught:
        _build([unit], "auto-c0000-000", smoke_script)
    assert caught.value.refusal.code == "tool_world_unresolvable"
    assert "cannot read" in caught.value.refusal.detail


# ------------------------------------------------- canonicalization wiring
#
# These exercise the opt-in owner-derived path end to end against a synthetic
# owner snapshot, so they run without the real schema-1 product registry.

from tests.test_port_assembly_abi import FakeParser, _write_product  # noqa: E402


def _synthetic_snapshot(root: Path):
    """A synthetic owner registry parsed by the REAL pinned Clang.

    The deep module refuses (`parser_tool_identity_mismatch`) unless the parser
    that produced the owner snapshot is byte-identical to the ToolWorld's clang
    identity -- the ABI evidence has to come from the same compiler that
    compiles the bundle. So the registry may be synthetic, but the parser
    cannot be.
    """
    import src.port_assembly_abi as abi

    parser = abi.ClangDeclaratorParser.from_product_root(PRODUCT_ROOT)
    registry_path, _ = _write_product(root.resolve(), parser=parser)
    return abi.load_owner_snapshot(root.resolve(), registry_path, parser)


OWNED_SYMBOL = "zz_00262b4_"
OWNER_PROTOTYPE = f"void {OWNED_SYMBOL}(int value);"


def _write_unit(directory: Path, name: str, declaration: str, body: str | None = None) -> None:
    """One staged-shaped unit that declares OWNED_SYMBOL its own way.

    No include guard. A declaration site's span walks back to the previous
    statement terminator, so the FIRST declaration in a container swallows any
    leading preprocessor directives and the dialect preflight refuses them.
    Real staged headers do lead with directives; see the open question in
    assembly-abi-resume-status.md.
    """
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "gnt4_shim.h").write_text(
        declaration + "\n", encoding="utf-8", newline="\n"
    )
    statement = body if body is not None else OWNED_SYMBOL + "(1);"
    (directory / "unit.c").write_text(
        "void " + name.replace("-", "_") + "(void) { " + statement + " }\n",
        encoding="utf-8",
        newline="\n",
    )


def _artifact(directory: Path, name: str):
    from src.port_assembly_gate import UnitArtifact, unit_artifact_sha256

    return UnitArtifact(
        name, directory, unit_artifact_sha256(directory), "", [], [], "compile_only"
    )


@requires_toolchain
def test_canonicalization_replaces_a_compatible_variant_and_links(
    tmp_path: Path, smoke_script: Path
):
    """Two units spell a compatible declaration differently.

    The registry-less merge calls that a contested conflict on text alone.
    Owner-derived canonicalization proves the pair compatible with Clang and
    replaces both with the one owner prototype, so the window reaches the
    linker with a single ABI.
    """
    from src.port_assembly_gate import (
        CanonicalizationRequest,
        merge_headers,
        run_assembly_gate,
    )

    snapshot = _synthetic_snapshot(tmp_path / "product")

    staging = tmp_path / "staging"
    # A top-level parameter qualifier does not change the function type in C,
    # so Clang calls these compatible -- but the text merge sees two different
    # declarations. Parameter NAMES alone would not do: the merge already
    # normalises those away.
    _write_unit(staging / "unit-a", "unit-a", f"extern void {OWNED_SYMBOL}(int value);")
    _write_unit(
        staging / "unit-b", "unit-b", f"extern void {OWNED_SYMBOL}(const int value);"
    )
    units = [
        _artifact(staging / "unit-a", "unit-a"),
        _artifact(staging / "unit-b", "unit-b"),
    ]

    # Baseline: the current registry-less merge refuses this exact shape.
    headers = [
        (unit.name, (unit.directory / "gnt4_shim.h").read_text(encoding="utf-8-sig"))
        for unit in units
    ]
    assert merge_headers(headers).merged_text is None

    linked: dict[str, Any] = {}

    def link_runner(workdir, c_files, exports, allowed_extra):
        linked["c_files"] = list(c_files)
        return True, ""

    result = run_assembly_gate(
        units,
        tmp_path / "work",
        link_runner=link_runner,
        candidate=units[-1],
        canonicalization=CanonicalizationRequest(
            repo_root=PRODUCT_ROOT,
            owner_snapshot=snapshot,
            attempt=1,
            behavior_tier="compile_only",
            smoke_script=smoke_script,
        ),
    )

    assert result["passed"] is True, result["detail"]
    assert result["stage"] == "pass"
    assert result["conflicts"] == []
    assert sorted(linked["c_files"]) == ["unit-a/unit.c", "unit-b/unit.c"]
    for name in ("unit-a", "unit-b"):
        header = (tmp_path / "work" / name / "gnt4_shim.h").read_text(encoding="utf-8")
        assert OWNED_SYMBOL in header
    evidence = result["canonicalization"]
    assert evidence["behavior_claim"] is None
    assert len(evidence["receipt_sha256"]) == 64
    assert any(item["symbol"] == OWNED_SYMBOL for item in evidence["owners"])
    assert evidence["compatibility_checks"]


@requires_toolchain
def test_generic_placeholder_is_superseded_not_contested(
    tmp_path: Path, smoke_script: Path
):
    """Ghidra's `extern int NAME();` is the absence of a claim, not a rival one.

    Clang calls `int f()` incompatible with a `void f(int)`, so probing the
    placeholder contests the window. Measured on the staged corpus, 201 of 239
    owner-symbol declaration variants are exactly this shape -- probing them
    fails closed on 84% of windows instead of resolving them. The unique
    verified owner supersedes it instead.
    """
    from src.port_assembly_gate import CanonicalizationRequest, run_assembly_gate

    snapshot = _synthetic_snapshot(tmp_path / "product")
    staging = tmp_path / "staging"
    _write_unit(staging / "unit-a", "unit-a", f"extern int {OWNED_SYMBOL}();")
    _write_unit(staging / "unit-b", "unit-b", f"extern void {OWNED_SYMBOL}(int value);")
    units = [
        _artifact(staging / "unit-a", "unit-a"),
        _artifact(staging / "unit-b", "unit-b"),
    ]

    linked: dict[str, Any] = {}

    def link_runner(workdir, c_files, exports, allowed_extra):
        linked["c_files"] = list(c_files)
        return True, ""

    result = run_assembly_gate(
        units,
        tmp_path / "work",
        link_runner=link_runner,
        candidate=units[-1],
        canonicalization=CanonicalizationRequest(
            repo_root=PRODUCT_ROOT,
            owner_snapshot=snapshot,
            attempt=1,
            behavior_tier="compile_only",
            smoke_script=smoke_script,
        ),
    )

    assert result["passed"] is True, result["detail"]
    assert result["conflicts"] == []
    header = (tmp_path / "work" / "unit-a" / "gnt4_shim.h").read_text(encoding="utf-8")
    assert f"extern int {OWNED_SYMBOL}();" not in header
    assert OWNED_SYMBOL in header
    # The placeholder is recorded as discarded, and no probe is fabricated for it.
    evidence = result["canonicalization"]
    assert any(item["symbol"] == OWNED_SYMBOL for item in evidence["discarded_variants"])


@requires_toolchain
def test_consuming_body_resolves_against_an_imported_owner(
    tmp_path: Path, smoke_script: Path
):
    """Owner typed `void`, body consumes the result, owner NOT linked in.

    Substituting the void owner would turn `x = f(...)` into a compile error and
    the body is verbatim. Because the owner is an import, only the bundle's
    declarations have to agree, so the owner's parameters are kept with a
    value-returning result and the window resolves.
    """
    from src.port_assembly_gate import CanonicalizationRequest, run_assembly_gate

    snapshot = _synthetic_snapshot(tmp_path / "product")
    staging = tmp_path / "staging"
    _write_unit(
        staging / "unit-a",
        "unit-a",
        f"extern int {OWNED_SYMBOL}();",
        body=f"int taken = {OWNED_SYMBOL}(1); (void)taken;",
    )
    _write_unit(staging / "unit-b", "unit-b", f"extern int {OWNED_SYMBOL}();")
    units = [
        _artifact(staging / "unit-a", "unit-a"),
        _artifact(staging / "unit-b", "unit-b"),
    ]

    linked: dict[str, Any] = {}

    def link_runner(workdir, c_files, exports, allowed_extra):
        linked["ok"] = True
        return True, ""

    result = run_assembly_gate(
        units,
        tmp_path / "work",
        link_runner=link_runner,
        candidate=units[-1],
        canonicalization=CanonicalizationRequest(
            repo_root=PRODUCT_ROOT,
            owner_snapshot=snapshot,
            attempt=1,
            behavior_tier="compile_only",
            smoke_script=smoke_script,
        ),
    )

    assert result["passed"] is True, result["detail"]
    assert linked.get("ok") is True
    header = (tmp_path / "work" / "unit-a" / "gnt4_shim.h").read_text(encoding="utf-8")
    # value-returning, and carrying the owner's parameter list
    assert f"int {OWNED_SYMBOL}(" in header
    assert f"void {OWNED_SYMBOL}(" not in header


@requires_toolchain
def test_consuming_body_is_contested_when_the_owner_is_linked_in(
    tmp_path: Path, smoke_script: Path
):
    """Same shape, but the owner's own unit is IN the bundle.

    Now the definition is being linked, so its `void` result is binding and the
    consuming body is a genuine contradiction. The gate must stop before compile
    rather than invent a return type that disagrees with the definition it is
    about to link.
    """
    from src.port_assembly_gate import (
        CLASS_CANONICALIZATION_REFUSED,
        CanonicalizationRequest,
        run_assembly_gate,
    )

    snapshot = _synthetic_snapshot(tmp_path / "product")
    owner_unit = snapshot.owner_index[OWNED_SYMBOL][0].unit
    staging = tmp_path / "staging"
    _write_unit(
        staging / "unit-a",
        "unit-a",
        f"extern int {OWNED_SYMBOL}();",
        body=f"int taken = {OWNED_SYMBOL}(1); (void)taken;",
    )
    _write_unit(staging / owner_unit, owner_unit, f"extern int {OWNED_SYMBOL}();")
    units = [
        _artifact(staging / "unit-a", "unit-a"),
        _artifact(staging / owner_unit, owner_unit),
    ]

    def link_runner(workdir, c_files, exports, allowed_extra):
        raise AssertionError("a contested window must never reach the linker")

    result = run_assembly_gate(
        units,
        tmp_path / "work",
        link_runner=link_runner,
        candidate=units[-1],
        canonicalization=CanonicalizationRequest(
            repo_root=PRODUCT_ROOT,
            owner_snapshot=snapshot,
            attempt=1,
            behavior_tier="compile_only",
            smoke_script=smoke_script,
        ),
    )

    assert result["passed"] is False
    assert result["stage"] == "canonicalize"
    assert result["conflicts"][0]["class"] == CLASS_CANONICALIZATION_REFUSED


@requires_toolchain
def test_canonicalization_refusal_is_contested_and_writes_nothing(
    tmp_path: Path, smoke_script: Path
):
    """An owner-eligible callee with no owner must stop before compiling.

    The symbol has to match the internal shape (`zz_` + exactly seven hex
    digits); an eight-digit name is not owner-eligible at all and would simply
    pass through uncanonicalized.
    """
    from src.port_assembly_gate import (
        CLASS_CANONICALIZATION_REFUSED,
        CanonicalizationRequest,
        run_assembly_gate,
    )

    product = tmp_path / "product"
    snapshot = _synthetic_snapshot(product)

    staging = tmp_path / "staging"
    for name in ("unit-a", "unit-b"):
        directory = staging / name
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "gnt4_shim.h").write_text(
            "#ifndef GNT4_SHIM_H\n#define GNT4_SHIM_H\n"
            "extern int zz_0fffff0_();\n#endif\n",
            encoding="utf-8",
            newline="\n",
        )
        (directory / "unit.c").write_text(
            '#include "gnt4_shim.h"\n\n'
            f'void {name.replace("-", "_")}(void) {{ zz_0fffff0_(1); }}\n',
            encoding="utf-8",
            newline="\n",
        )
    units = [_artifact(staging / name, name) for name in ("unit-a", "unit-b")]

    def link_runner(workdir, c_files, exports, allowed_extra):
        raise AssertionError("a contested window must never reach the linker")

    workdir = tmp_path / "work"
    result = run_assembly_gate(
        units,
        workdir,
        link_runner=link_runner,
        candidate=units[-1],
        canonicalization=CanonicalizationRequest(
            repo_root=PRODUCT_ROOT,
            owner_snapshot=snapshot,
            attempt=1,
            behavior_tier="compile_only",
            smoke_script=smoke_script,
        ),
    )

    assert result["passed"] is False
    assert result["stage"] == "canonicalize"
    assert result["conflicts"]
    assert result["conflicts"][0]["class"] == CLASS_CANONICALIZATION_REFUSED
    # No partial canonical bundle survives a refusal.
    assert not (workdir / "unit-a").exists()
    assert not (workdir / "unit-b").exists()


@requires_toolchain
def test_omitting_canonicalization_leaves_the_merge_path_unchanged(tmp_path: Path):
    """The live gate must not change behaviour until the driver opts in."""
    from src.port_assembly_gate import run_assembly_gate

    staging = tmp_path / "staging"
    _write_unit(staging / "unit-a", "unit-a", f"extern int {OWNED_SYMBOL}();")
    _write_unit(
        staging / "unit-b", "unit-b", f"extern void {OWNED_SYMBOL}(int param_1);"
    )
    units = [
        _artifact(staging / "unit-a", "unit-a"),
        _artifact(staging / "unit-b", "unit-b"),
    ]

    def link_runner(workdir, c_files, exports, allowed_extra):
        raise AssertionError("the merge must refuse before linking")

    result = run_assembly_gate(
        units, tmp_path / "work", link_runner=link_runner, candidate=units[-1]
    )
    assert result["passed"] is False
    assert result["stage"] == "merge"
    assert result["conflicts"]
    assert "canonicalization" not in result


# ------------------------------------------- header must declare, never define


SEED_HEADER = (
    "static inline uint countLeadingZeros(int x) { return x; }\n"
    "extern int zz_00076d0_();\n"
    "typedef unsigned char undefined1;\n"
)


@pytest.mark.parametrize(
    ("header", "expected"),
    [
        (SEED_HEADER, []),
        # The model's shortcut to make a unit link: define the callee it is
        # missing. That creates a real symbol and replaces the ROM function.
        (SEED_HEADER + "void FUN_801336a4(void) { }\n", ["FUN_801336a4"]),
        ("static inline int helper(int x) { return x; }\n", []),
        ("static void h(void) { }\n", []),
        # `static` must match as a whole word, not a prefix.
        ("void staticky(void) { }\n", ["staticky"]),
        ("extern int zz_00076d0_();\n", []),
        ("void a1(void) { }\nint b2(int x) { return x; }\n", ["a1", "b2"]),
    ],
)
def test_header_defines_external_functions(header: str, expected: list[str]):
    from src.port_assembly_gate import header_defines_external_functions

    assert header_defines_external_functions(header) == expected


def test_the_real_seed_header_defines_nothing_external():
    """The shipped seed carries two `static inline` helpers and must pass."""
    from src.port_assembly_gate import header_defines_external_functions

    seed = (
        PRODUCT_ROOT
        / "research/decomp/generated/finish-game-port/gnt4_shim_seed.h"
    )
    if not seed.is_file():
        pytest.skip("seed header not present in this checkout")
    assert header_defines_external_functions(seed.read_text(encoding="utf-8-sig")) == []


# ------------------------------------------- SDK (gnt4_*) canonicalization
#
# The gate canonicalizes ROM symbols against the owner registry, but
# _EXTERNAL_PREFIXES kept gnt4_* out entirely: after the canon seed flipped
# gnt4_PSQUATScale_bl (and friends) from `void` to `undefined8` returns, every
# staged green baselined on the old seed contested every new candidate at
# wasm-ld ("function signature mismatch: ... ->void vs ->i64"). These exercise
# the gate-time unification against a FRESH seed read, with the real pinned
# Clang validating canon/variant pairs.

SDK_SYMBOL = "gnt4_PSQUATScale_bl"
SDK_CANON_DECL = f"extern undefined8 {SDK_SYMBOL}(double s, float *v, float *out);"
SDK_STALE_DECL = f"extern void   {SDK_SYMBOL}(double s, float *v, float *out);"
SDK_VOID_SYMBOL = "gnt4_VoidRet_bl"
SDK_VOID_CANON_DECL = f"extern void {SDK_VOID_SYMBOL}(int a);"


def _write_sdk_seed(path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "#ifndef GNT4_SHIM_SEED_H\n"
        "#define GNT4_SHIM_SEED_H\n"
        "typedef unsigned long long undefined8;\n"
        f"{SDK_CANON_DECL}\n"
        f"{SDK_VOID_CANON_DECL}\n"
        "#endif\n",
        encoding="utf-8",
        newline="\n",
    )
    return path


def _sdk_request(snapshot, smoke_script: Path, seed: Path):
    from src.port_assembly_gate import CanonicalizationRequest

    return CanonicalizationRequest(
        repo_root=PRODUCT_ROOT,
        owner_snapshot=snapshot,
        attempt=1,
        behavior_tier="compile_only",
        smoke_script=smoke_script,
        sdk_seed_path=seed,
    )


@requires_toolchain
def test_stale_void_sdk_declaration_is_unified_to_the_fresh_canon(
    tmp_path: Path, smoke_script: Path
):
    """The exact outage shape: a window green baselined on the old seed
    declares `void gnt4_PSQUATScale_bl(...)` while the candidate carries the
    current `undefined8` canon. Both derived headers must reach the linker
    with the canon prototype (one wasm signature), owner (ROM) symbols must
    keep canonicalizing exactly as before, and no SDK evidence may leak into
    the receipt's owner-bound compatibility checks.
    """
    import re as _re

    from src.port_assembly_gate import run_assembly_gate

    snapshot = _synthetic_snapshot(tmp_path / "product")
    seed = _write_sdk_seed(tmp_path / "product-seed" / "gnt4_shim_seed.h")
    staging = tmp_path / "staging"
    # Window unit: stale seed baseline. Its body CALLS the symbol in statement
    # position (result discarded), which is why the void declaration compiled
    # green in isolation.
    _write_unit(
        staging / "unit-a",
        "unit-a",
        f"extern void {OWNED_SYMBOL}(int value);\n" + SDK_STALE_DECL,
        body=f"{OWNED_SYMBOL}(1); {SDK_SYMBOL}(1.0, 0, 0);",
    )
    # Candidate: current canon, plus a top-level-qualifier owner variant so
    # the pre-existing owner probe path runs in the same window.
    _write_unit(
        staging / "unit-b",
        "unit-b",
        f"extern void {OWNED_SYMBOL}(const int value);\n" + SDK_CANON_DECL,
    )
    units = [
        _artifact(staging / "unit-a", "unit-a"),
        _artifact(staging / "unit-b", "unit-b"),
    ]

    linked: dict[str, Any] = {}

    def link_runner(workdir, c_files, exports, allowed_extra):
        linked["c_files"] = list(c_files)
        return True, ""

    result = run_assembly_gate(
        units,
        tmp_path / "work",
        link_runner=link_runner,
        candidate=units[-1],
        canonicalization=_sdk_request(snapshot, smoke_script, seed),
    )

    assert result["passed"] is True, result["detail"]
    assert result["conflicts"] == []
    canon_normal = " ".join(SDK_CANON_DECL.split())
    for name in ("unit-a", "unit-b"):
        header = (tmp_path / "work" / name / "gnt4_shim.h").read_text(encoding="utf-8")
        assert canon_normal in header
        assert _re.search(rf"void\s+{SDK_SYMBOL}", header) is None
        assert OWNED_SYMBOL in header  # owner path still canonicalizes
    evidence = result["canonicalization"]
    assert evidence["sdk_canon"]["declarations"] == 2
    assert evidence["sdk_canon"]["seed_path"] == str(seed)
    assert any(item["symbol"] == SDK_SYMBOL for item in evidence["discarded_variants"])
    # SDK pairs are validated but never recorded as owner-bound evidence.
    assert all(
        item["symbol"] == OWNED_SYMBOL for item in evidence["compatibility_checks"]
    )


@requires_toolchain
def test_sdk_parameter_class_divergence_refuses_loudly(
    tmp_path: Path, smoke_script: Path
):
    """A gnt4_* declaration whose PARAMETERS disagree with the canon beyond
    spelling is a real contradiction: Clang rejects the pair and the gate
    stops before compile with `sdk_variant_abi_incompatible`, surfaced exactly
    like `owner_variant_abi_incompatible`.
    """
    from src.port_assembly_gate import (
        CLASS_CANONICALIZATION_REFUSED,
        run_assembly_gate,
    )

    snapshot = _synthetic_snapshot(tmp_path / "product")
    seed = _write_sdk_seed(tmp_path / "product-seed" / "gnt4_shim_seed.h")
    staging = tmp_path / "staging"
    _write_unit(
        staging / "unit-a",
        "unit-a",
        f"extern void {SDK_SYMBOL}(int a);",
        body=f"{SDK_SYMBOL}(1);",
    )
    _write_unit(
        staging / "unit-b",
        "unit-b",
        SDK_CANON_DECL,
        body=f"{SDK_SYMBOL}(1.0, 0, 0);",
    )
    units = [
        _artifact(staging / "unit-a", "unit-a"),
        _artifact(staging / "unit-b", "unit-b"),
    ]

    def link_runner(workdir, c_files, exports, allowed_extra):
        raise AssertionError("a contested window must never reach the linker")

    result = run_assembly_gate(
        units,
        tmp_path / "work",
        link_runner=link_runner,
        candidate=units[-1],
        canonicalization=_sdk_request(snapshot, smoke_script, seed),
    )

    assert result["passed"] is False
    assert result["stage"] == "canonicalize"
    assert result["conflicts"][0]["class"] == CLASS_CANONICALIZATION_REFUSED
    assert result["conflicts"][0]["symbol"] == SDK_SYMBOL
    assert "sdk_variant_abi_incompatible" in result["detail"]


@requires_toolchain
def test_sdk_symbol_absent_from_canon_is_untouched(
    tmp_path: Path, smoke_script: Path
):
    from src.port_assembly_gate import run_assembly_gate

    snapshot = _synthetic_snapshot(tmp_path / "product")
    seed = _write_sdk_seed(tmp_path / "product-seed" / "gnt4_shim_seed.h")
    staging = tmp_path / "staging"
    absent = "extern void gnt4_NotInSeed_bl(int a);"
    _write_unit(
        staging / "unit-a",
        "unit-a",
        absent,
        body="gnt4_NotInSeed_bl(1);",
    )
    _write_unit(
        staging / "unit-b",
        "unit-b",
        SDK_CANON_DECL,
        body=f"{SDK_SYMBOL}(1.0, 0, 0);",
    )
    units = [
        _artifact(staging / "unit-a", "unit-a"),
        _artifact(staging / "unit-b", "unit-b"),
    ]

    def link_runner(workdir, c_files, exports, allowed_extra):
        return True, ""

    result = run_assembly_gate(
        units,
        tmp_path / "work",
        link_runner=link_runner,
        candidate=units[-1],
        canonicalization=_sdk_request(snapshot, smoke_script, seed),
    )

    assert result["passed"] is True, result["detail"]
    header = (tmp_path / "work" / "unit-a" / "gnt4_shim.h").read_text(encoding="utf-8")
    assert absent in header  # byte-for-byte: no canon exists, no rewrite


@requires_toolchain
def test_sdk_consuming_call_under_a_void_canon_refuses(
    tmp_path: Path, smoke_script: Path
):
    """The unsafe direction: the caller declared a value and CONSUMES it, but
    the canon says void. Rewriting would miscompile or silently reinterpret,
    so the gate must refuse, not unify.
    """
    from src.port_assembly_gate import (
        CLASS_CANONICALIZATION_REFUSED,
        run_assembly_gate,
    )

    snapshot = _synthetic_snapshot(tmp_path / "product")
    seed = _write_sdk_seed(tmp_path / "product-seed" / "gnt4_shim_seed.h")
    staging = tmp_path / "staging"
    _write_unit(
        staging / "unit-a",
        "unit-a",
        f"extern undefined8 {SDK_VOID_SYMBOL}(int a);",
        body=f"int taken = {SDK_VOID_SYMBOL}(1); (void)taken;",
    )
    _write_unit(
        staging / "unit-b",
        "unit-b",
        SDK_VOID_CANON_DECL,
        body=f"{SDK_VOID_SYMBOL}(2);",
    )
    units = [
        _artifact(staging / "unit-a", "unit-a"),
        _artifact(staging / "unit-b", "unit-b"),
    ]

    def link_runner(workdir, c_files, exports, allowed_extra):
        raise AssertionError("a contested window must never reach the linker")

    result = run_assembly_gate(
        units,
        tmp_path / "work",
        link_runner=link_runner,
        candidate=units[-1],
        canonicalization=_sdk_request(snapshot, smoke_script, seed),
    )

    assert result["passed"] is False
    assert result["stage"] == "canonicalize"
    assert result["conflicts"][0]["class"] == CLASS_CANONICALIZATION_REFUSED
    assert result["conflicts"][0]["symbol"] == SDK_VOID_SYMBOL
    assert "sdk_variant_abi_incompatible" in result["detail"]


@requires_toolchain
def test_sdk_discarded_result_unifies_to_a_void_canon(
    tmp_path: Path, smoke_script: Path
):
    """Same divergence, but every call in the bundle discards the result, so
    unifying to the void canon cannot change any call site's meaning."""
    import re as _re

    from src.port_assembly_gate import run_assembly_gate

    snapshot = _synthetic_snapshot(tmp_path / "product")
    seed = _write_sdk_seed(tmp_path / "product-seed" / "gnt4_shim_seed.h")
    staging = tmp_path / "staging"
    _write_unit(
        staging / "unit-a",
        "unit-a",
        f"extern undefined8 {SDK_VOID_SYMBOL}(int a);",
        body=f"{SDK_VOID_SYMBOL}(1);",
    )
    _write_unit(
        staging / "unit-b",
        "unit-b",
        SDK_VOID_CANON_DECL,
        body=f"{SDK_VOID_SYMBOL}(2);",
    )
    units = [
        _artifact(staging / "unit-a", "unit-a"),
        _artifact(staging / "unit-b", "unit-b"),
    ]

    def link_runner(workdir, c_files, exports, allowed_extra):
        return True, ""

    result = run_assembly_gate(
        units,
        tmp_path / "work",
        link_runner=link_runner,
        candidate=units[-1],
        canonicalization=_sdk_request(snapshot, smoke_script, seed),
    )

    assert result["passed"] is True, result["detail"]
    header = (tmp_path / "work" / "unit-a" / "gnt4_shim.h").read_text(encoding="utf-8")
    assert " ".join(SDK_VOID_CANON_DECL.split()) in header
    assert _re.search(rf"undefined8\s+{SDK_VOID_SYMBOL}", header) is None


@requires_toolchain
def test_sdk_placeholder_under_a_consumed_void_canon_refuses_without_a_probe(
    tmp_path: Path, smoke_script: Path
):
    """Ghidra's `extern int NAME();` placeholder claims nothing, but when the
    canon returns void and a body consumes the call there is no import-safe
    fallback: the canon IS the import contract. Refuse loudly."""
    from src.port_assembly_gate import (
        CLASS_CANONICALIZATION_REFUSED,
        run_assembly_gate,
    )

    snapshot = _synthetic_snapshot(tmp_path / "product")
    seed = _write_sdk_seed(tmp_path / "product-seed" / "gnt4_shim_seed.h")
    staging = tmp_path / "staging"
    _write_unit(
        staging / "unit-a",
        "unit-a",
        f"extern int {SDK_VOID_SYMBOL}();",
        body=f"int taken = {SDK_VOID_SYMBOL}(1); (void)taken;",
    )
    _write_unit(
        staging / "unit-b",
        "unit-b",
        SDK_VOID_CANON_DECL,
        body=f"{SDK_VOID_SYMBOL}(2);",
    )
    units = [
        _artifact(staging / "unit-a", "unit-a"),
        _artifact(staging / "unit-b", "unit-b"),
    ]

    def link_runner(workdir, c_files, exports, allowed_extra):
        raise AssertionError("a contested window must never reach the linker")

    result = run_assembly_gate(
        units,
        tmp_path / "work",
        link_runner=link_runner,
        candidate=units[-1],
        canonicalization=_sdk_request(snapshot, smoke_script, seed),
    )

    assert result["passed"] is False
    assert result["conflicts"][0]["class"] == CLASS_CANONICALIZATION_REFUSED
    assert result["conflicts"][0]["symbol"] == SDK_VOID_SYMBOL
    assert "sdk_variant_abi_incompatible" in result["detail"]


@requires_toolchain
def test_sdk_seed_configured_but_unreadable_fails_closed(
    tmp_path: Path, smoke_script: Path
):
    from src.port_assembly_gate import (
        CLASS_CANONICALIZATION_REFUSED,
        run_assembly_gate,
    )

    snapshot = _synthetic_snapshot(tmp_path / "product")
    staging = tmp_path / "staging"
    _write_unit(staging / "unit-a", "unit-a", SDK_CANON_DECL)
    _write_unit(staging / "unit-b", "unit-b", SDK_CANON_DECL)
    units = [
        _artifact(staging / "unit-a", "unit-a"),
        _artifact(staging / "unit-b", "unit-b"),
    ]

    def link_runner(workdir, c_files, exports, allowed_extra):
        raise AssertionError("an unreadable canon must never reach the linker")

    result = run_assembly_gate(
        units,
        tmp_path / "work",
        link_runner=link_runner,
        candidate=units[-1],
        canonicalization=_sdk_request(
            snapshot, smoke_script, tmp_path / "absent" / "gnt4_shim_seed.h"
        ),
    )

    assert result["passed"] is False
    assert result["stage"] == "canonicalize"
    assert result["conflicts"][0]["class"] == CLASS_CANONICALIZATION_REFUSED
    assert "sdk_canon_unavailable" in result["detail"]
