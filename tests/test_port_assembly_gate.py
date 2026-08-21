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
