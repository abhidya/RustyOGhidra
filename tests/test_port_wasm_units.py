"""Offline tests for the wasm-unit driver mode (src/port_wasm_units.py)."""

from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path

import pytest

from src.port_driver import EXIT_NO_WORK, EXIT_PROGRESSED, EXIT_STOPPED
from src.port_wasm_units import (
    WasmUnitDriver,
    extract_verbatim,
    scan_disallowed_imports,
)


def _write_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    (repo / "research/decomp/ghidra-export").mkdir(parents=True)
    (repo / "research/decomp/generated/finish-game-port").mkdir(parents=True)
    (repo / "research/decomp/poc").mkdir(parents=True)
    chunk = repo / "research/decomp/ghidra-export/chunk_9999.c"
    chunk.write_text(
        "// line1\nint zz_test_(int a)\n{\n  return a + 1;\n}\n// tail\n",
        encoding="utf-8",
    )
    header = repo / "research/decomp/poc/seed.h"
    header.write_text("/* seed header */\n", encoding="utf-8")
    queue = {
        "queue_schema": 1,
        "units": [
            {
                "name": "unit-a",
                "extractions": [
                    {"file": "research/decomp/ghidra-export/chunk_9999.c", "start": 2, "end": 5}
                ],
                "prelude": ["int zz_test_(int a);"],
                "exported_functions": ["zz_test_"],
                "header_seed": "research/decomp/poc/seed.h",
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
    return repo


def _completed(rc: int = 0, stdout: str = "") -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(args=["git"], returncode=rc, stdout=stdout, stderr="")


def test_extract_verbatim_is_byte_faithful(tmp_path):
    repo = _write_repo(tmp_path)
    text, records = extract_verbatim(
        repo, [{"file": "research/decomp/ghidra-export/chunk_9999.c", "start": 2, "end": 5}]
    )
    raw = "int zz_test_(int a)\n{\n  return a + 1;\n}\n"
    assert raw in text
    assert records[0]["sha256"] == hashlib.sha256(raw.encode()).hexdigest()


def test_extract_verbatim_rejects_bad_range(tmp_path):
    repo = _write_repo(tmp_path)
    with pytest.raises(ValueError):
        extract_verbatim(
            repo,
            [{"file": "research/decomp/ghidra-export/chunk_9999.c", "start": 2, "end": 99}],
        )


def test_scan_disallowed_imports_flags_non_sdk(tmp_path):
    wasm = tmp_path / "unit.wasm"
    wasm.write_bytes(
        b"\x00asm....env.gnt4_PSVECSubtract_bl\x00...env.CONCAT44\x00...env.memory\x00"
    )
    assert scan_disallowed_imports(wasm) == ["CONCAT44"]


def _driver(repo: Path, **kwargs) -> WasmUnitDriver:
    defaults = dict(
        repo_root=repo,
        build_runner=lambda workdir, exports, extra=None: (True, ""),
        oracle_runner=lambda unit, wasm: (True, "1/1", "PASS log"),
        git_runner=lambda *args: _completed(0, "abc123\n"),
    )
    defaults.update(kwargs)
    return WasmUnitDriver(**defaults)


def test_control_stop_exits_before_any_unit(tmp_path, monkeypatch):
    monkeypatch.delenv("OGHIDRA_PORT_LIVENESS_PATH", raising=False)
    repo = _write_repo(tmp_path)
    control = repo / "research/decomp/generated/finish-game-port/control.json"
    control.write_text(json.dumps({"command": "stop_after_stage"}), encoding="utf-8")
    processed = []
    driver = _driver(repo, build_runner=lambda *a: processed.append(a) or (True, ""))
    assert driver.run() == EXIT_STOPPED
    assert processed == []


def test_green_unit_commits_artifacts_and_completes(tmp_path, monkeypatch):
    monkeypatch.delenv("OGHIDRA_PORT_LIVENESS_PATH", raising=False)
    repo = _write_repo(tmp_path)
    git_calls = []

    def fake_git(*args):
        git_calls.append(args)
        if args[0] == "rev-parse":
            return _completed(0, "deadbeef\n")
        return _completed(0)

    def fake_build(workdir, exports, extra=None):
        (workdir / "unit.wasm").write_bytes(b"\x00asm")
        return True, ""

    driver = _driver(repo, git_runner=fake_git, build_runner=fake_build)
    assert driver.run() == EXIT_NO_WORK

    state = json.loads(
        (repo / "research/decomp/generated/finish-game-port/wasm-units-state.json").read_text()
    )
    record = state["units"]["unit-a"]
    assert record["status"] == "green"
    assert record["commit"] == "deadbeef"
    artifact_dir = repo / "research/decomp/port-units/unit-a"
    for name in ("unit.c", "gnt4_shim.h", "unit.wasm", "oracle.log", "provenance.json"):
        assert (artifact_dir / name).is_file(), name
    provenance = json.loads((artifact_dir / "provenance.json").read_text())
    assert provenance["extractions"][0]["sha256"]
    commit_message = next(args for args in git_calls if args[0] == "commit")[2]
    assert commit_message.startswith("port: unit-a wasm unit green")
    assert "Co-Authored-By: Claude Fable 5" in commit_message
    # unit.c embeds the verbatim body untouched
    unit_c = (artifact_dir / "unit.c").read_text()
    assert "return a + 1;" in unit_c
    run_state = json.loads(
        (repo / "research/decomp/generated/finish-game-port/run-state.json").read_text()
    )
    assert run_state["run_mode"] == "driver"
    assert run_state["status"] == "completed"


def test_red_unit_stays_retryable_and_reports_progress(tmp_path, monkeypatch):
    monkeypatch.delenv("OGHIDRA_PORT_LIVENESS_PATH", raising=False)
    repo = _write_repo(tmp_path)

    class NoBlockLLM:
        default_model = "fake"

        def generate(self, **_kwargs):
            return "no code block here"

    driver = _driver(
        repo,
        build_runner=lambda workdir, exports, extra=None: (False, "error: bad"),
        llm=NoBlockLLM(),
    )
    assert driver.run() == EXIT_PROGRESSED
    state = json.loads(
        (repo / "research/decomp/generated/finish-game-port/wasm-units-state.json").read_text()
    )
    record = state["units"]["unit-a"]
    assert record["status"] == "red_retryable"
    assert record["attempts"] == 1
    assert "no code block" in record["error"]
    # no artifacts, no commit for a red unit
    assert not (repo / "research/decomp/port-units/unit-a").exists()


def test_oracle_red_blocks_commit(tmp_path, monkeypatch):
    monkeypatch.delenv("OGHIDRA_PORT_LIVENESS_PATH", raising=False)
    repo = _write_repo(tmp_path)
    git_calls = []

    def fake_build(workdir, exports, extra=None):
        (workdir / "unit.wasm").write_bytes(b"\x00asm")
        return True, ""

    driver = _driver(
        repo,
        build_runner=fake_build,
        oracle_runner=lambda unit, wasm: (False, "3/9", "FAIL log"),
        git_runner=lambda *args: git_calls.append(args) or _completed(0),
    )
    assert driver.run() == EXIT_PROGRESSED
    assert git_calls == []
    state = json.loads(
        (repo / "research/decomp/generated/finish-game-port/wasm-units-state.json").read_text()
    )
    assert state["units"]["unit-a"]["status"] == "red_retryable"


def test_compile_fix_header_only_loop(tmp_path, monkeypatch):
    """The LLM's header lands in the workdir; the verbatim C is never rewritten."""
    monkeypatch.delenv("OGHIDRA_PORT_LIVENESS_PATH", raising=False)
    repo = _write_repo(tmp_path)
    builds = []

    def flaky_build(workdir, exports, extra=None):
        builds.append((workdir / "gnt4_shim.h").read_text())
        if len(builds) == 1:
            return False, "error: use of undeclared identifier 'bool'"
        (workdir / "unit.wasm").write_bytes(b"\x00asm")
        return True, ""

    class FixLLM:
        default_model = "fake-27b"

        def generate(self, **_kwargs):
            return "```c\n#include <stdbool.h>\n/* fixed */\n```"

    driver = _driver(repo, build_runner=flaky_build, llm=FixLLM())
    assert driver.run() == EXIT_NO_WORK
    assert builds[0] == "/* seed header */\n"
    assert "stdbool" in builds[1]
    state = json.loads(
        (repo / "research/decomp/generated/finish-game-port/wasm-units-state.json").read_text()
    )
    record = state["units"]["unit-a"]
    assert record["status"] == "green"
    assert record["model_requests"] == 1
    provenance = json.loads(
        (repo / "research/decomp/port-units/unit-a/provenance.json").read_text()
    )
    assert provenance["model"] == "fake-27b"
    assert provenance["compile_iterations"] == 2


def test_compile_only_unit_commits_to_staging_unverified(tmp_path, monkeypatch):
    monkeypatch.delenv("OGHIDRA_PORT_LIVENESS_PATH", raising=False)
    repo = _write_repo(tmp_path)
    queue_path = repo / "research/decomp/generated/finish-game-port/wasm-units.json"
    queue = json.loads(queue_path.read_text())
    queue["units"][0]["oracle"] = {"type": "compile_only"}
    queue["units"][0]["allowed_extra_imports"] = ["FUN_80001234"]
    queue_path.write_text(json.dumps(queue), encoding="utf-8")
    git_calls = []

    def fake_git(*args):
        git_calls.append(args)
        if args[0] == "rev-parse":
            return _completed(0, "cafe1234\n")
        return _completed(0)

    def fake_build(workdir, exports, extra=None):
        assert extra == ["FUN_80001234"]
        (workdir / "unit.wasm").write_bytes(b"\x00asm")
        return True, ""

    oracle_calls = []
    driver = _driver(
        repo,
        git_runner=fake_git,
        build_runner=fake_build,
        oracle_runner=lambda unit, wasm: oracle_calls.append(unit) or (True, "x", "y"),
    )
    assert driver.run() == EXIT_NO_WORK
    assert oracle_calls == []  # compile_only never runs a behavioral oracle
    staged = repo / "research/decomp/port-units-staging/unit-a/provenance.json"
    prov = json.loads(staged.read_text())
    assert prov["verified"] is False and prov["tier"] == "compile_only"
    add_call = next(c for c in git_calls if c[0] == "add")
    assert "port-units-staging" in add_call[1]
    commit_call = next(c for c in git_calls if c[0] == "commit")
    assert "port-staging:" in commit_call[2] and "unoracled" in commit_call[2]
