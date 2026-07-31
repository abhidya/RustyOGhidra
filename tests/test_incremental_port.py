import subprocess
import json
from pathlib import Path

from src.incremental_port import (
    IncrementalPortTransaction,
    PortUnit,
    QwenPatchProvider,
)
from src.source_patch import BrowserSourcePatch


def _git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def _repo_with_bare_remote(tmp_path: Path) -> tuple[Path, Path]:
    remote = tmp_path / "remote.git"
    production = tmp_path / "production"
    _git(tmp_path, "init", "--bare", str(remote))
    _git(tmp_path, "clone", str(remote), str(production))
    _git(production, "config", "user.email", "poc@example.invalid")
    _git(production, "config", "user.name", "Incremental POC")
    _git(production, "switch", "-c", "main")
    source = production / "packages/combat/src/state.ts"
    source.parent.mkdir(parents=True)
    source.write_text("export const STATE_IDLE = 0;\n", encoding="utf-8")
    _git(production, "add", ".")
    _git(production, "commit", "-m", "initial")
    _git(production, "push", "-u", "origin", "main")
    _git(remote, "symbolic-ref", "HEAD", "refs/heads/main")
    return production, remote


def _patch_for(
    unit: PortUnit,
    _worktree: Path,
    _record_dir: Path,
) -> BrowserSourcePatch:
    if unit.unit_id == "unit-one":
        line = "export const STATE_ACTIVE = 1;"
        context = "export const STATE_IDLE = 0;"
        hunk = "@@ -1,1 +1,2 @@"
    else:
        line = "export const STATE_RECOVER = 2;"
        context = "export const STATE_ACTIVE = 1;"
        hunk = "@@ -2,1 +2,2 @@"
    return BrowserSourcePatch(
        summary=unit.unit_id,
        semantics=[f"implements {unit.unit_id}"],
        diff=(
            "diff --git a/packages/combat/src/state.ts "
            "b/packages/combat/src/state.ts\n"
            "--- a/packages/combat/src/state.ts\n"
            "+++ b/packages/combat/src/state.ts\n"
            f"{hunk}\n"
            f" {context}\n"
            f"+{line}\n"
        ),
    )


def test_two_units_accumulate_and_push_once(tmp_path: Path):
    production, remote = _repo_with_bare_remote(tmp_path)
    original = (production / "packages/combat/src/state.ts").read_bytes()
    transaction = IncrementalPortTransaction(
        repo_root=production,
        run_root=tmp_path / "runs",
        patch_provider=_patch_for,
        gate_runner=lambda _root, _unit: (True, "passed"),
    )

    result = transaction.run(
        [PortUnit(unit_id="unit-one"), PortUnit(unit_id="unit-two")],
        push_main=True,
    )

    assert result.status == "pushed"
    assert len(result.commits) == 2
    assert result.push_command == ["git", "push", "origin", "HEAD:refs/heads/main"]
    remote_source = _git(
        production, "show", "origin/main:packages/combat/src/state.ts"
    )
    assert "STATE_ACTIVE" in remote_source
    assert "STATE_RECOVER" in remote_source
    assert (production / "packages/combat/src/state.ts").read_bytes() == original
    assert _git(production, "status", "--porcelain") == ""
    assert _git(remote, "rev-parse", "main") == result.commits[-1]


def test_second_unit_failure_pushes_nothing(tmp_path: Path):
    production, remote = _repo_with_bare_remote(tmp_path)
    base = _git(remote, "rev-parse", "main")

    def gates(_root: Path, unit: PortUnit) -> tuple[bool, str]:
        return (unit.unit_id != "unit-two", "second unit failed")

    result = IncrementalPortTransaction(
        repo_root=production,
        run_root=tmp_path / "runs",
        patch_provider=_patch_for,
        gate_runner=gates,
    ).run(
        [PortUnit(unit_id="unit-one"), PortUnit(unit_id="unit-two")],
        push_main=True,
    )

    assert result.status == "failed"
    assert _git(remote, "rev-parse", "main") == base
    assert result.push_command is None


def test_remote_main_race_retains_candidate_and_does_not_push(tmp_path: Path):
    production, remote = _repo_with_bare_remote(tmp_path)

    def advance_remote() -> None:
        racer = tmp_path / "racer"
        _git(tmp_path, "clone", str(remote), str(racer))
        _git(racer, "config", "user.email", "race@example.invalid")
        _git(racer, "config", "user.name", "Race")
        (racer / "race.txt").write_text("advance\n", encoding="utf-8")
        _git(racer, "add", "race.txt")
        _git(racer, "commit", "-m", "advance remote")
        _git(racer, "push", "origin", "main")

    result = IncrementalPortTransaction(
        repo_root=production,
        run_root=tmp_path / "runs",
        patch_provider=_patch_for,
        gate_runner=lambda _root, _unit: (True, "passed"),
        before_push=advance_remote,
    ).run(
        [PortUnit(unit_id="unit-one"), PortUnit(unit_id="unit-two")],
        push_main=True,
    )

    assert result.status == "push_race"
    assert result.worktree is not None
    assert Path(result.worktree).is_dir()
    assert result.push_command is None


def test_qwen_provider_repairs_a_diff_rejected_before_mutation(tmp_path: Path):
    source = tmp_path / "packages/combat/src/state.ts"
    source.parent.mkdir(parents=True)
    source.write_text("export const STATE_IDLE = 0;\n", encoding="utf-8")
    evidence = tmp_path / "unit.json"
    evidence.write_text(
        json.dumps(
            {
                "unit_id": "unit-one",
                "kind": "state_dispatcher",
                "root_addresses": ["0x80000000"],
                "handlers": [],
                "evidence": [],
            }
        ),
        encoding="utf-8",
    )

    class RepairingLLM:
        calls = 0

        def generate_structured(self, **kwargs):
            self.calls += 1
            if self.calls == 1:
                diff = (
                    "--- a/packages/combat/src/state.ts\n"
                    "+++ b/packages/combat/src/state.ts\n"
                    "@@ -1 +1,2 @@\n"
                    " export const STATE_IDLE = 0;\n"
                    "+export const BROKEN = 1;\n"
                )
            else:
                assert "does not contain a unified diff" in kwargs["prompt"]
                diff = (
                    "diff --git a/packages/combat/src/state.ts "
                    "b/packages/combat/src/state.ts\n"
                    "--- a/packages/combat/src/state.ts\n"
                    "+++ b/packages/combat/src/state.ts\n"
                    "@@ -1 +1,2 @@\n"
                    " export const STATE_IDLE = 0;\n"
                    "+export const STATE_ACTIVE = 1;\n"
                )
            return (
                json.dumps(
                    {
                        "summary": "repair",
                        "action": "edit",
                        "semantics": [],
                        "diff": diff,
                    }
                ),
                "tool_call",
            )

    llm = RepairingLLM()
    patch = QwenPatchProvider(lambda: (llm, "fake", "qwen"))(
        PortUnit(unit_id="unit-one", evidence_path=evidence),
        tmp_path,
        tmp_path / "record",
    )

    assert "STATE_ACTIVE" in patch.diff
    assert llm.calls == 2
    assert (tmp_path / "record/model-attempt-01/rejected.txt").is_file()
