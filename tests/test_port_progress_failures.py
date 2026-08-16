"""Failure-path regressions for the progress journal and product commits.

Every test here is a defect the 2026-08-16 adversarial git review reproduced in
a scratch repository. The common shape: a git failure that looked like success,
or a git failure that silently froze the branch with nothing scheduled to fix it.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from src.port_progress import RESULT_RETRYABLE, ProgressJournal, UnitTransition
from src.port_wasm_units import WasmUnitDriver


def git(*args: str, cwd: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", *args], cwd=str(cwd), capture_output=True, text=True, timeout=120
    )


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    root = tmp_path / "product"
    root.mkdir()
    git("init", "-b", "main", cwd=root)
    git("config", "user.email", "t@example.com", cwd=root)
    git("config", "user.name", "T", cwd=root)
    (root / "README.md").write_text("product\n", encoding="utf-8")
    git("add", "-A", cwd=root)
    git("commit", "-m", "initial", cwd=root)
    return root


@pytest.fixture
def journal(repo: Path, tmp_path: Path) -> ProgressJournal:
    return ProgressJournal(
        repo, run_root=tmp_path / "run", worktree=tmp_path / "wt",
        run_id="r", enable_push=False,
    )


UNITS = {"unit-a": {"status": "red_retryable", "attempts": 1}}


def a_transition() -> UnitTransition:
    return UnitTransition("unit-a", RESULT_RETRYABLE, "build", 1)


# ------------------------------------------------------------------ journal


def test_a_wedged_index_lock_is_repaired_rather_than_frozen(journal, repo):
    """A killed `git commit` leaves .git/worktrees/<id>/index.lock. rev-parse
    still succeeds there, so the old health check short-circuited and the branch
    never committed again -- silently, with no pending flag."""
    assert journal.prepare()
    lock = repo / ".git" / "worktrees" / journal.worktree.name / "index.lock"
    lock.parent.mkdir(parents=True, exist_ok=True)
    lock.write_text("", encoding="utf-8")

    assert journal._worktree_healthy() is False       # detected, not ignored
    result = journal.checkpoint(transition=a_transition(), units=UNITS)

    assert result["recorded"] is True
    assert result.get("committed") is True            # prepare() rebuilt it


def test_a_commit_failure_is_recorded_as_pending_for_retry(journal):
    def failing(*args, cwd=None):
        if args and args[0] == "commit":
            return subprocess.CompletedProcess(args, 1, "", "fatal: cannot lock ref")
        return journal._git(*args, cwd=cwd)

    journal._git_runner = failing
    result = journal.checkpoint(transition=a_transition(), units=UNITS)

    assert result["committed"] is False
    assert journal.push_is_pending() is True          # something will retry it


def test_a_corrupt_events_file_does_not_wedge_the_journal(journal):
    journal.checkpoint(transition=a_transition(), units=UNITS)
    events = journal.progress_root / "events.jsonl"
    with events.open("ab") as handle:
        handle.write(b'{"partial": "\xe2\x82')       # truncated multibyte

    result = journal.checkpoint(transition=a_transition(), units=UNITS)

    assert result["recorded"] is True
    assert result.get("committed") is True


def test_a_contended_lock_records_a_pending_state_instead_of_dropping_it(
    repo, tmp_path
):
    """A pause issued while the driver holds the lock must not vanish -- that is
    exactly when GitHub would keep rendering RUNNING over a paused machine."""
    holder = ProgressJournal(
        repo, run_root=tmp_path / "run", worktree=tmp_path / "wt",
        run_id="a", enable_push=False,
    )
    other = ProgressJournal(
        repo, run_root=tmp_path / "run", worktree=tmp_path / "wt2",
        run_id="b", enable_push=False,
    )
    assert holder.lock.acquire()
    try:
        result = other.checkpoint(transition=a_transition(), units=UNITS)
        assert result["committed"] is False
        assert other.push_is_pending() is True
    finally:
        holder.lock.release()


def test_seeding_cannot_clobber_an_existing_journal_branch(journal, repo):
    assert journal.prepare()
    before = git("rev-parse", "port-progress", cwd=repo).stdout.strip()

    assert journal._seed_branch() is False            # fails closed
    assert git("rev-parse", "port-progress", cwd=repo).stdout.strip() == before


def test_a_leftover_directory_does_not_wedge_prepare_forever(journal, repo):
    assert journal.prepare()
    git("worktree", "remove", "--force", str(journal.worktree), cwd=repo)
    journal.worktree.mkdir(parents=True, exist_ok=True)
    (journal.worktree / "leftover.txt").write_text("junk", encoding="utf-8")
    journal._prepared = False

    assert journal.prepare() is True


def test_flush_does_not_explode_when_the_worktree_is_gone(journal, repo, tmp_path):
    journal.enable_push = True
    journal.checkpoint(transition=a_transition(), units=UNITS)
    git("worktree", "remove", "--force", str(journal.worktree), cwd=repo)

    outcome = journal.flush_pending_push()            # must not raise

    assert "pushed" in outcome


# ------------------------------------------------------------ product commit


def _wasm_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "wrepo"
    (repo / "research/decomp/ghidra-export").mkdir(parents=True)
    (repo / "research/decomp/generated/finish-game-port").mkdir(parents=True)
    (repo / "research/decomp/poc").mkdir(parents=True)
    (repo / "research/decomp/ghidra-export/chunk_9999.c").write_text(
        "// l\nint zz_test_(int a)\n{\n  return a + 1;\n}\n// t\n", encoding="utf-8"
    )
    (repo / "research/decomp/poc/seed.h").write_text("/* s */\n", encoding="utf-8")
    (repo / "research/decomp/generated/finish-game-port/wasm-units.json").write_text(
        json.dumps({
            "queue_schema": 1,
            "units": [{
                "name": "unit-a",
                "extractions": [{
                    "file": "research/decomp/ghidra-export/chunk_9999.c",
                    "start": 2, "end": 5,
                }],
                "exported_functions": ["zz_test_"],
                "header_seed": "research/decomp/poc/seed.h",
                "oracle": {"type": "compile_only"},
            }],
        }),
        encoding="utf-8",
    )
    return repo


class NullJournal:
    def checkpoint(self, **kwargs):
        return {"recorded": True}

    def push_is_pending(self):
        return False

    def flush_pending_push(self):
        return {}


def _build(workdir, exports, extra=None):
    (workdir / "unit.wasm").write_bytes(b"\x00asm\x01\x00\x00\x00")
    return True, ""


def test_a_failed_product_commit_never_settles_the_unit(tmp_path):
    """`green` is a SETTLED status: marking a unit green when git never took the
    artifact removes it from the queue forever with nothing in the product tree,
    and renders on GitHub as an ordinary green."""
    repo = _wasm_repo(tmp_path)

    def failing_git(*args):
        if args and args[0] == "commit":
            return subprocess.CompletedProcess(args, 1, "", "fatal: index.lock exists")
        return subprocess.CompletedProcess(args, 0, "", "")

    driver = WasmUnitDriver(
        repo_root=repo, units_budget=1, journal=NullJournal(),
        git_runner=failing_git, build_runner=_build,
        oracle_runner=lambda unit, wasm: (True, "ok", "PASS"),
    )
    driver.run()

    state = json.loads(
        (repo / "research/decomp/generated/finish-game-port/wasm-units-state.json")
        .read_text(encoding="utf-8")
    )
    assert state["units"]["unit-a"]["status"] == "red_retryable"
    assert "product commit failed" in state["units"]["unit-a"]["error"]


def test_a_push_timeout_does_not_escape_the_driver(tmp_path):
    repo = _wasm_repo(tmp_path)

    def timing_out(*args):
        if args and args[0] == "push":
            raise subprocess.TimeoutExpired(cmd="git push", timeout=300)
        return subprocess.CompletedProcess(args, 0, "", "deadbeef\n")

    driver = WasmUnitDriver(
        repo_root=repo, units_budget=1, journal=NullJournal(),
        git_runner=timing_out, build_runner=_build,
        oracle_runner=lambda unit, wasm: (True, "ok", "PASS"),
    )

    driver.run()   # must not raise

    state = json.loads(
        (repo / "research/decomp/generated/finish-game-port/wasm-units-state.json")
        .read_text(encoding="utf-8")
    )
    assert state["units"]["unit-a"]["status"] == "red_retryable"


def test_an_unreadable_state_file_is_preserved_not_destroyed(tmp_path):
    """The state file holds every green verdict in the run."""
    repo = _wasm_repo(tmp_path)
    state_path = repo / "research/decomp/generated/finish-game-port/wasm-units-state.json"
    state_path.write_text('{"state_schema": 99, "units": {"unit-a": {"status": "green"}}}',
                          encoding="utf-8")

    driver = WasmUnitDriver(
        repo_root=repo, units_budget=1, journal=NullJournal(),
        git_runner=lambda *a: subprocess.CompletedProcess(a, 0, "sha\n", ""),
        build_runner=_build, oracle_runner=lambda unit, wasm: (True, "ok", "PASS"),
    )
    driver.run()

    preserved = list(state_path.parent.glob("wasm-units-state.json.unreadable-*"))
    assert preserved, "the previous state file must survive as a backup"
    assert "green" in preserved[0].read_text(encoding="utf-8")
