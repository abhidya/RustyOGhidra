"""port-progress journal regressions.

The problem being defended against: for weeks, GitHub could look dead while the
rig burned through dozens of units, because only *green* units produced commits.
Every test here pins a way the remote journal could go back to lying.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from src.port_progress import (
    RESULT_GATE_FAILED,
    RESULT_GREEN,
    RESULT_RETRYABLE,
    RESULT_STAGED,
    MachineState,
    ProgressJournal,
    UnitTransition,
    classify_counts,
    stable_unit_id,
)


def git(*args: str, cwd: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", *args], cwd=str(cwd), capture_output=True, text=True, timeout=120
    )


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    root = tmp_path / "product"
    root.mkdir()
    git("init", "-b", "main", cwd=root)
    git("config", "user.email", "test@example.com", cwd=root)
    git("config", "user.name", "Test", cwd=root)
    (root / "README.md").write_text("product\n", encoding="utf-8")
    git("add", "-A", cwd=root)
    git("commit", "-m", "initial", cwd=root)
    return root


@pytest.fixture
def journal(repo: Path, tmp_path: Path) -> ProgressJournal:
    return ProgressJournal(
        repo,
        run_root=tmp_path / "run",
        worktree=tmp_path / "wt",
        run_id="test-run",
        enable_push=False,
    )


UNITS = {
    "damage-core": {"status": "green", "attempts": 1, "tier": "oracle_green"},
    "auto-c0000-000": {"status": "green", "attempts": 2, "tier": "compile_only"},
    "auto-c0000-001": {"status": "red_retryable", "attempts": 3},
    "auto-c0000-002": {"status": "pending", "attempts": 0},
    "auto-c0000-003": {"status": "structural_ineligible", "attempts": 1},
    "auto-c0000-004": {"status": "porting", "attempts": 1},
}


# ------------------------------------------------------------------ plumbing


def test_branch_is_seeded_without_checking_out_the_product_tree(journal, repo):
    assert journal.prepare()
    assert (journal.worktree / "workflow-progress" / "README.md").is_file()
    # The seed commit is an orphan carrying ONLY the journal directory: no
    # product file was ever materialised into the progress worktree.
    listed = git("ls-tree", "-r", "--name-only", "port-progress", cwd=repo).stdout.split()
    assert listed == ["workflow-progress/README.md"]
    # The product worktree is untouched.
    assert git("rev-parse", "--abbrev-ref", "HEAD", cwd=repo).stdout.strip() == "main"


def test_stable_transition_id_is_idempotent_across_local_and_branch(journal, repo):
    transition = UnitTransition(
        unit="damage-core",
        result=RESULT_GREEN,
        stage="commit",
        product_commit="abc123",
        product_pushed=True,
        extra={
            "transition_id": "stable-green-transition",
            "transition_timestamp": "2026-08-21T12:34:56Z",
            "transition_run_id": "stable-origin-run",
        },
    )
    first = journal.checkpoint(
        transition=transition,
        units=UNITS,
        machine=MachineState(workflow_state="running"),
        driver_running=True,
    )
    second = journal.checkpoint(
        transition=transition,
        units=UNITS,
        machine=MachineState(workflow_state="running"),
        driver_running=True,
    )
    assert first["recorded"] is True
    assert second["recorded"] is True and second["idempotent"] is True
    records = [
        json.loads(line)
        for line in (
            journal.progress_root / "events.jsonl"
        ).read_text(encoding="utf-8").splitlines()
    ]
    matching = [
        record
        for record in records
        if record.get("extra", {}).get("transition_id")
        == "stable-green-transition"
    ]
    assert len(matching) == 1
    assert matching[0]["timestamp"] == "2026-08-21T12:34:56Z"
    assert matching[0]["run_id"] == "stable-origin-run"
    subjects = git(
        "log", "--format=%s", "refs/heads/port-progress", cwd=repo
    ).stdout.splitlines()
    assert sum(subject.startswith("progress: damage-core green") for subject in subjects) == 1
    assert git("status", "--porcelain", cwd=repo).stdout.strip() == ""


def test_product_worktree_head_is_never_moved_by_a_checkpoint(journal, repo):
    before = git("rev-parse", "HEAD", cwd=repo).stdout.strip()
    journal.checkpoint(
        transition=UnitTransition("damage-core", RESULT_GREEN, "commit", 1),
        units=UNITS,
    )
    assert git("rev-parse", "HEAD", cwd=repo).stdout.strip() == before
    assert git("status", "--porcelain", cwd=repo).stdout.strip() == ""


# --------------------------------------------------------------- checkpoints


def test_retryable_red_unit_produces_a_remote_progress_commit(journal, repo):
    result = journal.checkpoint(
        transition=UnitTransition(
            "auto-c0000-001", RESULT_RETRYABLE, "compile-fix", 3,
            detail="Custom API returned no assistant content",
        ),
        units=UNITS,
    )

    assert result["committed"] is True
    subject = git("log", "-1", "--format=%s", "port-progress", cwd=repo).stdout.strip()
    assert subject == "progress: auto-c0000-001 retryable at compile-fix"
    assert "auto-c0000-001" in subject   # every subject carries the unit id


def test_gate_failure_produces_a_stage_specific_subject(journal, repo):
    journal.checkpoint(
        transition=UnitTransition("collision-core", RESULT_GATE_FAILED, "wasm-link", 2),
        units=UNITS,
    )
    subject = git("log", "-1", "--format=%s", "port-progress", cwd=repo).stdout.strip()
    assert subject == "progress: collision-core gate_failed at wasm-link"


def test_green_checkpoint_references_the_product_commit_sha(journal, repo):
    journal.checkpoint(
        transition=UnitTransition(
            "damage-core", RESULT_GREEN, "commit", 1,
            product_commit="abc123def456", product_pushed=True,
            oracle_summary="19998/20000",
        ),
        units=UNITS,
    )

    record = json.loads(
        (journal.worktree / "workflow-progress" / "units" / "damage-core.json").read_text(
            encoding="utf-8"
        )
    )
    assert record["product_commit"] == "abc123def456"
    assert record["product_effect"] == "durable product commit"
    summary = json.loads(
        (journal.worktree / "workflow-progress" / "summary.json").read_text(encoding="utf-8")
    )
    assert summary["last_product_commit"] == "abc123def456"
    subject = git("log", "-1", "--format=%s", "port-progress", cwd=repo).stdout.strip()
    assert subject.startswith("progress: damage-core green ")


def test_non_product_categories_say_so_explicitly(journal):
    journal.checkpoint(
        transition=UnitTransition("auto-c0000-001", RESULT_RETRYABLE, "oracle", 1),
        units=UNITS,
    )
    record = json.loads(
        (journal.worktree / "workflow-progress" / "units" / "auto-c0000-001.json").read_text(
            encoding="utf-8"
        )
    )
    assert record["product_effect"] == "no product-tree change by design"


def test_every_transition_commits_rather_than_batching(journal, repo):
    for index in range(5):
        journal.checkpoint(
            transition=UnitTransition(f"auto-c0000-00{index}", RESULT_RETRYABLE, "build", 1),
            units=UNITS,
        )
    subjects = git(
        "log", "--format=%s", "port-progress", cwd=repo
    ).stdout.strip().splitlines()
    # 5 transitions + the seed commit -- no hourly batch, no 10-unit batch.
    assert len(subjects) == 6


def test_unit_history_accumulates_across_attempts(journal):
    for attempt in (1, 2, 3):
        journal.checkpoint(
            transition=UnitTransition(
                "auto-c0000-001", RESULT_RETRYABLE, "compile-fix", attempt
            ),
            units=UNITS,
        )
    record = json.loads(
        (journal.worktree / "workflow-progress" / "units" / "auto-c0000-001.json").read_text(
            encoding="utf-8"
        )
    )
    assert [entry["attempt"] for entry in record["history"]] == [1, 2, 3]


# ------------------------------------------------------------------- content


def test_current_json_carries_the_required_fields(journal):
    journal.checkpoint(
        transition=UnitTransition("auto-c0000-001", RESULT_RETRYABLE, "build", 2),
        units=UNITS,
        machine=MachineState(
            workflow_state="running", driver_status="running",
            active_model="configured/model", context_length=32768,
            configured_model="configured/model",
        ),
        previous_unit="damage-core", previous_result=RESULT_GREEN,
        current_unit="auto-c0000-002", current_stage="extract", current_attempt=1,
        driver_running=True,
    )
    current = json.loads(
        (journal.worktree / "workflow-progress" / "current.json").read_text(encoding="utf-8")
    )
    for key in (
        "timestamp", "run_id", "port_mode", "workflow_state", "current_unit",
        "previous_unit", "previous_result", "current_stage", "current_attempt",
        "active_model", "context_length", "driver_status", "last_transition",
        "last_green", "last_product_commit", "block_reason", "manual_paused", "queue",
    ):
        assert key in current, key


def test_summary_counts_every_class(journal):
    journal.checkpoint(
        transition=UnitTransition("auto-c0000-001", RESULT_RETRYABLE, "build", 1),
        units=UNITS,
    )
    summary = json.loads(
        (journal.worktree / "workflow-progress" / "summary.json").read_text(encoding="utf-8")
    )
    assert summary["total_units"] == 6
    assert summary["green"] == 1            # oracle_green tier only
    assert summary["staged"] == 1           # compile_only tier
    assert summary["retryable"] == 1
    assert summary["untouched"] == 1
    assert summary["structural_ineligible"] == 1
    assert summary["active"] == 1
    assert summary["total_attempts"] == 8


def test_readme_leads_with_the_state_banner_and_recent_transitions(journal):
    journal.checkpoint(
        transition=UnitTransition("auto-c0000-001", RESULT_RETRYABLE, "wasm-link", 4),
        units=UNITS,
        machine=MachineState(workflow_state="running", configured_model="configured/model"),
        current_unit="auto-c0000-002", current_stage="extract",
        driver_running=True,
    )
    readme = (journal.worktree / "workflow-progress" / "README.md").read_text(encoding="utf-8")
    assert readme.startswith("# Port workflow: RUNNING")
    for expected in (
        "Current unit", "Current stage", "Queue progress", "Retries outstanding",
        "Last transition", "Last green", "Last product commit", "Current model",
    ):
        assert expected in readme
    assert "auto-c0000-001" in readme
    assert "wasm-link" in readme


@pytest.mark.parametrize(
    ("state", "banner"),
    [
        (MachineState(manual_paused=True), "PAUSED"),
        (MachineState(block_reason="Unsloth cannot start"), "BLOCKED"),
        (MachineState(workflow_state="complete"), "COMPLETE"),
    ],
)
def test_readme_banner_reflects_machine_state(journal, state, banner):
    journal.checkpoint(transition=None, units=UNITS, machine=state)
    readme = (journal.worktree / "workflow-progress" / "README.md").read_text(encoding="utf-8")
    assert readme.startswith(f"# Port workflow: {banner}")


def test_health_classifications(journal):
    counts = classify_counts(UNITS)
    assert ProgressJournal._health(counts, MachineState(manual_paused=True), 0, 0, False) == "manual_paused"
    assert ProgressJournal._health(counts, MachineState(block_reason="x"), 0, 0, False) == "blocked"
    assert ProgressJournal._health(counts, MachineState(workflow_state="provider_paused"), 0, 0, False) == "provider_paused"
    assert ProgressJournal._health(counts, MachineState(), 0, 0, False) == "idle"
    assert ProgressJournal._health(counts, MachineState(), 5, 2, True) == "healthy_progress"
    assert ProgressJournal._health(counts, MachineState(), 5, 0, True) == "active_no_green"
    assert ProgressJournal._health(counts, MachineState(), 0, 0, True) == "possibly_stuck"
    settled = {"a": {"status": "green", "tier": "oracle_green"}}
    assert ProgressJournal._health(classify_counts(settled), MachineState(), 0, 0, True) == "complete"


def test_events_file_is_bounded(journal, monkeypatch):
    monkeypatch.setattr("src.port_progress.MAX_EVENT_LINES", 5)
    for index in range(12):
        journal.checkpoint(
            transition=UnitTransition(f"unit-{index}", RESULT_RETRYABLE, "build", 1),
            units=UNITS,
        )
    lines = (journal.worktree / "workflow-progress" / "events.jsonl").read_text(
        encoding="utf-8"
    ).strip().splitlines()
    assert len(lines) == 5


# ----------------------------------------------------------------- unit ids


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("collision-core", "collision-core"),
        ("chunk_0021/unit_017", "chunk_0021__unit_017"),
        ("auto-c0000-001", "auto-c0000-001"),
        ("weird name: with*chars", "weird_name_with_chars"),
    ],
)
def test_stable_unit_ids(name, expected):
    assert stable_unit_id(name) == expected
    assert stable_unit_id(name) == stable_unit_id(name)   # stable across calls


def test_distinct_units_do_not_collide(journal):
    assert stable_unit_id("chunk_0021/unit_017") != stable_unit_id("chunk_0021/unit_018")


# ---------------------------------------------------------------- push paths


def test_push_failure_is_recorded_as_pending_and_never_raises(repo, tmp_path):
    calls: list[tuple] = []

    def failing_git(*args, cwd=None):
        calls.append(args)
        if args and args[0] == "push":
            return subprocess.CompletedProcess(args, 1, "", "fatal: unable to access")
        return subprocess.run(
            ["git", *args], cwd=str(cwd or repo), capture_output=True, text=True, timeout=120
        )

    journal = ProgressJournal(
        repo, run_root=tmp_path / "run", worktree=tmp_path / "wt",
        run_id="r", git_runner=failing_git, enable_push=True,
    )
    result = journal.checkpoint(
        transition=UnitTransition("auto-c0000-001", RESULT_RETRYABLE, "build", 1),
        units=UNITS,
    )

    assert result["committed"] is True     # the unit still succeeded locally
    assert result["pushed"] is False
    assert journal.push_is_pending() is True


def test_pending_push_is_retried_and_cleared_on_success(repo, tmp_path):
    state = {"fail": True}

    def flaky_git(*args, cwd=None):
        if args and args[0] == "push":
            if state["fail"]:
                return subprocess.CompletedProcess(args, 1, "", "fatal: unable to access")
            return subprocess.CompletedProcess(args, 0, "", "")
        return subprocess.run(
            ["git", *args], cwd=str(cwd or repo), capture_output=True, text=True, timeout=120
        )

    journal = ProgressJournal(
        repo, run_root=tmp_path / "run", worktree=tmp_path / "wt",
        run_id="r", git_runner=flaky_git, enable_push=True,
    )
    journal.checkpoint(
        transition=UnitTransition("auto-c0000-001", RESULT_RETRYABLE, "build", 1),
        units=UNITS,
    )
    assert journal.push_is_pending()

    state["fail"] = False
    outcome = journal.flush_pending_push()

    assert outcome["pushed"] is True
    assert journal.push_is_pending() is False


def test_transition_is_durable_locally_even_when_git_is_entirely_broken(repo, tmp_path):
    def broken_git(*args, cwd=None):
        return subprocess.CompletedProcess(args, 128, "", "fatal: not a git repository")

    journal = ProgressJournal(
        repo, run_root=tmp_path / "run", worktree=tmp_path / "wt",
        run_id="r", git_runner=broken_git, enable_push=True,
    )
    result = journal.checkpoint(
        transition=UnitTransition("auto-c0000-001", RESULT_RETRYABLE, "build", 1),
        units=UNITS,
    )

    assert result["recorded"] is True      # never raises, never loses the record
    local = (tmp_path / "run" / "progress" / "events.jsonl").read_text(encoding="utf-8")
    assert "auto-c0000-001" in local


def test_checkpoint_reports_not_recorded_when_every_durability_path_fails(
    repo, tmp_path, monkeypatch
):
    journal = ProgressJournal(
        repo,
        run_root=tmp_path / "run",
        worktree=tmp_path / "wt",
        run_id="r",
        enable_push=False,
    )

    def fail_local(_record):
        raise OSError("disk unavailable")

    def fail_branch(*_args, **_kwargs):
        raise RuntimeError("progress branch unavailable")

    monkeypatch.setattr(journal, "_append_local_event", fail_local)
    monkeypatch.setattr(journal, "_checkpoint_locked", fail_branch)
    result = journal.checkpoint(
        transition=UnitTransition("auto-c0000-001", RESULT_RETRYABLE, "build", 1),
        units=UNITS,
    )

    assert result["recorded"] is False
    assert result["committed"] is False
    assert "local journal append failed" in result["detail"]


def test_concurrent_writer_is_serialised_by_the_progress_lock(repo, tmp_path):
    first = ProgressJournal(
        repo, run_root=tmp_path / "run", worktree=tmp_path / "wt",
        run_id="a", enable_push=False,
    )
    second = ProgressJournal(
        repo, run_root=tmp_path / "run", worktree=tmp_path / "wt2",
        run_id="b", enable_push=False,
    )
    assert first.lock.acquire()
    try:
        result = second.checkpoint(
            transition=UnitTransition("auto-c0000-001", RESULT_RETRYABLE, "build", 1),
            units=UNITS,
        )
        assert result["committed"] is False
        assert "progress.lock" in result["detail"]
        # The transition is still durable locally, so nothing is lost.
        assert "auto-c0000-001" in (
            tmp_path / "run" / "progress" / "events.jsonl"
        ).read_text(encoding="utf-8")
    finally:
        first.lock.release()
