"""The durable remote workflow journal (`port-progress` branch).

Problem this solves: the wasm-unit workflow only commits *green* units to the
product repo, so a night spent burning through 40 units that all went red looked
identical on GitHub to a night where nothing ran at all. The owner cannot remote
into the machine to tell the difference.

Design:

* A dedicated branch, ``port-progress``, carries a compact generated tree under
  ``workflow-progress/``. Product history stays clean -- no failed candidate
  source ever lands in the product tree merely for observability.
* The branch is written through a **separate git worktree** (default
  ``<repo>/.tmp/port-progress-worktree``, which is gitignored). The product
  worktree's index and HEAD are never touched, so a progress commit can never
  race, corrupt, or accidentally include a product commit in flight.
* **Every unit transition emits a checkpoint** -- green, staged, retryable, gate
  failure, deferred, structurally ineligible, blocked. No hourly batch, no
  "every 10 units". Before the workflow starts unit B, unit A's record exists.
* Local durability first, then the commit, then the push. A failed push is
  recorded as pending and retried on a later transition; it never fails a unit
  and never reverts product work.

The rig supervisor writes machine-level states (manual pause, blocked, idle,
complete) through the same journal, so ``current.json`` explains *why* nothing is
running when nothing is running.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable

from src.port_chunk_workflow import atomic_write_json, utc_now
from src.port_driver import DriverLock

PROGRESS_BRANCH = "port-progress"
PROGRESS_DIR = "workflow-progress"
PROGRESS_SCHEMA = 1
# Bounded journal: the branch is a rolling window, not an archive. Each commit
# rewrites this blob, so an unbounded file would grow the branch quadratically.
MAX_EVENT_LINES = 2000
README_TRANSITIONS = 50
GIT_TIMEOUT_SECONDS = 300
GIT_TRAILER = "Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"

# Unit result classes. These are the states that cause the selector to move on.
RESULT_GREEN = "green"
RESULT_STAGED = "staged"
RESULT_RETRYABLE = "retryable"
RESULT_GATE_FAILED = "gate_failed"
RESULT_DEFERRED = "deferred"
RESULT_STRUCTURAL_INELIGIBLE = "structural_ineligible"
RESULT_BLOCKED = "blocked"

# Health classifications surfaced in summary.json / README.md.
HEALTH_HEALTHY = "healthy_progress"
HEALTH_ACTIVE_NO_GREEN = "active_no_green"
HEALTH_POSSIBLY_STUCK = "possibly_stuck"  # telemetry only; never kills work
HEALTH_BLOCKED = "blocked"
HEALTH_MANUAL_PAUSED = "manual_paused"
HEALTH_PROVIDER_PAUSED = "provider_paused"
HEALTH_IDLE = "idle"
HEALTH_COMPLETE = "complete"

_UNSAFE = re.compile(r"[^A-Za-z0-9._-]+")


def stable_unit_id(name: str) -> str:
    """Filesystem-safe, stable, collision-free id for a queue unit name.

    Stable across runs (pure function of the name) and reversible enough to read:
    ``chunk_0021/unit_017`` -> ``chunk_0021__unit_017``.
    """
    return _UNSAFE.sub("_", str(name).replace("/", "__")).strip("_") or "unnamed"


def _parse_iso(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


@dataclass
class UnitTransition:
    """One durable record of a unit leaving the selector's hands."""

    unit: str
    result: str
    stage: str
    attempt: int = 0
    detail: str = ""
    product_commit: str | None = None
    product_pushed: bool | None = None
    oracle_summary: str | None = None
    model: str | None = None
    tier: str | None = None
    # True when this category was SUPPOSED to write the product repo and the
    # commit failed. Without it, a failed product commit is indistinguishable
    # from "this category does not touch the product tree by design".
    product_commit_failed: bool = False
    product_commit_detail: str = ""
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def product_effect(self) -> str:
        if self.product_commit:
            return "durable product commit"
        if self.product_commit_failed:
            return f"PRODUCT COMMIT FAILED: {self.product_commit_detail[:200]}"
        return "no product-tree change by design"

    def to_record(self, timestamp: str, run_id: str) -> dict[str, Any]:
        return {
            "schema": PROGRESS_SCHEMA,
            "unit": self.unit,
            "unit_id": stable_unit_id(self.unit),
            "timestamp": timestamp,
            "run_id": run_id,
            "result": self.result,
            "stage": self.stage,
            "attempt": self.attempt,
            "detail": self.detail[:2000],
            "product_commit": self.product_commit,
            "product_pushed": self.product_pushed,
            "product_effect": self.product_effect,
            "product_commit_failed": self.product_commit_failed,
            "oracle_summary": self.oracle_summary,
            "model": self.model,
            "tier": self.tier,
            **({"extra": self.extra} if self.extra else {}),
        }


@dataclass
class MachineState:
    """What the rig supervisor knows and the port driver does not."""

    workflow_state: str = "unknown"
    driver_status: str = "unknown"
    manual_paused: bool = False
    block_reason: str | None = None
    active_model: str | None = None
    context_length: int | None = None
    configured_model: str | None = None
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "workflow_state": self.workflow_state,
            "driver_status": self.driver_status,
            "manual_paused": self.manual_paused,
            "block_reason": self.block_reason,
            "active_model": self.active_model,
            "context_length": self.context_length,
            "configured_model": self.configured_model,
            "detail": self.detail,
        }


def classify_counts(units: dict[str, dict[str, Any]]) -> dict[str, int]:
    """Map driver unit records onto the progress vocabulary."""
    counts = {
        "total": len(units),
        "green": 0,
        "staged": 0,
        "retryable": 0,
        "untouched": 0,
        "deferred": 0,
        "structural_ineligible": 0,
        "active": 0,
        "total_attempts": 0,
    }
    for record in units.values():
        if not isinstance(record, dict):
            continue
        counts["total_attempts"] += int(record.get("attempts") or 0)
        status = record.get("status")
        if status == "green":
            if record.get("tier") == "compile_only":
                counts["staged"] += 1
            else:
                counts["green"] += 1
        elif status == "red_retryable":
            counts["retryable"] += 1
        elif status == "structural_ineligible":
            counts["structural_ineligible"] += 1
        elif status == "deferred":
            counts["deferred"] += 1
        elif status == "porting":
            counts["active"] += 1
        else:
            counts["untouched"] += 1
    return counts


class ProgressJournal:
    """Writes the ``port-progress`` branch. One writer at a time (file lock)."""

    def __init__(
        self,
        repo_root: str | Path,
        *,
        run_root: str | Path | None = None,
        branch: str = PROGRESS_BRANCH,
        worktree: str | Path | None = None,
        run_id: str = "",
        remote: str = "origin",
        git_runner: Callable[..., subprocess.CompletedProcess] | None = None,
        clock: Callable[[], float] = time.monotonic,
        enable_push: bool = True,
    ):
        self.repo_root = Path(repo_root).resolve()
        self.run_root = (
            Path(run_root)
            if run_root is not None
            else self.repo_root / "research/decomp/generated/finish-game-port"
        )
        self.branch = branch
        self.remote = remote
        self.worktree = Path(
            worktree if worktree is not None else self.repo_root / ".tmp/port-progress-worktree"
        )
        self.run_id = run_id or utc_now()
        self._git_runner = git_runner or self._git
        self.clock = clock
        self.enable_push = enable_push
        # Local durability lives OUTSIDE git so a git outage cannot lose a
        # transition (run_root is gitignored by design).
        self.local_dir = self.run_root / "progress"
        self.pending_path = self.local_dir / "pending-push.json"
        self.lock = DriverLock(self.run_root / "progress.lock")
        self._prepared = False
        # DriverLock opens its file with "x" and does not create parents; make
        # the journal usable the moment it is constructed.
        try:
            self.local_dir.mkdir(parents=True, exist_ok=True)
        except OSError:
            pass

    # --------------------------------------------------------------------- git

    def _git(self, *args: str, cwd: Path | None = None) -> subprocess.CompletedProcess:
        return subprocess.run(
            ["git", *args],
            cwd=str(cwd or self.repo_root),
            capture_output=True,
            text=True,
            timeout=GIT_TIMEOUT_SECONDS,
        )

    def _git_wt(self, *args: str) -> subprocess.CompletedProcess:
        return self._git_runner(*args, cwd=self.worktree)

    @property
    def progress_root(self) -> Path:
        return self.worktree / PROGRESS_DIR

    def _branch_exists_local(self) -> bool:
        return self._git_runner("rev-parse", "--verify", f"refs/heads/{self.branch}").returncode == 0

    def _branch_exists_remote(self) -> bool:
        result = self._git_runner("ls-remote", "--heads", self.remote, self.branch)
        return result.returncode == 0 and bool(result.stdout.strip())

    def _seed_branch(self) -> bool:
        """Create the orphan branch with git plumbing -- no checkout of the huge
        product tree, no temporary state in the product worktree."""
        readme = (
            f"# {PROGRESS_DIR}\n\nGenerated workflow journal for the GotYaForce port "
            "pipeline. Machine-written; do not edit by hand.\n"
        )
        # hash-object needs real stdin, so it bypasses the injected runner
        # (which never wires stdin -- an inherited stdin here would hang).
        blob = subprocess.run(
            ["git", "hash-object", "-w", "--stdin"],
            cwd=str(self.repo_root),
            input=readme,
            capture_output=True,
            text=True,
            timeout=GIT_TIMEOUT_SECONDS,
        )
        if blob.returncode != 0:
            return False
        sha = blob.stdout.strip()
        index = self.run_root / ".port-progress-index"
        index.parent.mkdir(parents=True, exist_ok=True)
        index.unlink(missing_ok=True)
        environment = {**os.environ, "GIT_INDEX_FILE": str(index)}

        def plumbing(*args: str, stdin: str | None = None) -> subprocess.CompletedProcess:
            return subprocess.run(
                ["git", *args],
                cwd=str(self.repo_root),
                env=environment,
                input=stdin,
                capture_output=True,
                text=True,
                timeout=GIT_TIMEOUT_SECONDS,
            )

        try:
            added = plumbing(
                "update-index", "--add", "--cacheinfo",
                f"100644,{sha},{PROGRESS_DIR}/README.md",
            )
            if added.returncode != 0:
                return False
            tree = plumbing("write-tree")
            if tree.returncode != 0:
                return False
            commit = plumbing(
                "commit-tree", tree.stdout.strip(), "-m",
                f"progress: initialise {self.branch} journal\n\n{GIT_TRAILER}",
            )
            if commit.returncode != 0:
                return False
            # The empty old-value means "must not already exist": without it a
            # seed can silently clobber an existing journal branch, and the only
            # thing standing between that and total loss is a separate rev-parse.
            return (
                self._git_runner(
                    "update-ref", f"refs/heads/{self.branch}",
                    commit.stdout.strip(), "",
                ).returncode
                == 0
            )
        finally:
            index.unlink(missing_ok=True)

    def _worktree_healthy(self) -> bool:
        if not self.worktree.is_dir():
            return False
        head = self._git_wt("rev-parse", "--abbrev-ref", "HEAD")
        if head.returncode != 0 or head.stdout.strip() != self.branch:
            return False
        # A stale index.lock -- the exact leftover a killed `git commit` leaves,
        # and supervisor kills are the NORMAL path here -- wedges every future
        # commit while `rev-parse` and even `status` keep succeeding, because
        # neither takes the index lock. Look for the lock itself, so prepare()
        # rebuilds instead of short-circuiting on a worktree that can never
        # commit again.
        git_dir = self._git_wt("rev-parse", "--absolute-git-dir")
        if git_dir.returncode != 0:
            return False
        if (Path(git_dir.stdout.strip()) / "index.lock").exists():
            return False
        # The journal directory must exist too: a worktree checked out at the
        # seed commit before the directory was created would otherwise be
        # "healthy" while every write lands outside git's view.
        self.progress_root.mkdir(parents=True, exist_ok=True)
        (self.progress_root / "units").mkdir(parents=True, exist_ok=True)
        return True

    def prepare(self) -> bool:
        """Ensure the branch and its dedicated worktree exist. Idempotent."""
        if self._prepared and self._worktree_healthy():
            return True
        if self._worktree_healthy():
            self._prepared = True
            return True
        self._git_runner("worktree", "prune")
        if self.worktree.exists():
            removed = self._git_runner("worktree", "remove", "--force", str(self.worktree))
            if removed.returncode != 0:
                # `--force` twice is what removes a LOCKED worktree; a single
                # --force reports "cannot remove a locked working tree".
                removed = self._git_runner(
                    "worktree", "remove", "--force", "--force", str(self.worktree)
                )
            if removed.returncode != 0 and self.worktree.exists():
                # Not a registered worktree at all (a leftover directory), which
                # makes `worktree add` fail forever with "already exists".
                try:
                    shutil.rmtree(self.worktree, ignore_errors=True)
                except OSError:
                    return False
            self._git_runner("worktree", "prune")
        if not self._branch_exists_local():
            if self._branch_exists_remote():
                fetched = self._git_runner(
                    "fetch", self.remote, f"{self.branch}:refs/heads/{self.branch}"
                )
                if fetched.returncode != 0 and not self._branch_exists_local():
                    return False
            elif not self._seed_branch():
                return False
        self.worktree.parent.mkdir(parents=True, exist_ok=True)
        added = self._git_runner("worktree", "add", str(self.worktree), self.branch)
        if added.returncode != 0:
            return False
        self.progress_root.mkdir(parents=True, exist_ok=True)
        (self.progress_root / "units").mkdir(parents=True, exist_ok=True)
        self._prepared = True
        return True

    # ------------------------------------------------------------------ local

    def _append_local_event(self, record: dict[str, Any]) -> None:
        self.local_dir.mkdir(parents=True, exist_ok=True)
        with (self.local_dir / "events.jsonl").open(
            "a", encoding="utf-8", newline="\n"
        ) as handle:
            handle.write(json.dumps(record, ensure_ascii=False, default=str) + "\n")

    def _read_pending(self) -> dict[str, Any]:
        try:
            payload = json.loads(self.pending_path.read_text(encoding="utf-8-sig"))
        except (OSError, json.JSONDecodeError, ValueError):
            return {"pending": False, "failures": 0}
        return payload if isinstance(payload, dict) else {"pending": False, "failures": 0}

    def _write_pending(self, pending: bool, detail: str = "", failures: int = 0) -> None:
        try:
            atomic_write_json(
                self.pending_path,
                {
                    "pending": pending,
                    "failures": failures,
                    "detail": detail[:600],
                    "updated_at": utc_now(),
                },
            )
        except OSError:
            pass  # telemetry about telemetry must never raise

    # ---------------------------------------------------------------- rendering

    def _local_events(self) -> list[dict[str, Any]]:
        try:
            lines = (self.local_dir / "events.jsonl").read_text(encoding="utf-8").splitlines()
        except OSError:
            return []
        records = []
        for line in lines[-MAX_EVENT_LINES:]:
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return records

    def _write_events(self, record: dict[str, Any]) -> list[dict[str, Any]]:
        """Append the record, replaying anything the branch missed.

        Transitions recorded while the worktree was unavailable exist only in
        the local mirror. Retrying the *push* would never bring them back, so
        the branch is reconciled against the mirror here: every local event
        newer than the branch's newest is replayed before the new one lands.
        """
        path = self.progress_root / "events.jsonl"
        path.parent.mkdir(parents=True, exist_ok=True)
        try:
            # errors="replace": a kill during the previous write can leave a
            # truncated multibyte sequence, and a strict read would then raise
            # on EVERY later checkpoint -- before reaching the write that would
            # have repaired the file. Permanently wedged, from one bad byte.
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            lines = []
        newest = None
        # Identity of what the branch already holds. Timestamp ordering alone is
        # not enough: two writers (the driver and the rig's `port-contract
        # checkpoint`) share the local mirror, so an event already on the branch
        # but not the newest line would be replayed again on every checkpoint.
        present: set[tuple[Any, Any, Any]] = set()
        for line in reversed(lines):
            try:
                parsed = json.loads(line)
            except json.JSONDecodeError:
                continue
            present.add((parsed.get("timestamp"), parsed.get("unit"), parsed.get("result")))
            if newest is None:
                newest = _parse_iso(parsed.get("timestamp"))
        for missed in self._local_events():
            stamp = _parse_iso(missed.get("timestamp"))
            if stamp is None or (newest is not None and stamp < newest):
                continue
            key = (missed.get("timestamp"), missed.get("unit"), missed.get("result"))
            if key in present:
                continue
            if key == (record.get("timestamp"), record.get("unit"), record.get("result")):
                continue  # the record being written now
            present.add(key)
            lines.append(json.dumps(missed, ensure_ascii=False, default=str))
        lines.append(json.dumps(record, ensure_ascii=False, default=str))
        lines = lines[-MAX_EVENT_LINES:]
        path.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
        parsed = []
        for line in lines:
            try:
                parsed.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return parsed

    @staticmethod
    def _health(
        counts: dict[str, int],
        machine: MachineState,
        transitions_last_hour: int,
        greens_last_hour: int,
        driver_running: bool,
    ) -> str:
        if machine.manual_paused:
            return HEALTH_MANUAL_PAUSED
        if machine.block_reason:
            return HEALTH_BLOCKED
        if machine.workflow_state == "provider_paused":
            return HEALTH_PROVIDER_PAUSED
        remaining = counts["total"] - counts["green"] - counts["staged"]
        if counts["total"] and remaining <= 0:
            return HEALTH_COMPLETE
        if machine.workflow_state == "complete":
            return HEALTH_COMPLETE
        if not driver_running:
            return HEALTH_IDLE
        if greens_last_hour > 0:
            return HEALTH_HEALTHY
        if transitions_last_hour > 0:
            return HEALTH_ACTIVE_NO_GREEN
        return HEALTH_POSSIBLY_STUCK  # telemetry only -- never kills work

    def _render_readme(
        self,
        current: dict[str, Any],
        summary: dict[str, Any],
        events: list[dict[str, Any]],
    ) -> str:
        state = summary.get("health", "unknown")
        banner = {
            HEALTH_MANUAL_PAUSED: "PAUSED",
            HEALTH_BLOCKED: "BLOCKED",
            HEALTH_PROVIDER_PAUSED: "PAUSED",
            HEALTH_COMPLETE: "COMPLETE",
            HEALTH_IDLE: "IDLE",
        }.get(state, "RUNNING")
        counts = summary
        done = counts.get("green", 0) + counts.get("staged", 0)
        total = counts.get("total_units", 0)
        lines = [
            f"# Port workflow: {banner}",
            "",
            f"*Generated {current.get('timestamp', '')} - machine-written, do not edit.*",
            "",
            "| | |",
            "|---|---|",
            f"| **State** | `{banner}` ({state}) |",
            f"| **Current unit** | `{current.get('current_unit') or '-'}` |",
            f"| **Current stage** | `{current.get('current_stage') or '-'}` (attempt "
            f"{current.get('current_attempt') or 0}) |",
            f"| **Queue progress** | {done}/{total} settled "
            f"({counts.get('green', 0)} green, {counts.get('staged', 0)} staged) |",
            f"| **Retries outstanding** | {counts.get('retryable', 0)} |",
            f"| **Untouched** | {counts.get('untouched', 0)} |",
            f"| **Last transition** | {current.get('last_transition') or '-'} |",
            f"| **Last green** | {counts.get('last_green_at') or 'never'} "
            f"(`{counts.get('last_green_unit') or '-'}`) |",
            f"| **Last product commit** | `{counts.get('last_product_commit') or '-'}` |",
            f"| **Current model** | "
            f"`{current.get('active_model') or current.get('configured_model') or '-'}` "
            f"@ {current.get('context_length') or '?'} ctx |",
            f"| **Driver** | {current.get('driver_status') or '-'} |",
        ]
        if current.get("block_reason"):
            lines += ["", f"> **Blocked:** {current['block_reason']}"]
        if current.get("manual_paused"):
            lines += ["", "> **Manually paused by the owner** (rig gate). No heavy work runs."]
        if summary.get("repeated_failure_classes"):
            lines += ["", "**Repeated recent failure classes**", ""]
            for label, count in summary["repeated_failure_classes"]:
                lines.append(f"- `{label}` x{count}")
        lines += ["", f"## Last {README_TRANSITIONS} transitions", ""]
        lines += ["| time | unit | result | stage | attempt | detail |", "|---|---|---|---|---|---|"]
        for record in reversed(events[-README_TRANSITIONS:]):
            detail = (record.get("detail") or "").replace("|", "\\|").replace("\n", " ")[:110]
            lines.append(
                f"| {record.get('timestamp', '')} | `{record.get('unit') or '-'}` "
                f"| {record.get('result', '')} | {record.get('stage', '')} "
                f"| {record.get('attempt', 0)} | {detail} |"
            )
        lines.append("")
        return "\n".join(lines)

    # -------------------------------------------------------------- checkpoint

    def checkpoint(
        self,
        *,
        transition: UnitTransition | None,
        units: dict[str, dict[str, Any]] | None = None,
        machine: MachineState | None = None,
        previous_unit: str | None = None,
        previous_result: str | None = None,
        current_unit: str | None = None,
        current_stage: str | None = None,
        current_attempt: int = 0,
        driver_running: bool = False,
        queue_counters: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Persist locally, snapshot, commit, push. Never raises for git reasons."""
        machine = machine or MachineState()
        units = units or {}
        timestamp = utc_now()
        record = (
            transition.to_record(timestamp, self.run_id)
            if transition is not None
            else {
                "schema": PROGRESS_SCHEMA,
                "unit": None,
                "unit_id": None,
                "timestamp": timestamp,
                "run_id": self.run_id,
                "result": machine.workflow_state,
                "stage": "machine",
                "attempt": 0,
                "detail": machine.detail,
            }
        )
        # 1. LOCAL durability first. Everything after this is best-effort.
        try:
            self._append_local_event(record)
        except OSError:
            pass

        try:
            return self._checkpoint_locked(
                record, transition, units, machine, previous_unit, previous_result,
                current_unit, current_stage, current_attempt, driver_running,
                queue_counters, timestamp,
            )
        except Exception as error:  # noqa: BLE001
            # The contract is "never raises". `port-contract checkpoint` is
            # invoked by the rig, where an escaping traceback becomes a failed
            # machine-state record; the driver's caller swallows it, but then the
            # branch dies silently. Degrade to a recorded pending instead.
            self._write_pending(
                True, f"checkpoint raised: {error}", self._read_pending().get("failures", 0) + 1
            )
            return {"recorded": True, "committed": False, "pushed": False,
                    "detail": f"checkpoint raised: {error}"}

    def _checkpoint_locked(
        self,
        record: dict[str, Any],
        transition: UnitTransition | None,
        units: dict[str, dict[str, Any]],
        machine: MachineState,
        previous_unit: str | None,
        previous_result: str | None,
        current_unit: str | None,
        current_stage: str | None,
        current_attempt: int,
        driver_running: bool,
        queue_counters: dict[str, Any] | None,
        timestamp: str,
    ) -> dict[str, Any]:
        result: dict[str, Any] = {"recorded": True, "committed": False, "pushed": False}
        if not self.lock.acquire():
            # The driver can hold this lock for the length of a push. A pause or
            # block issued in that window would otherwise never reach
            # current.json, and GitHub would keep rendering RUNNING over a
            # paused machine. Record it so the next checkpoint replays it from
            # the local mirror.
            result["detail"] = "another writer holds progress.lock"
            self._write_pending(True, "checkpoint skipped: progress.lock contended",
                                self._read_pending().get("failures", 0) + 1)
            return result
        try:
            if not self.prepare():
                self._write_pending(True, "worktree/branch unavailable", self._read_pending().get("failures", 0) + 1)
                result["detail"] = "progress worktree unavailable"
                return result
            events = self._write_events(record)
            counts = classify_counts(units)
            summary = self._build_summary(counts, events, machine, driver_running)
            current = {
                "schema": PROGRESS_SCHEMA,
                "timestamp": timestamp,
                "run_id": self.run_id,
                "port_mode": os.environ.get("OGHIDRA_PORT_MODE", "") or "wasm_units",
                "workflow_state": machine.workflow_state,
                "current_unit": current_unit,
                "previous_unit": previous_unit,
                "previous_result": previous_result,
                "current_stage": current_stage,
                "current_attempt": current_attempt,
                "active_model": machine.active_model,
                "configured_model": machine.configured_model,
                "context_length": machine.context_length,
                "driver_status": machine.driver_status,
                "driver_running": driver_running,
                "last_transition": timestamp,
                "last_green": summary.get("last_green_at"),
                "last_product_commit": summary.get("last_product_commit"),
                "block_reason": machine.block_reason,
                "manual_paused": machine.manual_paused,
                "queue": queue_counters or {
                    "total": counts["total"],
                    "green": counts["green"],
                    "staged": counts["staged"],
                    "retryable": counts["retryable"],
                    "untouched": counts["untouched"],
                    "active": counts["active"],
                },
            }
            atomic_write_json(self.progress_root / "current.json", current)
            atomic_write_json(self.progress_root / "summary.json", summary)
            if transition is not None:
                unit_path = self.progress_root / "units" / f"{stable_unit_id(transition.unit)}.json"
                atomic_write_json(unit_path, self._unit_file(unit_path, record, units))
            (self.progress_root / "README.md").write_text(
                self._render_readme(current, summary, events), encoding="utf-8", newline="\n"
            )
            # Mirror current/summary locally so the rig dashboard can read them
            # without going through git.
            try:
                atomic_write_json(self.local_dir / "current.json", current)
                atomic_write_json(self.local_dir / "summary.json", summary)
            except OSError:
                pass

            subject = self._commit_subject(transition, machine, counts, current_unit)
            result.update(self._commit_and_push(subject))
            result["health"] = summary["health"]
        finally:
            self.lock.release()
        return result

    def _unit_file(
        self,
        path: Path,
        record: dict[str, Any],
        units: dict[str, dict[str, Any]],
    ) -> dict[str, Any]:
        try:
            existing = json.loads(path.read_text(encoding="utf-8-sig"))
        except (OSError, json.JSONDecodeError, ValueError):
            existing = {}
        history = existing.get("history") if isinstance(existing, dict) else None
        history = history if isinstance(history, list) else []
        history.append(
            {
                "timestamp": record["timestamp"],
                "result": record["result"],
                "stage": record["stage"],
                "attempt": record["attempt"],
                "detail": record["detail"][:400],
                "product_commit": record.get("product_commit"),
            }
        )
        driver_record = units.get(record["unit"]) if record.get("unit") else None
        return {
            **record,
            "driver_record": driver_record,
            "history": history[-50:],
        }

    def _build_summary(
        self,
        counts: dict[str, int],
        events: list[dict[str, Any]],
        machine: MachineState,
        driver_running: bool,
    ) -> dict[str, Any]:
        now = datetime.now(timezone.utc)
        hour_ago = now - timedelta(hours=1)
        transitions_last_hour = 0
        greens_last_hour = 0
        last_green_at = None
        last_green_unit = None
        last_product_commit = None
        failure_classes: dict[str, int] = {}
        for record in events:
            stamp = _parse_iso(record.get("timestamp"))
            if record.get("unit") and stamp and stamp >= hour_ago:
                transitions_last_hour += 1
                if record.get("result") in (RESULT_GREEN, RESULT_STAGED):
                    greens_last_hour += 1
            if record.get("result") in (RESULT_GREEN, RESULT_STAGED):
                last_green_at = record.get("timestamp")
                last_green_unit = record.get("unit")
            if record.get("product_commit"):
                last_product_commit = record["product_commit"]
            if record.get("result") in (
                RESULT_RETRYABLE, RESULT_GATE_FAILED, RESULT_STRUCTURAL_INELIGIBLE
            ) and stamp and stamp >= hour_ago:
                label = f"{record.get('stage')}:{(record.get('detail') or '')[:60]}"
                failure_classes[label] = failure_classes.get(label, 0) + 1
        repeated = sorted(
            ((label, count) for label, count in failure_classes.items() if count > 1),
            key=lambda item: -item[1],
        )[:5]
        return {
            "schema": PROGRESS_SCHEMA,
            "generated_at": utc_now(),
            "run_id": self.run_id,
            "total_units": counts["total"],
            "green": counts["green"],
            "staged": counts["staged"],
            "retryable": counts["retryable"],
            "untouched": counts["untouched"],
            "deferred": counts["deferred"],
            "structural_ineligible": counts["structural_ineligible"],
            "active": counts["active"],
            "total_attempts": counts["total_attempts"],
            "transitions_last_hour": transitions_last_hour,
            "greens_last_hour": greens_last_hour,
            "last_green_at": last_green_at,
            "last_green_unit": last_green_unit,
            "last_product_commit": last_product_commit,
            "repeated_failure_classes": repeated,
            "health": self._health(
                counts, machine, transitions_last_hour, greens_last_hour, driver_running
            ),
            "machine": machine.to_dict(),
        }

    @staticmethod
    def _commit_subject(
        transition: UnitTransition | None,
        machine: MachineState,
        counts: dict[str, int],
        current_unit: str | None = None,
    ) -> str:
        if transition is None:
            # Machine-state records still name the unit in flight when there is
            # one, so `git log --oneline` alone answers "which unit was this
            # about?" for every commit on the branch.
            unit = f" [{current_unit}]" if current_unit else " [no unit in flight]"
            return (
                f"progress: rig {machine.workflow_state}{unit} - "
                f"{machine.detail[:60] or 'state change'}"
            )
        settled = counts["green"] + counts["staged"]
        if transition.result in (RESULT_GREEN, RESULT_STAGED):
            return (
                f"progress: {transition.unit} {transition.result} "
                f"{settled}/{counts['total']}"
            )
        return f"progress: {transition.unit} {transition.result} at {transition.stage}"

    # --------------------------------------------------------------- git write

    def _commit_and_push(self, subject: str) -> dict[str, Any]:
        added = self._git_wt("add", "--", PROGRESS_DIR)
        if added.returncode != 0:
            return {"committed": False, "pushed": False, "detail": (added.stderr or "")[-300:]}
        committed = self._git_wt("commit", "-m", f"{subject}\n\n{GIT_TRAILER}")
        if committed.returncode != 0:
            combined = (committed.stdout + committed.stderr).lower()
            if "nothing to commit" in combined or "no changes added" in combined:
                return {"committed": False, "pushed": False, "detail": "no changes"}
            detail = (committed.stdout + committed.stderr)[-300:]
            # A commit that failed for a real reason leaves work unpublished;
            # record it as pending so a later transition retries the push AND
            # carries these changes with it.
            self._write_pending(True, f"commit failed: {detail}", self._read_pending().get("failures", 0) + 1)
            return {"committed": False, "pushed": False, "detail": detail}
        outcome: dict[str, Any] = {"committed": True, "pushed": False}
        head = self._git_wt("rev-parse", "HEAD")
        if head.returncode == 0:
            outcome["commit"] = head.stdout.strip()
        if not self.enable_push:
            outcome["detail"] = "push disabled"
            return outcome
        outcome.update(self.flush_pending_push())
        return outcome

    def flush_pending_push(self) -> dict[str, Any]:
        """Push the branch; on failure record pending and keep working.

        A GitHub outage must never fail a unit, so every failure path here is a
        recorded fact, not an exception.
        """
        pending = self._read_pending()
        failures = int(pending.get("failures") or 0)
        if not self.worktree.is_dir() and not self.prepare():
            self._write_pending(True, "progress worktree unavailable", failures + 1)
            return {"pushed": False, "push_pending": True,
                    "push_detail": "progress worktree unavailable"}
        pushed = self._git_wt("push", self.remote, f"{self.branch}:{self.branch}")
        if pushed.returncode == 0:
            self._write_pending(False, "", 0)
            return {"pushed": True, "push_pending": False}
        detail = (pushed.stdout + pushed.stderr)[-400:]
        failures += 1
        # Non-fast-forward means the remote moved (another machine/worktree).
        # Reconcile with our generated state winning; the branch is a machine
        # journal, not shared source.
        if "non-fast-forward" in detail or "fetch first" in detail or "rejected" in detail:
            self._git_runner("fetch", self.remote, f"{self.branch}:refs/remotes/{self.remote}/{self.branch}")
            merged = self._git_wt(
                "merge", "-X", "ours", "--no-edit", f"{self.remote}/{self.branch}"
            )
            if merged.returncode == 0:
                retry = self._git_wt("push", self.remote, f"{self.branch}:{self.branch}")
                if retry.returncode == 0:
                    self._write_pending(False, "", 0)
                    return {"pushed": True, "push_pending": False, "reconciled": True}
                detail = (retry.stdout + retry.stderr)[-400:]
            elif "unrelated histories" in (merged.stdout + merged.stderr).lower():
                # Our branch was seeded locally while ls-remote was unreachable,
                # so the remote already had a different journal. The branch is a
                # machine journal, not shared source: adopt the remote's history
                # and replay onto it rather than pushing forever into a wall.
                detail = "unrelated histories; re-seeding from the remote journal"
                self._git_runner("worktree", "remove", "--force", str(self.worktree))
                self._git_runner("branch", "-D", self.branch)
                self._prepared = False
                self.prepare()
            else:
                self._git_wt("merge", "--abort")
        self._write_pending(True, detail, failures)
        return {"pushed": False, "push_pending": True, "push_detail": detail}

    def push_is_pending(self) -> bool:
        return bool(self._read_pending().get("pending"))


def journal_for(
    repo_root: str | Path,
    *,
    run_root: str | Path | None = None,
    run_id: str = "",
    enable_push: bool | None = None,
) -> ProgressJournal:
    """Factory honouring ``OGHIDRA_PROGRESS_DISABLE_PUSH`` (used by tests)."""
    if enable_push is None:
        enable_push = os.environ.get("OGHIDRA_PROGRESS_DISABLE_PUSH", "") not in ("1", "true", "True")
    return ProgressJournal(
        repo_root, run_root=run_root, run_id=run_id, enable_push=enable_push
    )
