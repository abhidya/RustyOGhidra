"""Durable process control for the GotYaForce autonomous port runner."""

from __future__ import annotations

import json
import os
import shutil
import statistics
import subprocess
import sys
import time
import webbrowser
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal


RunMode = Literal["fresh", "resume", "replay"]


def find_gotyaforce_root(start: str | Path | None = None) -> Path:
    """Locate the checkout that owns the autonomous pnpm scripts."""
    origin = Path(start).resolve() if start is not None else Path(__file__).resolve()
    candidates = [origin, *origin.parents] if origin.is_dir() else [origin.parent, *origin.parents]
    for candidate in candidates:
        package = candidate / "package.json"
        controller = candidate / "scripts" / "finish-game-port-poc.mjs"
        if package.is_file() and controller.is_file():
            return candidate
    raise FileNotFoundError("Could not locate GotYaForce root from OGhidra")


def _read_json(path: Path, fallback: Any) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return fallback


def _atomic_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(f"{path.suffix}.{os.getpid()}.tmp")
    temporary.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def _pid_alive(pid: int | None) -> bool:
    if not pid or pid <= 0:
        return False
    if os.name == "nt":
        import ctypes

        process_query_limited_information = 0x1000
        still_active = 259
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.OpenProcess(process_query_limited_information, False, pid)
        if not handle:
            return False
        try:
            exit_code = ctypes.c_ulong()
            return bool(kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code))) and exit_code.value == still_active
        finally:
            kernel32.CloseHandle(handle)
    try:
        os.kill(pid, 0)
    except (OSError, ValueError):
        return False
    return True


def _parse_timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=timezone.utc)


def _seconds_between(start: Any, end: Any) -> float | None:
    started = _parse_timestamp(start)
    finished = _parse_timestamp(end)
    if started is None or finished is None:
        return None
    return max(0.0, (finished - started).total_seconds())


def format_duration(seconds: float | None) -> str:
    """Render a duration without implying precision the telemetry does not have."""
    if seconds is None:
        return "Calibrating"
    rounded = max(0, round(seconds))
    hours, remainder = divmod(rounded, 3600)
    minutes, remaining_seconds = divmod(remainder, 60)
    if hours:
        return f"{hours}h {minutes:02d}m"
    if minutes:
        return f"{minutes}m {remaining_seconds:02d}s"
    return f"{remaining_seconds}s"


@dataclass(frozen=True)
class PortRunSnapshot:
    status: str = "not_started"
    run_mode: str = "unknown"
    objective: str = "Finish the GotYaForce browser port autonomously"
    current_stage: str | None = None
    completed_stages: int = 0
    total_stages: int = 0
    progress_percent: float = 0.0
    stages: tuple[dict[str, Any], ...] = ()
    queue: tuple[dict[str, Any], ...] = ()
    promotion: dict[str, Any] = field(default_factory=dict)
    updated_at: str | None = None
    elapsed_seconds: float = 0.0
    eta_seconds: float | None = None
    eta_source: str = "calibrating"
    stages_per_minute: float = 0.0
    completed_work: int = 0
    total_work: int = 0
    items_per_second: float = 0.0
    queue_summary: dict[str, int] = field(default_factory=dict)
    prompt_tokens: int = 0
    completion_tokens: int = 0
    tokens_per_second: float = 0.0
    token_source: str = "unavailable"
    llm_api_calls: int = 0
    structured_tool_calls: int = 0
    ghidra_tool_calls: int = 0
    ghidra_tool_call_breakdown: dict[str, int] = field(default_factory=dict)
    model_active: bool = False
    model_status: str = "idle"
    session_path: str | None = None
    session_role: str = "none"
    vectors_required: bool = False


class PortRunController:
    """Start, observe, pause, resume, and preview the detached port process."""

    def __init__(self, repo_root: str | Path | None = None):
        self.repo_root = find_gotyaforce_root(repo_root)
        self.oghidra_root = self.repo_root / "research" / "tools" / "OGhidra"
        self.run_root = self.repo_root / "research" / "decomp" / "generated" / "finish-game-port"
        self.state_path = self.run_root / "run-state.json"
        self.control_path = self.run_root / "control.json"
        self.metadata_path = self.run_root / "gui-process.json"
        self.log_path = self.run_root / "gui-controller.log"
        self.activity_path = self.run_root / "activity.jsonl"
        self.preview_metadata_path = self.run_root / "gui-preview.json"
        self.preview_log_path = self.run_root / "gui-preview.log"
        self.liveness_path = self.run_root / "llm-liveness.json"
        self.history_path = self.run_root / "gui-run-history.json"
        self.evidence_path = self.run_root / "collection-metrics.json"
        self._process: subprocess.Popen | None = None
        self._preview_process: subprocess.Popen | None = None
        self._log_offset = 0
        self._activity_offset = 0

    def _pnpm(self) -> str:
        executable = shutil.which("pnpm.cmd" if os.name == "nt" else "pnpm")
        if executable:
            return executable
        executable = shutil.which("pnpm")
        if executable:
            return executable
        raise FileNotFoundError("pnpm is not available on PATH")

    @staticmethod
    def _detached_options() -> dict[str, Any]:
        if os.name == "nt":
            return {
                "creationflags": (
                    getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
                    | getattr(subprocess, "CREATE_NO_WINDOW", 0)
                )
            }
        return {"start_new_session": True}

    def command_for(self, mode: RunMode) -> list[str]:
        if mode not in {"fresh", "resume", "replay"}:
            raise ValueError(f"unknown port-run mode: {mode}")
        python = self.oghidra_root / ".venv" / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
        if not python.is_file():
            python = Path(sys.executable)
        return [
            str(python),
            str(self.oghidra_root / "main.py"),
            "finish-port",
            "--mode",
            mode,
        ]

    def process_pid(self) -> int | None:
        if self._process is not None and self._process.poll() is None:
            return self._process.pid
        metadata = _read_json(self.metadata_path, {})
        pid = metadata.get("pid")
        return int(pid) if isinstance(pid, int) and _pid_alive(pid) else None

    def is_running(self) -> bool:
        return self.process_pid() is not None

    def recommended_mode(self) -> RunMode:
        payload = _read_json(self.state_path, {})
        manifest = self.run_root / "whole-program-manifest.json"
        resumable_status = payload.get("status") in {
            "partial",
            "paused",
            "stopped",
            "failed",
            "blocked",
        }
        stale_running_status = payload.get("status") == "running" and not self.is_running()
        if manifest.is_file() and (resumable_status or stale_running_status):
            return "resume"
        return "fresh"

    def start(self, mode: RunMode = "fresh", session_path: str | Path | None = None) -> int:
        active = self.process_pid()
        if active:
            return active
        self.run_root.mkdir(parents=True, exist_ok=True)
        self.set_control("run")
        command = self.command_for(mode)
        resolved_session = None
        if session_path is not None:
            candidate = Path(session_path).resolve()
            if candidate.is_file():
                resolved_session = candidate
        environment = {
            **os.environ,
            "OGHIDRA_GUI_CONTROLLED": "1",
            "OGHIDRA_PORT_LIVENESS_PATH": str(self.liveness_path),
        }
        if resolved_session is not None:
            environment["OGHIDRA_ACTIVE_SESSION"] = str(resolved_session)
        with self.log_path.open("a", encoding="utf-8", newline="\n") as log:
            log.write(f"\n[{time.strftime('%Y-%m-%d %H:%M:%S')}] GUI start: {' '.join(command)}\n")
            log.flush()
            self._process = subprocess.Popen(
                command,
                cwd=self.repo_root,
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=log,
                stderr=subprocess.STDOUT,
                close_fds=True,
                **self._detached_options(),
            )
        _atomic_json(
            self.metadata_path,
            {
                "pid": self._process.pid,
                "mode": mode,
                "command": command,
                "started_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
                "log": str(self.log_path),
                "session_path": str(resolved_session) if resolved_session else None,
                "session_role": "advisory" if resolved_session else "none",
                "vectors_required": False,
            },
        )
        return self._process.pid

    def set_control(self, command: Literal["run", "pause_after_stage", "stop_after_stage"]) -> None:
        _atomic_json(
            self.control_path,
            {"command": command, "updated_at": time.strftime("%Y-%m-%dT%H:%M:%S")},
        )

    def pause(self) -> None:
        self.set_control("pause_after_stage")

    def resume(self, session_path: str | Path | None = None) -> int:
        if self.is_running():
            self.set_control("run")
            return self.process_pid() or 0
        return self.start("resume", session_path=session_path)

    def stop_after_stage(self) -> None:
        self.set_control("stop_after_stage")

    def _stop_worker_tree(self) -> None:
        pid = self.process_pid()
        if pid is None:
            return
        if os.name == "nt":
            subprocess.run(
                ["taskkill", "/PID", str(pid), "/T", "/F"],
                capture_output=True,
                text=True,
                check=False,
            )
        elif self._process is not None:
            self._process.terminate()
            try:
                self._process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._process.kill()
        self._process = None

    def _restore_active_source(self, state: dict[str, Any]) -> None:
        active = next(
            (
                item
                for item in state.get("queue", [])
                if isinstance(item, dict) and item.get("status") == "model_running"
            ),
            None,
        )
        address = str(active.get("address") or "") if active else ""
        if not address:
            return
        checkpoint_root = self.run_root / "source-checkpoints" / address.removeprefix("0x")
        original_manifest = _read_json(checkpoint_root / "original-source.json", {})
        files = original_manifest.get("files", {}) if isinstance(original_manifest, dict) else {}
        for relative, original in files.items():
            if not isinstance(relative, str) or not isinstance(original, dict):
                continue
            target = (self.repo_root / relative).resolve()
            if self.repo_root.resolve() not in target.parents:
                continue
            if original.get("existed"):
                backup_value = original.get("backup")
                backup = Path(backup_value).resolve() if isinstance(backup_value, str) else None
                if backup and backup.is_file() and checkpoint_root.resolve() in backup.parents:
                    target.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(backup, target)
            elif target.is_file():
                target.unlink()

    def clear_failed_and_restart(
        self,
        session_path: str | Path | None = None,
    ) -> dict[str, Any]:
        """Archive failed diagnostics, requeue failed units, and start one clean resume."""
        self._stop_worker_tree()
        state = _read_json(self.state_path, {})
        self._restore_active_source(state if isinstance(state, dict) else {})

        manifest = _read_json(self.run_root / "whole-program-manifest.json", {})
        functions = manifest.get("functions", {}) if isinstance(manifest, dict) else {}
        reset_count = 0
        for record in functions.values():
            if not isinstance(record, dict):
                continue
            if record.get("port_status") in {"model_invalid", "model_running"}:
                reset_count += 1
                for key in ("port_status", "group_id", "canonical_address"):
                    record.pop(key, None)
        manifest["groups"] = {}
        manifest["schedule"] = []
        manifest["groups_complete"] = False
        manifest["bundles_complete"] = all(
            isinstance(record, dict) and record.get("status") != "discovered"
            for record in functions.values()
        )

        local_root = Path(
            os.getenv("LOCALAPPDATA", str(self.run_root.parent))
        ).resolve()
        archive = (
            local_root
            / "OGhidra"
            / "finish-game-port-archives"
            / f"{datetime.now().strftime('%Y%m%d-%H%M%S-%f')}-model-reset"
        )
        archive.mkdir(parents=True, exist_ok=False)
        for name in (
            "source-checkpoints",
            "activity.jsonl",
            "llm-liveness.json",
            "run-state.json",
            "gui-controller.log",
            "gui-process.json",
            "scheduler.log",
            "scheduler.err.log",
        ):
            source = (self.run_root / name).resolve()
            if source.exists() and source.parent == self.run_root.resolve():
                shutil.move(str(source), str(archive / name))

        _atomic_json(self.run_root / "whole-program-manifest.json", manifest)
        self._activity_offset = 0
        self._log_offset = 0
        pid = self.start("resume", session_path=session_path)
        return {
            "pid": pid,
            "archive": str(archive),
            "reset_functions": reset_count,
            "total_functions": len(functions),
            "preserved_bundles": sum(
                isinstance(record, dict) and record.get("status") == "bundled"
                for record in functions.values()
            ),
        }

    def _record_completed_run(self, payload: dict[str, Any]) -> None:
        if payload.get("status") != "completed" or not payload.get("started_at"):
            return
        history = _read_json(self.history_path, {"runs": []})
        runs = history.get("runs") if isinstance(history, dict) else None
        if not isinstance(runs, list):
            runs = []
        if any(item.get("started_at") == payload["started_at"] for item in runs if isinstance(item, dict)):
            return
        raw_stages = payload.get("stages") if isinstance(payload.get("stages"), dict) else {}
        durations = {
            stage_id: duration
            for stage_id, stage in raw_stages.items()
            if isinstance(stage, dict)
            and (duration := _seconds_between(stage.get("started_at"), stage.get("finished_at"))) is not None
        }
        runs.append(
            {
                "started_at": payload["started_at"],
                "completed_at": payload.get("completed_at") or payload.get("updated_at"),
                "run_mode": payload.get("run_mode", "unknown"),
                "stage_durations_seconds": durations,
            }
        )
        _atomic_json(self.history_path, {"schema": 1, "runs": runs[-20:]})

    def _elapsed_and_eta(
        self,
        payload: dict[str, Any],
        stages: tuple[dict[str, Any], ...],
    ) -> tuple[float, float | None, str]:
        started = _parse_timestamp(payload.get("started_at"))
        if started is None:
            return 0.0, None, "calibrating"
        terminal = payload.get("status") in {"completed", "failed", "stopped"}
        end = (
            _parse_timestamp(payload.get("completed_at"))
            or _parse_timestamp(payload.get("failed_at"))
            or _parse_timestamp(payload.get("stopped_at"))
            or _parse_timestamp(payload.get("updated_at"))
            if terminal
            else datetime.now(timezone.utc)
        )
        elapsed = max(0.0, ((end or datetime.now(timezone.utc)) - started).total_seconds())
        if payload.get("status") == "completed":
            return elapsed, 0.0, "complete"

        history = _read_json(self.history_path, {"runs": []})
        runs = history.get("runs", []) if isinstance(history, dict) else []
        mode = payload.get("run_mode", "unknown")
        compatible = [
            item for item in runs
            if isinstance(item, dict)
            and item.get("run_mode") == mode
            and isinstance(item.get("stage_durations_seconds"), dict)
        ]
        remaining = [stage for stage in stages if stage.get("status") != "passed"]
        if not remaining or not compatible:
            return elapsed, None, "calibrating"

        eta = 0.0
        now = datetime.now(timezone.utc)
        for stage in remaining:
            stage_id = str(stage.get("id"))
            samples = [
                float(item["stage_durations_seconds"][stage_id])
                for item in compatible
                if isinstance(item["stage_durations_seconds"].get(stage_id), (int, float))
            ]
            if not samples:
                return elapsed, None, "calibrating"
            estimate = statistics.median(samples)
            if stage.get("status") == "running":
                stage_started = _parse_timestamp(stage.get("started_at"))
                if stage_started is not None:
                    estimate = max(0.0, estimate - (now - stage_started).total_seconds())
            eta += estimate
        return elapsed, eta, "historical_stage_median"

    def snapshot(self) -> PortRunSnapshot:
        payload = _read_json(self.state_path, {})
        self._record_completed_run(payload)
        raw_stages = payload.get("stages") if isinstance(payload.get("stages"), dict) else {}
        stages = tuple(
            {"id": stage_id, **stage}
            for stage_id, stage in raw_stages.items()
            if isinstance(stage, dict)
        )
        completed = sum(stage.get("status") == "passed" for stage in stages)
        configured_total = payload.get("total_stages")
        total = (
            int(configured_total)
            if isinstance(configured_total, int) and configured_total >= len(stages)
            else len(stages)
        )
        scope = payload.get("scope") if isinstance(payload.get("scope"), dict) else {}
        queue_payload = payload.get("queue")
        if not isinstance(queue_payload, list):
            queue_payload = [
                {
                    "address": scope.get("function_address", "0x8012b458"),
                    "family": scope.get("production_family", "Eagle Jet"),
                    "status": payload.get("promotion", {}).get("status", payload.get("status", "queued")),
                }
            ] if payload else []
        elapsed, eta, eta_source = self._elapsed_and_eta(payload, stages)
        work_progress = payload.get("progress") if isinstance(payload.get("progress"), dict) else {}
        if isinstance(work_progress.get("percent"), (int, float)):
            progress_percent = float(work_progress["percent"])
        else:
            progress_percent = (completed / total * 100.0) if total else 0.0
        if isinstance(work_progress.get("eta_seconds"), (int, float)):
            eta = float(work_progress["eta_seconds"])
            eta_source = str(work_progress.get("eta_source", "observed_unit_rate"))
        liveness = _read_json(self.liveness_path, {})
        evidence = _read_json(self.evidence_path, {})
        collection = evidence.get("collection_metrics") if isinstance(evidence, dict) else {}
        if not isinstance(collection, dict):
            collection = {}
        breakdown = collection.get("tool_call_breakdown", collection.get("breakdown"))
        if not isinstance(breakdown, dict):
            breakdown = {}
        process_metadata = _read_json(self.metadata_path, {})
        session = payload.get("session") if isinstance(payload.get("session"), dict) else {}
        session_path = session.get("path") or process_metadata.get("session_path")
        session_role = session.get("role") or process_metadata.get("session_role") or "none"
        return PortRunSnapshot(
            status=str(payload.get("status", "not_started")),
            run_mode=str(payload.get("run_mode", "unknown")),
            objective=str(payload.get("objective", "Finish the GotYaForce browser port autonomously")),
            current_stage=payload.get("current_stage"),
            completed_stages=completed,
            total_stages=total,
            progress_percent=progress_percent,
            stages=stages,
            queue=tuple(item for item in queue_payload if isinstance(item, dict)),
            promotion=payload.get("promotion") if isinstance(payload.get("promotion"), dict) else {},
            updated_at=payload.get("updated_at"),
            elapsed_seconds=elapsed,
            eta_seconds=eta,
            eta_source=eta_source,
            stages_per_minute=(completed / elapsed * 60.0) if elapsed else 0.0,
            completed_work=int(work_progress.get("completed_work", 0) or 0),
            total_work=int(work_progress.get("total_work", 0) or 0),
            items_per_second=float(work_progress.get("items_per_second", 0.0) or 0.0),
            queue_summary={
                str(key): int(value)
                for key, value in (
                    payload.get("queue_summary", {})
                    if isinstance(payload.get("queue_summary"), dict)
                    else {}
                ).items()
                if isinstance(value, int)
            },
            prompt_tokens=int(liveness.get("prompt_tokens", 0) or 0),
            completion_tokens=int(liveness.get("completion_tokens", 0) or 0),
            tokens_per_second=float(liveness.get("tokens_per_second", 0.0) or 0.0),
            token_source=str(liveness.get("token_source", "unavailable")),
            llm_api_calls=int(liveness.get("api_calls", 0) or 0),
            structured_tool_calls=int(liveness.get("structured_tool_calls", 0) or 0),
            ghidra_tool_calls=int(collection.get("tool_calls", 0) or 0),
            ghidra_tool_call_breakdown={
                str(key): int(value)
                for key, value in breakdown.items()
                if isinstance(value, int)
            },
            model_active=bool(liveness.get("active", False)),
            model_status=str(liveness.get("status", "idle")),
            session_path=str(session_path) if session_path else None,
            session_role=str(session_role),
            vectors_required=False,
        )

    def read_log_delta(self) -> str:
        try:
            size = self.log_path.stat().st_size
        except FileNotFoundError:
            return ""
        if size < self._log_offset:
            self._log_offset = 0
        with self.log_path.open("r", encoding="utf-8", errors="replace") as handle:
            handle.seek(self._log_offset)
            value = handle.read()
            self._log_offset = handle.tell()
        return value

    def read_activity_delta(self) -> list[dict[str, Any]]:
        initial_tail_bytes = 192 * 1024
        poll_bytes = 64 * 1024
        max_events = 500
        try:
            size = self.activity_path.stat().st_size
        except FileNotFoundError:
            return []
        if size < self._activity_offset:
            self._activity_offset = 0
        lines: list[bytes] = []
        with self.activity_path.open("rb") as handle:
            if self._activity_offset == 0 and size > initial_tail_bytes:
                handle.seek(size - initial_tail_bytes)
                handle.readline()  # discard the partial JSONL record
                self._activity_offset = handle.tell()
            else:
                handle.seek(self._activity_offset)

            start = handle.tell()
            while len(lines) < max_events and handle.tell() - start < poll_bytes:
                line_start = handle.tell()
                line = handle.readline()
                if not line:
                    break
                if not line.endswith(b"\n"):
                    handle.seek(line_start)
                    break
                lines.append(line)
            self._activity_offset = handle.tell()
        events = []
        for line in lines:
            try:
                event = json.loads(line.decode("utf-8", errors="replace"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                continue
            if isinstance(event, dict):
                events.append(event)
        return events

    def start_preview(self) -> str:
        metadata = _read_json(self.preview_metadata_path, {})
        pid = metadata.get("pid")
        url = "http://127.0.0.1:4173/"
        if isinstance(pid, int) and _pid_alive(pid):
            webbrowser.open(url)
            return url
        command = [
            self._pnpm(),
            "--filter",
            "game",
            "preview",
            "--host",
            "127.0.0.1",
            "--port",
            "4173",
            "--strictPort",
        ]
        with self.preview_log_path.open("a", encoding="utf-8", newline="\n") as log:
            self._preview_process = subprocess.Popen(
                command,
                cwd=self.repo_root,
                stdin=subprocess.DEVNULL,
                stdout=log,
                stderr=subprocess.STDOUT,
                close_fds=True,
                **self._detached_options(),
            )
        _atomic_json(
            self.preview_metadata_path,
            {"pid": self._preview_process.pid, "url": url, "started_at": time.strftime("%Y-%m-%dT%H:%M:%S")},
        )
        webbrowser.open(url)
        return url

    def detach(self) -> None:
        """Detach the UI without terminating durable port or preview processes."""
        self._process = None
        self._preview_process = None
