"""Autonomous driver for the chunk/unit port pipeline (rig task #20, design D1-D6).

Policy lives here; ChunkPortWorkflow / SequentialSourcePortLoop stay mechanisms.
One invocation performs one durable step (analyze-if-needed OR port-one-unit) and
exits, so a SIGKILL loses at most one in-flight request; the supervisor relaunches
to advance. Durable truth is port-ledger.json (atomic writes, single writer via
driver.lock); run-state.json stays the live GUI snapshot.

Exit codes: 0 no-work-left | 2 stopped | 3 progressed-more-remains |
4 provider-paused | 5 another driver holds the lock.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any

from src.port_chunk_workflow import (
    ChunkAnalysis,
    ChunkPortWorkflow,
    ExecutionUnit,
    ProviderUnavailable,
    UnitSkipResult,
    atomic_write_json,
    normalize_address,
    normalize_chunk_name,
    unit_eligibility,
    utc_now,
)
from src.port_run_controller import _pid_alive, find_gotyaforce_root


LEDGER_SCHEMA = 1
EVENTS_ROTATE_BYTES = 32 * 1024 * 1024
# Refuse to write a session index that lost most of the corpus (G21): the real
# corpus carries ~6,580 curated function summaries.
SESSION_INDEX_FLOOR = 1000
SESSION_SUMMARY_CHARS = 600
# Session-corpus names that are still decompiler placeholders carry no signal.
PLACEHOLDER_NAME = re.compile(r"^(?:FUN|LAB)_[0-9a-fA-F]{8}$|^zz_[0-9a-fA-F]+_?$")
# Product ordering: faithful browser combat, family-by-family. The first ported
# unit must be the chunk_0048 challenge-flow controller (session corpus names).
DEFAULT_PRIORITY_CHUNKS = ["chunk_0048"]
DEFAULT_PRIORITY_ENTRY_SYMBOLS = [
    "dispatch_challenge_flow_state",
    "init_challenge_flow_state",
    "build_challenge_battle_setup",
]
ANALYSIS_REQUEST_BUDGET = 3
TERMINAL_UNIT_STATUSES = {"integrated", "rejected_final", "skipped", "alias"}

EXIT_NO_WORK = 0
EXIT_STOPPED = 2
EXIT_PROGRESSED = 3
EXIT_PROVIDER_PAUSED = 4
EXIT_LOCKED = 5


def build_session_index(
    sessions_root: str | Path,
    output_path: str | Path,
    *,
    floor: int = SESSION_INDEX_FLOOR,
) -> dict[str, Any]:
    """Merge every analysis_sessions/*/session.json into one rename+summary index.

    Latest analysis_timestamp wins per address across ALL sessions (locked
    decision #4). Refuses to write an index below ``floor`` entries so a corrupt
    session cannot silently degrade grounding to zero (G21/R23).
    """
    sessions_root = Path(sessions_root)
    merged: dict[str, dict[str, Any]] = {}
    sessions_merged = 0
    for session_path in sorted(sessions_root.glob("*/session.json")):
        try:
            payload = json.loads(session_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue
        functions = payload.get("analyzed_functions")
        if not isinstance(functions, dict):
            continue
        sessions_merged += 1
        for raw_address, record in functions.items():
            if not isinstance(record, dict):
                continue
            try:
                address = normalize_address(str(raw_address))
            except ValueError:
                continue
            timestamp = record.get("analysis_timestamp")
            timestamp = float(timestamp) if isinstance(timestamp, (int, float)) else 0.0
            existing = merged.get(address)
            if existing is not None and existing["analysis_timestamp"] >= timestamp:
                continue
            summary = record.get("behavior_summary")
            merged[address] = {
                "address": address,
                "name": record.get("new_name") or record.get("old_name") or "",
                "summary": (
                    str(summary)[:SESSION_SUMMARY_CHARS] if isinstance(summary, str) else ""
                ),
                "analysis_timestamp": timestamp,
                "session": session_path.parent.name,
            }
    if len(merged) < floor:
        raise ValueError(
            f"refusing to write session index with {len(merged)} entries "
            f"(floor {floor}): sessions look corrupt or missing"
        )
    index = {
        "index_schema": 1,
        "generated_at": utc_now(),
        "sessions_merged": sessions_merged,
        "function_count": len(merged),
        "functions": merged,
    }
    atomic_write_json(Path(output_path), index)
    return index


class DriverEvents:
    """One bounded machine-readable event stream for the driver (R19/R20, G26)."""

    def __init__(self, path: Path, run_id: str):
        self.path = path
        self.run_id = run_id

    def emit(self, kind: str, **fields: Any) -> None:
        try:
            if self.path.is_file() and self.path.stat().st_size > EVENTS_ROTATE_BYTES:
                os.replace(self.path, self.path.with_suffix(".jsonl.1"))
        except OSError:
            pass
        event = {"timestamp": utc_now(), "run_id": self.run_id, "kind": kind, **fields}
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(json.dumps(event, ensure_ascii=False, default=str) + "\n")


class DriverLock:
    """Single-instance guard (R9). Stale locks from SIGKILLed drivers are reclaimed."""

    def __init__(self, path: Path):
        self.path = path
        self._held = False

    def acquire(self) -> bool:
        for _attempt in (1, 2):
            try:
                with self.path.open("x", encoding="utf-8") as handle:
                    json.dump({"pid": os.getpid(), "started_at": utc_now()}, handle)
                self._held = True
                return True
            except FileExistsError:
                try:
                    holder = json.loads(self.path.read_text(encoding="utf-8"))
                    holder_pid = int(holder.get("pid", 0))
                except (json.JSONDecodeError, OSError, ValueError):
                    holder_pid = 0
                if holder_pid and _pid_alive(holder_pid):
                    return False
                try:
                    self.path.unlink()
                except OSError:
                    return False
        return False

    def release(self) -> None:
        if self._held:
            try:
                self.path.unlink()
            except OSError:
                pass
            self._held = False


class PortDriver:
    """Select work, run one durable step at a time, record everything in the ledger."""

    def __init__(
        self,
        *,
        repo_root: str | Path | None = None,
        workflow: Any | None = None,
        units_budget: int = 1,
        until_blocked: bool = False,
    ):
        self.repo_root = (
            Path(repo_root).resolve() if repo_root is not None else find_gotyaforce_root()
        )
        self.workflow = workflow or ChunkPortWorkflow(repo_root=self.repo_root)
        self.run_root = self.repo_root / "research/decomp/generated/finish-game-port"
        self.ledger_path = self.run_root / "port-ledger.json"
        self.history_path = self.run_root / "ledger-history.jsonl"
        self.lock = DriverLock(self.run_root / "driver.lock")
        self.run_id = os.getenv("OGHIDRA_PORT_RUN_ID") or utc_now()
        self.events = DriverEvents(self.run_root / "events.jsonl", self.run_id)
        self.units_budget = max(1, units_budget)
        self.until_blocked = until_blocked

    # ------------------------------------------------------------------ ledger

    def _load_or_create_ledger(self) -> dict[str, Any]:
        if self.ledger_path.is_file():
            return json.loads(self.ledger_path.read_text(encoding="utf-8"))
        manifest_path = self.run_root / "whole-program-manifest.json"
        integrated: list[str] = []
        fingerprints: dict[str, str] = {}
        functions_total = 0
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            functions = manifest.get("functions", {})
            functions_total = len(functions)
            for address, record in functions.items():
                if not isinstance(record, dict):
                    continue
                if record.get("port_status") == "integrated":
                    integrated.append(normalize_address(address))
                    fingerprint = record.get("fingerprint")
                    if isinstance(fingerprint, str):
                        fingerprints[normalize_address(address)] = fingerprint
        except (FileNotFoundError, json.JSONDecodeError, OSError):
            pass
        export_root = self.repo_root / "research" / "decomp" / "ghidra-export"
        chunks_total = len(list(export_root.glob("chunk_*.c")))
        ledger = {
            "ledger_schema": LEDGER_SCHEMA,
            "created_at": utc_now(),
            "updated_at": utc_now(),
            "priority_chunks": list(DEFAULT_PRIORITY_CHUNKS),
            "priority_entry_symbols": list(DEFAULT_PRIORITY_ENTRY_SYMBOLS),
            "counters": {
                "chunks_total": chunks_total,
                "chunks_analyzed": 0,
                "units_known": 0,
                "units_integrated": 0,
                "functions_total": functions_total,
                "functions_integrated": len(integrated),
                "model_requests_total": 0,
            },
            "imported_legacy": {
                "imported_at": utc_now(),
                "source": str(manifest_path),
                "integrated_addresses": sorted(integrated),
                "fingerprints": fingerprints,
            },
            "integrated_addresses": sorted(integrated),
            "chunks": {},
        }
        self._save_ledger(ledger, reason="created_with_legacy_import")
        return ledger

    def _save_ledger(self, ledger: dict[str, Any], *, reason: str) -> None:
        ledger["updated_at"] = utc_now()
        atomic_write_json(self.ledger_path, ledger)
        entry = {
            "timestamp": ledger["updated_at"],
            "run_id": self.run_id,
            "reason": reason,
            "counters": ledger["counters"],
        }
        with self.history_path.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(json.dumps(entry, default=str) + "\n")

    # ----------------------------------------------------------------- control

    def _control_command(self) -> str:
        try:
            return json.loads(
                (self.run_root / "control.json").read_text(encoding="utf-8")
            ).get("command", "run")
        except (FileNotFoundError, json.JSONDecodeError, OSError):
            return "run"

    # -------------------------------------------------------------- selection

    def _chunk_order(self, ledger: dict[str, Any]) -> list[str]:
        export_root = self.repo_root / "research" / "decomp" / "ghidra-export"
        all_chunks = sorted(
            path.name.removesuffix(".c") for path in export_root.glob("chunk_*.c")
        )
        priority = [
            normalize_chunk_name(name).removesuffix(".c")
            for name in ledger.get("priority_chunks", [])
        ]
        rest = [name for name in all_chunks if name not in priority]
        return [name for name in priority if name in all_chunks] + rest

    def _chunk_record(self, ledger: dict[str, Any], chunk: str) -> dict[str, Any]:
        return ledger.setdefault("chunks", {}).setdefault(
            chunk, {"analysis": {}, "units": {}}
        )

    def _unit_record(
        self, ledger: dict[str, Any], chunk: str, unit_id: str
    ) -> dict[str, Any]:
        return self._chunk_record(ledger, chunk)["units"].setdefault(
            unit_id, {"status": "pending"}
        )

    @staticmethod
    def _is_priority_unit(unit: ExecutionUnit, ledger: dict[str, Any]) -> bool:
        priority = set(ledger.get("priority_entry_symbols", []))
        return bool(priority & set(unit.runtime_entry_symbols))

    def _classify_units(
        self, ledger: dict[str, Any], chunk: str, analysis: ChunkAnalysis
    ) -> tuple[list[ExecutionUnit], bool]:
        """Record eligibility for every unit; return (portable-now units, any_pending_model)."""
        integrated = set(ledger.get("integrated_addresses", []))
        deterministic = analysis.generated_by == "deterministic"
        portable: list[ExecutionUnit] = []
        any_pending_model = False
        for unit in analysis.units:
            record = self._unit_record(ledger, chunk, unit.id)
            record.setdefault("entry_symbols", unit.runtime_entry_symbols)
            if record.get("status") in TERMINAL_UNIT_STATUSES:
                continue
            if set(unit.function_addresses) <= integrated:
                record.update(
                    status="alias",
                    eligibility="duplicate_fingerprint",
                    detail="every function already integrated by an earlier port",
                )
                continue
            eligibility, reason = unit_eligibility(unit)
            if eligibility != "eligible":
                record.update(status="skipped", eligibility=eligibility, detail=reason)
                self.events.emit(
                    "unit_skipped", chunk=chunk, unit=unit.id, eligibility=eligibility
                )
                continue
            if deterministic and len(unit.function_addresses) == 1:
                # Locked decision #2: singletons always wait for model analysis (G12).
                record.update(status="pending", eligibility="ineligible_singleton_pending_model")
                any_pending_model = True
                continue
            if deterministic and not self._is_priority_unit(unit, ledger):
                # Locked decision #2: deterministic units port early ONLY when
                # combat-relevant; everything else waits for model analysis.
                record.update(status="pending", eligibility="eligible_pending_model_analysis")
                any_pending_model = True
                continue
            record.update(status="pending", eligibility="eligible")
            portable.append(unit)
        return portable, any_pending_model

    def _order_units(
        self, ledger: dict[str, Any], analysis: ChunkAnalysis, units: list[ExecutionUnit]
    ) -> list[ExecutionUnit]:
        """Priority symbols first, then leaf-first within the chunk, ties by address (D2)."""
        chunk_units = {unit.id: set(unit.function_addresses) for unit in analysis.units}

        def internal_dependencies(unit: ExecutionUnit) -> int:
            other_addresses = set().union(
                *(
                    addresses
                    for unit_id, addresses in chunk_units.items()
                    if unit_id != unit.id
                )
            ) if len(chunk_units) > 1 else set()
            return len(set(unit.external_dependencies) & other_addresses)

        return sorted(
            units,
            key=lambda unit: (
                not self._is_priority_unit(unit, ledger),
                internal_dependencies(unit),
                int(unit.function_addresses[0], 16),
            ),
        )

    def _next_step(self, ledger: dict[str, Any]) -> tuple[str, str, ExecutionUnit | None]:
        """Return (action, chunk, unit): action in {port, analyze, none}."""
        for chunk in self._chunk_order(ledger):
            chunk_record = self._chunk_record(ledger, chunk)
            analysis_record = chunk_record["analysis"]
            if analysis_record.get("status") == "analysis_blocked":
                continue
            try:
                analysis = self.workflow.load_analysis(chunk)
            except (FileNotFoundError, ValueError):
                if analysis_record.get("model_requests_spent", 0) >= ANALYSIS_REQUEST_BUDGET:
                    analysis_record["status"] = "analysis_blocked"
                    analysis_record["detail"] = "analysis request budget exhausted"
                    continue
                return ("analyze", chunk, None)
            analysis_record.setdefault("generated_by", analysis.generated_by)
            # A unit left "porting" means the previous driver died mid-port:
            # resume it first so a SIGKILL costs at most the in-flight request (R5).
            interrupted = [
                unit
                for unit in analysis.units
                if chunk_record["units"].get(unit.id, {}).get("status") == "porting"
            ]
            portable, any_pending_model = self._classify_units(ledger, chunk, analysis)
            if interrupted:
                return ("port", chunk, interrupted[0])
            if portable:
                ordered = self._order_units(ledger, analysis, portable)
                return ("port", chunk, ordered[0])
            if any_pending_model and analysis.generated_by == "deterministic":
                if analysis_record.get("model_requests_spent", 0) >= ANALYSIS_REQUEST_BUDGET:
                    analysis_record["status"] = "analysis_blocked"
                    analysis_record["detail"] = "analysis request budget exhausted"
                    continue
                return ("analyze", chunk, None)
        return ("none", "", None)

    # ------------------------------------------------------------------ steps

    def _run_analysis(self, ledger: dict[str, Any], chunk: str) -> str:
        record = self._chunk_record(ledger, chunk)["analysis"]
        record["status"] = "analyzing"
        record["model_requests_spent"] = record.get("model_requests_spent", 0) + 1
        ledger["counters"]["model_requests_total"] = (
            ledger["counters"].get("model_requests_total", 0) + 1
        )
        self._save_ledger(ledger, reason=f"analysis_started:{chunk}")
        self.events.emit("analysis_started", chunk=chunk, attempt=record["model_requests_spent"])
        try:
            analysis = self.workflow.analyze(chunk, force=True)
        except ProviderUnavailable:
            record["status"] = "paused_provider"
            self._save_ledger(ledger, reason=f"provider_paused:{chunk}")
            self.events.emit("provider_paused", chunk=chunk)
            raise
        except Exception as error:
            record["status"] = "analysis_failed"
            record["error"] = f"{type(error).__name__}: {error}"
            if record["model_requests_spent"] >= ANALYSIS_REQUEST_BUDGET:
                record["status"] = "analysis_blocked"
                record["detail"] = "analysis request budget exhausted"
                self.events.emit("analysis_blocked", chunk=chunk, error=record["error"])
            self._save_ledger(ledger, reason=f"analysis_failed:{chunk}")
            return "analysis_failed"
        record["status"] = "analyzed"
        record["generated_by"] = analysis.generated_by
        record["chunk_sha256"] = analysis.chunk_sha256
        record.pop("error", None)
        counters = ledger["counters"]
        counters["chunks_analyzed"] = sum(
            1
            for chunk_record in ledger["chunks"].values()
            if chunk_record["analysis"].get("status") == "analyzed"
        )
        self._save_ledger(ledger, reason=f"analysis_done:{chunk}")
        self.events.emit(
            "analysis_done",
            chunk=chunk,
            generated_by=analysis.generated_by,
            units=len(analysis.units),
        )
        return "analyzed"

    def _run_port(self, ledger: dict[str, Any], chunk: str, unit: ExecutionUnit) -> str:
        record = self._unit_record(ledger, chunk, unit.id)
        unit_root = self.workflow.chunk_root(chunk) / "units" / unit.id
        record.update(
            status="porting",
            entry_symbols=unit.runtime_entry_symbols,
            selection_rationale=(
                "priority_entry_symbols"
                if self._is_priority_unit(unit, ledger)
                else "leaf_first_in_chunk"
            ),
        )
        self._save_ledger(ledger, reason=f"unit_started:{chunk}/{unit.id}")
        self.events.emit(
            "unit_started",
            chunk=chunk,
            unit=unit.id,
            functions=len(unit.function_addresses),
            unit_activity_path=str(unit_root / "activity.jsonl"),
        )
        try:
            result = self.workflow.port_unit(chunk, unit.id)
        except ProviderUnavailable:
            record["status"] = "paused_provider"
            self._save_ledger(ledger, reason=f"provider_paused:{chunk}/{unit.id}")
            self.events.emit("provider_paused", chunk=chunk, unit=unit.id)
            raise
        if isinstance(result, UnitSkipResult):
            record.update(status="skipped", eligibility=result.eligibility, detail=result.reason)
            self._save_ledger(ledger, reason=f"unit_skipped:{chunk}/{unit.id}")
            self.events.emit(
                "unit_skipped", chunk=chunk, unit=unit.id, eligibility=result.eligibility
            )
            return "skipped"
        record["attempts_spent"] = record.get("attempts_spent", 0) + result.attempts
        if result.passed:
            record.update(status="integrated", files=result.files, error=None)
            integrated = set(ledger.get("integrated_addresses", []))
            integrated.update(unit.function_addresses)
            ledger["integrated_addresses"] = sorted(integrated)
            counters = ledger["counters"]
            counters["units_integrated"] = counters.get("units_integrated", 0) + 1
            counters["functions_integrated"] = len(integrated)
            self._save_ledger(ledger, reason=f"unit_integrated:{chunk}/{unit.id}")
            self.events.emit(
                "unit_integrated", chunk=chunk, unit=unit.id, files=result.files
            )
            return "integrated"
        record.update(status="rejected_final", error=result.error)
        self._save_ledger(ledger, reason=f"unit_rejected:{chunk}/{unit.id}")
        self.events.emit("unit_rejected", chunk=chunk, unit=unit.id, error=result.error)
        return "rejected"

    # --------------------------------------------------------------- progress

    def _write_progress(self, ledger: dict[str, Any], status: str) -> None:
        counters = ledger["counters"]
        units_known = sum(
            len(chunk_record.get("units", {})) for chunk_record in ledger["chunks"].values()
        )
        counters["units_known"] = units_known
        functions_total = counters.get("functions_total", 0)
        functions_integrated = counters.get("functions_integrated", 0)
        percent = (
            functions_integrated / functions_total * 100.0 if functions_total else 0.0
        )
        pending = [
            {"address": unit_record.get("entry_symbols", [""])[0] if unit_record.get("entry_symbols") else unit_id,
             "family": unit_id,
             "status": unit_record.get("status", "pending")}
            for chunk_record in ledger["chunks"].values()
            for unit_id, unit_record in chunk_record.get("units", {}).items()
            if unit_record.get("status") in {"pending", "porting"}
        ][:5]
        state = {
            "run_schema": 3,
            "run_mode": "driver",
            "objective": "Port coherent GameCube execution units, combat families first",
            "run_id": self.run_id,
            "status": status,
            "updated_at": utc_now(),
            "progress": {
                "completed_work": functions_integrated,
                "total_work": functions_total,
                "percent": percent,
            },
            "counters": {
                "chunks_analyzed": counters.get("chunks_analyzed", 0),
                "chunks_total": counters.get("chunks_total", 0),
                "units_integrated": counters.get("units_integrated", 0),
                "units_known": units_known,
                "functions_integrated": functions_integrated,
                "functions_total": functions_total,
                "model_requests_total": counters.get("model_requests_total", 0),
            },
            "queue": pending,
        }
        atomic_write_json(self.run_root / "run-state.json", state)
        self.events.emit("progress", **state["counters"])

    # -------------------------------------------------------------------- run

    def run(self) -> int:
        if not self.lock.acquire():
            print("another finish-port --drive instance holds driver.lock; exiting")
            return EXIT_LOCKED
        try:
            ledger = self._load_or_create_ledger()
            self.events.emit("driver_started", units_budget=self.units_budget)
            steps_done = 0
            while True:
                command = self._control_command()
                if command in {"stop_after_stage", "pause_after_stage"}:
                    self._write_progress(ledger, "stopped")
                    self.events.emit("driver_stopped", reason=f"control:{command}")
                    return EXIT_STOPPED
                action, chunk, unit = self._next_step(ledger)
                if action == "none":
                    self._save_ledger(ledger, reason="no_work_left")
                    self._write_progress(ledger, "completed")
                    self.events.emit("driver_stopped", reason="no_work_left")
                    return EXIT_NO_WORK
                self.events.emit(
                    "selection",
                    action=action,
                    chunk=chunk,
                    unit=unit.id if unit is not None else None,
                )
                try:
                    if action == "analyze":
                        self._write_progress(ledger, "analyzing")
                        self._run_analysis(ledger, chunk)
                    else:
                        self._write_progress(ledger, "porting")
                        self._run_port(ledger, chunk, unit)
                except ProviderUnavailable as error:
                    self._write_progress(ledger, "paused_provider_unavailable")
                    self.events.emit("driver_stopped", reason="provider_paused")
                    print(f"provider unavailable; pausing: {error}")
                    return EXIT_PROVIDER_PAUSED
                steps_done += 1
                self._write_progress(ledger, "running")
                if not self.until_blocked and steps_done >= self.units_budget:
                    self.events.emit("driver_stopped", reason="units_budget_reached")
                    return EXIT_PROGRESSED
        finally:
            self.lock.release()
