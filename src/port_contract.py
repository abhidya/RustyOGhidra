"""The machine-invocable contract between RustyOGhidra and the rig supervisor.

RustyOGhidra owns port execution (queues, unit selection, LLM work, validation,
oracle gates, product commits, progress state). The rig owns the machine
(startup, Unsloth availability, model lifecycle, Palworld protection, the manual
gate, and whether heavy work may run at all). This module is the seam.

    python main.py port-contract config     --json   # the ONE model config
    python main.py port-contract status     --json   # work eligibility + run state
    python main.py port-contract stop                # cooperative stop at a boundary
    python main.py port-contract run                 # clear the stop
    python main.py port-contract checkpoint ...      # machine state -> port-progress
    python main.py port-contract progress-flush      # retry a pending progress push

Exit codes mirror the driver's vocabulary where it makes sense:
    0 ok | 1 hard error | 6 contract/queue unusable
The driver itself keeps its own codes: 0 no-work | 2 stopped | 3 progressed |
4 provider-paused | 5 locked.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

from src.port_chunk_workflow import atomic_write_json, utc_now
from src.port_model_config import resolve_port_model_config
from src.port_run_controller import _pid_alive, find_gotyaforce_root

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_UNUSABLE = 6

CONTRACT_SCHEMA = 1


def _wasm_constants() -> tuple[set[str], int]:
    """Settled statuses and queue schema, taken FROM THE DRIVER.

    Duplicating them here would let the supervisor and the driver disagree
    about what counts as work -- and every such disagreement is a relaunch
    storm, because the driver's exit codes are all "healthy".
    """
    from src.port_wasm_units import QUEUE_SCHEMA as driver_queue_schema
    from src.port_wasm_units import WasmUnitDriver

    return set(WasmUnitDriver.SETTLED_STATUSES), driver_queue_schema


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError, ValueError):
        return None


def run_root_for(repo_root: Path) -> Path:
    return repo_root / "research/decomp/generated/finish-game-port"


def queue_status(repo_root: Path, port_mode: str) -> dict[str, Any]:
    """Is there actionable work? Answered from the queue, with no model touched.

    Startup ordering rule: the rig asks this BEFORE Unsloth exists, so nothing
    in here may require a served model (the old failure mode was loading a
    35 GB model only to discover the queue was empty)."""
    root = run_root_for(repo_root)
    if port_mode != "wasm_units":
        ledger = _read_json(root / "port-ledger.json")
        if ledger is None:
            return {
                "mode": port_mode, "eligible": False, "reason": "port-ledger.json unreadable",
                "total": 0, "settled": 0, "remaining": 0,
            }
        chunks = ledger.get("chunks") or {}
        remaining = sum(
            1 for record in chunks.values()
            if isinstance(record, dict) and record.get("status") not in {"completed", "integrated"}
        )
        return {
            "mode": port_mode,
            "eligible": remaining > 0,
            "reason": "chunk queue has work" if remaining else "chunk queue drained",
            "total": len(chunks), "settled": len(chunks) - remaining, "remaining": remaining,
        }

    settled_statuses, queue_schema = _wasm_constants()
    queue = _read_json(root / "wasm-units.json")
    if not isinstance(queue, dict) or not isinstance(queue.get("units"), list):
        return {
            "mode": port_mode, "eligible": False, "reason": "wasm-units.json unusable",
            "total": 0, "settled": 0, "remaining": 0, "unusable": True,
        }
    # The driver refuses a queue whose schema it does not know. If this probe
    # ignored that, the rig would keep reporting "work is eligible" while every
    # launched driver exited instantly -- a relaunch storm on a queue that can
    # never be read.
    if queue.get("queue_schema") != queue_schema:
        return {
            "mode": port_mode, "eligible": False,
            "reason": (
                f"wasm-units.json queue_schema={queue.get('queue_schema')!r}; "
                f"the driver only reads {queue_schema}"
            ),
            "total": len(queue["units"]), "settled": 0, "remaining": 0, "unusable": True,
        }
    names = [unit.get("name") for unit in queue["units"] if isinstance(unit, dict)]
    state = _read_json(root / "wasm-units-state.json") or {}
    records = state.get("units") if isinstance(state.get("units"), dict) else {}
    counts = {
        "green": 0, "staged": 0, "retryable": 0, "untouched": 0,
        "structural_ineligible": 0, "active": 0,
    }
    remaining = 0
    for name in names:
        record = records.get(name) if isinstance(records, dict) else None
        status = record.get("status") if isinstance(record, dict) else "pending"
        if status not in settled_statuses:
            remaining += 1
        if status == "green":
            counts["staged" if (record or {}).get("tier") == "compile_only" else "green"] += 1
        elif status == "red_retryable":
            counts["retryable"] += 1
        elif status == "structural_ineligible":
            counts["structural_ineligible"] += 1
        elif status == "porting":
            counts["active"] += 1
        else:
            counts["untouched"] += 1
    return {
        "mode": port_mode,
        "eligible": remaining > 0,
        "reason": (
            f"{remaining} wasm unit(s) still need work" if remaining
            else "every queued wasm unit is settled (green or structurally ineligible)"
        ),
        "total": len(names),
        "settled": len(names) - remaining,
        "remaining": remaining,
        "counts": counts,
    }


def driver_status(repo_root: Path, port_mode: str) -> dict[str, Any]:
    root = run_root_for(repo_root)
    lock_path = root / ("wasm-units.lock" if port_mode == "wasm_units" else "driver.lock")
    holder = _read_json(lock_path)
    pid = None
    if isinstance(holder, dict):
        try:
            pid = int(holder.get("pid") or 0) or None
        except (TypeError, ValueError):
            pid = None
    alive = bool(pid and _pid_alive(pid))
    run_state = _read_json(root / "run-state.json") or {}
    return {
        "lock_path": str(lock_path),
        "lock_present": lock_path.exists(),
        "lock_pid": pid,
        "lock_pid_alive": alive,
        "lock_stale": lock_path.exists() and not alive,
        "run_status": run_state.get("status"),
        "run_id": run_state.get("run_id"),
        "run_unit": run_state.get("unit"),
        "updated_at": run_state.get("updated_at"),
    }


def build_status(repo_root: Path) -> dict[str, Any]:
    model = resolve_port_model_config()
    work = queue_status(repo_root, model.port_mode)
    return {
        "schema": CONTRACT_SCHEMA,
        "generated_at": utc_now(),
        "repo_root": str(repo_root),
        "run_root": str(run_root_for(repo_root)),
        "port_mode": model.port_mode,
        "model": model.to_public_dict(),
        "work": work,
        "driver": driver_status(repo_root, model.port_mode),
        "control": _read_json(run_root_for(repo_root) / "control.json"),
        "liveness": _read_json(run_root_for(repo_root) / "llm-liveness.json"),
    }


def write_control(repo_root: Path, command: str, source: str) -> Path:
    path = run_root_for(repo_root) / "control.json"
    atomic_write_json(
        path, {"command": command, "updated_at": utc_now(), "source": source}
    )
    return path


def main(argv: list[str] | None = None) -> int:
    # Shared flags live on a parent parser so they are accepted on either side
    # of the subcommand -- callers script this and must not have to remember.
    # default=SUPPRESS is load-bearing: with `parents=[common]` on BOTH the top
    # parser and each subparser, the subparser's defaults overwrite whatever the
    # top parser already parsed -- so `port-contract --json status` silently
    # printed key-value text while claiming to be machine-readable.
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "--repo-root", default=argparse.SUPPRESS,
        help="GotYaForce checkout (default: auto-detect)",
    )
    common.add_argument(
        "--json", action="store_true", default=argparse.SUPPRESS,
        help="machine-readable output",
    )
    parser = argparse.ArgumentParser(
        prog="port-contract", description=__doc__, parents=[common]
    )
    sub = parser.add_subparsers(dest="action", required=True)
    sub.add_parser("config", parents=[common], help="the authoritative port-model configuration")
    sub.add_parser("status", parents=[common], help="work eligibility, driver and run state")
    stop = sub.add_parser("stop", parents=[common], help="cooperative stop at the next unit boundary")
    stop.add_argument("--source", default="rig-supervisor")
    start = sub.add_parser("run", parents=[common], help="clear a cooperative stop")
    start.add_argument("--source", default="rig-supervisor")
    sub.add_parser("progress-flush", parents=[common], help="retry a pending port-progress push")
    checkpoint = sub.add_parser(
        "checkpoint", parents=[common],
        help="record a machine-level state on the port-progress branch",
    )
    checkpoint.add_argument("--state", required=True, help="workflow state, e.g. manual_paused")
    checkpoint.add_argument("--detail", default="")
    checkpoint.add_argument("--driver-status", default="stopped")
    checkpoint.add_argument("--block-reason", default="")
    checkpoint.add_argument("--active-model", default="")
    checkpoint.add_argument("--context-length", type=int, default=0)
    checkpoint.add_argument("--manual-paused", action="store_true")
    checkpoint.add_argument("--driver-running", action="store_true")
    arguments = parser.parse_args(argv)
    # SUPPRESS means the attributes only exist when actually passed.
    as_json = getattr(arguments, "json", False)
    repo_root_argument = getattr(arguments, "repo_root", None)

    repo_root = (
        Path(repo_root_argument).resolve() if repo_root_argument else find_gotyaforce_root()
    )

    if arguments.action == "config":
        model = resolve_port_model_config()
        payload = model.to_public_dict()
        print(json.dumps(payload, indent=2) if as_json else _plain(payload))
        return EXIT_OK

    if arguments.action == "status":
        payload = build_status(repo_root)
        print(json.dumps(payload, indent=2) if as_json else _plain(payload))
        return EXIT_UNUSABLE if payload["work"].get("unusable") else EXIT_OK

    if arguments.action in ("stop", "run"):
        command = "stop_after_stage" if arguments.action == "stop" else "run"
        path = write_control(repo_root, command, arguments.source)
        print(f"control.json <- {command} ({path})")
        return EXIT_OK

    if arguments.action == "progress-flush":
        from src.port_progress import journal_for

        journal = journal_for(repo_root, run_root=run_root_for(repo_root))
        outcome = journal.flush_pending_push() if journal.push_is_pending() else {"pushed": True, "push_pending": False, "noop": True}
        print(json.dumps(outcome, indent=2))
        return EXIT_OK

    if arguments.action == "checkpoint":
        from src.port_progress import MachineState, journal_for

        model = resolve_port_model_config()
        state = _read_json(run_root_for(repo_root) / "wasm-units-state.json") or {}
        units = state.get("units") if isinstance(state.get("units"), dict) else {}
        journal = journal_for(repo_root, run_root=run_root_for(repo_root))
        outcome = journal.checkpoint(
            transition=None,
            units=units,
            machine=MachineState(
                workflow_state=arguments.state,
                driver_status=arguments.driver_status,
                manual_paused=arguments.manual_paused,
                block_reason=arguments.block_reason or None,
                active_model=arguments.active_model or None,
                context_length=arguments.context_length or None,
                configured_model=model.model,
                detail=arguments.detail,
            ),
            driver_running=arguments.driver_running,
        )
        print(json.dumps(outcome, indent=2, default=str))
        return EXIT_OK

    return EXIT_ERROR


def _plain(payload: dict[str, Any]) -> str:
    lines = []
    for key, value in payload.items():
        lines.append(f"{key}: {json.dumps(value, default=str) if isinstance(value, (dict, list)) else value}")
    return "\n".join(lines)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
