"""Durable whole-program scheduler for the autonomous GotYaForce port workflow."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable

from src.config import get_config
from src.port_artifact import normalize_address
from src.port_cli import _ghidra_for_config, _llm_for_config
from src.port_evidence import collect_function_evidence
from src.port_exporter import export_port_artifact, historical_summary
from src.port_run_controller import find_gotyaforce_root
from src.port_source_loop import SequentialSourcePortLoop
from src.port_workflow import atomic_write_json


FUNCTION_LINE = re.compile(r"^(?P<name>.+?)\s+at\s+(?P<address>[0-9a-fA-F]{8,16})$")
EXPORT_FUNCTION = re.compile(
    r"^// ==== (?P<address>[0-9a-fA-F]{8})\s+(?P<name>.+?) ====$",
    re.MULTILINE,
)
PAGINATION_TOTAL = re.compile(r"\[Total:\s*(\d+)\]")
DIRECT_CALL = re.compile(r"\b(?:bl|bla|call)\s+(?:0x)?([0-9a-fA-F]{8})\b", re.IGNORECASE)
LEADING_ADDRESS = re.compile(r"^\s*(?:0x)?[0-9a-fA-F]{8,16}:\s*")
COMMENT = re.compile(r"\s*;\s*.*$")
TERMINAL_UNIT_STATES = {
    "integrated",
    "excluded",
    "alias",
    "proven_unreachable",
    "missing_profile",
    "needs_oracle",
    "bundle_failed",
    "model_invalid",
    "evidence_rejected",
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def parse_function_line(line: str) -> dict[str, str] | None:
    match = FUNCTION_LINE.match(line.strip())
    if not match:
        return None
    return {
        "name": match.group("name").strip(),
        "address": normalize_address(match.group("address")),
    }


def normalize_instruction_lines(lines: Iterable[str]) -> list[str]:
    """Normalize listing addresses/comments while preserving operands and call targets."""
    normalized = []
    for value in lines:
        line = COMMENT.sub("", str(value)).strip()
        line = LEADING_ADDRESS.sub("", line).strip()
        if line and not line.startswith("[") and not line.lower().startswith(("error", "request failed")):
            normalized.append(re.sub(r"\s+", " ", line).lower())
    return normalized


def fingerprint_instructions(lines: Iterable[str]) -> str | None:
    normalized = normalize_instruction_lines(lines)
    if not normalized:
        return None
    return hashlib.sha256("\n".join(normalized).encode("utf-8")).hexdigest()


def extract_direct_calls(lines: Iterable[str], own_address: str) -> list[str]:
    calls = {
        normalize_address(match.group(1))
        for line in lines
        for match in DIRECT_CALL.finditer(str(line))
    }
    calls.discard(normalize_address(own_address))
    return sorted(calls)


def is_thunk(lines: Iterable[str]) -> bool:
    normalized = normalize_instruction_lines(lines)
    if not normalized or len(normalized) > 3:
        return False
    non_return = [line for line in normalized if not line.startswith(("blr", "bctr"))]
    return len(non_return) == 1 and bool(re.match(r"^b\s+", non_return[0]))


def exact_groups(records: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    by_fingerprint: dict[str, list[dict[str, Any]]] = defaultdict(list)
    ungrouped: list[dict[str, Any]] = []
    for record in records:
        fingerprint = record.get("fingerprint")
        if fingerprint:
            by_fingerprint[str(fingerprint)].append(record)
        else:
            ungrouped.append(record)
    groups = []
    for fingerprint, members in sorted(by_fingerprint.items()):
        ordered = sorted(members, key=lambda item: item["address"])
        proof = (
            "exact_normalized_pcode"
            if all(item.get("fingerprint_kind") == "exact_normalized_pcode" for item in ordered)
            else "exact_normalized_disassembly"
        )
        groups.append(
            {
                "id": f"exact-{fingerprint[:16]}",
                "canonical_address": ordered[0]["address"],
                "member_addresses": [item["address"] for item in ordered],
                "proof": proof,
                "fingerprint": fingerprint,
                "dependencies": sorted(
                    {
                        dependency
                        for item in ordered
                        for dependency in item.get("dependencies", [])
                    }
                ),
                "status": "queued",
                "attempts": 0,
            }
        )
    for record in sorted(ungrouped, key=lambda item: item["address"]):
        groups.append(
            {
                "id": f"ungrouped-{record['address'][2:]}",
                "canonical_address": record["address"],
                "member_addresses": [record["address"]],
                "proof": "none",
                "fingerprint": None,
                "dependencies": record.get("dependencies", []),
                "status": "bundle_failed",
                "attempts": 0,
            }
        )
    return groups


def dependency_order(groups: Iterable[dict[str, Any]]) -> list[str]:
    """Return a stable leaf-first order; cycles remain stable by address."""
    group_list = list(groups)
    owner = {
        address: group["id"]
        for group in group_list
        for address in group.get("member_addresses", [])
    }
    dependencies: dict[str, set[str]] = {}
    dependents: dict[str, set[str]] = defaultdict(set)
    for group in group_list:
        group_id = group["id"]
        group_dependencies = {
            owner[address]
            for address in group.get("dependencies", [])
            if address in owner and owner[address] != group_id
        }
        dependencies[group_id] = group_dependencies
        for dependency in group_dependencies:
            dependents[dependency].add(group_id)
    ready = deque(
        sorted(
            (group_id for group_id, values in dependencies.items() if not values),
            key=lambda group_id: next(
                group["canonical_address"] for group in group_list if group["id"] == group_id
            ),
        )
    )
    ordered: list[str] = []
    while ready:
        group_id = ready.popleft()
        ordered.append(group_id)
        for dependent in sorted(dependents[group_id]):
            dependencies[dependent].discard(group_id)
            if not dependencies[dependent] and dependent not in ordered and dependent not in ready:
                ready.append(dependent)
    remaining = sorted(
        (group["id"] for group in group_list if group["id"] not in ordered),
        key=lambda group_id: next(
            group["canonical_address"] for group in group_list if group["id"] == group_id
        ),
    )
    return [*ordered, *remaining]


class StopRequested(RuntimeError):
    pass


class PortScheduler:
    MANIFEST_SCHEMA = 1
    BUNDLE_SCHEMA = 1

    def __init__(
        self,
        *,
        repo_root: str | Path | None = None,
        mode: str = "fresh",
        session_path: str | Path | None = None,
        max_bundles: int | None = None,
        max_units: int | None = None,
        ghidra: Any | None = None,
        llm_factory: Callable[[], tuple[Any, str, str]] | None = None,
    ):
        self.repo_root = find_gotyaforce_root(repo_root)
        self.oghidra_root = self.repo_root / "research" / "tools" / "OGhidra"
        self.run_root = self.repo_root / "research" / "decomp" / "generated" / "finish-game-port"
        self.bundle_root = self.run_root / "bundles"
        self.artifact_root = self.run_root / "artifacts"
        self.state_path = self.run_root / "run-state.json"
        self.manifest_path = self.run_root / "whole-program-manifest.json"
        self.manifest_backup_path = self.run_root / "whole-program-manifest.previous.json"
        self.control_path = self.run_root / "control.json"
        self.liveness_path = self.run_root / "llm-liveness.json"
        self.run_id = utc_now()
        os.environ["OGHIDRA_PORT_LIVENESS_PATH"] = str(self.liveness_path)
        os.environ["OGHIDRA_PORT_RUN_ID"] = self.run_id
        self.mode = mode
        self.session_path = Path(session_path).resolve() if session_path else None
        self.max_bundles = max_bundles
        self.max_units = max_units
        self.config = get_config()
        if ghidra is None:
            bootstrap_llm, _, _ = _llm_for_config(self.config)
            self.ghidra = _ghidra_for_config(self.config, bootstrap_llm)
        else:
            self.ghidra = ghidra
        self.llm_factory = llm_factory or (lambda: _llm_for_config(self.config))
        self.run_root.mkdir(parents=True, exist_ok=True)
        self.bundle_root.mkdir(parents=True, exist_ok=True)
        self.artifact_root.mkdir(parents=True, exist_ok=True)
        self.source_loop = SequentialSourcePortLoop(
            repo_root=self.repo_root,
            run_root=self.run_root,
            llm_factory=self.llm_factory,
        )
        self.manifest = self._load_or_create_manifest()
        self.state = self._new_state()
        self._save_all()

    def _load_or_create_manifest(self) -> dict[str, Any]:
        if self.mode != "fresh" and self.manifest_path.is_file():
            return json.loads(self.manifest_path.read_text(encoding="utf-8"))
        if self.mode == "fresh" and self.manifest_path.is_file():
            previous = json.loads(self.manifest_path.read_text(encoding="utf-8"))
            if previous.get("functions"):
                atomic_write_json(self.manifest_backup_path, previous)
        return {
            "manifest_schema": self.MANIFEST_SCHEMA,
            "program": {},
            "inventory_complete": False,
            "bundles_complete": False,
            "groups_complete": False,
            "functions": {},
            "groups": {},
            "schedule": [],
            "created_at": utc_now(),
            "updated_at": utc_now(),
        }

    def _restore_inventory_from_export(self) -> int:
        export_root = self.repo_root / "research" / "decomp" / "ghidra-export"
        for source in sorted(export_root.glob("*.c")):
            text = source.read_text(encoding="utf-8", errors="replace")
            for match in EXPORT_FUNCTION.finditer(text):
                address = normalize_address(match.group("address"))
                self.manifest["functions"].setdefault(
                    address,
                    {
                        "name": match.group("name").strip(),
                        "address": address,
                        "status": "discovered",
                        "bundle_path": None,
                        "fingerprint": None,
                        "dependencies": [],
                    },
                )

        for address, record in self.manifest["functions"].items():
            bundle_path = self.bundle_root / f"{address[2:]}.bundle.json"
            if not bundle_path.is_file():
                continue
            try:
                bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                continue
            fingerprints = bundle.get("fingerprints", {})
            fingerprint = (
                fingerprints.get("normalized_pcode")
                or fingerprints.get("instruction_shape")
                or fingerprints.get("normalized_disassembly")
            )
            if not fingerprint:
                continue
            record.update(
                {
                    "status": "bundled",
                    "bundle_path": str(bundle_path),
                    "bundle_source": "restored_checkpoint",
                    "fingerprint": fingerprint,
                    "fingerprint_kind": (
                        "exact_normalized_pcode"
                        if fingerprints.get("normalized_pcode")
                        else "exact_normalized_disassembly"
                    ),
                    "dependencies": sorted(
                        {
                            normalize_address(value)
                            for value in bundle.get("calls", [])
                        }
                    ),
                    "thunk": bool(bundle.get("identity", {}).get("thunk", False)),
                }
            )
        return len(self.manifest["functions"])

    def _new_state(self) -> dict[str, Any]:
        stages = {
            "inventory": {"label": "Inventory all Ghidra functions", "status": "pending"},
            "bundles": {"label": "Extract and fingerprint structured bundles", "status": "pending"},
            "groups": {"label": "Build exact equivalence groups and dependency order", "status": "pending"},
            "units": {"label": "Generate, verify, and integrate canonical units", "status": "pending"},
            "acceptance": {"label": "Build and run complete-game acceptance gates", "status": "pending"},
        }
        return {
            "run_schema": 2,
            "run_mode": self.mode,
            "objective": "Finish the GotYaForce browser port autonomously",
            "scope": {"kind": "whole_program"},
            "session": {
                "path": str(self.session_path) if self.session_path and self.session_path.is_file() else None,
                "role": "advisory" if self.session_path and self.session_path.is_file() else "none",
                "vectors_required": False,
            },
            "status": "running",
            "started_at": self.run_id,
            "updated_at": utc_now(),
            "current_stage": None,
            "total_stages": len(stages),
            "stages": stages,
            "queue": [],
            "progress": {},
            "promotion": {"status": "not_started", "rolled_back": False},
            "manifest": str(self.manifest_path),
        }

    def _save_all(self) -> None:
        self.manifest["updated_at"] = utc_now()
        self.state["updated_at"] = utc_now()
        atomic_write_json(self.manifest_path, self.manifest)
        atomic_write_json(self.state_path, self.state)

    def _stage(self, stage_id: str, status: str, detail: str | None = None) -> None:
        stage = self.state["stages"][stage_id]
        stage["status"] = status
        if status == "running" and "started_at" not in stage:
            stage["started_at"] = utc_now()
        if status in {"passed", "failed", "partial"}:
            stage["finished_at"] = utc_now()
        if detail:
            stage["detail"] = detail
        self.state["current_stage"] = stage_id if status == "running" else None
        self._save_all()

    def _check_control(self) -> None:
        try:
            command = json.loads(self.control_path.read_text(encoding="utf-8")).get("command", "run")
        except (FileNotFoundError, json.JSONDecodeError, OSError):
            command = "run"
        if command == "stop_after_stage":
            raise StopRequested("stop requested at a durable scheduler boundary")
        announced = False
        while command == "pause_after_stage":
            if not announced:
                announced = True
                self.state["status"] = "paused"
                self._save_all()
            time.sleep(0.5)
            try:
                command = json.loads(self.control_path.read_text(encoding="utf-8")).get("command", "run")
            except (FileNotFoundError, json.JSONDecodeError, OSError):
                command = "run"
            if command == "stop_after_stage":
                raise StopRequested("stop requested at a durable scheduler boundary")
        if announced:
            self.state["status"] = "running"
            self._save_all()

    def _progress(
        self,
        *,
        phase: str,
        completed: int,
        total: int,
        started: float,
        rate_completed: int | None = None,
    ) -> None:
        elapsed = max(time.monotonic() - started, 1e-6)
        samples = rate_completed if rate_completed is not None else completed
        rate = samples / elapsed
        eta = (total - completed) / rate if samples >= 3 and rate else None
        self.state["progress"] = {
            "phase": phase,
            "completed_work": completed,
            "total_work": total,
            "percent": completed / total * 100.0 if total else 0.0,
            "items_per_second": rate,
            "eta_seconds": eta,
            "eta_source": "observed_unit_rate" if eta is not None else "calibrating",
        }
        self._save_all()

    def inventory(self) -> None:
        if self.manifest.get("inventory_complete") and self.manifest.get("functions"):
            self._stage("inventory", "passed", f"{len(self.manifest['functions'])} functions restored")
            return
        if self.manifest.get("inventory_complete"):
            self.manifest["inventory_complete"] = False
            self.manifest["bundles_complete"] = False
            self.manifest["groups_complete"] = False
        self._stage("inventory", "running")
        started = time.monotonic()
        offset = 0
        page_size = 200
        total = 0
        while True:
            self._check_control()
            raw = self.ghidra.list_functions(offset=offset, limit=page_size)
            lines = raw if isinstance(raw, list) else str(raw).splitlines()
            for line in lines:
                total_match = PAGINATION_TOTAL.search(str(line))
                if total_match:
                    total = int(total_match.group(1))
                parsed = parse_function_line(str(line))
                if parsed:
                    self.manifest["functions"].setdefault(
                        parsed["address"],
                        {
                            **parsed,
                            "status": "discovered",
                            "bundle_path": None,
                            "fingerprint": None,
                            "dependencies": [],
                        },
                    )
            self._progress(
                phase="inventory",
                completed=len(self.manifest["functions"]),
                total=total or len(self.manifest["functions"]),
                started=started,
            )
            has_more = any("[Next:" in str(line) for line in lines)
            if not has_more:
                break
            offset += page_size
        if not self.manifest["functions"]:
            restored = self._restore_inventory_from_export()
            if not restored:
                raise ConnectionError(
                    "Ghidra returned no functions and no ghidra-export inventory is available; "
                    "open boot.dol in CodeBrowser and retry"
                )
            self.manifest["program"]["inventory_source"] = "ghidra-export checkpoint"
        self.manifest["inventory_complete"] = True
        self.manifest["program"]["function_count"] = len(self.manifest["functions"])
        self._stage("inventory", "passed", f"{len(self.manifest['functions'])} functions inventoried")

    def _bundle_one(self, record: dict[str, Any]) -> dict[str, Any]:
        address = record["address"]
        get_structured = getattr(self.ghidra, "get_function_bundle", None)
        structured = get_structured(address) if callable(get_structured) else None
        if isinstance(structured, dict) and structured.get("bundle_schema") == self.BUNDLE_SCHEMA:
            target = self.bundle_root / f"{address[2:]}.bundle.json"
            atomic_write_json(target, structured)
            fingerprints = structured.get("fingerprints", {})
            fingerprint = (
                fingerprints.get("normalized_pcode")
                or fingerprints.get("instruction_shape")
            )
            dependencies = [
                normalize_address(value)
                for value in structured.get("calls", [])
            ]
            return {
                **record,
                "status": "bundled" if fingerprint else "bundle_failed",
                "bundle_path": str(target),
                "bundle_source": "function_bundle_v1",
                "fingerprint": fingerprint,
                "fingerprint_kind": (
                    "exact_normalized_pcode"
                    if fingerprints.get("normalized_pcode")
                    else "exact_normalized_disassembly"
                ),
                "dependencies": sorted(set(dependencies)),
                "thunk": bool(structured.get("identity", {}).get("thunk", False)),
            }
        disassembly = self.ghidra.disassemble_function(address)
        if isinstance(disassembly, str):
            disassembly = disassembly.splitlines()
        normalized = normalize_instruction_lines(disassembly)
        raw_disassembly = "\n".join(str(line) for line in disassembly)
        if not normalized and re.search(
            r"request failed|connection|actively refused|no program loaded",
            raw_disassembly,
            re.IGNORECASE,
        ):
            raise ConnectionError(raw_disassembly.strip())
        metadata = self.ghidra.get_function_by_address(address)
        bundle = {
            "bundle_schema": self.BUNDLE_SCHEMA,
            "identity": {
                "address": address,
                "name": record["name"],
                "metadata": metadata,
                "thunk": is_thunk(disassembly),
            },
            "decompiler": {
                "c": None,
                "completed": False,
                "deferred": True,
                "warnings": [],
                "errors": [],
            },
            "normalized_disassembly": normalized,
            "calls": extract_direct_calls(disassembly, address),
            "fingerprints": {
                "normalized_disassembly": fingerprint_instructions(disassembly),
                "normalized_pcode": None,
            },
        }
        target = self.bundle_root / f"{address[2:]}.bundle.json"
        atomic_write_json(target, bundle)
        return {
            **record,
            "status": "bundled" if normalized else "bundle_failed",
            "bundle_path": str(target),
            "bundle_source": "legacy_text_fallback",
            "fingerprint": bundle["fingerprints"]["normalized_disassembly"],
            "fingerprint_kind": "exact_normalized_disassembly",
            "dependencies": bundle["calls"],
            "thunk": bundle["identity"]["thunk"],
        }

    def bundle(self) -> bool:
        if self.manifest.get("bundles_complete"):
            self._stage("bundles", "passed", "all function bundles restored")
            return True
        self._stage("bundles", "running")
        records = list(self.manifest["functions"].values())
        for record in records:
            if (
                record.get("status") == "bundle_failed"
                and not record.get("fingerprint")
                and int(record.get("bundle_attempts", 0)) < 3
            ):
                record["status"] = "discovered"
        legacy = [record for record in records if record.get("bundle_source") == "legacy_text_fallback"]
        get_structured = getattr(self.ghidra, "get_function_bundle", None)
        if legacy and callable(get_structured):
            probe = get_structured(legacy[0]["address"])
            if isinstance(probe, dict) and probe.get("bundle_schema") == self.BUNDLE_SCHEMA:
                for record in legacy:
                    record["status"] = "discovered"
                    record["invalidated_reason"] = "function_bundle_v1 became available"
                self.manifest["bundles_complete"] = False
        pending = [record for record in records if record.get("status") == "discovered"]
        if self.max_bundles is not None:
            pending = pending[: self.max_bundles]
        started = time.monotonic()
        completed_before = len(records) - sum(record.get("status") == "discovered" for record in records)
        for index, record in enumerate(pending, start=1):
            self._check_control()
            record["bundle_attempts"] = int(record.get("bundle_attempts", 0)) + 1
            try:
                updated = self._bundle_one(record)
            except Exception as error:
                updated = {
                    **record,
                    "status": "discovered" if isinstance(error, ConnectionError) else "bundle_failed",
                    "error": str(error),
                }
                self.manifest["functions"][record["address"]] = updated
                self._save_all()
                if isinstance(error, ConnectionError):
                    raise
            self.manifest["functions"][record["address"]] = updated
            if index % 50 == 0 or index == len(pending):
                self._progress(
                    phase="bundles",
                    completed=completed_before + index,
                    total=len(records),
                    started=started,
                    rate_completed=index,
                )
        remaining = sum(
            record.get("status") == "discovered"
            for record in self.manifest["functions"].values()
        )
        self.manifest["bundles_complete"] = remaining == 0
        if remaining:
            self._stage("bundles", "partial", f"{remaining} bundles remain; diagnostic limit reached")
            self.state["status"] = "partial"
            self._save_all()
            return False
        self._stage("bundles", "passed", f"{len(records)} bundles extracted")
        return True

    def group(self) -> None:
        if self.manifest.get("groups_complete"):
            self._stage("groups", "passed", f"{len(self.manifest['groups'])} groups restored")
            return
        self._stage("groups", "running")
        groups = exact_groups(self.manifest["functions"].values())
        schedule = dependency_order(groups)
        self.manifest["groups"] = {group["id"]: group for group in groups}
        self.manifest["schedule"] = schedule
        for group in groups:
            canonical = group["canonical_address"]
            for member in group["member_addresses"]:
                function = self.manifest["functions"][member]
                function["group_id"] = group["id"]
                function["canonical_address"] = canonical
                if member != canonical and function.get("status") == "bundled":
                    function["status"] = "alias"
        self.manifest["groups_complete"] = True
        avoided = sum(max(0, len(group["member_addresses"]) - 1) for group in groups)
        self._stage(
            "groups",
            "passed",
            f"{len(groups)} canonical groups; {avoided} Qwen calls avoided by exact grouping",
        )

    def _known_integrated(self, address: str) -> bool:
        if address != "0x8012b458":
            return False
        verification = (
            self.repo_root
            / "research"
            / "decomp"
            / "generated"
            / "finish-game-port-poc"
            / "8012b458-auto-verification.json"
        )
        if not verification.is_file():
            return False
        try:
            payload = json.loads(verification.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return False
        return payload.get("status") == "passed"

    def _queue_view(self, active: dict[str, Any] | None = None) -> None:
        groups = list(self.manifest["groups"].values())
        recent = [
            group for group in groups
            if group.get("status") != "queued"
        ][-100:]
        visible = ([active] if active else []) + [
            group for group in recent
            if active is None or group["id"] != active["id"]
        ]
        self.state["queue"] = [
            {
                "address": group["canonical_address"],
                "family": f"{len(group['member_addresses'])} address group",
                "status": group.get("status", "queued"),
            }
            for group in visible
        ]
        counts: dict[str, int] = defaultdict(int)
        for group in groups:
            counts[group.get("status", "queued")] += 1
        terminal = {"integrated", "excluded", "alias", "bundle_failed"}
        remaining_functions = sum(
            record.get("port_status") not in terminal
            for record in self.manifest["functions"].values()
        )
        represented = sum(
            count
            for status, count in counts.items()
            if status not in terminal
        )
        counts["waiting"] = max(0, remaining_functions - represented)
        self.state["queue_summary"] = dict(sorted(counts.items()))

    def _process_group(self, group: dict[str, Any]) -> None:
        address = group["canonical_address"]
        group["attempts"] = int(group.get("attempts", 0)) + 1
        if self._known_integrated(address):
            group["status"] = "integrated"
            group["verification"] = "existing verified importer profile"
            return
        function = self.manifest["functions"][address]
        if function.get("status") == "bundle_failed":
            group["status"] = "bundle_failed"
            return

        group["status"] = "model_running"
        self._queue_view(group)
        self._save_all()
        try:
            bundle_path = Path(function["bundle_path"])
            bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
            result = self.source_loop.run(
                address=address,
                aliases=group["member_addresses"],
                bundle=bundle,
            )
        except Exception as error:
            group["status"] = "model_invalid"
            group["error"] = str(error)
            return
        group["source_files"] = result.files
        group["attempts"] = result.attempts
        group["git_checkpoint"] = result.checkpoint
        if not result.passed:
            group["status"] = "model_invalid"
            group["error"] = result.error
            return
        if result.action == "exclude":
            group["status"] = "excluded"
            group["verification"] = "Qwen classified platform/toolchain code outside browser runtime"
            return
        group["status"] = "integrated"
        group["verification"] = "typecheck, combat build, ROM, game-session, and browser build passed"

    def process_units(self) -> None:
        self._stage("units", "running")
        groups = self.manifest["groups"]
        scheduled = [
            groups[group_id]
            for group_id in self.manifest["schedule"]
            if groups[group_id].get("status") not in TERMINAL_UNIT_STATES
        ]
        scheduled.sort(
            key=lambda group: (
                0 if self._known_integrated(group["canonical_address"]) else 1,
                group["canonical_address"],
            )
        )
        if self.max_units is not None:
            scheduled = scheduled[: self.max_units]
        total = len(groups)
        terminal_before = sum(
            group.get("status") in TERMINAL_UNIT_STATES for group in groups.values()
        )
        started = time.monotonic()
        for index, group in enumerate(scheduled, start=1):
            self._check_control()
            self._process_group(group)
            self._queue_view(group)
            self._progress(
                phase="units",
                completed=terminal_before + index,
                total=total,
                started=started,
                rate_completed=index,
            )
        remaining = sum(
            group.get("status") not in TERMINAL_UNIT_STATES for group in groups.values()
        )
        if remaining:
            self._stage("units", "partial", f"{remaining} canonical units remain")
            self.state["status"] = "partial"
        else:
            counts = self.state.get("queue_summary", {})
            blockers = counts.get("missing_profile", 0) + counts.get("needs_oracle", 0)
            self._stage(
                "units",
                "passed" if blockers == 0 else "partial",
                f"{total - blockers}/{total} canonical units terminal without importer/oracle blockers",
            )
            self.state["status"] = "blocked" if blockers else "running"
        self._save_all()

    def stream_units(self) -> None:
        """Extract one missing bundle, port it immediately, then advance."""
        self._stage("bundles", "running", "streaming bundles directly into Qwen")
        self._stage("groups", "passed", "exact fingerprints deduplicate as they arrive")
        self._stage("units", "running", "Qwen source edit -> six gates -> Git push")
        records = sorted(self.manifest["functions"].values(), key=lambda item: item["address"])
        terminal = {"integrated", "excluded", "alias", "bundle_failed"}
        fingerprint_owner = {
            record["fingerprint"]: record["address"]
            for record in records
            if record.get("fingerprint")
            and record.get("port_status") in {"integrated", "excluded"}
        }
        initial_completed = sum(
            record.get("port_status") in terminal for record in records
        )
        completed = initial_completed
        processed_this_run = 0
        started = time.monotonic()
        self._progress(
            phase="stream",
            completed=completed,
            total=len(records),
            started=started,
            rate_completed=0,
        )

        for record in records:
            port_status = record.get("port_status")
            if port_status in terminal:
                continue
            if self.max_units is not None and processed_this_run >= self.max_units:
                break

            self._check_control()
            if record.get("status") == "discovered":
                record["bundle_attempts"] = int(record.get("bundle_attempts", 0)) + 1
                updated = self._bundle_one(record)
                self.manifest["functions"][record["address"]] = updated
                record = updated
            if record.get("status") == "bundle_failed":
                record["port_status"] = "bundle_failed"
                completed += 1
                self._progress(
                    phase="stream",
                    completed=completed,
                    total=len(records),
                    started=started,
                    rate_completed=completed - initial_completed,
                )
                continue

            fingerprint = record.get("fingerprint")
            if fingerprint and fingerprint in fingerprint_owner:
                record["port_status"] = "alias"
                record["canonical_address"] = fingerprint_owner[fingerprint]
                completed += 1
                self._progress(
                    phase="stream",
                    completed=completed,
                    total=len(records),
                    started=started,
                    rate_completed=completed - initial_completed,
                )
                continue

            group_id = f"stream-{record['address'][2:]}"
            group = self.manifest["groups"].setdefault(
                group_id,
                {
                    "id": group_id,
                    "canonical_address": record["address"],
                    "member_addresses": [record["address"]],
                    "proof": "streamed",
                    "fingerprint": fingerprint,
                    "dependencies": record.get("dependencies", []),
                    "status": "queued",
                    "attempts": 0,
                },
            )
            self._process_group(group)
            record["port_status"] = group["status"]
            record["group_id"] = group_id
            record["canonical_address"] = record["address"]
            if fingerprint and group["status"] in {"integrated", "excluded"}:
                fingerprint_owner[fingerprint] = record["address"]
            completed += 1
            processed_this_run += 1
            self._queue_view(group)
            self._progress(
                phase="stream",
                completed=completed,
                total=len(records),
                started=started,
                rate_completed=completed - initial_completed,
            )

        remaining = sum(record.get("port_status") not in terminal for record in records)
        self.manifest["bundles_complete"] = all(
            record.get("status") != "discovered" for record in records
        )
        self.manifest["groups_complete"] = remaining == 0
        self.manifest["schedule"] = list(self.manifest["groups"])
        if remaining:
            self._stage("bundles", "partial", f"{remaining} functions remain in the streamed loop")
            self._stage("units", "partial", f"{remaining} functions remain")
            self.state["status"] = "partial"
        else:
            self._stage("bundles", "passed", f"{len(records)} bundles consumed")
            self._stage(
                "units",
                "passed",
                f"{len(records)} functions integrated, excluded, or deduplicated",
            )
            self.state["status"] = "running"
        self._save_all()

    def acceptance(self) -> None:
        groups = self.manifest["groups"].values()
        blockers = [
            group for group in groups
            if group.get("status") in {"missing_profile", "needs_oracle", "model_invalid", "evidence_rejected"}
        ]
        failed_bundles = [
            record
            for record in self.manifest["functions"].values()
            if record.get("port_status") == "bundle_failed"
        ]
        if blockers or failed_bundles:
            blocker_count = len(blockers) + len(failed_bundles)
            self._stage(
                "acceptance",
                "failed",
                f"{blocker_count} functions block complete-game acceptance",
            )
            self.state["status"] = "blocked"
            self.state["completion"] = {
                "browser_build": "not_run",
                "canonical_units": len(self.manifest["groups"]),
                "integrated": sum(
                    group.get("status") == "integrated"
                    for group in self.manifest["groups"].values()
                ),
                "remaining_blockers": blocker_count,
            }
            self._save_all()
            return
        self._stage("acceptance", "running")
        commands = [
            ["pnpm", "--filter", "@gf/combat", "build"],
            ["pnpm", "selfcheck:rom"],
            ["pnpm", "--filter", "game", "build"],
        ]
        for command in commands:
            result = subprocess.run(
                command,
                cwd=self.repo_root,
                capture_output=True,
                text=True,
                shell=os.name == "nt",
            )
            if result.returncode:
                self._stage("acceptance", "failed", f"{' '.join(command)} failed")
                self.state["status"] = "failed"
                self._save_all()
                return
        self._stage("acceptance", "passed", "combat, ROM, and browser builds passed")
        self.state["status"] = "completed"
        self.state["completed_at"] = utc_now()
        self._save_all()

    def run(self) -> int:
        try:
            self.inventory()
            self.stream_units()
            if self.state["status"] != "partial":
                self.acceptance()
        except StopRequested as error:
            self.state["status"] = "stopped"
            self.state["stop_reason"] = str(error)
            self.state["stopped_at"] = utc_now()
            self._save_all()
            return 2
        except Exception as error:
            self.state["status"] = "failed"
            self.state["error"] = str(error)
            self.state["failed_at"] = utc_now()
            self._save_all()
            raise
        return 0 if self.state["status"] == "completed" else 3


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=["fresh", "resume", "replay"], default="fresh")
    parser.add_argument("--session")
    parser.add_argument("--max-bundles", type=int)
    parser.add_argument("--max-units", type=int)
    args = parser.parse_args(argv)
    scheduler = PortScheduler(
        mode=args.mode,
        session_path=args.session or os.getenv("OGHIDRA_ACTIVE_SESSION"),
        max_bundles=args.max_bundles,
        max_units=args.max_units,
    )
    return scheduler.run()
