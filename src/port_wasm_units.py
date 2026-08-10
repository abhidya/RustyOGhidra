"""wasm-unit mode for the finish-port driver (production form of the 2026-08-09 POC).

Ports VERBATIM Ghidra C units to wasm, gates them (emcc link -> post-link import
whitelist -> oracle corpus diff), and commits each green unit into the product
repo ("commit-per-match"). The unit queue is a JSON file the owner curates:
research/decomp/generated/finish-game-port/wasm-units.json.

Activated only when OGHIDRA_PORT_MODE=wasm_units; otherwise the classic chunk
driver runs untouched (see src/port_scheduler.py dispatch). Supervision contract
is identical to port_driver: control.json honored at unit boundaries,
llm-liveness.json heartbeats, events.jsonl, run-state.json, and the port_driver
exit-code vocabulary, so the existing watchdog needs no changes.

Design rules carried over from the POC (POC-RESULTS-2026-08-09.md):
  - The extracted C is VERBATIM and never edited; the LLM compile-fix loop may
    only rewrite the scaffold header (gnt4_shim.h), max 8 iterations.
  - Never trust link success: undefined symbols silently become wasm env
    imports; only the gnt4_* SDK seam may remain imported (whitelist gate).
  - Only the oracle decides green. Failed units stay retryable forever
    (no countdowns); rotation is least-attempted-first.
"""

from __future__ import annotations

import json
import hashlib
import os
import re
import shutil
import subprocess
import time
from datetime import datetime
from pathlib import Path
from typing import Any

from src.port_chunk_workflow import atomic_write_json, utc_now
from src.port_driver import (
    EXIT_NO_WORK,
    EXIT_PROGRESSED,
    EXIT_STOPPED,
    EXIT_LOCKED,
    DriverEvents,
    DriverLock,
)
from src.port_run_controller import find_gotyaforce_root


QUEUE_SCHEMA = 1
STATE_SCHEMA = 1
MAX_COMPILE_ITERS = 8
BUILD_TIMEOUT_SECONDS = 600
ORACLE_TIMEOUT_SECONDS = 1800
# Post-link import whitelist (POC finding: a missing CONCAT44 linked "fine" as a
# dead env import). Only the SDK seam may be imported; these wasm plumbing names
# are structural, not code imports.
ALLOWED_IMPORT_PREFIX = "gnt4_"
BENIGN_IMPORTS = {
    "memory",
    "__memory_base",
    "__table_base",
    "__indirect_function_table",
    "__stack_pointer",
}
# node.exe is not on the service PATH; OGHIDRA_NODE_EXE overrides, then PATH,
# then the rig's known runtime checkout.
NODE_FALLBACKS = [
    r"D:\manny\Documents\CustomCard\.codex\runtime\node\node-v24.18.0-win-x64\node.exe",
]

SYSTEM_PROMPT = """You are the compile-fix stage of a Ghidra-C -> wasm port pipeline for a
GameCube (PowerPC, big-endian) game. A verbatim Ghidra-decompiled C file fails to
compile with emscripten (clang, wasm32). You may ONLY change the support header
gnt4_shim.h — the .c file is verbatim decompiler output and must never be edited.

Fix the header so the C compiles AND keeps the original PowerPC runtime semantics
(Ghidra decompiler idioms must behave exactly as they did on the GameCube).
Output the COMPLETE corrected gnt4_shim.h in a single ```c code block. No other text
is used by the pipeline."""

CODE_BLOCK = re.compile(r"```(?:c|cpp|h)?\s*\n(.*?)```", re.S)
GIT_TRAILER = "Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"


def resolve_node_exe() -> str:
    """node for oracle harnesses: env override -> PATH -> rig runtime checkout."""
    override = os.getenv("OGHIDRA_NODE_EXE")
    if override and Path(override).is_file():
        return override
    found = shutil.which("node")
    if found:
        return found
    for candidate in NODE_FALLBACKS:
        if Path(candidate).is_file():
            return candidate
    raise FileNotFoundError(
        "node executable not found (set OGHIDRA_NODE_EXE or add node to PATH)"
    )


def extract_verbatim(repo_root: Path, extractions: list[dict[str, Any]]) -> tuple[str, list[dict[str, Any]]]:
    """Python equivalent of the POC's sed extraction: 1-based inclusive ranges,
    bytes kept verbatim. Returns (combined text with markers, per-block records
    incl. sha256 of the raw extracted text)."""
    blocks: list[str] = []
    records: list[dict[str, Any]] = []
    for spec in extractions:
        source = repo_root / spec["file"]
        start, end = int(spec["start"]), int(spec["end"])
        lines = source.read_text(encoding="utf-8", errors="replace").splitlines(keepends=True)
        if not (1 <= start <= end <= len(lines)):
            raise ValueError(f"extraction range {start}-{end} out of bounds for {source}")
        raw = "".join(lines[start - 1 : end])
        records.append(
            {
                "file": spec["file"],
                "start": start,
                "end": end,
                "sha256": hashlib.sha256(raw.encode("utf-8")).hexdigest(),
            }
        )
        blocks.append(f"/* ==== VERBATIM: {spec['file']} {start}-{end} ==== */\n{raw}")
    return "\n".join(blocks), records


def scan_disallowed_imports(wasm_path: Path) -> list[str]:
    """POC link gate: find env.* import names that are not gnt4_* SDK functions.

    Same heuristic scan model_loop.py proved (name strings following 'env.' in
    the binary); false negatives are impossible for the failure mode this guards
    (an identifier-shaped undefined symbol imported from env)."""
    data = wasm_path.read_bytes()
    names = [
        match.decode("utf-8", "ignore").split("\x00")[0]
        for match in re.findall(rb"env.([\x20-\x7e]{2,40})", data)
    ]
    return sorted(
        {
            name
            for name in names
            if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name)
            and not name.startswith(ALLOWED_IMPORT_PREFIX)
            and name not in BENIGN_IMPORTS
        }
    )


class WasmUnitDriver:
    """Queue-driven wasm unit porter with the port_driver supervision contract."""

    def __init__(
        self,
        *,
        repo_root: str | Path | None = None,
        units_budget: int = 1,
        until_blocked: bool = False,
        llm: Any | None = None,
        build_runner: Any | None = None,
        oracle_runner: Any | None = None,
        git_runner: Any | None = None,
    ):
        self.repo_root = (
            Path(repo_root).resolve() if repo_root is not None else find_gotyaforce_root()
        )
        self.run_root = self.repo_root / "research/decomp/generated/finish-game-port"
        self.queue_path = self.run_root / "wasm-units.json"
        self.state_path = self.run_root / "wasm-units-state.json"
        self.work_root = self.run_root / "wasm-units"
        self.artifact_root = self.repo_root / "research/decomp/port-units"
        self.staging_root = self.repo_root / "research/decomp/port-units-staging"
        self.lock = DriverLock(self.run_root / "wasm-units.lock")
        self.run_id = os.getenv("OGHIDRA_PORT_RUN_ID") or utc_now()
        self.events = DriverEvents(self.run_root / "events.jsonl", self.run_id)
        self.units_budget = max(1, units_budget)
        self.until_blocked = until_blocked
        self._llm = llm
        self._build_runner = build_runner or self._emcc_build
        self._oracle_runner = oracle_runner or self._run_oracle
        self._git_runner = git_runner or self._git
        self._greens_this_run = 0

    # ------------------------------------------------------------------- state

    def _load_queue(self) -> list[dict[str, Any]]:
        payload = json.loads(self.queue_path.read_text(encoding="utf-8-sig"))
        if payload.get("queue_schema") != QUEUE_SCHEMA:
            raise ValueError(f"wasm-units.json queue_schema != {QUEUE_SCHEMA}")
        units = payload.get("units")
        if not isinstance(units, list) or not units:
            raise ValueError("wasm-units.json has no units")
        return units

    def _load_state(self) -> dict[str, Any]:
        try:
            state = json.loads(self.state_path.read_text(encoding="utf-8-sig"))
            if state.get("state_schema") == STATE_SCHEMA:
                return state
        except (FileNotFoundError, json.JSONDecodeError, OSError):
            pass
        return {"state_schema": STATE_SCHEMA, "created_at": utc_now(), "units": {}}

    def _save_state(self, state: dict[str, Any]) -> None:
        state["updated_at"] = utc_now()
        atomic_write_json(self.state_path, state)

    def _unit_state(self, state: dict[str, Any], name: str) -> dict[str, Any]:
        return state["units"].setdefault(name, {"status": "pending", "attempts": 0})

    # ----------------------------------------------------------------- control

    def _control_command(self) -> str:
        try:
            return json.loads(
                (self.run_root / "control.json").read_text(encoding="utf-8-sig")
            ).get("command", "run")
        except (FileNotFoundError, json.JSONDecodeError, OSError):
            return "run"

    def _heartbeat(self, status: str) -> None:
        """Keep llm-liveness.json fresh between LLM calls (the CustomAPIClient
        owns it during streaming). Merge-update so client metrics survive."""
        path_value = os.getenv("OGHIDRA_PORT_LIVENESS_PATH")
        if not path_value:
            return
        path = Path(path_value)
        try:
            payload = json.loads(path.read_text(encoding="utf-8-sig"))
        except (FileNotFoundError, json.JSONDecodeError, OSError):
            payload = {}
        payload.update(
            {
                "run_id": self.run_id,
                "status": status,
                "active": not status.endswith(":idle"),
                "updated_at": datetime.now().isoformat(),
            }
        )
        try:
            atomic_write_json(path, payload)
        except OSError:
            pass  # telemetry never blocks port work

    def _write_progress(self, state: dict[str, Any], status: str, *, unit: str | None = None) -> None:
        units = state.get("units", {})
        greens = sum(1 for record in units.values() if record.get("status") == "green")
        total = max(len(units), 1)
        payload = {
            "run_schema": 3,
            "run_mode": "driver",
            "objective": "Port verbatim Ghidra C units to oracle-gated wasm (wasm_units mode)",
            "run_id": self.run_id,
            "status": status,
            "updated_at": utc_now(),
            "progress": {
                "completed_work": greens,
                "total_work": len(units),
                "percent": greens / total * 100.0,
            },
            "counters": {
                "units_integrated": greens,
                "units_known": len(units),
                "model_requests_total": sum(
                    record.get("model_requests", 0) for record in units.values()
                ),
            },
            "queue": [
                {"family": name, "status": record.get("status", "pending")}
                for name, record in units.items()
                if record.get("status") != "green"
            ][:5],
        }
        if unit is not None:
            payload["unit"] = unit
        atomic_write_json(self.run_root / "run-state.json", payload)
        self.events.emit("progress", **payload["counters"])

    # --------------------------------------------------------------------- llm

    def _llm_client(self) -> Any:
        if self._llm is None:
            from src.config import get_config
            from src.custom_api_client import CustomAPIClient

            self._llm = CustomAPIClient(get_config().custom_api)
        return self._llm

    def _compile_fix(self, unit_c: str, header: str, errors: str) -> str | None:
        """One LLM round; returns the corrected header text or None."""
        prompt = (
            f"Verbatim decompiled C (read-only):\n```c\n{unit_c}\n```\n\n"
            f"Current gnt4_shim.h:\n```c\n{header}\n```\n\n"
            f"Exact compiler output:\n```\n{errors}\n```\n\n"
            "Return the complete corrected gnt4_shim.h."
        )
        reply = self._llm_client().generate(
            prompt=prompt, system_prompt=SYSTEM_PROMPT, temperature=0.6
        )
        matches = CODE_BLOCK.findall(reply or "")
        if not matches:
            return None
        return max(matches, key=len)

    # ------------------------------------------------------------------- build

    def _emcc_build(
        self,
        workdir: Path,
        exports: list[str],
        allowed_extra: list[str] | None = None,
    ) -> tuple[bool, str]:
        bash = shutil.which("bash") or r"C:\Program Files\Git\bin\bash.exe"
        emsdk = self.repo_root / "research/tools/emsdk"
        exports_flag = ",".join("_" + name for name in exports)
        script = (
            f"source \"$(cygpath -u '{emsdk}')/emsdk_env.sh\" >/dev/null 2>&1; "
            f"cd \"$(cygpath -u '{workdir}')\" && "
            "emcc unit.c -O1 -fno-strict-aliasing --no-entry "
            "-Wno-implicit-function-declaration -Wno-int-conversion "
            "-Wno-deprecated-non-prototype "
            "-sERROR_ON_UNDEFINED_SYMBOLS=0 -sINITIAL_MEMORY=2155479040 "
            "-sALLOW_MEMORY_GROWTH=0 "
            f"-sEXPORTED_FUNCTIONS={exports_flag} "
            "-o unit.wasm"
        )
        completed = subprocess.run(
            [bash, "-lc", script],
            capture_output=True,
            text=True,
            timeout=BUILD_TIMEOUT_SECONDS,
        )
        if completed.returncode != 0:
            return False, (completed.stderr + completed.stdout)[-6000:]
        bad = scan_disallowed_imports(workdir / "unit.wasm")
        # Auto-generated units may declare external callees (functions outside the
        # unit's extraction set). Those stay wasm imports by design — the JS side
        # stubs+logs them (auto-stub rule) — so they are whitelisted per unit.
        if allowed_extra:
            bad = [name for name in bad if name not in allowed_extra]
        if bad:
            return False, (
                "link gate: these symbols are UNDEFINED and became wasm imports, but "
                "they are not gnt4_* SDK functions, so they must be DEFINED in "
                f"gnt4_shim.h with correct PowerPC semantics: {', '.join(bad)}\n"
                "(Ghidra decompiler helper idioms like CONCAT44 must behave exactly "
                "as the original PPC code did.)"
            )
        return True, ""

    # ------------------------------------------------------------------ oracle

    def _run_oracle(self, unit: dict[str, Any], wasm_path: Path) -> tuple[bool, str, str]:
        """Run the unit's oracle command. Returns (passed, summary, full_log)."""
        oracle = unit["oracle"]
        command = list(oracle["command"])
        if command and command[0] == "node":
            command[0] = resolve_node_exe()
        env = dict(os.environ)
        for key, value in (oracle.get("env") or {}).items():
            env[key] = str(value).replace("{wasm}", str(wasm_path))
        completed = subprocess.run(
            command,
            cwd=str(self.repo_root / oracle["cwd"]),
            env=env,
            capture_output=True,
            text=True,
            timeout=ORACLE_TIMEOUT_SECONDS,
        )
        log = completed.stdout + ("\n--- stderr ---\n" + completed.stderr if completed.stderr else "")
        passed = completed.returncode == 0
        for pattern in oracle.get("success_patterns") or []:
            if not re.search(pattern, log):
                passed = False
        summary = ", ".join(re.findall(r"\d+/\d+", completed.stdout)[:4]) or (
            "pass" if passed else f"exit {completed.returncode}"
        )
        return passed, summary, log

    # --------------------------------------------------------------------- git

    def _git(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["git", *args],
            cwd=str(self.repo_root),
            capture_output=True,
            text=True,
            timeout=300,
        )

    def _commit_unit(
        self, name: str, summary: str, *, staging: bool = False
    ) -> tuple[str | None, bool, str]:
        """git add + commit + push the unit's artifact dir. Returns
        (commit_sha or None, pushed, detail)."""
        rel = (
            f"research/decomp/port-units-staging/{name}"
            if staging
            else f"research/decomp/port-units/{name}"
        )
        added = self._git_runner("add", rel)
        if added.returncode != 0:
            return None, False, (added.stdout + added.stderr)[-400:]
        message = (
            f"port-staging: {name} wasm unit LINKED (unoracled, not for integration)\n\n{GIT_TRAILER}"
            if staging
            else f"port: {name} wasm unit green (oracle {summary})\n\n{GIT_TRAILER}"
        )
        committed = self._git_runner("commit", "-m", message)
        if committed.returncode != 0:
            return None, False, (committed.stdout + committed.stderr)[-400:]
        sha = ""
        rev = self._git_runner("rev-parse", "HEAD")
        if rev.returncode == 0:
            sha = rev.stdout.strip()
        pushed = self._git_runner("push")
        if pushed.returncode != 0:
            pushed = self._git_runner("push", "-u", "origin", "HEAD")
        return sha or None, pushed.returncode == 0, (
            "" if pushed.returncode == 0 else (pushed.stdout + pushed.stderr)[-400:]
        )

    # -------------------------------------------------------------------- unit

    def _process_unit(self, unit: dict[str, Any], state: dict[str, Any]) -> str:
        name = unit["name"]
        record = self._unit_state(state, name)
        record["status"] = "porting"
        record["attempts"] = record.get("attempts", 0) + 1
        self._save_state(state)
        self.events.emit("wasm_unit_started", unit=name, attempts=record["attempts"])
        self._heartbeat(f"wasm_units:{name}:extract")

        workdir = self.work_root / name
        workdir.mkdir(parents=True, exist_ok=True)

        # 1. verbatim extraction (sha256-recorded)
        try:
            verbatim, extraction_records = extract_verbatim(self.repo_root, unit["extractions"])
        except (OSError, ValueError, KeyError) as error:
            return self._fail(state, record, name, f"extraction: {error}")
        prelude = "\n".join(unit.get("prelude", []))
        unit_c = (
            "#include \"gnt4_shim.h\"\n\n"
            + (prelude + "\n\n" if prelude else "")
            + verbatim
        )
        (workdir / "unit.c").write_text(unit_c, encoding="utf-8", newline="\n")
        combined_sha = hashlib.sha256(verbatim.encode("utf-8")).hexdigest()

        # 2. header scaffold: reset to the seed every attempt (deterministic base)
        header_seed = self.repo_root / unit["header_seed"]
        try:
            header = header_seed.read_text(encoding="utf-8")
        except OSError as error:
            return self._fail(state, record, name, f"header seed: {error}")
        (workdir / "gnt4_shim.h").write_text(header, encoding="utf-8", newline="\n")

        # 3. build + LLM compile-fix loop (header-only edits, max 8 iters)
        exports = unit["exported_functions"]
        model_used: str | None = None
        iterations = 0
        linked = False
        build_error = ""
        for iteration in range(1, MAX_COMPILE_ITERS + 1):
            iterations = iteration
            self._heartbeat(f"wasm_units:{name}:build:{iteration}")
            try:
                linked, build_error = self._build_runner(
                    workdir, exports, unit.get("allowed_extra_imports") or None
                )
            except (OSError, subprocess.SubprocessError) as error:
                return self._fail(state, record, name, f"build runner: {error}")
            self.events.emit(
                "wasm_unit_build", unit=name, iteration=iteration, linked=linked
            )
            if linked:
                break
            if iteration == MAX_COMPILE_ITERS:
                break
            self._heartbeat(f"wasm_units:{name}:compile_fix:{iteration}")
            try:
                fixed = self._compile_fix(
                    unit_c, (workdir / "gnt4_shim.h").read_text(encoding="utf-8"), build_error
                )
            except Exception as error:  # LLM/provider failure: red, retryable
                return self._fail(state, record, name, f"compile-fix LLM: {error}")
            record["model_requests"] = record.get("model_requests", 0) + 1
            model_used = getattr(self._llm, "default_model", None) or model_used
            self._save_state(state)
            if fixed is None:
                return self._fail(state, record, name, "compile-fix returned no code block")
            (workdir / "gnt4_shim.h").write_text(fixed, encoding="utf-8", newline="\n")
            (workdir / f"header-iter{iteration}.h").write_text(
                fixed, encoding="utf-8", newline="\n"
            )
        if not linked:
            return self._fail(state, record, name, f"not linked: {build_error[:600]}")

        # 4. oracle gate. Tier "compile_only" (auto-generated chunk units) has no
        # oracle yet: it passes build+import gates only, lands in the STAGING
        # artifact tree with verified:false provenance, and is never wired into
        # the app. Design stage 4 (oracle before trust) still governs promotion.
        oracle_spec = unit.get("oracle") or {}
        compile_only = oracle_spec.get("type") == "compile_only"
        if compile_only:
            passed, summary, oracle_log = True, "compile-only (UNVERIFIED)", (
                "compile_only tier: build + import whitelist gates only; no "
                "behavioral oracle was run. NOT for app integration."
            )
        else:
            self._heartbeat(f"wasm_units:{name}:oracle")
            try:
                passed, summary, oracle_log = self._oracle_runner(unit, workdir / "unit.wasm")
            except (OSError, subprocess.SubprocessError, FileNotFoundError) as error:
                return self._fail(state, record, name, f"oracle runner: {error}")
        (workdir / "oracle.log").write_text(oracle_log, encoding="utf-8", newline="\n")
        if not passed:
            return self._fail(state, record, name, f"oracle red: {summary}")

        # 5. green: artifacts + provenance + commit-per-match
        artifact_dir = (
            self.staging_root if compile_only else self.artifact_root
        ) / name
        artifact_dir.mkdir(parents=True, exist_ok=True)
        for file_name in ("unit.c", "gnt4_shim.h", "unit.wasm", "oracle.log"):
            shutil.copyfile(workdir / file_name, artifact_dir / file_name)
        provenance = {
            "unit": name,
            "run_id": self.run_id,
            "generated_at": utc_now(),
            "extractions": extraction_records,
            "extracted_sha256": combined_sha,
            "exported_functions": exports,
            "compile_iterations": iterations,
            "model": model_used,
            "model_requests": record.get("model_requests", 0),
            "verified": not compile_only,
            "tier": "compile_only" if compile_only else "oracle_green",
            "allowed_extra_imports": unit.get("allowed_extra_imports") or [],
            "oracle": (
                {"type": "compile_only", "summary": summary}
                if compile_only
                else {
                    "command": oracle_spec["command"],
                    "cwd": oracle_spec["cwd"],
                    "summary": summary,
                }
            ),
        }
        atomic_write_json(artifact_dir / "provenance.json", provenance)
        sha, pushed, push_detail = self._commit_unit(name, summary, staging=compile_only)
        record.update(
            status="green",
            error=None,
            oracle_summary=summary,
            commit=sha,
            pushed=pushed,
        )
        self._save_state(state)
        self._greens_this_run += 1
        self.events.emit(
            "wasm_unit_green",
            unit=name,
            oracle_summary=summary,
            commit=sha,
            pushed=pushed,
            push_detail=push_detail,
        )
        return "green"

    def _fail(self, state: dict[str, Any], record: dict[str, Any], name: str, error: str) -> str:
        # Owner design: no countdown kills a unit; red units sink behind
        # less-attempted work and come around again.
        record.update(status="red_retryable", error=error[:2000])
        self._save_state(state)
        self.events.emit(
            "wasm_unit_red", unit=name, error=error[:600], attempts=record.get("attempts", 0)
        )
        return "red_retryable"

    # --------------------------------------------------------------------- run

    def _next_unit(
        self,
        queue: list[dict[str, Any]],
        state: dict[str, Any],
        processed: set[str],
    ) -> dict[str, Any] | None:
        candidates = []
        for index, unit in enumerate(queue):
            name = unit["name"]
            record = self._unit_state(state, name)
            if record.get("status") == "green" or name in processed:
                continue
            candidates.append((record.get("attempts", 0), index, unit))
        if not candidates:
            return None
        candidates.sort(key=lambda item: (item[0], item[1]))
        return candidates[0][2]

    def run(self) -> int:
        if not self.lock.acquire():
            print("another wasm-units driver holds wasm-units.lock; exiting")
            return EXIT_LOCKED
        try:
            try:
                queue = self._load_queue()
            except (FileNotFoundError, json.JSONDecodeError, ValueError, OSError) as error:
                print(f"wasm-units queue unusable: {error}")
                self.events.emit("wasm_queue_unusable", error=str(error)[:400])
                return EXIT_STOPPED
            state = self._load_state()
            for unit in queue:  # make every queued unit visible in state/progress
                self._unit_state(state, unit["name"])
            self._save_state(state)
            self.events.emit(
                "driver_started", mode="wasm_units", units_budget=self.units_budget
            )
            processed: set[str] = set()
            steps_done = 0
            while True:
                command = self._control_command()
                if command in {"stop_after_stage", "pause_after_stage"}:
                    self._write_progress(state, "stopped")
                    self.events.emit("driver_stopped", reason=f"control:{command}")
                    return EXIT_STOPPED
                unit = self._next_unit(queue, state, processed)
                if unit is None:
                    all_green = all(
                        record.get("status") == "green"
                        for record in state["units"].values()
                    )
                    self._write_progress(state, "completed" if all_green else "running")
                    self.events.emit(
                        "driver_stopped",
                        reason="no_work_left" if all_green else "pass_complete",
                    )
                    return EXIT_NO_WORK if all_green else EXIT_PROGRESSED
                self.events.emit("selection", action="wasm_unit", unit=unit["name"])
                self._write_progress(state, "porting", unit=unit["name"])
                self._process_unit(unit, state)
                processed.add(unit["name"])
                steps_done += 1
                self._write_progress(state, "running")
                if not self.until_blocked and steps_done >= self.units_budget:
                    remaining = self._next_unit(queue, state, processed)
                    all_green = all(
                        record.get("status") == "green"
                        for record in state["units"].values()
                    )
                    done = all_green and remaining is None
                    if done:
                        self._write_progress(state, "completed")
                    self.events.emit("driver_stopped", reason="units_budget_reached")
                    return EXIT_NO_WORK if done else EXIT_PROGRESSED
        finally:
            self._heartbeat("wasm_units:idle")
            self.lock.release()
