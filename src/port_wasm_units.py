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
from pathlib import Path
from typing import Any

from src.port_chunk_workflow import TRANSIENT_MARKERS, atomic_write_json, utc_now
from src.port_driver import (
    EXIT_NO_WORK,
    EXIT_PROGRESSED,
    EXIT_PROVIDER_PAUSED,
    EXIT_STOPPED,
    EXIT_LOCKED,
    DriverEvents,
    DriverLock,
)
from src.port_model_config import resolve_port_model_config
from src.port_progress import (
    RESULT_DEFERRED,
    RESULT_GATE_FAILED,
    RESULT_GREEN,
    RESULT_RETRYABLE,
    RESULT_STAGED,
    RESULT_STRUCTURAL_INELIGIBLE,
    MachineState,
    UnitTransition,
    journal_for,
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

# Thinking OFF, exactly as the chunk-era source loop learned to do it
# (src/port_source_loop.py PORT_DISABLE_THINKING). This server reports
# reasoning_style=enable_thinking with reasoning_always_on=false, so thinking is
# ON unless the request says otherwise -- and when it is on, the model spends the
# whole max_tokens budget in `reasoning_content` and returns an EMPTY `content`.
# The client then raises "returned no assistant content", which is how 8 of the
# 19 reds on 2026-08-15 were recorded as unit faults, plus 3 more that simply hit
# the 1200s read timeout mid-spiral. The disable machinery already existed; the
# wasm-unit path just never inherited it.
DISABLE_THINKING = os.getenv("OGHIDRA_PORT_DISABLE_THINKING", "1").lower() not in (
    "0", "false", "no",
)

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
        journal: Any | None = None,
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
        # Remote workflow journal: one durable progress record per unit
        # transition, on the port-progress branch. Never allowed to fail a unit.
        self._journal = journal if journal is not None else journal_for(
            self.repo_root, run_root=self.run_root, run_id=self.run_id
        )
        self._previous_unit: str | None = None
        self._previous_result: str | None = None
        self._model_config = resolve_port_model_config()
        self._provider_paused_detail: str | None = None

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
        except FileNotFoundError:
            return {"state_schema": STATE_SCHEMA, "created_at": utc_now(), "units": {}}
        except (json.JSONDecodeError, OSError):
            state = None
        # An unreadable or wrong-schema state file holds every green verdict and
        # attempt count in the run. Starting fresh over it would silently re-port
        # and re-commit units that are already done, so keep a copy and say so.
        backup = self.state_path.with_name(
            f"{self.state_path.name}.unreadable-{utc_now().replace(':', '').replace('-', '')}"
        )
        try:
            shutil.copyfile(self.state_path, backup)
            print(
                f"WARNING: {self.state_path.name} was unreadable or a foreign schema "
                f"(found {state.get('state_schema') if isinstance(state, dict) else 'unparseable'}); "
                f"preserved at {backup.name} and starting a fresh state file"
            )
            self.events.emit("state_file_reset", backup=backup.name)
        except OSError as error:
            print(f"WARNING: could not preserve the previous state file: {error}")
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
                # UTC-Z, like every sibling stamp in this file. A naive local
                # stamp here made every consumer diffing against UTC see a
                # constant multi-hour staleness.
                "updated_at": utc_now(),
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

    # ---------------------------------------------------------------- progress

    def _checkpoint(
        self,
        state: dict[str, Any],
        transition: UnitTransition | None,
        *,
        current_unit: str | None = None,
        current_stage: str | None = None,
        current_attempt: int = 0,
        workflow_state: str = "running",
        driver_running: bool = True,
    ) -> None:
        """Emit one remote progress checkpoint. Telemetry: never fails a unit.

        Called at EVERY unit transition, before the selector moves on -- the
        unit-transition invariant. A git/network fault degrades to a recorded
        pending push, never to a lost unit or a raised exception.
        """
        machine = MachineState(
            workflow_state=workflow_state,
            driver_status="running" if driver_running else "stopped",
            configured_model=self._model_config.model,
            active_model=self._model_config.model,
            context_length=self._model_config.max_seq_length or None,
        )
        try:
            self._journal.checkpoint(
                transition=transition,
                units=state.get("units", {}),
                machine=machine,
                previous_unit=self._previous_unit,
                previous_result=self._previous_result,
                current_unit=current_unit,
                current_stage=current_stage,
                current_attempt=current_attempt,
                driver_running=driver_running,
            )
        except Exception as error:  # noqa: BLE001 - telemetry is never fatal
            self.events.emit("progress_checkpoint_failed", error=str(error)[:400])
        if transition is not None:
            self._previous_unit = transition.unit
            self._previous_result = transition.result

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
            prompt=prompt,
            system_prompt=SYSTEM_PROMPT + (" /no_think" if DISABLE_THINKING else ""),
            temperature=0.6,
            # Belt and braces, same as the source loop: the template kwarg is
            # honoured by llama.cpp/vLLM/SGLang and ignored elsewhere, and the
            # Qwen `/no_think` soft switch covers the rest.
            **(
                {"chat_template_kwargs": {"enable_thinking": False}}
                if DISABLE_THINKING
                else {}
            ),
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
        committed = self._git_runner("commit", "-m", message, "--", rel)
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
            # The queue entry does not describe extractable code: retrying the
            # identical spec cannot help, so this is structural, not retryable.
            return self._fail(
                state, record, name, f"extraction: {error}",
                stage="extract", result=RESULT_STRUCTURAL_INELIGIBLE,
            )
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
            return self._fail(
                state, record, name, f"header seed: {error}",
                stage="header-seed", result=RESULT_STRUCTURAL_INELIGIBLE,
            )
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
                return self._fail(
                    state, record, name, f"build runner: {error}", stage="build",
                )
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
            except Exception as error:  # noqa: BLE001
                # A PROVIDER outage is not this unit's fault. Blaming the unit
                # is how 19 consecutive units were marked red_retryable on
                # 2026-08-15 for "Serving context still 32768 < required 33974"
                # and "Custom API returned no assistant content" -- provider
                # faults, recorded as per-unit verdicts, with the rig unable to
                # see an outage at all because wasm mode never raised one.
                if self._is_context_budget_fault(error):
                    # Not a provider outage and not a bad unit: this unit's
                    # prompt simply does not fit the configured serving context.
                    # Naming it as its own class makes the repeated-failure
                    # section of the README say exactly which knob to turn,
                    # instead of burying 1,500 units under "compile-fix LLM".
                    return self._fail(
                        state, record, name, f"context budget: {error}",
                        stage="context-budget", result=RESULT_GATE_FAILED,
                    )
                if self._is_provider_fault(error):
                    return self._provider_pause(state, record, name, str(error))
                return self._fail(
                    state, record, name, f"compile-fix LLM: {error}", stage="compile-fix",
                )
            record["model_requests"] = record.get("model_requests", 0) + 1
            model_used = getattr(self._llm, "default_model", None) or model_used
            self._save_state(state)
            if fixed is None:
                return self._fail(
                    state, record, name, "compile-fix returned no code block",
                    stage="compile-fix",
                )
            (workdir / "gnt4_shim.h").write_text(fixed, encoding="utf-8", newline="\n")
            (workdir / f"header-iter{iteration}.h").write_text(
                fixed, encoding="utf-8", newline="\n"
            )
        if not linked:
            return self._fail(
                state, record, name, f"not linked: {build_error[:600]}",
                stage="wasm-link", result=RESULT_GATE_FAILED,
            )

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
                return self._fail(
                    state, record, name, f"oracle runner: {error}", stage="oracle",
                )
        (workdir / "oracle.log").write_text(oracle_log, encoding="utf-8", newline="\n")
        if not passed:
            return self._fail(
                state, record, name, f"oracle red: {summary}",
                stage="oracle", result=RESULT_GATE_FAILED,
            )

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
        try:
            sha, pushed, push_detail = self._commit_unit(name, summary, staging=compile_only)
        except (OSError, subprocess.SubprocessError) as error:
            # A stalled `git push` hits the 300s timeout and raises
            # TimeoutExpired (a SubprocessError, NOT an OSError). Unguarded, it
            # escaped run() entirely and left the unit stuck as `porting` after
            # the local commit had already succeeded.
            return self._fail(
                state, record, name, f"product commit/push: {error}", stage="commit",
            )
        if sha is None:
            # The artifact never entered git history. Marking it green would
            # SETTLE it -- removing it from the queue forever with nothing in the
            # product tree, and rendering on GitHub as an ordinary green.
            return self._fail(
                state, record, name,
                f"product commit failed, unit not settled: {push_detail}",
                stage="commit",
            )
        self._checkpoint(
            state,
            UnitTransition(
                unit=name,
                result=RESULT_STAGED if compile_only else RESULT_GREEN,
                stage="commit",
                attempt=record.get("attempts", 0),
                detail=(
                    "compile-only staging artifact (UNVERIFIED, not integrated)"
                    if compile_only
                    else f"oracle green: {summary}"
                ),
                product_commit=sha,
                product_pushed=pushed,
                oracle_summary=summary,
                model=model_used or self._model_config.model,
                tier="compile_only" if compile_only else "oracle_green",
            ),
        )
        record.update(
            status="green",
            error=None,
            oracle_summary=summary,
            commit=sha,
            pushed=pushed,
            tier="compile_only" if compile_only else "oracle_green",
            last_stage="commit",
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

    @staticmethod
    def _is_context_budget_fault(error: Exception) -> bool:
        """The prompt cannot fit the CONFIGURED context, so no retry can help
        until the configuration changes. Distinct from a provider outage."""
        message = str(error).lower()
        return (
            "a reload cannot help" in message
            or "context_length_exceeded" in message
            or ("exceeds the" in message and "context window" in message)
        )

    @staticmethod
    def _is_provider_fault(error: Exception) -> bool:
        """Is this the serving host failing, rather than the unit being bad?

        Uses the SAME marker list the chunk workflow's pause rule uses, plus the
        two shapes the wasm compile-fix loop actually produced live: a served
        context too small for the request, and an empty assistant response.
        """
        message = str(error).lower()
        if any(marker in message for marker in TRANSIENT_MARKERS):
            return True
        return (
            "returned no assistant content" in message
            or "serving context still" in message
        )

    def _provider_pause(
        self, state: dict[str, Any], record: dict[str, Any], name: str, detail: str
    ) -> str:
        """Hand the unit back untouched and tell the machine the provider is out.

        The unit keeps its previous status (it earned no verdict) and its
        attempt is refunded, so it does not sink behind the queue for a fault
        that was not its own.
        """
        record["attempts"] = max(0, record.get("attempts", 1) - 1)
        record["status"] = "pending"
        record["error"] = f"provider unavailable: {detail[:800]}"
        record["last_stage"] = "compile-fix"
        self._save_state(state)
        self._provider_paused_detail = detail[:600]
        self.events.emit("provider_unavailable", unit=name, error=detail[:600])
        self._checkpoint(
            state,
            UnitTransition(
                unit=name,
                result=RESULT_DEFERRED,
                stage="compile-fix",
                attempt=record.get("attempts", 0),
                detail=f"provider unavailable, unit not blamed: {detail[:400]}",
                model=self._model_config.model,
            ),
            workflow_state="provider_paused",
        )
        return "provider_paused"

    def _fail(
        self,
        state: dict[str, Any],
        record: dict[str, Any],
        name: str,
        error: str,
        *,
        stage: str = "port",
        result: str = RESULT_RETRYABLE,
    ) -> str:
        # Owner design: no countdown kills a unit; red units sink behind
        # less-attempted work and come around again. `structural_ineligible` is
        # the one class that is NOT a retry candidate -- the queue entry itself
        # does not describe extractable code.
        status = (
            "structural_ineligible"
            if result == RESULT_STRUCTURAL_INELIGIBLE
            else "red_retryable"
        )
        transition = UnitTransition(
            unit=name,
            result=result,
            stage=stage,
            attempt=record.get("attempts", 0),
            detail=error,
            model=self._model_config.model,
            product_commit_failed=stage == "commit",
            product_commit_detail=error if stage == "commit" else "",
        )
        if status in self.SETTLED_STATUSES:
            # Settling removes the unit from the queue permanently, and
            # `_reconcile_interrupted` only rescues units left as `porting`.
            # Record it remotely BEFORE it becomes unrecoverable locally.
            self._checkpoint(state, transition)
            record.update(status=status, error=error[:2000], last_stage=stage)
            self._save_state(state)
        else:
            record.update(status=status, error=error[:2000], last_stage=stage)
            self._save_state(state)
            self._checkpoint(state, transition)
        self.events.emit(
            "wasm_unit_red", unit=name, error=error[:600], attempts=record.get("attempts", 0),
            stage=stage, result=result,
        )
        return status

    # --------------------------------------------------------------------- run

    # Statuses that permanently take a unit out of the work pool. Anything else
    # (pending, porting, red_retryable) still counts as work: red units are
    # retried forever by design, so only these two end the queue.
    SETTLED_STATUSES = {"green", "structural_ineligible"}

    def _reconcile_interrupted(self, state: dict[str, Any]) -> None:
        """A unit left `porting` by a killed run never got a transition record.

        The supervisor kills the driver tree on player join / manual pause, so
        this is the normal path, not an exception. Reclassify as `deferred` and
        emit the checkpoint the killed run owed -- otherwise GitHub shows unit A
        as still in flight while the selector has already moved to unit B.
        """
        for name, record in state.get("units", {}).items():
            if record.get("status") != "porting":
                continue
            record["status"] = "deferred"
            record["error"] = "interrupted before a verdict (driver killed or crashed)"
            # Refund the attempt. `_next_unit` orders least-attempted-first, so
            # charging an interrupted unit would push it behind the entire
            # queue -- and because the supervisor kills the driver on every
            # player join and manual pause, that is a starvation machine: each
            # interruption promotes a fresh unit and demotes the one in flight,
            # so nothing ever finishes.
            record["attempts"] = max(0, record.get("attempts", 1) - 1)
            self._save_state(state)
            self._checkpoint(
                state,
                UnitTransition(
                    unit=name,
                    result=RESULT_DEFERRED,
                    stage=record.get("last_stage") or "port",
                    attempt=record.get("attempts", 0),
                    detail="interrupted before a verdict; requeued",
                    model=self._model_config.model,
                ),
            )
            # Deferred is a transient class: the unit re-enters the pool as
            # pending so `_next_unit` treats it like any other retry candidate.
            record["status"] = "pending"
            self._save_state(state)

    def _flush_pending_progress(self) -> None:
        try:
            if self._journal.push_is_pending():
                self._journal.flush_pending_push()
        except Exception as error:  # noqa: BLE001 - telemetry is never fatal
            self.events.emit("progress_push_retry_failed", error=str(error)[:300])

    def _work_remains(self, state: dict[str, Any]) -> bool:
        return any(
            record.get("status") not in self.SETTLED_STATUSES
            for record in state.get("units", {}).values()
        )

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
            if record.get("status") in self.SETTLED_STATUSES or name in processed:
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
            self._reconcile_interrupted(state)
            self._save_state(state)
            self.events.emit(
                "driver_started", mode="wasm_units", units_budget=self.units_budget
            )
            # A pending progress push from a previous run is retried here, so a
            # GitHub outage that spanned a whole run still reaches the remote.
            self._flush_pending_progress()
            processed: set[str] = set()
            steps_done = 0
            while True:
                command = self._control_command()
                if command in {"stop_after_stage", "pause_after_stage"}:
                    self._write_progress(state, "stopped")
                    self.events.emit("driver_stopped", reason=f"control:{command}")
                    self._checkpoint(
                        state, None, workflow_state="stopped_at_boundary",
                        driver_running=False,
                    )
                    return EXIT_STOPPED
                unit = self._next_unit(queue, state, processed)
                if unit is None:
                    work_left = self._work_remains(state)
                    self._write_progress(state, "running" if work_left else "completed")
                    self.events.emit(
                        "driver_stopped",
                        reason="pass_complete" if work_left else "no_work_left",
                    )
                    self._checkpoint(
                        state, None,
                        workflow_state="running" if work_left else "complete",
                        driver_running=False,   # this run is ending right here
                    )
                    return EXIT_PROGRESSED if work_left else EXIT_NO_WORK
                self.events.emit("selection", action="wasm_unit", unit=unit["name"])
                self._write_progress(state, "porting", unit=unit["name"])
                try:
                    outcome = self._process_unit(unit, state)
                except Exception as error:  # noqa: BLE001
                    # An unexpected fault (a malformed queue entry, a copy
                    # failure, a git timeout) must still produce a transition
                    # record. Letting it escape leaves the unit stuck as
                    # `porting` with nothing on the progress branch until some
                    # later run reconciles it.
                    outcome = self._fail(
                        state, self._unit_state(state, unit["name"]), unit["name"],
                        f"unexpected fault: {error}", stage="port",
                    )
                if outcome == "provider_paused":
                    # The provider is out. Stop the pass rather than marching
                    # the rest of the queue into the same wall, and tell the
                    # machine layer in the vocabulary it already understands.
                    self._write_progress(state, "paused_provider_unavailable")
                    self.events.emit(
                        "driver_stopped", reason="provider_unavailable",
                        detail=(self._provider_paused_detail or "")[:300],
                    )
                    return EXIT_PROVIDER_PAUSED
                processed.add(unit["name"])
                steps_done += 1
                self._write_progress(state, "running")
                if not self.until_blocked and steps_done >= self.units_budget:
                    remaining = self._next_unit(queue, state, processed)
                    done = not self._work_remains(state) and remaining is None
                    if done:
                        self._write_progress(state, "completed")
                        self._checkpoint(
                            state, None, workflow_state="complete", driver_running=False,
                        )
                    self.events.emit("driver_stopped", reason="units_budget_reached")
                    return EXIT_NO_WORK if done else EXIT_PROGRESSED
        finally:
            self._heartbeat("wasm_units:idle")
            self.lock.release()
