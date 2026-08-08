"""Palworld gameplay watchdog: the thin Python supervisor (design 2026-08-08 §6 option 1+3).

Replaces palworld-oghidra-monitor.ps1. The port driver self-supervises via
``finish-port --drive --until-blocked`` (loops durable steps, honors control.json
at every step boundary); what remains here is exactly the residue that cannot
live inside the driver:

- keep one driver process alive while Palworld is empty;
- on player join: cooperative stop signal, Unsloth VRAM unload (force-cancel),
  then force-kill of every finish-port process tree, then liveness reset;
- Unsloth bring-up with engine-identity checks (LM Studio impersonated Unsloth
  on :8888 for five days -- every probe here validates the response SHAPE);
- the tool_choice-object chat-contract preflight;
- LM Studio embeddings sync on :1234 (best-effort, never blocking).

Supervision rules ported from the fixed PS monitor (post-mortem 2026-08-08 §4b):
telemetry writes are swallowed, protection steps before the kill are best-effort,
the crash guard is exit-code aware (0/2/3/4/5 are healthy fast exits), the
``completed`` latch un-latches when port-ledger.json outdates run-state.json,
and a run the watchdog killed on purpose never feeds the crash guard.

Run: ``python -m src.palworld_watchdog`` (single instance per state dir).
"""

from __future__ import annotations

import argparse
import base64
import json
import logging
import os
import re
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

import psutil
import requests

EXIT_HEALTHY = {0, 2, 3, 4, 5}  # port_driver: no-work/stopped/progressed/paused/locked
EXIT_NO_WORK = 0
EXIT_PROVIDER_PAUSED = 4
EXIT_LOCKED = 5

logger = logging.getLogger("palworld_watchdog")


def atomic_write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(f"{path.suffix}.{os.getpid()}.{uuid.uuid4().hex}.tmp")
    temporary.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
    os.replace(temporary, path)


@dataclass
class WatchdogConfig:
    repo_root: Path = Path(r"D:\GotYaForce")
    oghidra_root: Path = Path(r"D:\GotYaForce\research\tools\OGhidra")
    pal_config: Path = Path(
        r"C:\Program Files (x86)\Steam\steamapps\common\PalServer\Pal\Saved"
        r"\Config\WindowsServer\PalWorldSettings.ini"
    )
    pal_metrics_url: str = "http://127.0.0.1:8212/v1/api/metrics"
    pal_players_url: str = "http://127.0.0.1:8212/v1/api/players"
    # Rig dashboard contract (rig HANDOFF #15 + server.ps1 toast hook): the
    # supervisor is the PRODUCER of the palworld time-series, the roster, and
    # the legacy monitor-state file. Keep writing all three or the rig widget
    # sparkline flatlines and "heavy work BLOCKED" toasts never fire.
    rig_metrics_jsonl: Path = Path(r"D:\rig\state\palworld-metrics.jsonl")
    rig_players_json: Path = Path(r"D:\rig\state\palworld-players.json")
    reset_marker: Path = Path(r"D:\rig\state\reset-request.marker")
    legacy_state_path: Path = Path(
        r"D:\Palworld_Server_Setup\monitor\palworld-oghidra-monitor-state.json"
    )
    unsloth_base: str = "http://127.0.0.1:8888"
    unsloth_exe: Path = Path(r"C:\Users\manny\.unsloth\studio\bin\unsloth.exe")
    unsloth_workdir: Path = Path(os.environ.get("USERPROFILE", r"C:\Users\manny"))
    unsloth_llama_dir: Path = Path(r"C:\Users\manny\.unsloth\llama.cpp")
    # Settled 2026-08-07 (verified live 2026-08-08): UD-Q4_K_XL @ 131072. The
    # old PS control file still said ud-iq3_s @ 262144 -- do not copy it back.
    model_path: str = "unsloth/Qwen3.6-35B-A3B-MTP-GGUF"
    gguf_variant: str = "UD-Q4_K_XL"
    # Native max (owner decision 2026-08-08: latency is acceptable, coverage is
    # not negotiable -- four combat chunks need ~230k). q8_0 KV halves cache
    # bytes, making 262k @ q8 roughly VRAM-equal to the old 131k @ fp16.
    max_seq_length: int = 262144
    kv_cache_type: str | None = "q8_0"
    min_context: int = 80000
    lms_exe: Path = Path(r"C:\Users\manny\.lmstudio\bin\lms.exe")
    embed_probe_url: str = "http://127.0.0.1:1234/v1/models"
    embed_model_key: str = "text-embedding-nomic-embed-text-v1.5"
    poll_seconds: float = 3.0
    empty_grace_seconds: float = 60.0
    stop_grace_seconds: float = 5.0
    min_healthy_runtime_seconds: float = 120.0
    max_short_runs: int = 3
    block_recheck_minutes: float = 10.0

    @property
    def run_root(self) -> Path:
        return self.repo_root / "research/decomp/generated/finish-game-port"

    @property
    def control_path(self) -> Path:
        return self.run_root / "control.json"

    @property
    def run_state_path(self) -> Path:
        return self.run_root / "run-state.json"

    @property
    def ledger_path(self) -> Path:
        return self.run_root / "port-ledger.json"

    @property
    def liveness_path(self) -> Path:
        return self.run_root / "llm-liveness.json"

    @property
    def state_dir(self) -> Path:
        return self.oghidra_root / "watchdog"

    @property
    def api_key(self) -> str:
        env_path = self.oghidra_root / ".env"
        match = re.search(
            r"^\s*CUSTOM_API_KEY\s*=\s*(.+?)\s*$",
            env_path.read_text(encoding="utf-8"),
            re.MULTILINE,
        )
        if not match:
            raise RuntimeError(f"CUSTOM_API_KEY not present in {env_path}")
        return match.group(1)


class PalworldApi:
    def __init__(self, config: WatchdogConfig):
        self.config = config
        self._headers: dict[str, str] | None = None

    def _auth(self) -> dict[str, str]:
        if self._headers is None:
            text = self.config.pal_config.read_text(encoding="utf-8", errors="replace")
            match = re.search(r'AdminPassword="([^"]+)"', text)
            if not match:
                raise RuntimeError("Palworld AdminPassword missing from settings ini")
            token = base64.b64encode(f"admin:{match.group(1)}".encode()).decode()
            self._headers = {"Authorization": f"Basic {token}", "Accept": "application/json"}
        return self._headers

    def metrics(self) -> dict[str, Any]:
        response = requests.get(self.config.pal_metrics_url, headers=self._auth(), timeout=2)
        response.raise_for_status()
        body = response.json()
        if body.get("currentplayernum") is None:
            raise RuntimeError("metrics response missing currentplayernum")
        return body

    def roster(self) -> list[dict[str, Any]]:
        response = requests.get(self.config.pal_players_url, headers=self._auth(), timeout=3)
        response.raise_for_status()
        return list(response.json().get("players") or [])

    def server_running(self) -> bool:
        return any(
            process.info["name"] == "PalServer-Win64-Shipping-Cmd.exe"
            for process in psutil.process_iter(["name"])
        )


class UnslothApi:
    """Shape-validated Unsloth Studio client (rejects LM Studio impersonation)."""

    def __init__(self, config: WatchdogConfig):
        self.config = config

    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.config.api_key}", "Accept": "application/json"}

    def status(self) -> dict[str, Any] | None:
        try:
            response = requests.get(
                f"{self.config.unsloth_base}/api/inference/status",
                headers=self._headers(), timeout=5,
            )
            body = response.json()
        except (requests.RequestException, ValueError):
            return None
        if not isinstance(body, dict) or "error" in body:
            return None
        if "model_identifier" not in body and "active_model" not in body:
            return None
        return body

    def model_loaded(self) -> bool:
        status = self.status()
        if not status:
            return False
        for candidate in (status.get("model_identifier"), status.get("active_model")):
            if candidate and (
                candidate == self.config.model_path or "Qwen3.6-35B-A3B" in candidate
            ):
                context = status.get("context_length") or 0
                return context >= self.config.min_context
        return False

    def load(self) -> None:
        body = {
            "model_path": self.config.model_path,
            "gguf_variant": self.config.gguf_variant,
            "max_seq_length": self.config.max_seq_length,
        }
        if self.config.kv_cache_type:
            body["cache_type_kv"] = self.config.kv_cache_type
        response = requests.post(
            f"{self.config.unsloth_base}/api/inference/load",
            headers=self._headers(), timeout=60, json=body,
        )
        if response.status_code in (400, 422) and "cache_type_kv" in body:
            # Older studio builds may not accept the KV knob; context alone
            # still helps and the caller's readiness wait verifies the result.
            logger.warning("load rejected cache_type_kv; retrying without it")
            del body["cache_type_kv"]
            response = requests.post(
                f"{self.config.unsloth_base}/api/inference/load",
                headers=self._headers(), timeout=60, json=body,
            )
        response.raise_for_status()

    def unload_force(self) -> None:
        try:
            requests.post(
                f"{self.config.unsloth_base}/api/inference/unload",
                headers=self._headers(), timeout=60,
                json={"model_path": self.config.model_path, "force_cancel_active": True},
            )
        except requests.RequestException:
            pass  # protection proceeds to the kill regardless

    def chat_contract_ok(self) -> tuple[bool, str]:
        """tool_choice as an OBJECT: the exact contract LM Studio's backend broke."""
        probe_tool = {
            "type": "function",
            "function": {
                "name": "preflight_probe",
                "description": "Contract probe only.",
                "parameters": {
                    "type": "object",
                    "properties": {"ok": {"type": "boolean"}},
                    "required": ["ok"],
                },
            },
        }
        try:
            response = requests.post(
                f"{self.config.unsloth_base}/v1/chat/completions",
                headers=self._headers(), timeout=120,
                json={
                    "model": self.config.model_path,
                    "messages": [{"role": "user", "content": "ping"}],
                    "max_tokens": 1,
                    "tools": [probe_tool],
                    "tool_choice": {"type": "function", "function": {"name": "preflight_probe"}},
                },
            )
            response.raise_for_status()
            return True, "tool_choice object accepted"
        except requests.RequestException as error:
            detail = getattr(getattr(error, "response", None), "text", "") or str(error)
            return False, detail[:500]

    def start_server(self) -> None:
        try:
            self.config.unsloth_llama_dir.iterdir().__next__()
        except PermissionError as error:
            raise RuntimeError(f"unsloth llama.cpp ACL-locked: {error}") from error
        except (StopIteration, FileNotFoundError) as error:
            raise RuntimeError(f"unsloth llama.cpp missing/empty: {error}") from error
        logs = self.config.state_dir
        logs.mkdir(parents=True, exist_ok=True)
        subprocess.Popen(
            [str(self.config.unsloth_exe), "studio", "--port", "8888", "--host", "127.0.0.1"],
            cwd=str(self.config.unsloth_workdir),
            stdout=(logs / "unsloth.out.log").open("ab"),
            stderr=(logs / "unsloth.err.log").open("ab"),
            creationflags=subprocess.CREATE_NO_WINDOW,
        )


class DriverManager:
    """Owns the finish-port driver child process and its exit-code semantics."""

    def __init__(self, config: WatchdogConfig):
        self.config = config
        self.process: subprocess.Popen | None = None
        self.started_at: float | None = None

    def foreign_driver_pids(self) -> list[int]:
        pids = []
        own = self.process.pid if self.process and self.process.poll() is None else None
        for process in psutil.process_iter(["name", "cmdline"]):
            try:
                cmdline = " ".join(process.info["cmdline"] or [])
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
            if (
                (process.info["name"] or "").lower().startswith("python")
                and "finish-port" in cmdline
                and process.pid != own
            ):
                pids.append(process.pid)
        return pids

    def any_driver_alive(self) -> bool:
        if self.process and self.process.poll() is None:
            return True
        return bool(self.foreign_driver_pids())

    def launch(self) -> int:
        logs = self.config.state_dir
        logs.mkdir(parents=True, exist_ok=True)
        for name in ("driver.out.log", "driver.err.log"):
            log_path = logs / name
            if log_path.exists() and log_path.stat().st_size > 5 * 1024 * 1024:
                os.replace(log_path, logs / f"{name}.previous")
        self.process = subprocess.Popen(
            [
                str(self.config.oghidra_root / ".venv/Scripts/python.exe"),
                "main.py", "finish-port", "--drive", "--until-blocked",
            ],
            cwd=str(self.config.oghidra_root),
            stdout=(logs / "driver.out.log").open("ab"),
            stderr=(logs / "driver.err.log").open("ab"),
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        self.started_at = time.monotonic()
        return self.process.pid

    def reap(self) -> tuple[int | None, float | None]:
        """Return (exit_code, runtime_seconds) once the child has exited."""
        if self.process is None:
            return None, None
        code = self.process.poll()
        if code is None:
            return None, None
        runtime = time.monotonic() - self.started_at if self.started_at else None
        self.process = None
        self.started_at = None
        return code, runtime

    def kill_all(self) -> None:
        """taskkill /T covers each tree root; own child first, then foreigners."""
        targets = []
        if self.process and self.process.poll() is None:
            targets.append(self.process.pid)
        targets.extend(self.foreign_driver_pids())
        for pid in targets:
            subprocess.run(
                ["taskkill", "/PID", str(pid), "/T", "/F"],
                capture_output=True, timeout=30,
            )
        # A killed run says nothing about driver health.
        self.process = None
        self.started_at = None


class Watchdog:
    def __init__(
        self,
        config: WatchdogConfig,
        palworld: PalworldApi | None = None,
        unsloth: UnslothApi | None = None,
        driver: DriverManager | None = None,
        embeddings_sync: Callable[[], None] | None = None,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
    ):
        self.config = config
        self.palworld = palworld or PalworldApi(config)
        self.unsloth = unsloth or UnslothApi(config)
        self.driver = driver or DriverManager(config)
        self.embeddings_sync = embeddings_sync or self._default_embeddings_sync
        self.sleep = sleep
        self.clock = clock
        self.mode = "starting"
        self.blocked_reason: str | None = None
        self.blocked_at: float | None = None
        self.empty_since: float | None = None
        self.api_failures = 0
        self.short_run_count = 0
        self.locked_run_count = 0
        self.last_protection_at: float | None = None
        self.last_embeddings_at: float | None = None
        self.last_sample_at: float | None = None
        self.consecutive_loop_failures = 0

    # ----------------------------------------------------------------- telemetry

    def write_state(self, reason: str, players: int | None = None) -> None:
        driver_pid = (
            self.driver.process.pid
            if self.driver.process and self.driver.process.poll() is None
            else None
        )
        state = {
            "updated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "mode": self.mode,
            "players": players,
            "reason": reason,
            "api_failures": self.api_failures,
            "blocked_reason": self.blocked_reason,
            "driver_pid": driver_pid,
        }
        try:
            atomic_write_json(self.config.state_dir / "watchdog-state.json", state)
        except OSError as error:
            logger.warning("state write failed: %s", error)  # telemetry never kills protection
        # Legacy schema at the old monitor path: rig server.ps1 polls it for
        # the "heavy work BLOCKED" toast (fields: blocked, blocked_reason).
        try:
            atomic_write_json(
                self.config.legacy_state_path,
                {
                    **state,
                    "blocked": self.blocked_reason is not None,
                    "oghidra_pids": [driver_pid] if driver_pid else [],
                    "last_error": self.blocked_reason or "",
                },
            )
        except OSError as error:
            logger.warning("legacy state write failed: %s", error)

    def sample_palworld(self, metrics: dict[str, Any]) -> None:
        """30s time-series + roster for the rig dashboard (HANDOFF #15).

        Best-effort by contract: a sampling failure must never break gameplay
        protection.
        """
        now = self.clock()
        if self.last_sample_at is not None and now - self.last_sample_at < 30:
            return
        self.last_sample_at = now
        try:
            sample_path = self.config.rig_metrics_jsonl
            sample_path.parent.mkdir(parents=True, exist_ok=True)
            if sample_path.exists() and sample_path.stat().st_size > 5 * 1024 * 1024:
                os.replace(sample_path, sample_path.with_name(sample_path.name + ".previous"))
            sample = {
                "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                "players": int(metrics["currentplayernum"]),
                "fps": metrics.get("serverfps"),
                "frametime": metrics.get("serverframetime"),
                "uptime": metrics.get("uptime"),
            }
            with sample_path.open("a", encoding="utf-8", newline="\n") as handle:
                handle.write(json.dumps(sample) + "\n")
            atomic_write_json(
                self.config.rig_players_json,
                {
                    "updated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                    "players": self.palworld.roster(),
                },
            )
        except Exception as error:  # noqa: BLE001 - sampling is never fatal
            logger.warning("palworld sampling failed: %s", error)

    # ------------------------------------------------------------------- control

    def write_control(self, command: str) -> None:
        atomic_write_json(
            self.config.control_path,
            {
                "command": command,
                "updated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
                "source": "palworld-watchdog",
            },
        )

    def reset_liveness(self) -> None:
        """The killer must clean up: a SIGKILLed client cannot clear active:true."""
        if self.driver.any_driver_alive():
            return
        path = self.config.liveness_path
        if not path.is_file():
            return
        try:
            liveness = json.loads(path.read_text(encoding="utf-8"))
            if not liveness.get("active"):
                return
            liveness["active"] = False
            liveness["status"] = "stopped_by_watchdog"
            atomic_write_json(path, liveness)
            logger.info("cleared stale llm-liveness active flag")
        except (OSError, json.JSONDecodeError, ValueError) as error:
            logger.warning("liveness reset failed: %s", error)

    # ---------------------------------------------------------------- protection

    def protect(self, reason: str, players: int | None) -> None:
        """Nothing before kill_all may abort protection."""
        self.mode = "protected"
        try:
            self.write_control("stop_after_stage")
        except OSError as error:
            logger.warning("control write failed during protection: %s", error)
        self.unsloth.unload_force()  # swallows internally
        deadline = self.clock() + self.config.stop_grace_seconds
        while self.clock() < deadline and self.driver.any_driver_alive():
            self.sleep(0.25)
        self.driver.kill_all()
        self.reset_liveness()
        self.short_run_count = 0
        self.locked_run_count = 0
        self.last_protection_at = self.clock()
        logger.info("gameplay protection active: %s", reason)
        self.write_state(reason, players)

    # -------------------------------------------------------------- heavy work

    def _blocked(self, reason: str) -> None:
        if self.blocked_reason != reason:
            logger.error("BLOCKED: %s", reason)
            self.blocked_at = self.clock()
        self.blocked_reason = reason
        self.mode = "blocked"
        self.write_state(f"Blocked: {reason}", players=0)

    def _block_recheck_due(self) -> bool:
        if self.blocked_at is None:
            return True
        return (self.clock() - self.blocked_at) >= self.config.block_recheck_minutes * 60

    def _reset_requested(self) -> bool:
        """`rig reset` drops a marker file; consume it so the request fires once."""
        marker = self.config.reset_marker
        if not marker.exists():
            return False
        try:
            marker.unlink()
        except OSError:
            return False
        return True

    def _completed_latch_holds(self) -> bool:
        """True when run-state says completed AND the ledger has not moved since."""
        try:
            state = json.loads(self.config.run_state_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError, ValueError):
            return False
        if state.get("status") != "completed" or state.get("run_mode") != "driver":
            return False
        try:
            ledger_mtime = self.config.ledger_path.stat().st_mtime
            state_mtime = self.config.run_state_path.stat().st_mtime
        except OSError:
            return False
        if ledger_mtime > state_mtime:
            logger.info("port-ledger.json changed after completed state; probing for new work")
            return False
        return True

    def _provider_pause_holds(self) -> bool:
        try:
            state = json.loads(self.config.run_state_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError, ValueError):
            return False
        if state.get("status") != "paused_provider_unavailable":
            return False
        if self.unsloth.status() is None:
            logger.warning("exit-4 pause and Unsloth not answering; holding relaunch")
            return True
        logger.info("provider answered after exit-4 pause; resuming")
        return False

    def _crash_guard_trips(self, exit_code: int | None, runtime: float | None) -> bool:
        if exit_code is not None or runtime is not None:
            logger.info("driver exited code=%s runtime=%.0fs", exit_code, runtime or -1)
        healthy = exit_code is not None and exit_code in EXIT_HEALTHY
        if (
            runtime is not None
            and runtime < self.config.min_healthy_runtime_seconds
            and not healthy
        ):
            self.short_run_count += 1
            if self.short_run_count >= self.config.max_short_runs:
                tail = ""
                err_log = self.config.state_dir / "driver.err.log"
                if err_log.is_file():
                    tail = " / ".join(
                        err_log.read_text(encoding="utf-8", errors="replace").splitlines()[-3:]
                    )
                self._blocked(
                    f"driver crashed in under {self.config.min_healthy_runtime_seconds:.0f}s "
                    f"on {self.short_run_count} consecutive attempts. Last stderr: {tail}"
                )
                return True
        else:
            self.short_run_count = 0
        if exit_code == EXIT_LOCKED:
            self.locked_run_count += 1
            if self.locked_run_count >= self.config.max_short_runs:
                self._blocked("driver.lock held but no visible driver; stale lock or elevated process")
                return True
        else:
            self.locked_run_count = 0
        return False

    def _default_embeddings_sync(self) -> None:
        """Best-effort LM Studio embeddings on :1234; never blocks port work."""
        now = self.clock()
        if self.last_embeddings_at and now - self.last_embeddings_at < 300:
            return
        self.last_embeddings_at = now
        try:
            models = requests.get(self.config.embed_probe_url, timeout=3).json()
            if any("embed" in (m.get("id") or "") for m in models.get("data", [])):
                return
        except (requests.RequestException, ValueError):
            pass
        if not self.config.lms_exe.is_file():
            logger.warning("lms CLI missing; embeddings unavailable")
            return
        for arguments in (
            ["daemon", "up"],
            ["server", "start", "--port", "1234"],
            ["load", self.config.embed_model_key, "--identifier", self.config.embed_model_key, "--yes"],
        ):
            try:
                subprocess.run(
                    [str(self.config.lms_exe), *arguments],
                    capture_output=True, timeout=120,
                )
            except (subprocess.SubprocessError, OSError) as error:
                logger.warning("embeddings step %s failed: %s", arguments[0], error)
                return

    def enable_heavy_work(self) -> None:
        self.embeddings_sync()
        if self.driver.any_driver_alive():
            if self.mode != "running":
                self.mode = "running"
                self.write_state("Palworld empty; Unsloth and driver running.", players=0)
            return

        exit_code, runtime = self.driver.reap()
        self.reset_liveness()

        if self.blocked_reason:
            if self._reset_requested():
                logger.info("manual reset via rig reset; clearing block")
                self.blocked_reason = None
            elif self._block_recheck_due():
                logger.info("re-evaluating block: %s", self.blocked_reason)
                self.blocked_reason = None
            else:
                return

        if self._provider_pause_holds():
            return
        if exit_code == EXIT_NO_WORK or exit_code is None:
            if self._completed_latch_holds():
                return
        if self._crash_guard_trips(exit_code, runtime):
            return

        status = self.unsloth.status()
        if status is None:
            try:
                self.unsloth.start_server()
            except (RuntimeError, OSError) as error:
                self._blocked(f"Unsloth cannot start: {error}")
                return
            deadline = self.clock() + 300
            while self.clock() < deadline and self.unsloth.status() is None:
                self.sleep(2)
            if self.unsloth.status() is None:
                self._blocked("Unsloth did not answer /api/inference/status within 300s")
                return
        if not self.unsloth.model_loaded():
            try:
                self.unsloth.load()
            except requests.RequestException as error:
                self._blocked(f"Unsloth model load request failed: {error}")
                return
            deadline = self.clock() + 900
            while self.clock() < deadline and not self.unsloth.model_loaded():
                self.sleep(5)
            if not self.unsloth.model_loaded():
                self._blocked("Unsloth model not ready within 900s")
                return
        ok, detail = self.unsloth.chat_contract_ok()
        if not ok:
            self._blocked(f"chat contract preflight failed: {detail}")
            return

        self.blocked_reason = None
        try:
            self.write_control("run")
        except OSError as error:
            logger.warning("control write failed before launch: %s", error)
            return
        pid = self.driver.launch()
        self.mode = "running"
        logger.info("launched finish-port driver pid=%s", pid)
        self.write_state("Palworld empty; Unsloth and driver running.", players=0)

    # ---------------------------------------------------------------------- loop

    def iterate(self) -> None:
        players: int | None = None
        try:
            metrics = self.palworld.metrics()
            players = int(metrics["currentplayernum"])
            self.api_failures = 0
            self.sample_palworld(metrics)
        except (requests.RequestException, RuntimeError, OSError) as error:
            self.api_failures += 1
            self.write_state("Palworld API unavailable.", players=None)
            logger.debug("palworld api failure %s: %s", self.api_failures, error)

        if players is not None:
            if players > 0:
                self.empty_since = None
                if self.mode != "protected" or (
                    self.last_protection_at is None
                    or self.clock() - self.last_protection_at >= 30
                ):
                    self.protect(f"{players} Palworld player(s) connected.", players)
            else:
                if self.empty_since is None:
                    self.empty_since = self.clock()
                    logger.info("Palworld empty; grace %ss", self.config.empty_grace_seconds)
                if self.clock() - self.empty_since >= self.config.empty_grace_seconds:
                    self.enable_heavy_work()
        elif self.api_failures >= 3:
            if self.palworld.server_running():
                self.empty_since = None
                if self.mode != "protected":
                    self.protect("Palworld running but player status unknown; fail-safe.", None)
            else:
                if self.empty_since is None:
                    self.empty_since = self.clock()
                if self.clock() - self.empty_since >= self.config.empty_grace_seconds:
                    self.enable_heavy_work()

    def run_forever(self) -> None:
        logger.info("watchdog started")
        while True:
            try:
                self.iterate()
                self.consecutive_loop_failures = 0
            except Exception:  # one failed iteration may never kill protection
                self.consecutive_loop_failures += 1
                logger.exception("iteration failed (%s/10)", self.consecutive_loop_failures)
                if self.consecutive_loop_failures >= 10:
                    raise
            self.sleep(self.config.poll_seconds)


def acquire_single_instance(config: WatchdogConfig) -> Any:
    """Exclusive lock file with stale-pid reclamation; returns the handle."""
    config.state_dir.mkdir(parents=True, exist_ok=True)
    lock_path = config.state_dir / "watchdog.lock"
    if lock_path.exists():
        try:
            holder = int(lock_path.read_text(encoding="utf-8").strip() or 0)
        except (OSError, ValueError):
            holder = 0
        if holder and psutil.pid_exists(holder):
            return None
        lock_path.unlink(missing_ok=True)
    handle = lock_path.open("x", encoding="utf-8")
    handle.write(str(os.getpid()))
    handle.flush()
    return handle


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--once", action="store_true", help="run one iteration and exit")
    arguments = parser.parse_args()
    config = WatchdogConfig()
    config.state_dir.mkdir(parents=True, exist_ok=True)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler(config.state_dir / "watchdog.log", encoding="utf-8"),
        ],
    )
    lock = acquire_single_instance(config)
    if lock is None:
        print("another watchdog instance is running; exiting")
        return 0
    watchdog = Watchdog(config)
    try:
        if arguments.once:
            watchdog.iterate()
            return 0
        watchdog.run_forever()
        return 0
    finally:
        lock.close()
        (config.state_dir / "watchdog.lock").unlink(missing_ok=True)


if __name__ == "__main__":
    sys.exit(main())
