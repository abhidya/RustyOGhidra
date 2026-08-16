#!/usr/bin/env python3
"""
Custom API Client for OGhidra
-----------------------------
Handles communication with OpenAI-compatible APIs (GPT-5, custom endpoints, etc.).
"""

import json
import logging
import logging.handlers
import os
import requests
import re
import sys
import time
import uuid
import warnings
import threading
import email.utils
import random
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Dict, Any, List, Optional, Union, Tuple
from tenacity import Retrying, stop_after_attempt, wait_exponential, retry_if_exception
import urllib3

# Suppress SSL warnings when verification is disabled
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Also suppress requests warnings
warnings.filterwarnings("ignore", message="Unverified HTTPS request")

# Windows consoles default to cp1252, and model output contains emoji: printing
# a streamed delta or an error body then raises UnicodeEncodeError and kills an
# otherwise healthy port run. Every port entrypoint imports this module, so make
# the console lossy-but-crashproof once here. (File logs are already utf-8.)
for _stream in (sys.stdout, sys.stderr):
    if _stream is not None and hasattr(_stream, "reconfigure"):
        try:
            _stream.reconfigure(errors="replace")
        except (ValueError, OSError):
            pass

# Bounds for the dedicated LLM-interaction log. Overridable via env so a debug
# session can widen them without editing code.
_LLM_LOG_MAX_BYTES = int(os.getenv("LLM_LOG_MAX_BYTES", str(50 * 1024 * 1024)))
_LLM_LOG_BACKUP_COUNT = int(os.getenv("LLM_LOG_BACKUP_COUNT", "5"))


class APIResponseError(RuntimeError):
    """The API returned a response that cannot produce a model result."""


def is_retryable_exception(e):
    """Check if an exception is retryable (429, 500, 503, or connection/timeout)."""
    if isinstance(e, requests.exceptions.HTTPError):
        return e.response is not None and e.response.status_code in [429, 500, 503]
    return isinstance(e, (requests.exceptions.ConnectionError, requests.exceptions.Timeout))


def describe_empty_response(data: Any, reasoning_text: str = "") -> str:
    """Explain WHY a response carried no assistant content.

    The bare symptom ("returned no assistant content") cost two separate
    misdiagnoses -- a reasoning spiral, then a context-budget theory -- because
    it described what happened and nothing about why. finish_reason separates
    the cases that need different fixes:

      "length"    the budget was consumed without emitting content: a reasoning
                  spiral, or a repetition loop. Lower/raise max_tokens, or turn
                  thinking off.
      "stop"      the model genuinely chose to say nothing. A prompt problem.
      None / []   malformed or short-circuited response. A transport problem.
    """
    choices = data.get("choices") if isinstance(data, dict) else None
    first = choices[0] if isinstance(choices, list) and choices else {}
    finish_reason = first.get("finish_reason") if isinstance(first, dict) else None
    usage = data.get("usage") if isinstance(data, dict) else None
    usage = usage if isinstance(usage, dict) else {}
    return (
        "Custom API returned no assistant content or tool-call arguments "
        f"(finish_reason={finish_reason!r}, "
        f"choices={len(choices) if isinstance(choices, list) else 'absent'}, "
        f"reasoning_chars={len(reasoning_text or '')}, "
        f"prompt_tokens={usage.get('prompt_tokens')}, "
        f"completion_tokens={usage.get('completion_tokens')})"
    )


class CustomAPIClient:
    """Client for interacting with OpenAI-compatible Custom APIs."""

    def __init__(self, config):
        """
        Initialize the Custom API client.

        Args:
            config: CustomAPIConfig object with attributes:
                - api_url: Base URL for the API
                - api_key: API key for authentication
                - model: Default model to use
                - timeout: Request timeout
        """
        self.config = config
        self.base_url = str(config.api_url).rstrip("/")
        self.api_key = config.api_key
        self.default_model = config.model

        # Generation Config
        self.temperature = getattr(config, "temperature", 0.7)
        self.max_tokens = getattr(config, "max_tokens", 4096)

        # Use default system prompt from config if available
        self.default_system_prompt = getattr(config, "default_system_prompt", "")

        self.timeout = getattr(config, "timeout", 300)
        self.logger = logging.getLogger("custom-api-client")
        # Optional UI callback for surfacing retries without digging through logs
        # Signature: (event_type: str, payload: Dict[str, Any]) -> None
        self._ui_event_callback = getattr(config, "ui_event_callback", None)
        self.model_map = getattr(config, "model_map", {})

        # LLM Logging setup (reuse from config if available)
        self.llm_logging_enabled = getattr(config, "llm_logging_enabled", False)
        self.llm_log_file = getattr(config, "llm_log_file", "logs/llm_interactions_custom.log")
        self.llm_log_prompts = getattr(config, "llm_log_prompts", True)
        self.llm_log_responses = getattr(config, "llm_log_responses", True)
        self.llm_log_tokens = getattr(config, "llm_log_tokens", True)
        self.llm_log_timing = getattr(config, "llm_log_timing", True)
        self.llm_log_format = getattr(config, "llm_log_format", "json")
        self.llm_logger = None

        # Retry and Delay Config
        self.request_delay = getattr(config, "request_delay", 0.0)
        self.max_retries = getattr(config, "max_retries", 3)

        # Global throttling / concurrency control
        self.max_concurrency = int(getattr(config, "max_concurrency", 1) or 1)
        self.global_min_interval = float(getattr(config, "global_min_interval", 0.0) or 0.0)
        self.respect_retry_after = bool(getattr(config, "respect_retry_after", True))
        self.retry_after_max_seconds = int(getattr(config, "retry_after_max_seconds", 60) or 60)

        # Adaptive throttling
        # Automatically increases pacing after rate-limits, slowly relaxes after sustained success.
        self.adaptive_throttle_enabled = bool(getattr(config, "adaptive_throttle_enabled", True))
        self.adaptive_max_interval = float(getattr(config, "adaptive_max_interval", 10.0) or 10.0)
        self.adaptive_increase_factor = float(getattr(config, "adaptive_increase_factor", 1.5) or 1.5)
        self.adaptive_decrease_factor = float(getattr(config, "adaptive_decrease_factor", 0.9) or 0.9)
        self.adaptive_success_streak_threshold = int(getattr(config, "adaptive_success_streak_threshold", 10) or 10)
        self.adaptive_jitter_seconds = float(getattr(config, "adaptive_jitter_seconds", 0.25) or 0.25)

        self._request_semaphore = threading.Semaphore(self.max_concurrency)
        self._throttle_lock = threading.Lock()
        self._last_request_start = 0.0

        self._adaptive_lock = threading.Lock()
        self._adaptive_interval = max(0.0, self.global_min_interval)
        self._adaptive_success_streak = 0

        # SSL verification (disabled by default for custom APIs with cert issues)
        self.verify_ssl = getattr(config, "verify_ssl", False)

        # Serving-slot management (unsloth studio admin API on the same host as
        # the chat endpoint). Enabled only when a max_seq_length is configured;
        # generic OpenAI-compatible endpoints have no /api/inference/* routes.
        self.gguf_variant = str(getattr(config, "gguf_variant", "") or "")
        self.max_seq_length = int(getattr(config, "max_seq_length", 0) or 0)
        self.last_response_metadata: Dict[str, Any] = {}
        self.generation_metrics: Dict[str, Any] = {
            "api_calls": 0,
            "structured_tool_calls": 0,
            "prompt_tokens": 0,
            "completion_tokens": 0,
            "duration_seconds": 0.0,
            "generation_duration_seconds": 0.0,
            "tokens_per_second": 0.0,
            "end_to_end_tokens_per_second": 0.0,
            "throughput_scope": "unavailable",
            "current_prompt_tokens": 0,
            "current_completion_tokens": 0,
            "current_request_elapsed_seconds": 0.0,
            "token_source": "unavailable",
            "active": False,
            "status": "idle",
        }
        liveness_path = os.getenv("OGHIDRA_PORT_LIVENESS_PATH")
        self._liveness_path = Path(liveness_path).resolve() if liveness_path else None
        self._liveness_run_id = os.getenv("OGHIDRA_PORT_RUN_ID")
        self._metrics_lock = threading.Lock()
        if self._liveness_path is not None and self._liveness_run_id:
            try:
                previous_metrics = json.loads(self._liveness_path.read_text(encoding="utf-8"))
            except (FileNotFoundError, json.JSONDecodeError, OSError):
                previous_metrics = {}
            if previous_metrics.get("run_id") == self._liveness_run_id:
                for key in (
                    "api_calls",
                    "structured_tool_calls",
                    "prompt_tokens",
                    "completion_tokens",
                    "duration_seconds",
                    "generation_duration_seconds",
                    "tokens_per_second",
                    "end_to_end_tokens_per_second",
                ):
                    if isinstance(previous_metrics.get(key), (int, float)):
                        self.generation_metrics[key] = previous_metrics[key]
                self.generation_metrics["token_source"] = previous_metrics.get(
                    "token_source",
                    "unavailable",
                )
                self.generation_metrics["throughput_scope"] = previous_metrics.get(
                    "throughput_scope",
                    "legacy_end_to_end",
                )

        print(f"[Custom API] Initialized: url={self.base_url} model={self.default_model} delay={self.request_delay}s")

        if self.llm_logging_enabled:
            self._setup_llm_logger()

        self._log_throttle_state()
        self._write_liveness()

    @staticmethod
    def _estimate_tokens(text: str) -> int:
        """Deterministic fallback when an OpenAI-compatible endpoint omits usage."""
        if not text:
            return 0
        return len(re.findall(r"\w+|[^\w\s]", text, flags=re.UNICODE))

    def _write_liveness(self) -> None:
        if self._liveness_path is None:
            return
        payload = {
            **self.generation_metrics,
            "model": self.default_model,
            "run_id": self._liveness_run_id,
            # UTC, like request_started_at in this SAME record. A naive local
            # stamp put two timezones in one object (…T12:38:51Z alongside
            # …T08:38:51) and made every consumer that diffs against UTC see a
            # constant multi-hour staleness.
            "updated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        }
        self._liveness_path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self._liveness_path.with_suffix(
            f"{self._liveness_path.suffix}.{os.getpid()}.{uuid.uuid4().hex}.tmp"
        )
        try:
            temporary.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
            for retry_index in range(5):
                try:
                    os.replace(temporary, self._liveness_path)
                    return
                except PermissionError:
                    if retry_index == 4:
                        raise
                    time.sleep(0.02 * (retry_index + 1))
        except OSError as error:
            # Dashboard telemetry is diagnostic only. A transient Windows file
            # lock must never abort or replay an otherwise valid model turn.
            self.logger.warning(f"Could not update port liveness telemetry: {error}")
        finally:
            temporary.unlink(missing_ok=True)

    def begin_managed_generation(self, prompt: str) -> None:
        """Expose a PydanticAI-owned model run through the existing GUI telemetry."""
        self._managed_generation_started = time.perf_counter()
        self._managed_generation_first_output = None
        self._managed_generation_output = []
        self._managed_generation_counted_requests = 1
        with self._metrics_lock:
            self.generation_metrics["api_calls"] += 1
            self.generation_metrics["active"] = True
            self.generation_metrics["status"] = "awaiting_provider_output"
            self.generation_metrics["tokens_per_second"] = 0.0
            self.generation_metrics["throughput_scope"] = "pending"
            self.generation_metrics["current_prompt_tokens"] = self._estimate_tokens(prompt)
            self.generation_metrics["current_completion_tokens"] = 0
            self.generation_metrics["current_request_elapsed_seconds"] = 0.0
            self.generation_metrics["request_started_at"] = (
                datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
            )
            self._write_liveness()

    def advance_managed_generation_request(self) -> None:
        """Expose the continuation request after a PydanticAI workspace tool."""
        self._managed_generation_started = time.perf_counter()
        self._managed_generation_first_output = None
        self._managed_generation_output = []
        self._managed_generation_counted_requests = (
            int(getattr(self, "_managed_generation_counted_requests", 0)) + 1
        )
        with self._metrics_lock:
            self.generation_metrics["api_calls"] += 1
            self.generation_metrics["active"] = True
            self.generation_metrics["status"] = "awaiting_provider_output"
            self.generation_metrics["tokens_per_second"] = 0.0
            self.generation_metrics["throughput_scope"] = "pending"
            self.generation_metrics["current_completion_tokens"] = 0
            self.generation_metrics["current_request_elapsed_seconds"] = 0.0
            self.generation_metrics["request_started_at"] = (
                datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
            )
            self._write_liveness()

    def observe_managed_generation(self, text: str) -> None:
        """Record text/tool argument deltas emitted by PydanticAI."""
        if not text:
            return
        now = time.perf_counter()
        if self._managed_generation_first_output is None:
            self._managed_generation_first_output = now
        self._managed_generation_output.append(text)
        completion_tokens = self._estimate_tokens(
            "".join(self._managed_generation_output)
        )
        generation_elapsed = max(
            now - self._managed_generation_first_output,
            1e-9,
        )
        request_elapsed = max(
            now - self._managed_generation_started,
            0.0,
        )
        with self._metrics_lock:
            self.generation_metrics["status"] = "streaming"
            self.generation_metrics["current_completion_tokens"] = completion_tokens
            self.generation_metrics["current_request_elapsed_seconds"] = request_elapsed
            self.generation_metrics["tokens_per_second"] = (
                completion_tokens / generation_elapsed
            )
            self.generation_metrics["throughput_scope"] = (
                "live_stream_generation_window"
            )
            self._write_liveness()

    def end_managed_generation(self, *, usage: Any = None, error: str | None = None) -> None:
        """Close GUI telemetry for a PydanticAI-owned run."""
        requests_count = int(getattr(usage, "requests", 0) or 0)
        prompt_tokens = int(
            getattr(usage, "input_tokens", 0)
            or getattr(usage, "request_tokens", 0)
            or 0
        )
        completion_tokens = int(
            getattr(usage, "output_tokens", 0)
            or getattr(usage, "response_tokens", 0)
            or 0
        )
        counted_requests = int(
            getattr(self, "_managed_generation_counted_requests", 0)
        )
        with self._metrics_lock:
            self.generation_metrics["api_calls"] += max(
                0, requests_count - counted_requests
            )
            self.generation_metrics["prompt_tokens"] += prompt_tokens
            self.generation_metrics["completion_tokens"] += completion_tokens
            self.generation_metrics["active"] = False
            self.generation_metrics["status"] = "failed" if error else "completed"
            self.generation_metrics["current_prompt_tokens"] = 0
            self.generation_metrics["current_completion_tokens"] = 0
            self.generation_metrics["current_request_elapsed_seconds"] = 0.0
            if error:
                self.generation_metrics["last_error"] = error
            self._write_liveness()

    def _log_throttle_state(self) -> None:
        state = {
            "base_url": self.base_url,
            "default_model": self.default_model,
            "request_delay_seconds": self.request_delay,
            "max_concurrency": self.max_concurrency,
            "global_min_interval_seconds": self.global_min_interval,
            "respect_retry_after": self.respect_retry_after,
            "retry_after_max_seconds": self.retry_after_max_seconds,
            "adaptive_throttle_enabled": self.adaptive_throttle_enabled,
            "adaptive_max_interval_seconds": self.adaptive_max_interval,
            "adaptive_increase_factor": self.adaptive_increase_factor,
            "adaptive_decrease_factor": self.adaptive_decrease_factor,
            "adaptive_success_streak_threshold": self.adaptive_success_streak_threshold,
            "adaptive_jitter_seconds": self.adaptive_jitter_seconds,
        }

        if self.adaptive_throttle_enabled:
            with self._adaptive_lock:
                state["adaptive_current_interval_seconds"] = self._adaptive_interval
                state["adaptive_success_streak"] = self._adaptive_success_streak

        self.logger.info(f"[Custom API] Throttle state: {state}")
        self._log_llm_interaction("throttle_state", state)

    def _setup_llm_logger(self):
        """Setup dedicated logger for LLM interactions."""
        log_dir = Path(self.llm_log_file).parent
        log_dir.mkdir(parents=True, exist_ok=True)

        self.llm_logger = logging.getLogger("llm-interactions-custom")
        self.llm_logger.setLevel(logging.INFO)
        self.llm_logger.propagate = False
        self.llm_logger.handlers.clear()

        # Rotating, not plain: llm_log_prompts writes full prompts, and a single
        # port run can carry 240k-char prompts. The previous FileHandler grew
        # logs/llm_interactions_lmstudio_nemotron3.json to 443 MB unbounded.
        file_handler = logging.handlers.RotatingFileHandler(
            self.llm_log_file,
            maxBytes=_LLM_LOG_MAX_BYTES,
            backupCount=_LLM_LOG_BACKUP_COUNT,
            encoding="utf-8",
        )
        file_handler.setLevel(logging.INFO)

        if self.llm_log_format == "json":
            formatter = logging.Formatter("%(message)s")
        else:
            formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s", datefmt="%Y-%m-%d %H:%M:%S")

        file_handler.setFormatter(formatter)
        self.llm_logger.addHandler(file_handler)

        self.logger.info(f"Custom API LLM logging initialized. Log file: {self.llm_log_file}")

    def _log_llm_interaction(self, interaction_type: str, data: Dict[str, Any]):
        """Log LLM interaction to dedicated log file."""
        if not self.llm_logging_enabled or not self.llm_logger:
            return

        log_entry = {"timestamp": datetime.now().isoformat(), "interaction_type": interaction_type, "provider": "custom_api"}

        if self.llm_log_format == "json":
            log_entry.update(data)
            self.llm_logger.info(json.dumps(log_entry))
        else:
            lines = [f"Type: {interaction_type}"]
            for key, value in data.items():
                lines.append(f"{key}: {value}")
            self.llm_logger.info("\n".join(lines))

    def _emit_ui_event(self, event_type: str, payload: Dict[str, Any]) -> None:
        cb = self._ui_event_callback
        if not cb:
            return
        try:
            cb(event_type, payload)
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Serving-slot management (unsloth studio /api/inference/* admin API)
    # ------------------------------------------------------------------

    def _admin_base_url(self) -> str:
        """Root of the serving host (chat URL minus the OpenAI-compatible path)."""
        base = self.base_url
        for suffix in ("/v1/chat/completions", "/chat/completions", "/v1"):
            if base.endswith(suffix):
                base = base[: -len(suffix)]
                break
        return base.rstrip("/")

    def _admin_headers(self) -> Dict[str, str]:
        return {"Authorization": f"Bearer {self.api_key}", "Accept": "application/json"}

    def _served_context_length(self) -> Optional[int]:
        """Context the server is ACTUALLY serving, or None when unknowable.

        Only `context_length` from the inference monitor/status endpoints is
        trustworthy; `max_context_length` from /v1/models lies in both
        directions (observed 2026-08-09) and must never be consulted.
        """
        admin = self._admin_base_url()
        for endpoint in ("/api/inference/monitor", "/api/inference/status"):
            try:
                response = requests.get(
                    f"{admin}{endpoint}",
                    headers=self._admin_headers(),
                    timeout=10,
                    verify=self.verify_ssl,
                )
                body = response.json()
            except (requests.RequestException, ValueError):
                continue
            if isinstance(body, dict) and "error" not in body:
                context = body.get("context_length")
                if isinstance(context, int) and context > 0:
                    return context
        return None

    def _issue_serving_load(self) -> None:
        """(Re)load the served model at the configured max_seq_length."""
        body: Dict[str, Any] = {
            "model_path": self.default_model,
            "max_seq_length": self.max_seq_length,
        }
        if self.gguf_variant:
            body["gguf_variant"] = self.gguf_variant
        response = requests.post(
            f"{self._admin_base_url()}/api/inference/load",
            headers=self._admin_headers(),
            timeout=120,
            json=body,
            verify=self.verify_ssl,
        )
        response.raise_for_status()

    def _preflight_serving_context(self, required_tokens: int) -> None:
        """Assert served context >= prompt + output budget before dispatching.

        A JIT model reload silently resets the served context to 4096; the
        request then fails (or truncates) after minutes of prefill. When the
        served context is too small, re-issue the load at the configured
        max_seq_length and wait for it to take effect. No-op unless
        max_seq_length is configured (management opt-in) or when the admin
        endpoints are absent (generic OpenAI-compatible providers).
        """
        if self.max_seq_length <= 0:
            return
        served = self._served_context_length()
        if served is None or served >= required_tokens:
            return
        if self.max_seq_length < required_tokens:
            # The configured context CANNOT satisfy this request, so reloading
            # would evict and re-load tens of GB, poll for ten minutes, and then
            # fail with the same arithmetic. Observed live on 2026-08-15: every
            # oversized unit paid a full reload before failing, and the failure
            # was then recorded as a per-unit verdict. Fail immediately and name
            # the real cause instead.
            raise APIResponseError(
                f"request needs {required_tokens} tokens but the configured serving "
                f"context is {self.max_seq_length} (currently serving {served}); a "
                "reload cannot help. Raise CUSTOM_API_MAX_SEQ_LEN, lower "
                "CUSTOM_API_MAX_TOKENS, or split the prompt."
            )
        self.logger.warning(
            f"[Custom API] Served context {served} < required {required_tokens}; "
            f"re-issuing load at max_seq_length={self.max_seq_length}"
        )
        self._log_llm_interaction(
            "serving_context_reload",
            {
                "served_context": served,
                "required_tokens": required_tokens,
                "max_seq_length": self.max_seq_length,
            },
        )
        try:
            self._issue_serving_load()
        except requests.RequestException as error:
            raise APIResponseError(
                f"Serving context {served} < required {required_tokens} and reload "
                f"failed: {error}"
            ) from error
        # The load call returns before the model finishes (re)loading; poll the
        # monitor until the new context is visible. Model loads take minutes.
        deadline = time.monotonic() + 600
        while time.monotonic() < deadline:
            served = self._served_context_length()
            if served is not None and served >= required_tokens:
                return
            time.sleep(5)
        raise APIResponseError(
            f"Serving context still {served} < required {required_tokens} after "
            f"reload at max_seq_length={self.max_seq_length}; the request would "
            "fail or truncate -- split the prompt or raise the served context"
        )

    def _cancel_abandoned_generation(self, reason: str) -> None:
        """Force-cancel a server-side generation this client has abandoned.

        The server keeps generating for disconnected clients; a zombie request
        held the single serving slot for 79 minutes on 2026-08-09. There is no
        lighter cancel endpoint, so force-unload with cancel, then re-request
        the model so the next dispatch does not eat a cold load.
        """
        if self.max_seq_length <= 0:
            return
        self.logger.warning(f"[Custom API] Cancelling abandoned server generation ({reason})")
        self._log_llm_interaction("cancel_abandoned_generation", {"reason": reason})
        try:
            requests.post(
                f"{self._admin_base_url()}/api/inference/unload",
                headers=self._admin_headers(),
                timeout=60,
                json={"model_path": self.default_model, "force_cancel_active": True},
                verify=self.verify_ssl,
            )
        except requests.RequestException as error:
            self.logger.warning(f"[Custom API] cancel-on-abandon unload failed: {error}")
            return
        # The unload returns before the slot is actually clear, and the load
        # returns before the model is actually resident. Retrying blind across
        # that window is what turned one slow generation into a cascade,
        # observed live: three consecutive 1200s timeouts followed by a stub
        # response carrying finish_reason='stop' with prompt_tokens=0 and
        # completion_tokens=0 -- a server that never processed a prompt because
        # it was still reloading. That stub was then recorded as the unit's
        # verdict. Wait for each transition instead.
        if not self._wait_for_slot_empty(timeout=120):
            self.logger.warning(
                "[Custom API] abandoned generation still active after the unload; "
                "the retry would contend with it"
            )
        try:
            self._issue_serving_load()
        except requests.RequestException as error:
            # The slot is free (unload succeeded); a missing model surfaces as
            # the well-known "no model loaded" 400 the pause rule matches.
            self.logger.warning(f"[Custom API] cancel-on-abandon reload failed: {error}")
            return
        if not self._wait_for_model_ready(timeout=600):
            self.logger.warning(
                "[Custom API] model not resident again after cancel-on-abandon; "
                "the retry may land mid-reload"
            )

    def _serving_active_requests(self) -> Optional[int]:
        """Generations the SERVER thinks are running, or None when unknowable."""
        admin = self._admin_base_url()
        for endpoint in ("/api/inference/monitor", "/api/inference/status"):
            try:
                body = requests.get(
                    f"{admin}{endpoint}", headers=self._admin_headers(),
                    timeout=10, verify=self.verify_ssl,
                ).json()
            except (requests.RequestException, ValueError):
                continue
            if not isinstance(body, dict) or "error" in body:
                continue
            count = body.get("active_requests")
            if isinstance(count, int):
                return count
            queue = body.get("queue")
            if isinstance(queue, dict) and isinstance(queue.get("active"), int):
                return queue["active"]
        return None

    def _wait_for_slot_empty(self, timeout: float) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            active = self._serving_active_requests()
            if active == 0:
                return True
            if active is None:
                return True   # unknowable; do not block the retry forever
            time.sleep(2)
        return (self._serving_active_requests() or 0) == 0

    def _wait_for_model_ready(self, timeout: float) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            served = self._served_context_length()
            if served is not None and served > 0:
                return True
            time.sleep(3)
        return False

    @staticmethod
    def _read_streaming_response(
        response,
        callback: Callable[[str, Dict[str, Any]], None],
    ) -> Dict[str, Any]:
        """Consume OpenAI-compatible SSE and rebuild the normal response shape."""
        content_parts: List[str] = []
        reasoning_parts: List[str] = []
        tool_name: str | None = None
        tool_arguments: List[str] = []
        usage: Dict[str, Any] = {}
        finish_reason: str | None = None
        saw_sse = False
        raw_lines: List[str] = []

        # A one-byte read chunk prevents small final tool calls from sitting in
        # urllib3's default 512-byte buffer while an imperfect SSE server keeps
        # the HTTP connection open after generation has already finished.
        for raw_line in response.iter_lines(chunk_size=1, decode_unicode=True):
            if not raw_line:
                continue
            line = raw_line.decode("utf-8", errors="replace") if isinstance(raw_line, bytes) else raw_line
            if not line.startswith("data:"):
                raw_lines.append(line)
                continue
            saw_sse = True
            payload = line[5:].strip()
            if payload == "[DONE]":
                break
            try:
                chunk = json.loads(payload)
            except json.JSONDecodeError:
                continue
            if chunk.get("error"):
                error = chunk["error"]
                if isinstance(error, dict):
                    detail = error.get("message") or error.get("code") or json.dumps(error)
                else:
                    detail = str(error)
                raise APIResponseError(f"Custom API stream error: {detail}")
            if isinstance(chunk.get("usage"), dict):
                usage = chunk["usage"]
            choices = chunk.get("choices") or []
            if not choices:
                continue
            choice = choices[0]
            delta = choice.get("delta") or choice.get("message") or {}
            content = delta.get("content")
            if isinstance(content, str) and content:
                content_parts.append(content)
                callback("assistant_delta", {"text": content})
            reasoning = delta.get("reasoning_content")
            if isinstance(reasoning, str) and reasoning:
                reasoning_parts.append(reasoning)
                callback("assistant_delta", {"text": reasoning, "channel": "reasoning"})
            for tool_call in delta.get("tool_calls") or []:
                function = tool_call.get("function") or {}
                name = function.get("name")
                if isinstance(name, str) and name:
                    tool_name = name
                    callback("tool_call_start", {"name": name})
                arguments = function.get("arguments")
                if isinstance(arguments, str) and arguments:
                    tool_arguments.append(arguments)
                    callback("tool_call_delta", {"name": tool_name, "text": arguments})
            # OpenAI-compatible servers are allowed to finish with a
            # finish_reason chunk. Do not require a subsequent [DONE] sentinel
            # from local servers that leave the SSE socket open.
            if choice.get("finish_reason") is not None:
                finish_reason = choice["finish_reason"]
                break

        if not saw_sse:
            raw_body = "\n".join(raw_lines).strip()
            if not raw_body:
                raise APIResponseError("Custom API returned an empty non-SSE response")
            try:
                data = json.loads(raw_body)
            except json.JSONDecodeError as error:
                raise APIResponseError(
                    "Custom API returned neither SSE nor a valid JSON response"
                ) from error
            if isinstance(data, dict) and data.get("error"):
                api_error = data["error"]
                detail = (
                    api_error.get("message") or api_error.get("code") or json.dumps(api_error)
                    if isinstance(api_error, dict)
                    else str(api_error)
                )
                raise APIResponseError(f"Custom API error: {detail}")
            return data

        message: Dict[str, Any] = {"content": "".join(content_parts)}
        if reasoning_parts:
            message["reasoning_content"] = "".join(reasoning_parts)
        if tool_arguments:
            message["tool_calls"] = [
                {
                    "type": "function",
                    "function": {
                        "name": tool_name,
                        "arguments": "".join(tool_arguments),
                    },
                }
            ]
        if not message["content"] and "tool_calls" not in message:
            raise APIResponseError(
                "Custom API stream contained no assistant content or tool call"
            )
        # finish_reason None here means the stream ended WITHOUT the server
        # declaring completion -- a dropped/aborted stream. Callers must be
        # able to tell that apart from "stop": a truncated JSON body that
        # logged as plain success cost three 22-minute analysis attempts.
        return {
            "choices": [{"message": message, "finish_reason": finish_reason}],
            "usage": usage,
        }

    def _apply_global_throttle(self) -> None:
        """Enforce a global minimum interval between request starts."""
        effective_interval = self.global_min_interval
        if self.adaptive_throttle_enabled:
            with self._adaptive_lock:
                effective_interval = max(effective_interval, self._adaptive_interval)

        if effective_interval <= 0:
            return

        with self._throttle_lock:
            now = time.monotonic()
            elapsed = now - self._last_request_start
            if elapsed < effective_interval:
                time.sleep(effective_interval - elapsed)
            self._last_request_start = time.monotonic()

    def _adaptive_on_success(self, call_type: str = "generate") -> None:
        if not self.adaptive_throttle_enabled:
            return

        with self._adaptive_lock:
            base = max(0.0, self.global_min_interval)

            # If we're already elevated above baseline, only count generate successes.
            # This avoids embeddings causing premature relaxation during mixed workloads.
            if base > 0 and self._adaptive_interval > base * 1.5 and call_type != "generate":
                return

            self._adaptive_success_streak += 1
            if self._adaptive_success_streak >= self.adaptive_success_streak_threshold:
                new_interval = max(base, self._adaptive_interval * self.adaptive_decrease_factor)
                if new_interval != self._adaptive_interval:
                    self.logger.debug(
                        f"[AdaptiveThrottle] success_streak={self._adaptive_success_streak} interval {self._adaptive_interval:.2f}s -> {new_interval:.2f}s"
                    )
                    self._adaptive_interval = new_interval
                self._adaptive_success_streak = 0

    def _adaptive_on_rate_limit(self, retry_after_s: float = 0.0) -> None:
        if not self.adaptive_throttle_enabled:
            return
        with self._adaptive_lock:
            self._adaptive_success_streak = 0

            base = max(0.0, self.global_min_interval)
            cur = max(base, self._adaptive_interval)
            if retry_after_s > 0:
                target = max(cur, float(retry_after_s))
            else:
                seed = cur if cur > 0 else 1.0
                target = seed * self.adaptive_increase_factor

            jitter = 0.0
            if self.adaptive_jitter_seconds > 0:
                jitter = random.random() * self.adaptive_jitter_seconds

            new_interval = min(max(base, target + jitter), self.adaptive_max_interval)
            if new_interval > self._adaptive_interval:
                self.logger.debug(
                    f"[AdaptiveThrottle] rate_limit interval {self._adaptive_interval:.2f}s -> {new_interval:.2f}s"
                )
                self._adaptive_interval = new_interval

    def _parse_retry_after_seconds(self, resp: requests.Response) -> float:
        """Parse Retry-After header into seconds (0 if missing/invalid)."""
        if not self.respect_retry_after:
            return 0.0

        raw = resp.headers.get("Retry-After")
        if not raw:
            return 0.0

        raw = raw.strip()
        try:
            secs = float(raw)
            if secs < 0:
                return 0.0
            return min(secs, float(self.retry_after_max_seconds))
        except ValueError:
            pass

        # Retry-After can also be an HTTP date
        try:
            dt = email.utils.parsedate_to_datetime(raw)
            if dt is None:
                return 0.0
            now = datetime.now(dt.tzinfo) if dt.tzinfo else datetime.utcnow()
            delta = (dt - now).total_seconds()
            if delta <= 0:
                return 0.0
            return min(delta, float(self.retry_after_max_seconds))
        except Exception:
            return 0.0

    def _make_before_sleep(self, interaction_type: str, request_id: str, model: str, phase: Optional[str]):
        """Create a tenacity before_sleep callback that logs retries and adapts throttle."""

        def before_sleep(retry_state):
            exc = None
            try:
                if retry_state and retry_state.outcome:
                    exc = retry_state.outcome.exception()
            except Exception:
                exc = None

            status_code = None
            retry_after_s = 0.0
            if isinstance(exc, requests.exceptions.HTTPError) and getattr(exc, "response", None) is not None:
                try:
                    status_code = exc.response.status_code
                    retry_after_s = self._parse_retry_after_seconds(exc.response)
                except Exception:
                    status_code = None
                    retry_after_s = 0.0

            # Let Retry-After override/extend the next sleep duration.
            try:
                if retry_state.next_action is not None:
                    sleep_s = float(retry_state.next_action.sleep)
                    if retry_after_s > 0:
                        sleep_s = max(sleep_s, float(retry_after_s))

                    # Ensure retries are also paced by the adaptive interval.
                    if self.adaptive_throttle_enabled:
                        with self._adaptive_lock:
                            sleep_s = max(sleep_s, float(self._adaptive_interval))

                    retry_state.next_action.sleep = sleep_s
            except Exception:
                pass

            if status_code in (429, 503):
                self._adaptive_on_rate_limit(retry_after_s=retry_after_s)

            try:
                sleep_s = float(retry_state.next_action.sleep) if retry_state.next_action is not None else None
            except Exception:
                sleep_s = None

            adaptive_interval = None
            if self.adaptive_throttle_enabled:
                with self._adaptive_lock:
                    adaptive_interval = self._adaptive_interval

            self._log_llm_interaction(
                f"{interaction_type}_retry",
                {
                    "request_id": request_id,
                    "model": model,
                    "phase": phase,
                    "attempt_number": getattr(retry_state, "attempt_number", None),
                    "sleep_seconds": sleep_s,
                    "status_code": status_code,
                    "retry_after_seconds": retry_after_s if retry_after_s > 0 else None,
                    "adaptive_interval_seconds": adaptive_interval,
                    "error": str(exc) if exc else None,
                },
            )

            # Surface retry state to UI (do not spam llm_interactions log)
            self._emit_ui_event(
                "llm_retry",
                {
                    "provider": "custom_api",
                    "interaction": interaction_type,
                    "request_id": request_id,
                    "model": model,
                    "phase": phase,
                    "attempt_number": getattr(retry_state, "attempt_number", None),
                    "sleep_seconds": sleep_s,
                    "status_code": status_code,
                    "retry_after_seconds": retry_after_s if retry_after_s > 0 else None,
                    "adaptive_interval_seconds": adaptive_interval,
                    "error": str(exc) if exc else None,
                },
            )

        return before_sleep

    def query(self, prompt: Union[str, Tuple[str, str]], phase: Optional[str] = None) -> str:
        """
        High-level query interface compatible with Bridge.
        Handles both string prompts and (system, user) tuples.
        """
        system_prompt: Optional[str] = None
        user_prompt: str

        if isinstance(prompt, tuple) and len(prompt) == 2:
            system_prompt, user_prompt = prompt
        else:
            user_prompt = str(prompt)

        return self.generate(prompt=user_prompt, system_prompt=system_prompt, phase=phase)

    def generate(
        self,
        prompt: str,
        model: Optional[str] = None,
        system_prompt: Optional[str] = None,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        phase: Optional[str] = None,
        tools: Optional[List[Dict[str, Any]]] = None,
        tool_choice: Optional[Dict[str, Any] | str] = None,
        response_format: Optional[Dict[str, Any]] = None,
        stream_callback: Optional[Callable[[str, Dict[str, Any]], None]] = None,
        messages: Optional[List[Dict[str, Any]]] = None,
        chat_template_kwargs: Optional[Dict[str, Any]] = None,
    ) -> str:
        """
        Generate a response from the Custom API.
        Supports OpenAI-compatible chat completions format.
        """
        request_clock: float | None = None
        first_output_clock: float | None = None
        streamed_output: List[str] = []
        last_liveness_clock: float | None = None
        stream_read_started = False
        start_time = time.time() if self.llm_log_timing else None

        # Request Delay
        if self.request_delay > 0:
            self.logger.debug(f"Sleeping for {self.request_delay}s before request")
            time.sleep(self.request_delay)

        # Determine effective parameters
        effective_model = model or self.default_model
        effective_system = system_prompt or self.default_system_prompt
        effective_temperature = temperature if temperature is not None else self.temperature
        effective_max_tokens = max_tokens if max_tokens is not None else self.max_tokens

        # Build the conversation. Explicit messages preserve standard assistant/tool
        # turns so compatible servers can reuse the long prompt prefix.
        conversation = list(messages) if messages is not None else []
        if not conversation:
            if effective_system:
                conversation.append({"role": "system", "content": effective_system})
            conversation.append({"role": "user", "content": prompt})

        # Headers
        headers = {"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"}

        # Model-specific detection and adjustments
        model_lower = effective_model.lower()

        # Detect Claude models (Anthropic/Bedrock)
        is_claude_model = any(x in model_lower for x in ["claude", "anthropic"])

        # Detect reasoning models (OpenAI GPT-5, o1-series)
        is_reasoning_model = any(x in model_lower for x in ["gpt-5", "o1-", "o1mini", "o1preview"])

        # Detect other models with known limits
        is_gpt4 = "gpt-4" in model_lower and "gpt-5" not in model_lower

        # Adjust temperature for reasoning models
        if is_reasoning_model and effective_temperature != 1.0:
            self.logger.warning(f"⚙️  Adjusting temperature from {effective_temperature} to 1.0 for {effective_model}")
            effective_temperature = 1.0

        # Build payload
        payload = {
            "model": effective_model,
            "messages": conversation,
            "temperature": effective_temperature,
        }
        if chat_template_kwargs is not None:
            # e.g. {"enable_thinking": False}: the server's launch default
            # enables thinking, and a reasoning burn on a structured request
            # can consume the whole output budget with zero content.
            payload["chat_template_kwargs"] = chat_template_kwargs

        # Intelligent token limit adjustment based on model type
        if is_claude_model:
            # Claude models via Bedrock have 64K output limit but 200K input
            # Be conservative to avoid hitting limits
            max_output_tokens = min(effective_max_tokens, 32000)  # Cap at 32K for safety
            payload["max_tokens"] = max_output_tokens

            # Log adjustment if we reduced the limit
            if effective_max_tokens > max_output_tokens:
                self.logger.info(
                    f"⚙️  Adjusted max_tokens from {effective_max_tokens} to {max_output_tokens} for Claude model (64K limit)"
                )

        elif is_reasoning_model:
            # Reasoning models use max_completion_tokens with higher limits (128K for GPT-5)
            reasoning_default = min(effective_max_tokens, 32000)
            payload["max_completion_tokens"] = reasoning_default
            self.logger.debug(f"Using max_completion_tokens={reasoning_default} for reasoning model")

        elif is_gpt4:
            # GPT-4 has various context windows, be conservative
            max_output_tokens = min(effective_max_tokens, 16000)
            payload["max_tokens"] = max_output_tokens

        else:
            # Generic OpenAI-compatible API - use standard max_tokens
            payload["max_tokens"] = effective_max_tokens

        if tools:
            payload["tools"] = tools
        if tool_choice is not None:
            payload["tool_choice"] = tool_choice
        if response_format is not None:
            payload["response_format"] = response_format
        if stream_callback is not None:
            payload["stream"] = True
            # Ask OpenAI-compatible servers to attach usage to the final
            # stream chunk; servers that don't support it ignore the field.
            # Without this the streaming path reports no token accounting at
            # all ("tokens": {}) and truncation goes undetected.
            payload["stream_options"] = {"include_usage": True}

        # Construct API endpoint URL
        if self.base_url.endswith("/chat/completions") or self.base_url.endswith("/v1/chat/completions"):
            api_url = self.base_url
        else:
            api_url = f"{self.base_url}/v1/chat/completions"

        # Log request
        request_id = str(uuid.uuid4())
        if self.llm_logging_enabled:
            self._log_llm_interaction(
                "generate_request",
                {
                    "request_id": request_id,
                    "model": effective_model,
                    "phase": phase,
                    "temperature": effective_temperature,
                    "max_tokens": payload.get("max_tokens") or payload.get("max_completion_tokens"),
                    "prompt": prompt if self.llm_log_prompts else "[REDACTED]",
                    "system_prompt": effective_system if self.llm_log_prompts else "[REDACTED]",
                },
            )

        # Print what we're doing
        print(f"[Custom API] Generating response using model: {effective_model}")

        # Retry logic
        response_text = ""
        error_msg = None

        try:
            # Concurrency + global throttling
            self._request_semaphore.acquire()
            # Context preflight uses the ~2.05 chars/token measurement from the
            # chunk workflow (chars//2 slightly overestimates tokens, which is
            # the safe direction for a context gate).
            required_context_tokens = (
                len(json.dumps(conversation, ensure_ascii=False, default=str)) // 2
                + int(payload.get("max_tokens") or payload.get("max_completion_tokens") or 0)
            )
            self._preflight_serving_context(required_context_tokens)
            self._apply_global_throttle()

            retryer = Retrying(
                stop=stop_after_attempt(self.max_retries + 1),
                wait=wait_exponential(multiplier=1, min=2, max=10),
                retry=retry_if_exception(is_retryable_exception),
                before_sleep=self._make_before_sleep("generate", request_id, effective_model, phase),
                reraise=True,
            )

            def do_post():
                nonlocal request_clock, first_output_clock
                with self._metrics_lock:
                    self.generation_metrics["api_calls"] += 1
                    self.generation_metrics["active"] = True
                    self.generation_metrics["status"] = "generating"
                    self.generation_metrics["tokens_per_second"] = 0.0
                    self.generation_metrics["throughput_scope"] = "pending"
                    self.generation_metrics["current_prompt_tokens"] = self._estimate_tokens(
                        json.dumps(conversation, ensure_ascii=False, default=str)
                    )
                    self.generation_metrics["current_completion_tokens"] = 0
                    self.generation_metrics["current_request_elapsed_seconds"] = 0.0
                    self.generation_metrics["request_started_at"] = (
                        datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
                    )
                    self._write_liveness()
                request_clock = time.perf_counter()
                first_output_clock = None
                # Port-work phases need a very LONG read timeout, not none at
                # all: an 81k-token prompt can spend 30-60 min in prefill with
                # zero bytes on the wire, and requests' read timeout is
                # time-between-bytes, so a short one kills healthy requests.
                # But `None` is unbounded, and on 2026-08-09 the studio silently
                # lost its model binding mid-request: the driver sat in
                # awaiting_provider_output for FOUR HOURS (liveness frozen at
                # 04:10, pause not raised until 08:10) because nothing ever
                # gave up. The supervisor's stall probes did not catch it
                # either. A generous ceiling well past the longest legitimate
                # prefill bounds the loss and surfaces as requests.Timeout,
                # which TRANSIENT_MARKERS already maps to ProviderUnavailable --
                # so the driver pauses cleanly instead of blocking chunks.
                _long_read_phases = ("finish_game_source:", "chunk_analysis:")
                _stall_ceiling = int(
                    os.getenv("OGHIDRA_PORT_STALL_TIMEOUT_SECONDS", "5400")
                )
                request_timeout = (
                    (30, _stall_ceiling)
                    if phase and phase.startswith(_long_read_phases)
                    else self.timeout
                )
                request_arguments = {
                    "headers": headers,
                    "json": payload,
                    "timeout": request_timeout,
                    "verify": self.verify_ssl,
                }
                if stream_callback is not None:
                    request_arguments["stream"] = True
                resp = requests.post(api_url, **request_arguments)
                try:
                    resp.raise_for_status()
                except requests.exceptions.HTTPError as error:
                    # Keep the response body in the message: the server's 400
                    # for an unloaded model says "no model loaded" ONLY in the
                    # body, and the workflow's TRANSIENT_MARKERS pause rule
                    # matches on message text. Discarding the body turned
                    # provider outages into permanent analysis_blocked /
                    # rejected_final ledger verdicts (2026-08-08 storms).
                    detail = ""
                    try:
                        detail = (resp.text or "").strip()[:300]
                    except Exception:
                        pass
                    raise requests.exceptions.HTTPError(
                        f"{error} | body: {detail}", response=resp
                    ) from error
                return resp

            def observed_stream_callback(event_type: str, event: Dict[str, Any]) -> None:
                nonlocal first_output_clock, last_liveness_clock
                now = time.perf_counter()
                if (
                    first_output_clock is None
                    and event_type in {"assistant_delta", "tool_call_delta"}
                    and event.get("text")
                ):
                    first_output_clock = now
                text = event.get("text")
                if event_type in {"assistant_delta", "tool_call_delta"} and isinstance(text, str):
                    streamed_output.append(text)
                    if last_liveness_clock is None or now - last_liveness_clock >= 0.5:
                        current_tokens = self._estimate_tokens("".join(streamed_output))
                        generation_elapsed = max(
                            now - (first_output_clock or now),
                            1e-9,
                        )
                        request_elapsed = max(now - (request_clock or now), 0.0)
                        with self._metrics_lock:
                            self.generation_metrics["status"] = "streaming"
                            self.generation_metrics["current_completion_tokens"] = current_tokens
                            self.generation_metrics["current_request_elapsed_seconds"] = request_elapsed
                            self.generation_metrics["tokens_per_second"] = (
                                current_tokens / generation_elapsed
                            )
                            self.generation_metrics["throughput_scope"] = (
                                "live_stream_generation_window"
                            )
                            self._write_liveness()
                        last_liveness_clock = now
                if stream_callback is not None:
                    stream_callback(event_type, event)

            response = retryer(do_post)
            if stream_callback is not None:
                stream_read_started = True
                data = self._read_streaming_response(response, observed_stream_callback)
            else:
                data = response.json()

            # Extract response
            if "choices" in data and len(data["choices"]) > 0:
                message = data["choices"][0].get("message", {})
                reasoning_text = message.get("reasoning_content") or ""
                tool_calls = message.get("tool_calls") or []
                if tool_calls:
                    tool_call = tool_calls[0]
                    if not tool_call.get("id"):
                        tool_call = {**tool_call, "id": f"call_{request_id}"}
                    function = tool_call.get("function", {})
                    arguments = function.get("arguments", "")
                    response_text = arguments if isinstance(arguments, str) else json.dumps(arguments)
                    self.last_response_metadata = {
                        "structured_output_mode": "tool_call",
                        "tool_name": function.get("name"),
                        "tool_call": tool_call,
                        "assistant_message": {
                            "role": "assistant",
                            "content": message.get("content"),
                            "tool_calls": [tool_call],
                        },
                    }
                    with self._metrics_lock:
                        self.generation_metrics["structured_tool_calls"] += 1
                else:
                    response_text = message.get("content") or ""
                    self.last_response_metadata = {
                        "structured_output_mode": "json_schema" if response_format else "plain_json",
                        "tool_name": None,
                    }
            else:
                self.logger.warning("Unexpected Custom API response format")
                response_text = ""
                reasoning_text = ""
                self.last_response_metadata = {
                    "structured_output_mode": "plain_json",
                    "tool_name": None,
                }

            if not response_text.strip():
                raise APIResponseError(describe_empty_response(data, reasoning_text))

            completed_clock = time.perf_counter()
            duration_seconds = max(
                completed_clock - (request_clock or completed_clock),
                1e-9,
            )
            usage = data.get("usage") if isinstance(data.get("usage"), dict) else {}
            prompt_tokens = usage.get("prompt_tokens", usage.get("input_tokens"))
            completion_tokens = usage.get("completion_tokens", usage.get("output_tokens"))
            token_source = "api"
            if not isinstance(prompt_tokens, int):
                prompt_tokens = self._estimate_tokens(
                    json.dumps(conversation, ensure_ascii=False, default=str)
                )
                token_source = "estimated"
            if not isinstance(completion_tokens, int):
                completion_tokens = self._estimate_tokens(
                    f"{reasoning_text}\n{response_text}"
                )
                token_source = "estimated"
            if first_output_clock is not None:
                generation_duration_seconds = max(
                    completed_clock - first_output_clock,
                    1e-9,
                )
                throughput_scope = "stream_generation_window"
            else:
                generation_duration_seconds = duration_seconds
                throughput_scope = "end_to_end_fallback"
            tokens_per_second = completion_tokens / generation_duration_seconds
            end_to_end_tokens_per_second = completion_tokens / duration_seconds
            self.last_response_metadata.update(
                {
                    "prompt_tokens": prompt_tokens,
                    "completion_tokens": completion_tokens,
                    "duration_seconds": duration_seconds,
                    "generation_duration_seconds": generation_duration_seconds,
                    "tokens_per_second": tokens_per_second,
                    "end_to_end_tokens_per_second": end_to_end_tokens_per_second,
                    "throughput_scope": throughput_scope,
                    "token_source": token_source,
                }
            )
            with self._metrics_lock:
                self.generation_metrics["prompt_tokens"] += prompt_tokens
                self.generation_metrics["completion_tokens"] += completion_tokens
                self.generation_metrics["duration_seconds"] += duration_seconds
                self.generation_metrics["generation_duration_seconds"] = (
                    generation_duration_seconds
                )
                self.generation_metrics["tokens_per_second"] = tokens_per_second
                self.generation_metrics["end_to_end_tokens_per_second"] = (
                    end_to_end_tokens_per_second
                )
                self.generation_metrics["throughput_scope"] = throughput_scope
                self.generation_metrics["current_prompt_tokens"] = 0
                self.generation_metrics["current_completion_tokens"] = 0
                self.generation_metrics["current_request_elapsed_seconds"] = 0.0
                if (
                    self.generation_metrics["token_source"] in {"unavailable", "api"}
                    and token_source == "api"
                ):
                    self.generation_metrics["token_source"] = "api"
                else:
                    self.generation_metrics["token_source"] = "estimated"
                self.generation_metrics["active"] = False
                self.generation_metrics["status"] = "completed"
                self._write_liveness()

            # Log success
            if self.llm_logging_enabled:
                duration_ms = (time.time() - start_time) * 1000 if start_time else 0
                self._log_llm_interaction(
                    "generate_response",
                    {
                        "request_id": request_id,
                        "model": effective_model,
                        "phase": phase,
                        "status": "success",
                        "finish_reason": (data.get("choices") or [{}])[0].get("finish_reason"),
                        "response": response_text if self.llm_log_responses else "[REDACTED]",
                        "tokens": usage if self.llm_log_tokens else None,
                        "duration_ms": duration_ms if self.llm_log_timing else None,
                    },
                )

            self._adaptive_on_success("generate")
            return response_text

        except Exception as e:
            error_msg = str(e)
            self.logger.error(f"Error calling Custom API: {error_msg}")
            # Cancel-on-abandon: a read timeout (prefill or generation) or a
            # dropped stream leaves the server generating for a client that is
            # gone -- a zombie that hogs the single serving slot. A connect
            # timeout or an in-band SSE error means no orphaned generation.
            read_timed_out = isinstance(
                e, requests.exceptions.Timeout
            ) and not isinstance(e, requests.exceptions.ConnectTimeout)
            stream_dropped = stream_read_started and isinstance(
                e,
                (
                    requests.exceptions.ConnectionError,
                    requests.exceptions.ChunkedEncodingError,
                    OSError,
                ),
            )
            if read_timed_out or stream_dropped:
                self._cancel_abandoned_generation(f"{type(e).__name__}: {error_msg[:200]}")
            with self._metrics_lock:
                self.generation_metrics["active"] = False
                self.generation_metrics["status"] = "failed"
                self.generation_metrics["current_prompt_tokens"] = 0
                self.generation_metrics["current_completion_tokens"] = 0
                self.generation_metrics["last_error"] = error_msg
                self._write_liveness()

            # Enhanced error logging (HTTP errors)
            if isinstance(e, requests.exceptions.HTTPError) and getattr(e, "response", None) is not None:
                try:
                    http_resp = e.response
                    error_body = http_resp.text
                    self.logger.error(f"Response Status: {http_resp.status_code}")
                    self.logger.error(f"Response Body: {error_body[:1000]}")
                except Exception:
                    pass

            # Log request sizes for debugging
            prompt_size = len(prompt) if prompt else 0
            system_size = len(system_prompt) if system_prompt else 0
            self.logger.error(
                f"Request sizes - prompt: {prompt_size:,} chars, system: {system_size:,} chars, total: {prompt_size + system_size:,} chars"
            )

            # Log error
            if self.llm_logging_enabled:
                duration_ms = (time.time() - start_time) * 1000 if start_time else 0
                self._log_llm_interaction(
                    "generate_error",
                    {
                        "request_id": request_id,
                        "model": effective_model,
                        "phase": phase,
                        "status": "error",
                        "error": error_msg,
                        "duration_ms": duration_ms if self.llm_log_timing else None,
                    },
                )

            raise

        finally:
            # Ensure we always release semaphore
            try:
                self._request_semaphore.release()
            except Exception:
                pass

    def generate_structured(
        self,
        *,
        prompt: str,
        schema: Dict[str, Any],
        tool_name: str,
        model: Optional[str] = None,
        system_prompt: Optional[str] = None,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        phase: Optional[str] = None,
        accept_plain_tool_response: bool = False,
        prefer_json_schema: bool = False,
        stream_callback: Optional[Callable[[str, Dict[str, Any]], None]] = None,
        chat_template_kwargs: Optional[Dict[str, Any]] = None,
    ) -> Tuple[str, str]:
        """Generate schema-constrained JSON with observable compatibility fallbacks.

        Preferred order is an explicit function/tool call, then OpenAI JSON Schema
        response format, then a plain JSON response validated by the caller.
        """
        if prefer_json_schema:
            response_format = {
                "type": "json_schema",
                "json_schema": {
                    "name": tool_name,
                    "strict": True,
                    "schema": schema,
                },
            }
            response = self.generate(
                prompt=prompt,
                model=model,
                system_prompt=system_prompt,
                temperature=temperature,
                max_tokens=max_tokens,
                phase=phase,
                response_format=response_format,
                stream_callback=stream_callback,
                chat_template_kwargs=chat_template_kwargs,
            )
            return response, "json_schema"

        tool = {
            "type": "function",
            "function": {
                "name": tool_name,
                "description": "Submit one schema-valid source-derived port model.",
                "parameters": schema,
                "strict": True,
            },
        }
        choice = {"type": "function", "function": {"name": tool_name}}

        try:
            response = self.generate(
                prompt=prompt,
                model=model,
                system_prompt=system_prompt,
                temperature=temperature,
                max_tokens=max_tokens,
                phase=phase,
                tools=[tool],
                tool_choice=choice,
                stream_callback=stream_callback,
                chat_template_kwargs=chat_template_kwargs,
            )
            if self.last_response_metadata.get("structured_output_mode") == "tool_call":
                return response, "tool_call"
            if accept_plain_tool_response and response.strip():
                self.logger.info(
                    "Endpoint ignored forced tool_choice; returning plain response for caller validation"
                )
                return response, "plain_json"
            self.logger.info(
                "Endpoint ignored forced tool_choice; trying JSON Schema before accepting plain JSON"
            )
        except requests.exceptions.HTTPError as error:
            status = error.response.status_code if error.response is not None else None
            if status not in {400, 404, 415, 422}:
                raise
            self.logger.info("Structured tool calls unsupported by endpoint; trying JSON Schema")

        response_format = {
            "type": "json_schema",
            "json_schema": {
                "name": tool_name,
                "strict": True,
                "schema": schema,
            },
        }
        try:
            response = self.generate(
                prompt=prompt,
                model=model,
                system_prompt=system_prompt,
                temperature=temperature,
                max_tokens=max_tokens,
                phase=phase,
                response_format=response_format,
                stream_callback=stream_callback,
                chat_template_kwargs=chat_template_kwargs,
            )
            return response, "json_schema"
        except requests.exceptions.HTTPError as error:
            status = error.response.status_code if error.response is not None else None
            if status not in {400, 404, 415, 422}:
                raise
            self.logger.info("JSON Schema response format unsupported by endpoint; using validated plain JSON")

        response = self.generate(
            prompt=prompt,
            model=model,
            system_prompt=system_prompt,
            temperature=temperature,
            max_tokens=max_tokens,
            phase=phase,
            stream_callback=stream_callback,
            chat_template_kwargs=chat_template_kwargs,
        )
        return response, "plain_json"

    def generate_with_phase(self, prompt: str, phase: Optional[str] = None, system_prompt: Optional[str] = None) -> str:
        """Generate using phase-specific model configuration."""
        model_override = self.model_map.get(phase) if phase else None
        if model_override:
            return self.generate(prompt=prompt, model=model_override, system_prompt=system_prompt, phase=phase)
        return self.generate(prompt=prompt, system_prompt=system_prompt, phase=phase)

    def embed(self, text: str, model: Optional[str] = None) -> List[float]:
        """
        Generate embeddings using Custom API (OpenAI-compatible).
        Supports text-embedding-ada-002 and similar models.

        Args:
            text: Text to embed
            model: Embedding model to use (defaults to configured embedding_model)

        Returns:
            List of embedding values
        """
        if not text.strip():
            return []

        start_time = time.time() if self.llm_log_timing else None

        # Request Delay
        if self.request_delay > 0:
            self.logger.debug(f"Sleeping for {self.request_delay}s before embedding request")
            time.sleep(self.request_delay)

        embedding_model = model if model is not None else getattr(self.config, "embedding_model", "text-embedding-ada-002")

        # Construct embeddings endpoint URL.
        # Prefer an explicitly configured embedding endpoint (embeddings may be served on a
        # different host/port than chat, e.g. a second LM Studio instance).
        cfg_embed_url = (getattr(self.config, "embedding_api_url", "") or "").strip().rstrip("/")
        if cfg_embed_url:
            if cfg_embed_url.endswith("/embeddings"):
                api_url = cfg_embed_url
            elif cfg_embed_url.endswith("/v1"):
                api_url = f"{cfg_embed_url}/embeddings"
            else:
                api_url = f"{cfg_embed_url}/v1/embeddings"
        elif self.base_url.endswith("/embeddings") or self.base_url.endswith("/v1/embeddings"):
            api_url = self.base_url
        else:
            # Standard OpenAI embeddings endpoint
            # Remove the chat completions path if present
            base = self.base_url
            if base.endswith("/v1/chat/completions"):
                base = base[: -len("/v1/chat/completions")]
            elif base.endswith("/chat/completions"):
                base = base[: -len("/chat/completions")]
            api_url = f"{base.rstrip('/')}/v1/embeddings"

        headers = {"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"}

        payload = {"model": embedding_model, "input": text}

        request_id = str(uuid.uuid4())

        # Print what we're doing
        print(f"[Custom API] Generating embeddings using model: {embedding_model}")

        try:
            # Concurrency + global throttling
            self._request_semaphore.acquire()
            self._apply_global_throttle()

            # Setup retryer
            retryer = Retrying(
                stop=stop_after_attempt(self.max_retries + 1),
                wait=wait_exponential(multiplier=1, min=2, max=10),
                retry=retry_if_exception(is_retryable_exception),
                before_sleep=self._make_before_sleep("embed", request_id, embedding_model, phase=None),
                reraise=True,
            )

            def do_post():
                resp = requests.post(api_url, headers=headers, json=payload, timeout=self.timeout, verify=self.verify_ssl)
                resp.raise_for_status()
                return resp

            response = retryer(do_post)
            data = response.json()

            # Extract embedding from response
            if "data" in data and len(data["data"]) > 0:
                embedding = data["data"][0].get("embedding", [])
            else:
                self.logger.warning("Unexpected Custom API embeddings response format")
                embedding = []

            # Log success
            if self.llm_logging_enabled:
                duration_ms = (time.time() - start_time) * 1000 if start_time else 0
                usage = data.get("usage", {})
                self._log_llm_interaction(
                    "embed",
                    {
                        "request_id": request_id,
                        "model": embedding_model,
                        "status": "success",
                        "embedding_dim": len(embedding),
                        "text_length": len(text),
                        "tokens": usage if self.llm_log_tokens else None,
                        "duration_ms": duration_ms if self.llm_log_timing else None,
                    },
                )

            self._adaptive_on_success("embed")
            return embedding

        except Exception as e:
            error_msg = str(e)
            self.logger.error(f"Error calling Custom API embeddings: {error_msg}")

            # Log error
            if self.llm_logging_enabled:
                duration_ms = (time.time() - start_time) * 1000 if start_time else 0
                self._log_llm_interaction(
                    "embed_error",
                    {
                        "request_id": request_id,
                        "model": embedding_model,
                        "status": "error",
                        "error": error_msg,
                        "text_length": len(text),
                        "duration_ms": duration_ms if self.llm_log_timing else None,
                    },
                )

            raise

        finally:
            try:
                self._request_semaphore.release()
            except Exception:
                pass

    def _resolve_embeddings_url(self) -> str:
        """Resolve the /v1/embeddings endpoint (shared by embed and embed_batch)."""
        cfg_embed_url = (getattr(self.config, "embedding_api_url", "") or "").strip().rstrip("/")
        if cfg_embed_url:
            if cfg_embed_url.endswith("/embeddings"):
                return cfg_embed_url
            if cfg_embed_url.endswith("/v1"):
                return f"{cfg_embed_url}/embeddings"
            return f"{cfg_embed_url}/v1/embeddings"
        base = self.base_url
        if base.endswith("/embeddings") or base.endswith("/v1/embeddings"):
            return base
        if base.endswith("/v1/chat/completions"):
            base = base[: -len("/v1/chat/completions")]
        elif base.endswith("/chat/completions"):
            base = base[: -len("/chat/completions")]
        return f"{base.rstrip('/')}/v1/embeddings"

    def embed_batch(self, texts, model: Optional[str] = None, chunk: int = 64) -> List[List[float]]:
        """Embed many texts with as few HTTP round-trips as possible. The OpenAI-compatible
        /v1/embeddings endpoint accepts a LIST `input`, so send up to `chunk` texts per POST
        instead of one-per-call, and skip the per-item chat throttle (request_delay /
        global-min-interval) which is meaningless on a separate fast embedding endpoint.
        Returns vectors in input order, or [] on failure so callers can fall back to embed()."""
        valid = [t.strip() for t in (texts or []) if isinstance(t, str) and t.strip()]
        if not valid:
            return []
        embedding_model = model if model is not None else getattr(self.config, "embedding_model", "text-embedding-ada-002")
        api_url = self._resolve_embeddings_url()
        headers = {"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"}
        step = max(1, int(chunk))
        out: List[List[float]] = []
        for i in range(0, len(valid), step):
            batch = valid[i : i + step]
            payload = {"model": embedding_model, "input": batch}
            last_err = None
            for attempt in range(self.max_retries + 1):
                try:
                    resp = requests.post(api_url, headers=headers, json=payload, timeout=self.timeout, verify=self.verify_ssl)
                    resp.raise_for_status()
                    data = sorted(resp.json().get("data", []), key=lambda d: d.get("index", 0))
                    embs = [d.get("embedding", []) for d in data]
                    if len(embs) != len(batch) or any(not e for e in embs):
                        raise ValueError(f"expected {len(batch)} embeddings, got {len([e for e in embs if e])}")
                    out.extend(embs)
                    break
                except Exception as e:
                    last_err = e
                    time.sleep(min(2 * (attempt + 1), 6))
            else:
                self.logger.error(f"embed_batch failed for chunk at {i}: {last_err}")
                return []
        return out

    def check_health(self) -> bool:
        """Check if the Custom API endpoint is reachable."""
        try:
            headers = {"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"}
            test_payload = {"model": self.default_model, "messages": [{"role": "user", "content": "test"}], "max_tokens": 1}

            if self.base_url.endswith("/chat/completions") or self.base_url.endswith("/v1/chat/completions"):
                api_url = self.base_url
            else:
                api_url = f"{self.base_url}/v1/chat/completions"

            response = requests.post(api_url, headers=headers, json=test_payload, timeout=5, verify=self.verify_ssl)
            return response.status_code == 200
        except Exception as e:
            self.logger.error(f"Custom API health check failed: {e}")
            return False
