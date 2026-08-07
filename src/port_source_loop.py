"""Single-threaded Qwen source-edit, verify, retry, and Git checkpoint loop."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Callable, Literal
from urllib.parse import urlparse

from pydantic import BaseModel, Field, ValidationError
from pydantic_ai import (
    Agent,
    FunctionToolCallEvent,
    FunctionToolResultEvent,
    PartDeltaEvent,
    PartStartEvent,
    TextPartDelta,
    ThinkingPartDelta,
    PromptedOutput,
    TextOutput,
    ToolCallPartDelta,
    ToolOutput,
    UsageLimits,
)
from pydantic_ai.exceptions import ModelAPIError
import httpx
import psutil
from openai import APIError as OpenAIAPIError, AsyncOpenAI
from pydantic_ai.models.openai import (
    OpenAIChatModel,
    OpenAIChatModelSettings,
)
from pydantic_ai.profiles.openai import OpenAIModelProfile
from pydantic_ai.providers.openai import OpenAIProvider
import requests

from src.port_workflow import atomic_write_json
from src.port_activity import PortActivity
from src.custom_api_client import APIResponseError


# 65536, not 32768: the thinking model's reasoning spends from this same
# budget, and borg_action_state_machine attempt 1 (2026-08-07 05:26Z) burned
# all 32,768 tokens on chain-of-thought and died with "token limit exceeded
# before any response was generated". The serving context (~131k) minus the
# ~10-14k unit prompt leaves ample room.
MODEL_MAX_OUTPUT_TOKENS = int(os.getenv("OGHIDRA_PORT_MAX_TOKENS", "65536"))
MAX_REPAIR_ATTEMPTS = int(os.getenv("OGHIDRA_PORT_REPAIR_ATTEMPTS", "3"))
SOURCE_CONTEXT_FILE_LIMIT = int(os.getenv("OGHIDRA_PORT_SOURCE_FILE_LIMIT", "4"))
SOURCE_CONTEXT_FILE_CHAR_LIMIT = int(
    os.getenv("OGHIDRA_PORT_SOURCE_FILE_CHAR_LIMIT", "6000")
)
SOURCE_CONTEXT_TOTAL_CHAR_LIMIT = int(
    os.getenv("OGHIDRA_PORT_SOURCE_TOTAL_CHAR_LIMIT", "18000")
)
SOURCE_CONTEXT_WINDOW_LINES = int(os.getenv("OGHIDRA_PORT_SOURCE_WINDOW_LINES", "80"))
MAX_WORKSPACE_TOOL_CALLS = int(os.getenv("OGHIDRA_PORT_WORKSPACE_TOOL_CALLS", "3"))
# Port generation runs with model thinking DISABLED by default: the reasoning
# channel spends from the same output budget, and borg_action_state_machine
# (2026-08-07) burned 32,768 tokens of pure chain-of-thought across a
# reasoning spiral (same file re-read 5x) without ever emitting a patch.
# Applied as chat_template_kwargs.enable_thinking=false (vLLM/SGLang/llama.cpp
# servers; ignored elsewhere) plus the Qwen /no_think soft switch in the
# system prompt. Set OGHIDRA_PORT_DISABLE_THINKING=0 to re-enable thinking.
PORT_DISABLE_THINKING = os.getenv("OGHIDRA_PORT_DISABLE_THINKING", "1").lower() not in (
    "0",
    "false",
)
SOURCE_READ_MAX_LINES = int(os.getenv("OGHIDRA_PORT_SOURCE_READ_MAX_LINES", "800"))
SOURCE_SEARCH_RESULT_LIMIT = int(os.getenv("OGHIDRA_PORT_SOURCE_SEARCH_RESULTS", "40"))
ADJACENT_CONTEXT_FILE_LIMIT = int(os.getenv("OGHIDRA_PORT_ADJACENT_FILES", "8"))
EXCLUDED_CONTEXT_DIRECTORIES = {"node_modules", "dist", "build", "coverage", ".tmp"}
ALLOWED_SOURCE_ROOTS = ("apps/game/", "packages/", "scripts/")
ALLOWED_SUFFIXES = {".ts", ".tsx", ".js", ".mjs", ".json"}
# Ordered cheap-first: typecheck fails in seconds, browser smoke costs minutes.
VERIFY_COMMANDS = (
    ("pnpm", "typecheck"),
    ("pnpm", "--filter", "@gf/combat", "build"),
    ("pnpm", "selfcheck:rom"),
    ("pnpm", "selfcheck:game-session"),
    ("pnpm", "--filter", "game", "build"),
    ("pnpm", "smoke:browser"),
)
# The unit of value is a combat-family state machine routed to the right
# package (R27): patches touching packages/combat must also keep the family
# audits green. Both pass on current main (verified 2026-08-06).
COMBAT_AUDIT_COMMANDS = (
    ("pnpm", "audit:family-state-machines"),
    ("pnpm", "audit:move-wiring"),
)
TRANSIENT_PROVIDER_MARKERS = (
    "connection",
    "readerror",
    "remoteprotocolerror",
    "timed out",
    "timeout",
    "empty stream",
    "service unavailable",
    "no model loaded",
    "connection refused",
    "status_code: 429",
    "status_code: 500",
    "status_code: 502",
    "status_code: 503",
    "status_code: 504",
)
EXPORTED_SYMBOL = re.compile(
    r"^\s*export\s+(?:default\s+)?(?:async\s+)?"
    r"(?:function|class|const|let|var|enum)\s+([A-Za-z_$][\w$]*)",
    re.MULTILINE,
)


def is_provider_unavailable(error: BaseException | str) -> bool:
    message = str(error).lower()
    return any(marker in message for marker in TRANSIENT_PROVIDER_MARKERS)


class SourceTextEdit(BaseModel):
    find: str = Field(
        min_length=1,
        description="Exact existing source text to replace; it must occur exactly once",
    )
    replace: str = Field(description="Replacement source text")


class SourceFilePatch(BaseModel):
    path: str = Field(description="Repository-relative browser-port source path")
    content: str | None = Field(
        default=None,
        description="Complete contents for a new file; omit for edits to existing files",
    )
    edits: list[SourceTextEdit] = Field(
        default_factory=list,
        max_length=24,
        description="Ordered exact replacements for an existing file",
    )


class BrowserSourcePatch(BaseModel):
    summary: str
    action: Literal["edit"] = "edit"
    files: list[SourceFilePatch] = Field(default_factory=list, max_length=12)


class ReadBrowserSource(BaseModel):
    path: str = Field(description="Repository-relative browser-port source path")
    start_line: int = Field(default=1, ge=1)
    end_line: int | None = Field(default=None, ge=1)


class SearchBrowserSource(BaseModel):
    query: str = Field(
        min_length=2,
        max_length=160,
        description="Literal source text to find in browser-port source files",
    )


class SourceLoopResult(BaseModel):
    passed: bool
    attempts: int
    action: Literal["edit", "exclude"] = "edit"
    files: list[str] = Field(default_factory=list)
    checkpoint: str | None = None
    error: str | None = None
    dry_run: bool = False
    summary: str | None = None


class UnslothOpenAIChatModel(OpenAIChatModel):
    """PydanticAI model profile for Unsloth's OpenAI-compatible stream.

    PydanticAI requests a trailing usage-only SSE chunk by default. Unsloth's
    llama.cpp passthrough can finish generation without producing that optional
    chunk, leaving the proxy waiting after ``finish_reason`` while the GPU is
    already idle. Do not request the optional trailer: Unsloth then emits the
    standard ``[DONE]`` sentinel immediately and PydanticAI owns the complete
    SSE lifecycle, tool execution, and continuation request.
    """

    def _get_stream_options(
        self,
        model_settings: OpenAIChatModelSettings,
    ) -> dict[str, bool]:
        del model_settings
        return {"include_usage": False}


def _direct_llama_server_endpoint(
    configured_endpoint: str,
    model_name: str,
) -> str:
    """Use Unsloth's loaded llama-server directly for local GGUF inference.

    Unsloth Studio's HTTP proxy has repeatedly retained a completed
    continuation response after llama.cpp released its slot. The child
    llama-server is itself the OpenAI-compatible provider and has the exact
    model alias on its command line, so route PydanticAI directly to that
    process. Non-local/custom providers retain their configured endpoint.
    """
    parsed = urlparse(configured_endpoint)
    if parsed.hostname not in {"127.0.0.1", "localhost", "::1"}:
        return configured_endpoint

    for process in psutil.process_iter(["name", "cmdline"], ad_value=[]):
        name = str(process.info.get("name") or "").lower()
        if name not in {"llama-server", "llama-server.exe"}:
            continue
        command = [str(part) for part in (process.info.get("cmdline") or [])]
        try:
            port = command[command.index("--port") + 1]
        except (ValueError, IndexError):
            continue
        try:
            alias = command[command.index("--alias") + 1]
        except (ValueError, IndexError):
            alias = ""
        if alias and model_name and alias != model_name:
            continue
        candidate = f"http://127.0.0.1:{int(port)}/v1"
        try:
            response = requests.get(f"{candidate}/models", timeout=2)
            response.raise_for_status()
            ids = {
                str(item.get("id"))
                for item in response.json().get("data", [])
                if isinstance(item, dict)
            }
        except (OSError, ValueError, requests.RequestException):
            continue
        if not model_name or model_name in ids or alias == model_name:
            return candidate
    return configured_endpoint


def _json_payload(raw: str) -> dict[str, Any]:
    candidate = raw.strip()
    fenced = re.search(r"```(?:json)?\s*(.*?)```", candidate, re.DOTALL | re.IGNORECASE)
    if fenced:
        candidate = fenced.group(1).strip()
    try:
        return json.loads(candidate)
    except json.JSONDecodeError:
        start = candidate.find("{")
        if start < 0:
            raise
        decoder = json.JSONDecoder()
        payload, _ = decoder.raw_decode(candidate[start:])
        return payload


def _extract_browser_source_patch(text: str) -> BrowserSourcePatch:
    """Lenient final-output parser: pull the LAST balanced JSON object from prose.

    The model prefixes prose despite instructions; a strict parse burned the
    request budget in validation retries while a complete valid patch sat in
    the text (challenge_menu_objects, 2026-08-07). Scans string-aware from
    the last plausible patch-object start.
    """
    candidate = text.strip()
    fenced = re.findall(r"```(?:json)?\s*(.*?)```", candidate, re.DOTALL | re.IGNORECASE)
    if fenced:
        candidate = fenced[-1].strip()
    starts = [
        match.start()
        for match in re.finditer(r'\{\s*"(?:summary|action|files)"', candidate)
    ]
    if not starts:
        starts = [candidate.find("{")] if "{" in candidate else []
    for start in reversed(starts):
        if start < 0:
            continue
        depth = 0
        in_string = False
        escaped = False
        for index in range(start, len(candidate)):
            char = candidate[index]
            if escaped:
                escaped = False
                continue
            if char == "\\":
                escaped = True
                continue
            if char == '"':
                in_string = not in_string
                continue
            if in_string:
                continue
            if char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    try:
                        payload = json.loads(candidate[start : index + 1])
                    except json.JSONDecodeError:
                        break
                    return BrowserSourcePatch.model_validate(payload)
    raise ValueError(
        "response contained no balanced JSON object matching the browser source "
        "patch schema; emit the complete patch as a single JSON object"
    )


def _safe_source_path(repo_root: Path, relative: str) -> Path:
    normalized = relative.replace("\\", "/").lstrip("/")
    if (
        not normalized.startswith(ALLOWED_SOURCE_ROOTS)
        or Path(normalized).suffix.lower() not in ALLOWED_SUFFIXES
        or ".." in Path(normalized).parts
    ):
        raise ValueError(f"Qwen attempted to edit a disallowed path: {relative}")
    target = (repo_root / normalized).resolve()
    if repo_root.resolve() not in target.parents:
        raise ValueError(f"Qwen source path escapes the repository: {relative}")
    return target


def _read_browser_source(repo_root: Path, request: ReadBrowserSource) -> str:
    target = _safe_source_path(repo_root, request.path)
    requested_path = request.path
    if not target.is_file():
        extension_fallbacks = {
            ".js": (".ts", ".tsx"),
            ".mjs": (".ts",),
            ".ts": (".js",),
            ".tsx": (".ts", ".js"),
        }
        for suffix in extension_fallbacks.get(target.suffix.lower(), ()):
            candidate = target.with_suffix(suffix)
            if candidate.is_file():
                target = candidate
                break
    if not target.is_file():
        raise ValueError(
            f"browser source file does not exist: {request.path}. "
            "Use search_browser_source to locate the current path."
        )
    lines = target.read_text(encoding="utf-8").splitlines()
    start = min(request.start_line, len(lines) + 1)
    requested_end = request.end_line if request.end_line is not None else len(lines)
    end = min(max(requested_end, start - 1), len(lines), start + SOURCE_READ_MAX_LINES - 1)
    content = "\n".join(lines[start - 1 : end])
    return json.dumps(
        {
            "requested_path": requested_path,
            "path": target.relative_to(repo_root).as_posix(),
            "total_lines": len(lines),
            "start_line": start,
            "end_line": end,
            "truncated": end < len(lines),
            "content": content,
        },
        ensure_ascii=False,
    )


def _search_browser_source(repo_root: Path, request: SearchBrowserSource) -> str:
    query = request.query.lower()
    results: list[dict[str, Any]] = []
    roots = (repo_root / "apps" / "game" / "src", repo_root / "packages", repo_root / "scripts")
    for root in roots:
        if not root.is_dir():
            continue
        for path in root.rglob("*"):
            if not path.is_file() or path.suffix.lower() not in ALLOWED_SUFFIXES:
                continue
            relative = path.relative_to(repo_root)
            if EXCLUDED_CONTEXT_DIRECTORIES.intersection(part.lower() for part in relative.parts):
                continue
            try:
                lines = path.read_text(encoding="utf-8").splitlines()
            except (OSError, UnicodeDecodeError):
                continue
            for line_number, line in enumerate(lines, start=1):
                if query not in line.lower():
                    continue
                results.append(
                    {
                        "path": relative.as_posix(),
                        "line": line_number,
                        "text": line[:500],
                    }
                )
                if len(results) >= SOURCE_SEARCH_RESULT_LIMIT:
                    return json.dumps(
                        {"query": request.query, "truncated": True, "results": results},
                        ensure_ascii=False,
                    )
    return json.dumps(
        {"query": request.query, "truncated": False, "results": results},
        ensure_ascii=False,
    )


def _restore_originals(originals: dict[Path, bytes | None]) -> None:
    for target, content in originals.items():
        if content is None:
            target.unlink(missing_ok=True)
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content)


def _next_attempt_number(checkpoint_root: Path) -> int:
    """Return an immutable attempt number across process and scheduler restarts."""
    highest = 0
    if checkpoint_root.is_dir():
        for path in checkpoint_root.iterdir():
            match = re.fullmatch(r"attempt-(\d+)", path.name)
            if match and path.is_dir():
                highest = max(highest, int(match.group(1)))
    return highest + 1


def _semantic_integration_check(repo_root: Path, touched: set[str]) -> tuple[bool, str]:
    """Reject package-only code that is merely exported but never used by live runtime code."""
    production_targets = [
        relative
        for relative in sorted(touched)
        if relative.startswith(("apps/game/src/", "packages/"))
        and not any(marker in relative.lower() for marker in (".test.", ".spec.", ".selfcheck."))
    ]
    if not production_targets:
        return False, "No production browser runtime source file was changed."

    source_paths: list[Path] = []
    for root in (repo_root / "apps" / "game" / "src", repo_root / "packages"):
        if not root.is_dir():
            continue
        for path in root.rglob("*"):
            relative = path.relative_to(repo_root).as_posix().lower()
            if (
                path.is_file()
                and path.suffix.lower() in {".ts", ".tsx"}
                and not EXCLUDED_CONTEXT_DIRECTORIES.intersection(Path(relative).parts)
                and not any(marker in relative for marker in (".test.", ".spec.", ".selfcheck."))
            ):
                source_paths.append(path)

    for relative in production_targets:
        if relative == "apps/game/src/main.ts":
            return True, f"{relative} is the browser runtime entry point."
        target = repo_root / relative
        if not target.is_file():
            continue
        try:
            text = target.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        symbols = set(EXPORTED_SYMBOL.findall(text))
        for candidate in source_paths:
            if candidate.resolve() == target.resolve():
                continue
            try:
                candidate_text = candidate.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue
            for line in candidate_text.splitlines():
                stripped = line.strip()
                if stripped.startswith(("export {", "export *", "import ", "//", "*")):
                    continue
                if any(re.search(rf"\b{re.escape(symbol)}\b", line) for symbol in symbols):
                    return True, (
                        f"{relative} has a live production use in "
                        f"{candidate.relative_to(repo_root).as_posix()}."
                    )
    return False, (
        "Package source changes are not reachable from live browser runtime code. "
        "A re-export or test-only reference does not count; wire the implemented behavior "
        "into an actual gameplay call site."
    )


def _specific_symbol_reachability_check(
    repo_root: Path,
    touched: set[str],
    required_symbols: list[str],
) -> tuple[bool, str]:
    """Require each declared unit entry symbol at an executable production use site."""
    symbols = [symbol for symbol in dict.fromkeys(required_symbols) if symbol]
    if not symbols:
        return True, "No unit-specific runtime symbols were declared."
    source_paths: list[Path] = []
    for root in (repo_root / "apps" / "game" / "src", repo_root / "packages"):
        if not root.is_dir():
            continue
        for path in root.rglob("*"):
            relative = path.relative_to(repo_root).as_posix().lower()
            if (
                path.is_file()
                and path.suffix.lower() in {".ts", ".tsx"}
                and not EXCLUDED_CONTEXT_DIRECTORIES.intersection(Path(relative).parts)
                and not any(
                    marker in relative
                    for marker in (".test.", ".spec.", ".selfcheck.")
                )
            ):
                source_paths.append(path)
    missing: list[str] = []
    locations: dict[str, str] = {}
    for symbol in symbols:
        pattern = re.compile(rf"\b{re.escape(symbol)}\b")
        found = False
        for path in source_paths:
            try:
                lines = path.read_text(encoding="utf-8").splitlines()
            except (OSError, UnicodeDecodeError):
                continue
            inside_import = False
            for line_number, line in enumerate(lines, start=1):
                stripped = line.strip()
                # Multi-line import blocks: symbol names on their own lines do
                # not start with "import ", and counting them as use sites let
                # a patch pass reachability with nothing but an import list
                # (challenge_menu_objects, 2026-08-07 -- false positive at
                # battleScene.ts:21-26).
                if inside_import:
                    if "from" in stripped or stripped.endswith((";", '";', "';")):
                        inside_import = False
                    continue
                if stripped.startswith("import ") and "from" not in stripped and not stripped.endswith(";"):
                    inside_import = True
                    continue
                if not pattern.search(line):
                    continue
                if not stripped or stripped.startswith(("//", "*", "/*", "import ")):
                    continue
                if re.match(
                    rf"^(?:export\s+)?(?:async\s+)?(?:function|class|const|let|var)\s+{re.escape(symbol)}\b",
                    stripped,
                ):
                    continue
                if stripped.startswith(("export {", "export *")):
                    continue
                found = True
                locations[symbol] = (
                    f"{path.relative_to(repo_root).as_posix()}:{line_number}"
                )
                break
            if found:
                break
        if not found:
            missing.append(symbol)
    if missing:
        return False, (
            "Declared runtime entry symbols are not reached by executable production code: "
            + ", ".join(missing)
        )
    return True, "Unit runtime entries reached: " + ", ".join(
        f"{symbol} at {locations[symbol]}" for symbol in symbols
    )


def _source_tokens(bundle: dict[str, Any]) -> set[str]:
    identity = bundle.get("identity", {})
    text = " ".join(
        (
            str(identity.get("name", "")),
            str(identity.get("prototype", "")),
            str(bundle.get("decompiler", {}).get("c", ""))[:12000],
            str(bundle.get("browser_search_hints", ""))[:6000],
        )
    )
    words = re.findall(r"[A-Za-z][A-Za-z0-9_]{2,}", text)
    expanded: set[str] = set()
    for word in words:
        expanded.add(word.lower())
        expanded.update(part.lower() for part in re.findall(r"[A-Z]?[a-z]+|[A-Z]+(?=[A-Z]|$)", word))
    ignored = {
        "undefined", "param", "return", "void", "float", "int", "char", "short",
        "else", "true", "false", "function", "actor", "this", "const",
    }
    return {word for word in expanded if len(word) >= 4 and word not in ignored}


def _source_excerpt(path: Path, tokens: set[str], max_chars: int) -> str:
    """Return bounded windows around actual lexical matches, not a giant file prefix."""
    text = path.read_text(encoding="utf-8")
    if len(text) <= max_chars:
        return text

    lines = text.splitlines()
    matches: list[tuple[int, int]] = []
    for index, line in enumerate(lines):
        lowered = line.lower()
        score = sum(token in lowered for token in tokens)
        if score:
            matches.append((score, index))
    matches.sort(key=lambda item: (-item[0], item[1]))

    if not matches:
        return text[:max_chars]

    half_window = max(SOURCE_CONTEXT_WINDOW_LINES // 2, 1)
    ranges: list[tuple[int, int]] = []
    for _, index in matches:
        start = max(0, index - half_window)
        end = min(len(lines), index + half_window)
        if any(start < existing_end and end > existing_start for existing_start, existing_end in ranges):
            continue
        ranges.append((start, end))

    excerpts: list[str] = []
    used = 0
    for start, end in sorted(ranges):
        header = f"// lines {start + 1}-{end}\n"
        body = "\n".join(lines[start:end])
        available = max_chars - used - len(header) - (1 if excerpts else 0)
        if available <= 0:
            break
        entry = header + body[:available]
        excerpts.append(entry)
        used += len(entry) + (1 if len(excerpts) > 1 else 0)
    return "\n".join(excerpts)


def _rank_source_context(
    repo_root: Path,
    bundle: dict[str, Any],
    limit: int = SOURCE_CONTEXT_FILE_LIMIT,
) -> list[Path]:
    tokens = _source_tokens(bundle)
    candidates: list[tuple[int, int, Path]] = []
    seen: set[Path] = set()
    roots = (repo_root / "apps" / "game" / "src", repo_root / "packages")
    for root in roots:
        if not root.is_dir():
            continue
        for path in root.rglob("*"):
            if not path.is_file() or path.suffix.lower() not in {".ts", ".tsx"}:
                continue
            if EXCLUDED_CONTEXT_DIRECTORIES.intersection(
                part.lower() for part in path.relative_to(repo_root).parts
            ):
                continue
            resolved = path.resolve()
            if resolved in seen:
                continue
            seen.add(resolved)
            try:
                text = path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue
            relative = path.relative_to(repo_root).as_posix().lower()
            lowered = text.lower()
            score = sum(8 if token in relative else min(lowered.count(token), 5) for token in tokens)
            if score:
                candidates.append((score, -len(text), path))
    candidates.sort(key=lambda item: (-item[0], -item[1], item[2].as_posix()))
    selected = [path for _, _, path in candidates[:limit]]
    fallbacks = (
        repo_root / "packages" / "combat" / "src" / "index.ts",
        repo_root / "apps" / "game" / "src" / "sim" / "battleScene.ts",
    )
    for path in fallbacks:
        if path.is_file() and path not in selected and len(selected) < limit:
            selected.append(path)
    return selected


def _bundle_for_prompt(bundle: dict[str, Any]) -> dict[str, Any]:
    def bounded_lines(values: Any, *, max_items: int, max_chars: int) -> list[Any]:
        if not isinstance(values, list):
            return []
        selected: list[Any] = []
        used = 0
        for value in values[:max_items]:
            size = len(str(value))
            if selected and used + size > max_chars:
                break
            selected.append(value)
            used += size
        return selected

    decompiler = bundle.get("decompiler")
    decompiler_summary = dict(decompiler) if isinstance(decompiler, dict) else {}
    if "c" in decompiler_summary:
        decompiler_summary["c"] = str(decompiler_summary.get("c") or "")[:12000]
    return {
        "identity": bundle.get("identity"),
        "decompiler": decompiler_summary,
        "calls": bundle.get("calls", []),
        "data_references": bundle.get("data_references", []),
        "normalized_disassembly": bounded_lines(
            bundle.get("normalized_disassembly"),
            max_items=500,
            max_chars=6000,
        ),
        "normalized_pcode": bounded_lines(
            bundle.get("normalized_pcode"),
            max_items=1200,
            max_chars=12000,
        ),
        "fingerprints": bundle.get("fingerprints", {}),
    }


def _run_command(repo_root: Path, command: tuple[str, ...]) -> tuple[bool, str]:
    executable = command[0]
    if executable == "pnpm" and os.name == "nt":
        executable = shutil.which("pnpm.cmd") or "pnpm.cmd"
    result = subprocess.run(
        [executable, *command[1:]],
        cwd=repo_root,
        capture_output=True,
        text=True,
        timeout=30 * 60,
    )
    output = f"$ {' '.join(command)}\n{result.stdout}\n{result.stderr}".strip()
    return result.returncode == 0, output[-30000:]


def _git_checkpoint(
    repo_root: Path,
    address: str,
    summary: str,
    files: list[str],
) -> str:
    def git(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["git", *args],
            cwd=repo_root,
            capture_output=True,
            text=True,
            check=check,
        )

    if not files:
        raise RuntimeError("refusing to create an empty source checkpoint")
    git("add", "--", *files)
    staged = git("diff", "--cached", "--quiet", "--", *files, check=False)
    if staged.returncode == 0:
        raise RuntimeError(
            "Qwen patch produced no source diff; refusing to mark the function integrated"
        )
    message = f"port: integrate {address} {summary}"[:200]
    git("commit", "--only", "-m", message, "--", *files)
    pushed = git("push", check=False)
    if pushed.returncode != 0:
        pushed = git("push", "-u", "origin", "HEAD", check=False)
    if pushed.returncode != 0:
        raise RuntimeError(f"git push failed:\n{pushed.stdout}\n{pushed.stderr}")
    return git("rev-parse", "HEAD").stdout.strip()


class SequentialSourcePortLoop:
    def __init__(
        self,
        *,
        repo_root: Path,
        run_root: Path,
        llm_factory: Callable[[], tuple[Any, str, str]],
        verify_runner: Callable[[Path, tuple[str, ...]], tuple[bool, str]] = _run_command,
        git_checkpointer: Callable[[Path, str, str, list[str]], str] = _git_checkpoint,
        integration_checker: Callable[[Path, set[str]], tuple[bool, str]] = (
            _semantic_integration_check
        ),
    ):
        self.repo_root = repo_root.resolve()
        self.run_root = run_root.resolve()
        self.llm_factory = llm_factory
        self.verify_runner = verify_runner
        self.git_checkpointer = git_checkpointer
        self.integration_checker = integration_checker
        self.activity = PortActivity(self.run_root / "activity.jsonl")
        self.adjacent_context_paths = self._load_adjacent_context_paths()
        # Unit-scoped workspace-gate state; run() reseeds these per unit.
        self._workspace_seen: set[str] = set()
        self._workspace_served = 0

    def _load_adjacent_context_paths(self) -> list[str]:
        passed_files = sorted(
            self.run_root.glob("source-checkpoints/*/attempt-*/passed.json"),
            key=lambda path: path.stat().st_mtime,
            reverse=True,
        )
        for passed_file in passed_files:
            try:
                payload = json.loads(passed_file.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            files = payload.get("files")
            if isinstance(files, list):
                return [
                    str(path)
                    for path in files
                    if isinstance(path, str)
                ][:ADJACENT_CONTEXT_FILE_LIMIT]
        return []

    def _required_source_context(self, relative_paths: set[str]) -> str:
        entries: list[str] = []
        for relative in sorted(relative_paths):
            try:
                target = _safe_source_path(self.repo_root, relative)
            except ValueError:
                continue
            if not target.is_file():
                entries.append(f"--- {relative} ---\n(file does not currently exist)")
                continue
            try:
                content = target.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError) as error:
                entries.append(f"--- {relative} ---\n(unreadable: {error})")
                continue
            entries.append(f"--- {relative} ---\n{content}")
        return "\n".join(entries)

    @staticmethod
    def _workspace_tools() -> list[dict[str, Any]]:
        return [
            {
                "type": "function",
                "function": {
                    "name": "read_browser_source",
                    "description": (
                        "Read the exact current contents of one allowed browser-port source file. "
                        "Use this before editing any file whose current text is not supplied."
                    ),
                    "parameters": ReadBrowserSource.model_json_schema(),
                    "strict": True,
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "search_browser_source",
                    "description": (
                        "Search allowed browser-port source files for literal text and return paths "
                        "and matching lines. Use this to locate definitions, imports, exports, and call sites."
                    ),
                    "parameters": SearchBrowserSource.model_json_schema(),
                    "strict": True,
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "submit_browser_source_patch",
                    "description": "Submit the final schema-valid browser source patch.",
                    "parameters": BrowserSourcePatch.model_json_schema(),
                    "strict": True,
                },
            },
        ]

    def _execute_workspace_tool(self, name: str, raw: str) -> str:
        payload = _json_payload(raw)
        if name == "read_browser_source":
            return _read_browser_source(
                self.repo_root,
                ReadBrowserSource.model_validate(payload),
            )
        if name == "search_browser_source":
            return _search_browser_source(
                self.repo_root,
                SearchBrowserSource.model_validate(payload),
            )
        raise ValueError(f"unsupported Qwen workspace tool: {name}")

    def _generate_with_workspace_tools(
        self,
        *,
        llm: Any,
        prompt: str,
        model_name: str,
        phase: str,
        system_prompt: str,
        stream_event: Callable[[str, dict[str, Any]], None],
    ) -> tuple[str, str, list[dict[str, str]]]:
        """Let Qwen inspect current source, then require one final patch submission."""
        if all(
            hasattr(llm, attribute)
            for attribute in ("base_url", "api_key", "default_model")
        ):
            return self._generate_with_pydantic_ai(
                llm=llm,
                prompt=prompt,
                model_name=model_name,
                system_prompt=system_prompt,
                stream_event=stream_event,
            )

        if not callable(getattr(llm, "generate", None)):
            raw, mode = llm.generate_structured(
                prompt=prompt,
                schema=BrowserSourcePatch.model_json_schema(),
                tool_name="submit_browser_source_patch",
                model=model_name,
                system_prompt=system_prompt,
                temperature=0.1,
                max_tokens=MODEL_MAX_OUTPUT_TOKENS,
                phase=phase,
                accept_plain_tool_response=True,
                stream_callback=stream_event,
            )
            return raw, mode, []

        transcript: list[dict[str, str]] = []
        tools = self._workspace_tools()
        messages: list[dict[str, Any]] = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": prompt},
        ]
        for tool_index in range(1, MAX_WORKSPACE_TOOL_CALLS + 1):
            raw = llm.generate(
                prompt=prompt,
                model=model_name,
                system_prompt=system_prompt,
                temperature=0.1,
                max_tokens=MODEL_MAX_OUTPUT_TOKENS,
                phase=f"{phase}:tool_{tool_index}",
                tools=tools,
                # `required` makes Unsloth's streamed tool parser withhold a
                # non-tool prefix indefinitely after inference has finished.
                # `auto` still exposes the native tools, while allowing this
                # client-side loop to receive prose/schema misses and correct
                # them in the same conversation below.
                tool_choice="auto",
                stream_callback=stream_event,
                messages=messages,
            )
            metadata = getattr(llm, "last_response_metadata", {})
            tool_name = metadata.get("tool_name") if isinstance(metadata, dict) else None
            if tool_name == "submit_browser_source_patch":
                return raw, "tool_call", transcript
            if tool_name in {"read_browser_source", "search_browser_source"}:
                tool_call = metadata.get("tool_call") or {
                    "id": f"call_workspace_{tool_index}",
                    "type": "function",
                    "function": {"name": tool_name, "arguments": raw},
                }
                assistant_message = metadata.get("assistant_message") or {
                    "role": "assistant",
                    "content": None,
                    "tool_calls": [tool_call],
                }
                self.activity.emit(
                    "tool",
                    f"Qwen workspace tool · {tool_name}",
                    raw,
                    status="running",
                )
                try:
                    result = self._execute_workspace_tool(tool_name, raw)
                    tool_status = "complete"
                except Exception as error:
                    result = json.dumps(
                        {
                            "error": f"{type(error).__name__}: {error}",
                            "recoverable": True,
                            "instruction": (
                                "Correct the arguments or use search_browser_source, "
                                "then continue this same task."
                            ),
                        },
                        ensure_ascii=False,
                    )
                    tool_status = "failed"
                transcript.append({"name": tool_name, "arguments": raw, "result": result})
                messages.extend(
                    [
                        assistant_message,
                        {
                            "role": "tool",
                            "tool_call_id": tool_call["id"],
                            "name": tool_name,
                            "content": result,
                        },
                    ]
                )
                self.activity.emit(
                    "tool",
                    f"Workspace result · {tool_name}",
                    result,
                    status=tool_status,
                )
                continue
            try:
                BrowserSourcePatch.model_validate(_json_payload(raw))
                return raw, "plain_json", transcript
            except Exception:
                messages.extend(
                    [
                        {"role": "assistant", "content": raw},
                        {
                            "role": "user",
                            "content": (
                                "That response did not call a valid workspace tool and did not "
                                "match the final patch schema. Continue this same task: inspect "
                                "source if needed, then call submit_browser_source_patch."
                            ),
                        },
                    ]
                )
                transcript.append(
                    {
                        "name": "invalid_response",
                        "arguments": raw,
                        "result": (
                            "No valid workspace tool was called. Inspect source if necessary, "
                            "then call submit_browser_source_patch."
                        ),
                    }
                )

        raise APIResponseError(
            f"Qwen exhausted {MAX_WORKSPACE_TOOL_CALLS} workspace turns "
            "without submitting a browser source patch"
        )

    def _generate_with_pydantic_ai(
        self,
        *,
        llm: Any,
        prompt: str,
        model_name: str,
        system_prompt: str,
        stream_event: Callable[[str, dict[str, Any]], None],
    ) -> tuple[str, str, list[dict[str, str]]]:
        """Run the source-edit transaction through PydanticAI's streamed agent."""
        endpoint = str(llm.base_url).rstrip("/")
        if endpoint.endswith("/chat/completions"):
            endpoint = endpoint[: -len("/chat/completions")]
        configured_endpoint = endpoint
        endpoint = _direct_llama_server_endpoint(endpoint, model_name or llm.default_model)
        direct_llama_server = endpoint != configured_endpoint

        # The direct llama.cpp endpoint implements the standard streamed
        # usage trailer, so keep PydanticAI's default include_usage=True.
        # Besides token accounting, PydanticAI uses that usage to enforce the
        # per-run request limit.  Only the Studio proxy needs the compatibility
        # model that omits the optional trailer it fails to forward reliably.
        model_type = OpenAIChatModel if direct_llama_server else UnslothOpenAIChatModel
        model = model_type(
            model_name or llm.default_model,
            provider=OpenAIProvider(
                openai_client=AsyncOpenAI(
                    base_url=endpoint,
                    api_key=llm.api_key or "not-needed",
                    # The scheduler owns provider retries. A completed model
                    # turn is delimited by the protocol, not by a guessed
                    # wall-clock or event-gap timeout.
                    timeout=None,
                    max_retries=0,
                ),
            ),
            profile=OpenAIModelProfile(
                openai_supports_strict_tool_definition=False,
                openai_chat_supports_multiple_system_messages=False,
                openai_chat_supports_max_completion_tokens=False,
            ),
        )
        transcript: list[dict[str, str]] = []
        # Observed live (challenge_flow_state_controller, 2026-08-07): the
        # model read the same two files in the same sequence three times over
        # -- 30 workspace calls, zero patch -- because accumulated 800-line
        # tool results overflow the serving context, earlier reads fall out,
        # and the model re-reads what it forgot until the request limit kills
        # the attempt. The tool layer is the only enforcement point the local
        # server can't ignore: refuse exact-duplicate calls and stop serving
        # reads past a hard budget, each refusal explicitly steering to
        # submit_browser_source_patch.
        workspace_call_budget = MAX_WORKSPACE_TOOL_CALLS * 4

        def _workspace_gate(call_key: str, kind: str) -> str | None:
            # State lives on self, seeded per UNIT in run(): repair attempts
            # restart the agent, and attempt-scoped state let the model re-run
            # its whole sweep every attempt.
            if call_key in self._workspace_seen:
                return json.dumps(
                    {
                        "error": f"duplicate {kind}: this exact request was already answered for this unit",
                        "recoverable": True,
                        "instruction": (
                            "The content was already provided. Do not re-read. "
                            "Call submit_browser_source_patch with the edits now."
                        ),
                    },
                    ensure_ascii=False,
                )
            if self._workspace_served >= workspace_call_budget:
                return json.dumps(
                    {
                        "error": f"workspace budget exhausted ({workspace_call_budget} calls served)",
                        "recoverable": False,
                        "instruction": (
                            "No further reads will be served. "
                            "Call submit_browser_source_patch with the edits now."
                        ),
                    },
                    ensure_ascii=False,
                )
            self._workspace_seen.add(call_key)
            self._workspace_served += 1
            return None

        def read_browser_source(
            path: str,
            start_line: int = 1,
            end_line: int | None = None,
        ) -> str:
            """Read an allowed browser-port source file before editing it."""
            arguments = ReadBrowserSource(
                path=path,
                start_line=start_line,
                end_line=end_line,
            )
            raw_arguments = arguments.model_dump_json()
            self.activity.emit(
                "tool",
                "Qwen workspace tool · read_browser_source",
                raw_arguments,
                status="running",
            )
            refusal = _workspace_gate(f"read:{path}:{start_line}:{end_line}", "read")
            if refusal is not None:
                transcript.append(
                    {
                        "name": "read_browser_source",
                        "arguments": raw_arguments,
                        "result": refusal,
                    }
                )
                self.activity.emit(
                    "tool",
                    "Workspace result · read_browser_source",
                    refusal,
                    status="failed",
                )
                return refusal
            try:
                result = _read_browser_source(self.repo_root, arguments)
            except Exception as error:
                result = json.dumps(
                    {
                        "error": f"{type(error).__name__}: {error}",
                        "recoverable": True,
                        "instruction": (
                            "Correct the path or call search_browser_source, then continue."
                        ),
                    },
                    ensure_ascii=False,
                )
                status = "failed"
            else:
                status = "complete"
            transcript.append(
                {
                    "name": "read_browser_source",
                    "arguments": raw_arguments,
                    "result": result,
                }
            )
            self.activity.emit(
                "tool",
                "Workspace result · read_browser_source",
                result,
                status=status,
            )
            return result

        def search_browser_source(query: str) -> str:
            """Search allowed browser-port source files for literal text."""
            arguments = SearchBrowserSource(query=query)
            raw_arguments = arguments.model_dump_json()
            self.activity.emit(
                "tool",
                "Qwen workspace tool · search_browser_source",
                raw_arguments,
                status="running",
            )
            refusal = _workspace_gate(f"search:{query}", "search")
            if refusal is not None:
                transcript.append(
                    {
                        "name": "search_browser_source",
                        "arguments": raw_arguments,
                        "result": refusal,
                    }
                )
                self.activity.emit(
                    "tool",
                    "Workspace result · search_browser_source",
                    refusal,
                    status="failed",
                )
                return refusal
            try:
                result = _search_browser_source(self.repo_root, arguments)
            except Exception as error:
                result = json.dumps(
                    {
                        "error": f"{type(error).__name__}: {error}",
                        "recoverable": True,
                        "instruction": "Correct the search query, then continue.",
                    },
                    ensure_ascii=False,
                )
                status = "failed"
            else:
                status = "complete"
            transcript.append(
                {
                    "name": "search_browser_source",
                    "arguments": raw_arguments,
                    "result": result,
                }
            )
            self.activity.emit(
                "tool",
                "Workspace result · search_browser_source",
                result,
                status=status,
            )
            return result

        agent = Agent(
            model,
            instructions=system_prompt,
            tools=[read_browser_source, search_browser_source],
            # TextOutput with a lenient extractor, not ToolOutput and not
            # strict PromptedOutput:
            # - the local server's tool-call JSON parser 500s on large patch
            #   arguments (observed hourly on challenge_menu_objects
            #   2026-08-07), so the patch must NOT travel as a tool call;
            # - the model prefixes prose despite instructions, and a strict
            #   parse burned the whole request budget in validation retries
            #   while a complete, valid patch sat in the stream. The
            #   extractor pulls the last balanced JSON object out of the
            #   text and validates it directly.
            # Workspace tools stay native; their arguments are tiny.
            output_type=TextOutput(_extract_browser_source_patch),
            retries={
                "tools": MAX_REPAIR_ATTEMPTS,
                "output": MAX_REPAIR_ATTEMPTS,
            },
            model_settings=OpenAIChatModelSettings(
                temperature=0.1,
                max_tokens=MODEL_MAX_OUTPUT_TOKENS,
                tool_choice="auto",
                parallel_tool_calls=False,
                extra_body={
                    **(
                        {}
                        if direct_llama_server
                        else {
                            # This is response-only normalization: it never
                            # executes a tool or generates a hidden
                            # continuation. PydanticAI owns validation,
                            # execution, retries, and every model request.
                            "auto_heal_tool_calls": True,
                            # Do not let the server issue a hidden retry behind
                            # the PydanticAI agent loop.
                            "nudge_tool_calls": False,
                        }
                    ),
                    **(
                        {"chat_template_kwargs": {"enable_thinking": False}}
                        if PORT_DISABLE_THINKING
                        else {}
                    ),
                },
            ),
        )

        async def run_agent() -> tuple[BrowserSourcePatch, Any]:
            async def handle_event(event: Any) -> None:
                if isinstance(event, PartStartEvent):
                    part = event.part
                    content = getattr(part, "content", None)
                    if isinstance(content, str) and content:
                        llm.observe_managed_generation(content)
                        stream_event(
                            "assistant_delta",
                            {
                                "text": content,
                                "channel": (
                                    "reasoning"
                                    if "Thinking" in type(part).__name__
                                    else "assistant"
                                ),
                            },
                        )
                    tool_name = getattr(part, "tool_name", None)
                    if isinstance(tool_name, str) and tool_name:
                        stream_event("tool_call_start", {"name": tool_name})
                elif isinstance(event, PartDeltaEvent):
                    delta = event.delta
                    if isinstance(delta, (TextPartDelta, ThinkingPartDelta)):
                        if delta.content_delta:
                            llm.observe_managed_generation(delta.content_delta)
                            stream_event(
                                "assistant_delta",
                                {
                                    "text": delta.content_delta,
                                    "channel": (
                                        "reasoning"
                                        if isinstance(delta, ThinkingPartDelta)
                                        else "assistant"
                                    ),
                                },
                            )
                    elif isinstance(delta, ToolCallPartDelta) and delta.args_delta:
                        raw_delta = (
                            delta.args_delta
                            if isinstance(delta.args_delta, str)
                            else json.dumps(delta.args_delta)
                        )
                        llm.observe_managed_generation(raw_delta)
                        stream_event(
                            "tool_call_delta",
                            {
                                "name": delta.tool_name_delta,
                                "text": raw_delta,
                            },
                        )
                elif isinstance(event, FunctionToolCallEvent):
                    stream_event(
                        "tool_call_start",
                        {"name": event.part.tool_name},
                    )
                elif isinstance(event, FunctionToolResultEvent):
                    self.activity.emit(
                        "tool",
                        f"PydanticAI tool completed · {event.part.tool_name}",
                        str(event.part.content),
                        status="complete",
                    )
                    llm.advance_managed_generation_request()

            # Drive PydanticAI's graph directly. This keeps model requests and
            # tool execution in one task and avoids the zero-buffer background
            # event bridge used by run_stream_events(), which can strand a
            # Python 3.13 run after delivering FunctionToolResultEvent.
            async with agent.iter(
                prompt,
                usage_limits=UsageLimits(
                    # One initial request, one continuation per workspace tool
                    # result, one FINAL request for the patch -- plus headroom:
                    # PydanticAI retries of malformed tool calls consume
                    # requests too, so the exact-fit budgets kept killing
                    # attempts AFTER paying full generation (request_limit=4
                    # rejected fun-80195d8c 2026-08-06; the +2 fix at 5 still
                    # rejected challenge_flow_state_controller 2026-08-07).
                    # The attempt loop already bounds total cost; a generous
                    # limit only pays for requests actually made.
                    request_limit=int(
                        os.getenv(
                            "OGHIDRA_PORT_REQUEST_LIMIT",
                            str(MAX_WORKSPACE_TOOL_CALLS * 2 + 4),
                        )
                    ),
                ),
            ) as agent_run:
                async for node in agent_run:
                    if Agent.is_model_request_node(node):
                        async with node.stream(agent_run.ctx) as request_stream:
                            async for event in request_stream:
                                await handle_event(event)
                    elif Agent.is_call_tools_node(node):
                        async with node.stream(agent_run.ctx) as tool_stream:
                            async for event in tool_stream:
                                await handle_event(event)

            if agent_run.result is None:
                raise APIResponseError(
                    "PydanticAI graph ended without a validated browser source patch"
                )
            return agent_run.result.output, agent_run.usage

        llm.begin_managed_generation(prompt)
        try:
            patch, usage = asyncio.run(run_agent())
        except (ModelAPIError, OpenAIAPIError, httpx.TransportError) as error:
            message = f"{type(error).__name__}: {error}"
            llm.end_managed_generation(error=message)
            raise APIResponseError(message) from error
        except Exception as error:
            llm.end_managed_generation(
                error=f"{type(error).__name__}: {error}",
            )
            raise
        llm.end_managed_generation(usage=usage)
        return patch.model_dump_json(), "pydantic_ai_tool", transcript

    @staticmethod
    def _load_previous_patch(checkpoint_root: Path) -> dict[str, Any] | None:
        """Seed the cross-run ratchet from the newest archived attempt.

        Prefers the newest validated patch.json; falls back to parsing the
        newest response.txt tolerantly (malformed edits dropped -- the result
        is advisory prompt context, never applied directly).
        """
        attempts = sorted(
            (d for d in checkpoint_root.glob("attempt-*") if d.is_dir()),
            key=lambda d: d.name,
            reverse=True,
        )
        for attempt_dir in attempts:
            patch_path = attempt_dir / "patch.json"
            if patch_path.is_file():
                try:
                    payload = json.loads(patch_path.read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError):
                    continue
                payload = {
                    key: value
                    for key, value in payload.items()
                    if key in {"summary", "action", "files"}
                }
                try:
                    return BrowserSourcePatch.model_validate(payload).model_dump(mode="json")
                except ValidationError:
                    continue
        for attempt_dir in attempts:
            response_path = attempt_dir / "response.txt"
            if not response_path.is_file():
                continue
            try:
                raw = response_path.read_text(encoding="utf-8")
                payload = _json_payload(raw)
            except (OSError, ValueError, json.JSONDecodeError):
                continue
            files = payload.get("files")
            if isinstance(files, list):
                for entry in files:
                    if isinstance(entry, dict) and isinstance(entry.get("edits"), list):
                        entry["edits"] = [
                            edit
                            for edit in entry["edits"]
                            if isinstance(edit, dict) and (edit.get("find") or "").strip()
                        ]
            try:
                return BrowserSourcePatch.model_validate(payload).model_dump(mode="json")
            except ValidationError:
                continue
        return None

    @staticmethod
    def _readable_prompt(
        address: str,
        aliases: list[str],
        bundle: dict[str, Any],
        *,
        attempt: int,
        failure: str | None,
        analysis_context: dict[str, Any] | None = None,
    ) -> str:
        identity = bundle.get("identity", {})
        decompiler = bundle.get("decompiler", {})
        decompiled = decompiler.get("c") or "(decompiler output unavailable)"
        calls = ", ".join(bundle.get("calls", [])) or "none"
        lines = [
            f"Function: {identity.get('name', address)} at {address}",
            f"Equivalent addresses: {', '.join(aliases)}",
            f"Direct calls: {calls}",
            f"Attempt: {attempt}/{MAX_REPAIR_ATTEMPTS}",
            "",
            "Decompiler evidence:",
            str(decompiled)[:6000],
        ]
        if analysis_context:
            lines.extend(
                [
                    "",
                    "Saved analysis, sibling functions, and research grounding:",
                    json.dumps(analysis_context, indent=2, default=str)[:12000],
                ]
            )
        if failure:
            lines.extend(["", "Previous automatic check failed:", failure[-6000:]])
        return "\n".join(lines)

    def _prompt(
        self,
        bundle: dict[str, Any],
        *,
        aliases: list[str],
        failure: str | None,
        attempt: int,
        analysis_context: dict[str, Any] | None = None,
        required_context_paths: set[str] | None = None,
        previous_patch: dict[str, Any] | None = None,
    ) -> str:
        research = (analysis_context or {}).get("research_corpus", {})
        ranking_bundle = {
            **bundle,
            # Saved-session analysis remains visible to Qwen as advisory evidence below,
            # but cannot steer deterministic browser-source retrieval.
            "browser_search_hints": " ".join(
                str(research.get(key, "")) for key in ("exact", "semantic")
            ),
        }
        required_paths = set(self.adjacent_context_paths)
        required_paths.update(required_context_paths or set())
        required_context = self._required_source_context(required_paths)
        required_targets: set[Path] = set()
        for required_path in required_paths:
            try:
                required_targets.add(_safe_source_path(self.repo_root, required_path))
            except ValueError:
                continue
        context_files = [
            path
            for path in _rank_source_context(self.repo_root, ranking_bundle)
            if path.resolve() not in required_targets
        ]
        context_tokens = _source_tokens(ranking_bundle)
        contexts = []
        context_chars = 0
        for path in context_files:
            header = f"--- {path.relative_to(self.repo_root).as_posix()} ---\n"
            separator_chars = 1 if contexts else 0
            available = (
                SOURCE_CONTEXT_TOTAL_CHAR_LIMIT
                - context_chars
                - separator_chars
                - len(header)
            )
            if available <= 0:
                break
            body = _source_excerpt(
                path,
                context_tokens,
                min(SOURCE_CONTEXT_FILE_CHAR_LIMIT, available),
            )
            entry = f"{header}{body}"
            contexts.append(entry)
            context_chars += separator_chars + len(entry)
        previous_patch_section = (
            "\nYour previous patch (JSON below). CORRECT THIS PATCH MINIMALLY to fix the"
            "\nreported failure -- keep the same files, structure, and naming; do not"
            "\nredesign or relocate the implementation. Return the COMPLETE corrected"
            "\npatch with the FULL files array (every file, including unchanged new-file"
            "\ncontent) -- a delta with only the changed parts is rejected:\n"
            + json.dumps(previous_patch, ensure_ascii=False)
            + "\n"
            if previous_patch
            else ""
        )
        repair = (
            "\nThe previous patch failed these automatic gates. Modify the actual source to fix every error:\n"
            f"{failure}\n" + previous_patch_section
            if failure
            else ""
        )
        session_analysis = (analysis_context or {}).get("saved_session_analysis")
        if isinstance(session_analysis, dict):
            session_analysis = {
                key: (
                    str(value)[:4000]
                    if key in {"behavior_summary", "summary", "rationale"}
                    else value
                )
                for key, value in session_analysis.items()
                if key
                in {
                    "address",
                    "old_name",
                    "new_name",
                    "behavior_summary",
                    "summary",
                    "rationale",
                    "ai_confidence",
                }
            }
        authoritative_context = {
            key: value
            for key, value in (analysis_context or {}).items()
            if key != "saved_session_analysis"
        }
        # Real extracted ROM data lives in *.generated.ts modules; the model
        # cannot import what it does not know exists (observed: a grounded
        # patch fabricated nothing but also found nothing, 2026-08-07), and
        # listing paths without export names made it GUESS names/modules
        # (invented ./styles.generated.js for the obj0 floats). List both.
        generated_lines: list[str] = []
        for root in (self.repo_root / "apps", self.repo_root / "packages"):
            if not root.is_dir():
                continue
            for module_path in sorted(root.rglob("*.generated.ts")):
                try:
                    exports = re.findall(
                        r"^export const (\w+)",
                        module_path.read_text(encoding="utf-8"),
                        re.MULTILINE,
                    )
                except (OSError, UnicodeDecodeError):
                    exports = []
                generated_lines.append(
                    f"{module_path.relative_to(self.repo_root).as_posix()}"
                    f" -- exports: {', '.join(exports) or '(none)'}"
                )
        generated_modules = "\n".join(generated_lines) or "(none)"
        return f"""Implement this original GameCube function 1:1 in the existing GotYaForce browser game.

Product result:
- Implement observable gameplay behavior in the real browser runtime, not an isolated report or dead candidate.
- Preserve exact control flow, constants, comparisons, field effects, helper calls, and timing supported by evidence.
- Modify the existing ownership/integration point so the behavior is reachable during normal play.
- Preserve unrelated behavior and the repository's current TypeScript architecture.
- Add or update automatic tests when the supplied source shows an appropriate test surface.

Patch protocol:
- PREFERRED SHAPE: put the new implementation in a NEW file next to the integration
  target (complete content), then wire it into the existing file with ONE OR TWO tiny
  find/replace edits (an import plus a delegation call). Do not rewrite existing files.
- For an existing file, return ordered exact find/replace edits. Each find string must occur exactly once.
- Copy every find string BYTE-EXACT from read_browser_source output (same whitespace,
  same line breaks). A find string composed from memory matches 0 times and fails.
- Use complete content only when creating a new file.
- Keep edits minimal; do not reproduce an entire existing file. Full content for an
  existing file is REJECTED automatically: you cannot reproduce it faithfully and the
  validator protects the parts you did not see.
- Return action="edit" with at least one file and wire it into the existing runtime.
- REACHABILITY GATE (exact contract): every runtime_entry_symbol must appear VERBATIM at
  a production USE site -- a call (`spawn_challenge_menu_object_set(ctx)`) or a runtime
  dispatch-map registration (`{{ spawn_challenge_menu_object_set, ... }}`) in an existing
  gameplay file OTHER than where it is declared. Declarations, imports, alias exports,
  and `export {{}}` re-exports are all IGNORED by the checker. A new wrapper function that
  merely re-exposes the symbol does NOT count: the call must sit inside a code path the
  game already executes (an existing update loop, VM mode handler, or dispatcher table
  that existing code iterates). Wire each entry symbol into the real update/dispatch path
  of the scene or VM that owns this behavior.
- TypeScript conformance (typecheck gate is strict): prefix intentionally-unused
  parameters and locals with an underscore (`_param10`); declare any local you reassign
  with `let`, never `const`; reference only globals and constants that already exist in
  current source or in the generated ROM-table modules listed below.
- The scheduler already removed proven platform/runtime functions; do not exclude this unit.
- Do not emit placeholders, TODOs, fallbacks, documentation, shell commands, or generated reports.
- NEVER fabricate ROM data. Zero-filled arrays, null function-pointer tables, or guessed
  constants standing in for DAT_*/PTR_FUN_*/FLOAT_* contents are stub code and fail review.
  Real table contents are extracted into *.generated.ts modules (search for "generated" or
  the table address, e.g. challengeFlowTables.generated); import from those. If a table you
  need has no generated module, state the missing address in the patch summary and port only
  the functions whose data is available.
Available generated ROM-table modules (real extracted DOL data -- import from these
using EXACTLY the export names listed; generated files are READ-ONLY and any patch
touching a *.generated.ts file is rejected):
{generated_modules}
This exact body also represents these original addresses: {aliases}
Repair attempt: {attempt}/{MAX_REPAIR_ATTEMPTS}
{repair}
Authoritative Ghidra bundle:
{json.dumps(_bundle_for_prompt(bundle), indent=2)}

Fresh sibling decompiles, Ghidra tool evidence, and research leads:
{json.dumps(authoritative_context, indent=2, default=str)}

Advisory saved-session analysis:
This can suggest names or intent, but it may be stale or wrong. Resolve conflicts in favor of fresh
Ghidra evidence and current browser source.
{json.dumps(session_analysis, indent=2, default=str)}

Required current browser source:
These are complete current files from the previous adjacent integration or a failed/touched target.
Do not guess their contents.
{required_context or "(none)"}

Relevant current browser source excerpts:
Line windows are selected around matches. Use exact find/replace edits so unseen portions remain intact.
{chr(10).join(contexts)}
"""

    def run(
        self,
        *,
        address: str,
        aliases: list[str],
        bundle: dict[str, Any],
        analysis_context: dict[str, Any] | None = None,
        required_context_paths: set[str] | None = None,
        required_runtime_symbols: list[str] | None = None,
        dry_run: bool = False,
    ) -> SourceLoopResult:
        checkpoint_root = self.run_root / "source-checkpoints" / address.removeprefix("0x")
        checkpoint_root.mkdir(parents=True, exist_ok=True)
        # Unit-scoped, NOT attempt-scoped: repair attempts restart the agent,
        # and with per-attempt state the model re-ran its whole read/search
        # sweep every attempt (observed 3x on challenge_flow_state_controller,
        # cross-attempt duplicates sailing through a fresh dedup set).
        self._workspace_seen: set[str] = set()
        self._workspace_served = 0
        originals: dict[Path, bytes | None] = {}
        original_manifest: dict[str, dict[str, Any]] = {}
        failure: str | None = None
        touched: set[str] = set()
        attempted_paths: set[str] = set()
        # Ratchet: repair attempts correct the PREVIOUS patch instead of
        # regenerating from scratch. Without this, a near-passing attempt
        # (applied + one gate from green) was discarded and the next attempt
        # rolled new dice on file placement, wiring, and aliases -- observed
        # repeatedly on challenge_menu_objects 2026-08-07. Seeded from the
        # newest on-disk attempt so the ratchet survives the driver's
        # one-run-per-process design (a per-run ratchet only helps within a
        # single 3-attempt cycle and loses everything on relaunch).
        previous_patch: dict[str, Any] | None = self._load_previous_patch(checkpoint_root)

        first_checkpoint_attempt = _next_attempt_number(checkpoint_root)
        for attempt in range(1, MAX_REPAIR_ATTEMPTS + 1):
            checkpoint_attempt = first_checkpoint_attempt + attempt - 1
            attempt_root = checkpoint_root / f"attempt-{checkpoint_attempt:02d}"
            attempt_root.mkdir(parents=True, exist_ok=True)
            prompt = self._prompt(
                bundle,
                aliases=aliases,
                failure=failure,
                attempt=attempt,
                analysis_context=analysis_context,
                required_context_paths={
                    *attempted_paths,
                    *(required_context_paths or set()),
                },
                previous_patch=previous_patch,
            )
            (attempt_root / "prompt.txt").write_text(prompt, encoding="utf-8")
            self.activity.emit(
                "prompt",
                f"Port request · {address}",
                self._readable_prompt(
                    address,
                    aliases,
                    bundle,
                    attempt=attempt,
                    failure=failure,
                    analysis_context=analysis_context,
                ),
                address=address,
                status="sent",
            )
            self.activity.emit(
                "tool",
                "Structured response requested",
                "Qwen must inspect current source as needed, then call "
                "submit_browser_source_patch with minimal exact source edits.",
                address=address,
                status="running",
            )
            llm, provider, model_name = self.llm_factory()
            streamed = False

            def stream_event(event_type: str, payload: dict[str, Any]) -> None:
                nonlocal streamed
                text = str(payload.get("text") or "")
                if event_type in {"assistant_delta", "tool_call_delta"} and text:
                    streamed = True
                    self.activity.emit(
                        "assistant_delta" if event_type == "assistant_delta" else "tool_delta",
                        "Qwen" if event_type == "assistant_delta" else "Tool arguments",
                        text,
                        address=address,
                        status="streaming",
                    )
                elif event_type == "tool_call_start":
                    self.activity.emit(
                        "tool",
                        f"Qwen tool call started · {payload.get('name') or 'tool'}",
                        "",
                        address=address,
                        status="running",
                    )

            try:
                system_prompt = (
                    "You are the implementation engine for a 1:1 browser port. "
                    "The scheduler has already removed proven platform/runtime-only functions. "
                    "Use fresh Ghidra evidence as authority, saved-session analysis as advisory context, "
                    "and inspect current browser source with the bounded workspace tools before guessing. "
                    "Return minimal exact find/replace edits that make the behavior reachable in the "
                    "real browser runtime. You may not exclude the assigned unit. "
                    "Do not narrate a plan or analysis: every response must immediately call exactly one "
                    "workspace tool, ending with submit_browser_source_patch."
                    + (" /no_think" if PORT_DISABLE_THINKING else "")
                )
                try:
                    raw, structured_mode, workspace_trace = self._generate_with_workspace_tools(
                        llm=llm,
                        prompt=prompt,
                        model_name=model_name,
                        phase=f"finish_game_source:{address}:attempt_{attempt}",
                        system_prompt=system_prompt,
                        stream_event=stream_event,
                    )
                except Exception as agent_error:
                    # Composition fallback: when the agent explores itself to
                    # death (request limit), the model demonstrably retries
                    # refused reads instead of composing -- 72 gate refusals
                    # in one run. One final TOOLLESS structured request, the
                    # exact call shape the (working) analysis phase uses,
                    # turns every exhausted attempt into a composition shot:
                    # with no tools attached, emitting the patch is the only
                    # possible action.
                    if "request_limit" not in str(agent_error):
                        raise
                    self.activity.emit(
                        "tool",
                        "Composition fallback",
                        "Agent request budget exhausted; issuing one toolless "
                        "structured request for the final patch.",
                        address=address,
                        status="running",
                    )
                    raw, structured_mode = llm.generate_structured(
                        prompt=(
                            prompt
                            + "\n\nWorkspace tools are NO LONGER AVAILABLE. Using only the "
                            "evidence above, emit the complete browser source patch as a "
                            "single JSON object now. No prose."
                        ),
                        schema=BrowserSourcePatch.model_json_schema(),
                        tool_name="submit_browser_source_patch",
                        model=model_name,
                        system_prompt=system_prompt,
                        temperature=0.1,
                        max_tokens=MODEL_MAX_OUTPUT_TOKENS,
                        phase=f"finish_game_source:{address}:attempt_{attempt}:compose",
                        accept_plain_tool_response=True,
                        stream_callback=stream_event,
                        # The server's launch default enables thinking; without
                        # this the compose request burned its whole budget on
                        # reasoning and returned zero content.
                        chat_template_kwargs=(
                            {"enable_thinking": False} if PORT_DISABLE_THINKING else None
                        ),
                    )
                    workspace_trace = []
                (attempt_root / "response.txt").write_text(raw, encoding="utf-8")
                if workspace_trace:
                    atomic_write_json(
                        attempt_root / "workspace-tools.json",
                        {"calls": workspace_trace},
                    )
                if not streamed:
                    self.activity.emit(
                        "assistant",
                        "Qwen response",
                        raw,
                        address=address,
                        status="complete",
                    )
                try:
                    patch = BrowserSourcePatch.model_validate(_json_payload(raw))
                except (ValueError, ValidationError):
                    patch = _extract_browser_source_patch(raw)
                previous_patch = patch.model_dump(mode="json")
                attempted_paths.update(file.path for file in patch.files)
                atomic_write_json(
                    attempt_root / "patch.json",
                    {
                        "provider": provider,
                        "model": model_name,
                        "structured_mode": structured_mode,
                        **patch.model_dump(mode="json"),
                    },
                )
                self.activity.emit(
                    "tool",
                    f"Tool completed · {patch.action}",
                    patch.summary
                    + (
                        "\nFiles: " + ", ".join(file.path for file in patch.files)
                        if patch.files
                        else ""
                    ),
                    address=address,
                    status="complete",
                    metadata={"mode": structured_mode},
                )
                if dry_run:
                    self.activity.emit(
                        "result",
                        f"Prompt probe completed · {address}",
                        "Structured response validated; no source files were changed.",
                        address=address,
                        status="passed",
                    )
                    return SourceLoopResult(
                        passed=True,
                        attempts=attempt,
                        action=patch.action,
                        files=[file.path for file in patch.files],
                        dry_run=True,
                        summary=patch.summary,
                    )
                if not patch.files:
                    raise ValueError("Qwen selected action=edit without returning source files")
                for file_patch in patch.files:
                    target = _safe_source_path(self.repo_root, file_patch.path)
                    if file_patch.path.endswith(".generated.ts"):
                        raise ValueError(
                            f"{file_patch.path} is generator-owned (scripts/gen-*.mjs); "
                            "import from it instead of patching it"
                        )
                    if (file_patch.content is None) == (not file_patch.edits):
                        raise ValueError(
                            f"{file_patch.path} must provide either new-file content or existing-file edits"
                        )
                    if file_patch.edits and not target.is_file():
                        raise ValueError(
                            f"Qwen attempted exact edits on a file that does not exist: {file_patch.path}"
                        )
                    if file_patch.content is not None and target.is_file():
                        raise ValueError(
                            f"Qwen attempted complete replacement of existing file: {file_patch.path}"
                        )
                    if target not in originals:
                        original = target.read_bytes() if target.is_file() else None
                        originals[target] = original
                        relative = target.relative_to(self.repo_root).as_posix()
                        backup = checkpoint_root / "original-source" / relative
                        if original is not None:
                            backup.parent.mkdir(parents=True, exist_ok=True)
                            backup.write_bytes(original)
                        original_manifest[relative] = {
                            "existed": original is not None,
                            "backup": str(backup) if original is not None else None,
                        }
                        atomic_write_json(
                            checkpoint_root / "original-source.json",
                            {"files": original_manifest},
                        )
                    if file_patch.edits:
                        updated = target.read_text(encoding="utf-8")
                        for edit in file_patch.edits:
                            occurrences = updated.count(edit.find)
                            if occurrences == 1:
                                updated = updated.replace(edit.find, edit.replace, 1)
                                continue
                            if occurrences == 0:
                                # Whitespace-tolerant fallback: the compose
                                # phase writes anchors from memory (tools are
                                # closed), and indentation/whitespace drift is
                                # the dominant mismatch. Only a UNIQUE
                                # normalized match is spliced; git checkpoints
                                # and every gate still stand behind this.
                                pattern = re.compile(
                                    r"\s+".join(
                                        re.escape(part)
                                        for part in edit.find.split()
                                    )
                                )
                                matches = list(pattern.finditer(updated))
                                if len(matches) == 1:
                                    span = matches[0]
                                    updated = (
                                        updated[: span.start()]
                                        + edit.replace
                                        + updated[span.end() :]
                                    )
                                    continue
                            raise ValueError(
                                f"exact edit in {file_patch.path} matched {occurrences} times; expected 1"
                            )
                    else:
                        updated = file_patch.content or ""
                    target.parent.mkdir(parents=True, exist_ok=True)
                    fd, temporary = tempfile.mkstemp(prefix=f".{target.name}.", dir=target.parent)
                    try:
                        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
                            handle.write(updated)
                            if updated and not updated.endswith("\n"):
                                handle.write("\n")
                        os.replace(temporary, target)
                    except Exception:
                        Path(temporary).unlink(missing_ok=True)
                        raise
                    touched.add(target.relative_to(self.repo_root).as_posix())

                semantic_passed, semantic_output = self.integration_checker(
                    self.repo_root,
                    touched,
                )
                if semantic_passed and required_runtime_symbols:
                    semantic_passed, semantic_output = _specific_symbol_reachability_check(
                        self.repo_root,
                        touched,
                        required_runtime_symbols,
                    )
                gate_outputs = [f"$ semantic-integration\n{semantic_output}"]
                passed = semantic_passed
                self.activity.emit(
                    "gate",
                    f"{'Passed' if semantic_passed else 'Failed'} · semantic integration",
                    "" if semantic_passed else semantic_output,
                    address=address,
                    status="passed" if semantic_passed else "failed",
                )
                gate_commands = VERIFY_COMMANDS + (
                    COMBAT_AUDIT_COMMANDS
                    if any(path.startswith("packages/combat/") for path in touched)
                    else ()
                )
                for command in gate_commands:
                    if not passed:
                        break
                    command_text = " ".join(command)
                    self.activity.emit(
                        "gate",
                        f"Running · {command_text}",
                        "",
                        address=address,
                        status="running",
                    )
                    gate_passed, output = self.verify_runner(self.repo_root, command)
                    gate_outputs.append(output)
                    self.activity.emit(
                        "gate",
                        f"{'Passed' if gate_passed else 'Failed'} · {command_text}",
                        output[-6000:] if not gate_passed else "",
                        address=address,
                        status="passed" if gate_passed else "failed",
                    )
                    if not gate_passed:
                        passed = False
                        break
                failure = "\n\n".join(gate_outputs)
                (attempt_root / "verification.txt").write_text(failure, encoding="utf-8")
                if not passed:
                    _restore_originals(originals)
                    touched.clear()
                    self.activity.emit(
                        "retry",
                        f"Repair requested · attempt {attempt + 1}",
                        failure[-6000:],
                        address=address,
                        status="failed",
                    )
                    continue

                self.activity.emit(
                    "git",
                    "Git checkpoint · add, commit, push",
                    patch.summary,
                    address=address,
                    status="running",
                )
                commit = self.git_checkpointer(
                    self.repo_root,
                    address,
                    patch.summary,
                    sorted(touched),
                )
                self.activity.emit(
                    "git",
                    f"Pushed · {commit[:12]}",
                    ", ".join(sorted(touched)),
                    address=address,
                    status="passed",
                )
                atomic_write_json(
                    attempt_root / "passed.json",
                    {"commit": commit, "files": sorted(touched), "summary": patch.summary},
                )
                self.adjacent_context_paths = sorted(touched)[:ADJACENT_CONTEXT_FILE_LIMIT]
                return SourceLoopResult(
                    passed=True,
                    attempts=attempt,
                    action="edit",
                    files=sorted(touched),
                    checkpoint=commit,
                    summary=patch.summary,
                )
            except APIResponseError as error:
                _restore_originals(originals)
                touched.clear()
                failure = f"{type(error).__name__}: {error}"
                (attempt_root / "error.txt").write_text(failure, encoding="utf-8")
                self.activity.emit(
                    "error",
                    "Model response failed",
                    failure,
                    address=address,
                    status="failed",
                )
                return SourceLoopResult(
                    passed=False,
                    attempts=attempt,
                    action="edit",
                    files=[],
                    error=failure,
                )
            except Exception as error:
                _restore_originals(originals)
                touched.clear()
                failure = f"{type(error).__name__}: {error}"
                (attempt_root / "error.txt").write_text(failure, encoding="utf-8")
                self.activity.emit(
                    "error",
                    f"Attempt {attempt} failed",
                    failure,
                    address=address,
                    status="failed",
                )
                if is_provider_unavailable(error):
                    return SourceLoopResult(
                        passed=False,
                        attempts=attempt,
                        action="edit",
                        files=[],
                        error=failure,
                    )

        _restore_originals(originals)
        return SourceLoopResult(
            passed=False,
            attempts=MAX_REPAIR_ATTEMPTS,
            action="edit",
            files=sorted(touched),
            error=failure or "source repair attempts exhausted",
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run one live Qwen source-edit port proof")
    parser.add_argument("--address", required=True)
    args = parser.parse_args(argv)

    from src.config import get_config
    from src.port_cli import _llm_for_config
    from src.port_run_controller import find_gotyaforce_root

    config = get_config()
    base_url = str(config.ghidra.base_url).rstrip("/")
    response = requests.get(
        f"{base_url}/function_bundle",
        params={"address": args.address},
        timeout=120,
    )
    response.raise_for_status()
    bundle = response.json()
    if bundle.get("error"):
        raise RuntimeError(bundle["error"])
    repo_root = find_gotyaforce_root()
    run_root = repo_root / "research" / "decomp" / "generated" / "finish-game-port"
    os.environ["OGHIDRA_PORT_LIVENESS_PATH"] = str(run_root / "llm-liveness.json")
    os.environ["OGHIDRA_PORT_RUN_ID"] = f"source-poc:{args.address.lower()}"
    result = SequentialSourcePortLoop(
        repo_root=repo_root,
        run_root=run_root,
        llm_factory=lambda: _llm_for_config(config),
    ).run(address=args.address.lower(), aliases=[args.address.lower()], bundle=bundle)
    print(result.model_dump_json(indent=2))
    return 0 if result.passed else 3


if __name__ == "__main__":
    raise SystemExit(main())
