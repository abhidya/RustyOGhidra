"""Single-threaded Qwen source-edit, verify, retry, and Git checkpoint loop."""

from __future__ import annotations

import argparse
import inspect
import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Callable, Literal

from pydantic import BaseModel, Field
import requests

from src.port_workflow import atomic_write_json
from src.port_activity import PortActivity


MODEL_MAX_OUTPUT_TOKENS = int(os.getenv("OGHIDRA_PORT_MAX_TOKENS", "131072"))
MAX_REPAIR_ATTEMPTS = int(os.getenv("OGHIDRA_PORT_REPAIR_ATTEMPTS", "8"))
ALLOWED_SOURCE_ROOTS = ("apps/game/", "packages/", "scripts/")
ALLOWED_SUFFIXES = {".ts", ".tsx", ".js", ".mjs", ".json"}
VERIFY_COMMANDS = (
    ("pnpm", "typecheck"),
    ("pnpm", "--filter", "@gf/combat", "build"),
    ("pnpm", "selfcheck:rom"),
    ("pnpm", "selfcheck:game-session"),
    ("pnpm", "--filter", "game", "build"),
    ("pnpm", "smoke:browser"),
)


class SourceFilePatch(BaseModel):
    path: str = Field(description="Repository-relative browser-port source path")
    content: str = Field(description="Complete replacement contents for the file")


class BrowserSourcePatch(BaseModel):
    summary: str
    action: Literal["edit", "exclude"] = "edit"
    files: list[SourceFilePatch] = Field(default_factory=list, max_length=24)


class SourceLoopResult(BaseModel):
    passed: bool
    attempts: int
    action: Literal["edit", "exclude"] = "edit"
    files: list[str] = Field(default_factory=list)
    checkpoint: str | None = None
    error: str | None = None


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


def _source_tokens(bundle: dict[str, Any]) -> set[str]:
    identity = bundle.get("identity", {})
    text = " ".join(
        (
            str(identity.get("name", "")),
            str(identity.get("prototype", "")),
            str(bundle.get("decompiler", {}).get("c", ""))[:12000],
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


def _rank_source_context(repo_root: Path, bundle: dict[str, Any], limit: int = 8) -> list[Path]:
    tokens = _source_tokens(bundle)
    candidates: list[tuple[int, int, Path]] = []
    roots = (repo_root / "apps" / "game" / "src", repo_root / "packages")
    for root in roots:
        if not root.is_dir():
            continue
        for path in root.rglob("*"):
            if not path.is_file() or path.suffix.lower() not in {".ts", ".tsx"}:
                continue
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
    return {
        "identity": bundle.get("identity"),
        "decompiler": bundle.get("decompiler"),
        "calls": bundle.get("calls", []),
        "data_references": bundle.get("data_references", []),
        "normalized_disassembly": bundle.get("normalized_disassembly", [])[:500],
        "normalized_pcode": bundle.get("normalized_pcode", [])[:1200],
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


def _git_checkpoint(repo_root: Path, address: str, summary: str) -> str:
    def git(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["git", *args],
            cwd=repo_root,
            capture_output=True,
            text=True,
            check=check,
        )

    git("add", "-A")
    staged = git("diff", "--cached", "--quiet", check=False)
    if staged.returncode != 0:
        message = f"port: integrate {address} {summary}"[:200]
        git("commit", "-m", message)
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
        git_checkpointer: Callable[[Path, str, str], str] = _git_checkpoint,
    ):
        self.repo_root = repo_root.resolve()
        self.run_root = run_root.resolve()
        self.llm_factory = llm_factory
        self.verify_runner = verify_runner
        self.git_checkpointer = git_checkpointer
        self.activity = PortActivity(self.run_root / "activity.jsonl")

    @staticmethod
    def _readable_prompt(
        address: str,
        aliases: list[str],
        bundle: dict[str, Any],
        *,
        attempt: int,
        failure: str | None,
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
    ) -> str:
        context_files = _rank_source_context(self.repo_root, bundle)
        contexts = []
        for path in context_files:
            content = path.read_text(encoding="utf-8")
            contexts.append(
                f"--- {path.relative_to(self.repo_root).as_posix()} ---\n{content[:60000]}"
            )
        repair = (
            "\nThe previous patch failed these automatic gates. Modify the actual source to fix every error:\n"
            f"{failure}\n"
            if failure
            else ""
        )
        return f"""Port this original GameCube function into the existing GotYaForce browser game.

This is source implementation, not a report. Return complete source-file contents.
Modify existing gameplay integration points so the behavior is reachable in the running browser game.
Add or update automatic tests in the returned files when needed.
Use action="exclude" with no files only for platform/toolchain code that has no browser-game behavior.
For action="edit", return at least one complete file and wire it into the existing runtime.
Do not emit placeholders, TODOs, fallbacks, documentation, shell commands, or generated reports.
Preserve unrelated behavior and follow the repository's existing TypeScript architecture.
This exact body also represents these original addresses: {aliases}
Repair attempt: {attempt}/{MAX_REPAIR_ATTEMPTS}
{repair}
Authoritative Ghidra bundle:
{json.dumps(_bundle_for_prompt(bundle), indent=2)}

Relevant current browser source:
{chr(10).join(contexts)}
"""

    def run(self, *, address: str, aliases: list[str], bundle: dict[str, Any]) -> SourceLoopResult:
        checkpoint_root = self.run_root / "source-checkpoints" / address.removeprefix("0x")
        checkpoint_root.mkdir(parents=True, exist_ok=True)
        originals: dict[Path, bytes | None] = {}
        original_manifest: dict[str, dict[str, Any]] = {}
        failure: str | None = None
        touched: set[str] = set()

        for attempt in range(1, MAX_REPAIR_ATTEMPTS + 1):
            attempt_root = checkpoint_root / f"attempt-{attempt:02d}"
            attempt_root.mkdir(parents=True, exist_ok=True)
            prompt = self._prompt(bundle, aliases=aliases, failure=failure, attempt=attempt)
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
                ),
                address=address,
                status="sent",
            )
            self.activity.emit(
                "tool",
                "Structured response requested",
                "Qwen must call submit_browser_source_patch with either a complete source edit "
                "or an explicit non-browser exclusion.",
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
                generation_arguments = {
                    "prompt": prompt,
                    "schema": BrowserSourcePatch.model_json_schema(),
                    "tool_name": "submit_browser_source_patch",
                    "model": model_name,
                    "system_prompt": (
                        "You are the implementation engine for a 1:1 browser port. "
                        "Use the supplied Ghidra evidence and edit the real repository source."
                    ),
                    "temperature": 0.1,
                    "max_tokens": MODEL_MAX_OUTPUT_TOKENS,
                    "phase": f"finish_game_source:{address}:attempt_{attempt}",
                    "accept_plain_tool_response": True,
                }
                if "stream_callback" in inspect.signature(llm.generate_structured).parameters:
                    generation_arguments["stream_callback"] = stream_event
                raw, structured_mode = llm.generate_structured(
                    **generation_arguments,
                )
                (attempt_root / "response.txt").write_text(raw, encoding="utf-8")
                if not streamed:
                    self.activity.emit(
                        "assistant",
                        "Qwen response",
                        raw,
                        address=address,
                        status="complete",
                    )
                patch = BrowserSourcePatch.model_validate(_json_payload(raw))
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
                if patch.action == "exclude":
                    self.activity.emit(
                        "result",
                        f"Excluded · {address}",
                        "Qwen classified this as platform/toolchain code outside the browser runtime.",
                        address=address,
                        status="passed",
                    )
                    return SourceLoopResult(
                        passed=True,
                        attempts=attempt,
                        action="exclude",
                        files=[],
                    )
                if not patch.files:
                    raise ValueError("Qwen selected action=edit without returning source files")
                for file_patch in patch.files:
                    target = _safe_source_path(self.repo_root, file_patch.path)
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
                    target.parent.mkdir(parents=True, exist_ok=True)
                    fd, temporary = tempfile.mkstemp(prefix=f".{target.name}.", dir=target.parent)
                    try:
                        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
                            handle.write(file_patch.content)
                            if file_patch.content and not file_patch.content.endswith("\n"):
                                handle.write("\n")
                        os.replace(temporary, target)
                    except Exception:
                        Path(temporary).unlink(missing_ok=True)
                        raise
                    touched.add(target.relative_to(self.repo_root).as_posix())

                gate_outputs = []
                passed = True
                for command in VERIFY_COMMANDS:
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
                commit = self.git_checkpointer(self.repo_root, address, patch.summary)
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
                return SourceLoopResult(
                    passed=True,
                    attempts=attempt,
                    action="edit",
                    files=sorted(touched),
                    checkpoint=commit,
                )
            except Exception as error:
                failure = f"{type(error).__name__}: {error}"
                (attempt_root / "error.txt").write_text(failure, encoding="utf-8")
                self.activity.emit(
                    "error",
                    f"Attempt {attempt} failed",
                    failure,
                    address=address,
                    status="failed",
                )

        for target, content in originals.items():
            if content is None:
                target.unlink(missing_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(content)
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
