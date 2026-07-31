"""Cumulative two-unit port transaction in one disposable Git worktree."""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import time
import uuid
from pathlib import Path
from typing import Any, Callable, Literal

from pydantic import BaseModel, Field

from src.port_workflow import atomic_write_json
from src.source_patch import (
    BrowserSourcePatch,
    PatchValidationError,
    apply_unified_diff,
    check_unified_diff,
)


MODEL_MAX_OUTPUT_TOKENS = 8192
MAX_MODEL_ATTEMPTS = 2
VERIFY_COMMANDS = (
    ("pnpm", "typecheck"),
    ("pnpm", "--filter", "@gf/combat", "build"),
    ("pnpm", "selfcheck:rom"),
    ("pnpm", "selfcheck:game-session"),
    ("pnpm", "--filter", "game", "build"),
    ("pnpm", "smoke:browser"),
)


class PortUnit(BaseModel):
    unit_id: str = Field(min_length=1)
    evidence_path: Path | None = None


class IncrementalPortResult(BaseModel):
    status: Literal["pushed", "verified", "failed", "push_race"]
    base_commit: str | None = None
    commits: list[str] = Field(default_factory=list)
    worktree: str | None = None
    push_command: list[str] | None = None
    error: str | None = None


PatchProvider = Callable[[PortUnit, Path, Path], BrowserSourcePatch]
GateRunner = Callable[[Path, PortUnit], tuple[bool, str]]


def _json_payload(raw: str) -> dict[str, Any]:
    candidate = raw.strip()
    if "```" in candidate:
        raise PatchValidationError("Markdown-wrapped responses are not accepted")
    decoder = json.JSONDecoder()
    start = candidate.find("{")
    if start < 0:
        raise PatchValidationError("model response does not contain JSON")
    try:
        payload, end = decoder.raw_decode(candidate[start:])
    except json.JSONDecodeError as error:
        raise PatchValidationError(f"model returned truncated JSON: {error}") from error
    if candidate[start + end :].strip():
        raise PatchValidationError("model returned text after its JSON object")
    if not isinstance(payload, dict):
        raise PatchValidationError("model response must be a JSON object")
    return payload


def _source_context(worktree: Path, evidence: dict[str, Any]) -> str:
    terms = set(
        word.lower()
        for word in re.findall(r"[A-Za-z][A-Za-z0-9_]{4,}", json.dumps(evidence))
    )
    selected: list[Path] = []
    for relative in evidence.get("destination_context_paths", []):
        path = (worktree / str(relative)).resolve()
        if worktree.resolve() in path.parents and path.is_file() and path.suffix == ".ts":
            selected.append(path)

    candidates: list[tuple[int, Path]] = []
    for root in (
        worktree / "packages" / "combat" / "src",
        worktree / "apps" / "game" / "src" / "sim",
    ):
        if not root.is_dir():
            continue
        for path in root.rglob("*.ts"):
            relative = path.relative_to(worktree).as_posix().lower()
            score = sum(1 for term in terms if term in relative)
            if score:
                candidates.append((score, path))
    candidates.sort(key=lambda item: (-item[0], item[1].as_posix()))
    selected.extend(
        path for _, path in candidates if path not in selected
    )
    selected = selected[:4]
    for fallback in (
        worktree / "packages" / "combat" / "src" / "combat.ts",
        worktree / "packages" / "combat" / "src" / "types.ts",
        worktree / "apps" / "game" / "src" / "sim" / "battleScene.ts",
    ):
        if fallback.is_file() and fallback not in selected and len(selected) < 4:
            selected.append(fallback)
    return "\n\n".join(
        f"--- {path.relative_to(worktree).as_posix()} ---\n"
        f"{path.read_text(encoding='utf-8')[:8000]}"
        for path in selected
    )


def _compact_evidence(evidence: dict[str, Any]) -> dict[str, Any]:
    handlers = [
        {
            "address": handler.get("address"),
            "name": handler.get("name"),
            "decompile": handler.get("decompile"),
            "callers": handler.get("callers", []),
            "callees": handler.get("callees", []),
        }
        for handler in evidence.get("handlers", [])
    ]
    records = [
        record
        for record in evidence.get("evidence", [])
        if record.get("kind") in {"raw_table_entry", "destination_audit"}
    ]
    return {
        "unit_id": evidence.get("unit_id"),
        "kind": evidence.get("kind"),
        "root_addresses": evidence.get("root_addresses", []),
        "state_field": evidence.get("state_field"),
        "function_pointer_tables": evidence.get("function_pointer_tables", []),
        "handlers": handlers,
        "transitions": evidence.get("transitions", []),
        "callers": evidence.get("callers", []),
        "callees": evidence.get("callees", []),
        "destination_gap": evidence.get("destination_gap"),
        "existing_destination_code": evidence.get("existing_destination_code", []),
        "evidence": records,
        "unknowns": evidence.get("unknowns", []),
    }


class QwenPatchProvider:
    """Generate one small evidence-backed diff with at most one format repair."""

    def __init__(self, llm_factory: Callable[[], tuple[Any, str, str]]):
        self.llm_factory = llm_factory

    def __call__(
        self,
        unit: PortUnit,
        worktree: Path,
        record_dir: Path,
    ) -> BrowserSourcePatch:
        if unit.evidence_path is None:
            raise ValueError(f"{unit.unit_id} has no evidence artifact")
        evidence = json.loads(unit.evidence_path.read_text(encoding="utf-8"))
        compact_evidence = _compact_evidence(evidence)
        context = _source_context(worktree, evidence)
        failure: str | None = None
        for attempt in range(1, MAX_MODEL_ATTEMPTS + 1):
            prompt = f"""Implement this single original GG4E execution unit in GotYaForce.

Original evidence is authoritative. Do not invent missing transitions, constants, timers,
or ownership. Preserve unrelated behavior. Make the smallest production change that closes
a concrete destination gap and add/update a focused test only when needed.

Return exactly one JSON object matching the supplied schema. For action="edit", `diff`
must be a plain bounded unified diff with `diff --git`, `---`, `+++`, and exact context.
Never return complete file contents, Markdown fences, placeholders, generated reports,
shell commands, or edits outside apps/game, packages, and scripts.

Unit evidence:
{json.dumps(compact_evidence, indent=2)[:30000]}

Relevant destination source:
{context}
"""
            if failure:
                prompt += f"\nPrevious response was rejected:\n{failure[-4000:]}\n"
            attempt_dir = record_dir / f"model-attempt-{attempt:02d}"
            attempt_dir.mkdir(parents=True)
            (attempt_dir / "prompt.txt").write_text(prompt, encoding="utf-8")
            llm, provider, model_name = self.llm_factory()
            arguments: dict[str, Any] = {
                "prompt": prompt,
                "schema": BrowserSourcePatch.model_json_schema(),
                "tool_name": "submit_incremental_port_diff",
                "model": model_name,
                "system_prompt": (
                    "You are a precise 1:1 game-port implementation engine. "
                    "Output one bounded unified diff grounded in the supplied original evidence."
                ),
                "temperature": 0.1,
                "max_tokens": MODEL_MAX_OUTPUT_TOKENS,
                "phase": f"incremental_port:{unit.unit_id}:attempt_{attempt}",
                "accept_plain_tool_response": True,
            }
            atomic_write_json(
                attempt_dir / "status.json",
                {
                    "status": "waiting_for_gateway_response",
                    "started_at": time.time(),
                    "streaming": False,
                    "reason": (
                        "the configured gateway does not stream structured "
                        "tool-call arguments"
                    ),
                },
            )
            raw, mode = llm.generate_structured(**arguments)
            atomic_write_json(
                attempt_dir / "status.json",
                {
                    "status": "response_received",
                    "received_at": time.time(),
                    "streaming": False,
                },
            )
            (attempt_dir / "response.txt").write_text(raw, encoding="utf-8")
            try:
                patch = BrowserSourcePatch.model_validate(_json_payload(raw))
                if patch.action == "edit":
                    check_unified_diff(worktree, patch.diff)
                atomic_write_json(
                    attempt_dir / "accepted.json",
                    {
                        "provider": provider,
                        "model": model_name,
                        "mode": mode,
                        **patch.model_dump(mode="json"),
                    },
                )
                return patch
            except Exception as error:
                failure = f"{type(error).__name__}: {error}"
                (attempt_dir / "rejected.txt").write_text(
                    failure,
                    encoding="utf-8",
                )
        raise PatchValidationError(failure or "model attempts exhausted")


def run_default_gates(worktree: Path, _unit: PortUnit) -> tuple[bool, str]:
    outputs: list[str] = []
    for command in VERIFY_COMMANDS:
        executable = command[0]
        if executable == "pnpm" and os.name == "nt":
            executable = shutil.which("pnpm.cmd") or "pnpm.cmd"
        result = subprocess.run(
            [executable, *command[1:]],
            cwd=worktree,
            capture_output=True,
            text=True,
            timeout=30 * 60,
        )
        outputs.append(
            f"$ {' '.join(command)}\n{result.stdout}\n{result.stderr}".strip()
        )
        if result.returncode != 0:
            return False, "\n\n".join(outputs)
    return True, "\n\n".join(outputs)


class IncrementalPortTransaction:
    def __init__(
        self,
        *,
        repo_root: Path,
        run_root: Path,
        patch_provider: PatchProvider,
        gate_runner: GateRunner,
        before_push: Callable[[], None] | None = None,
    ):
        self.repo_root = repo_root.resolve()
        self.run_root = run_root.resolve()
        self.patch_provider = patch_provider
        self.gate_runner = gate_runner
        self.before_push = before_push

    def _git(
        self,
        *args: str,
        cwd: Path | None = None,
        check: bool = True,
    ) -> subprocess.CompletedProcess[str]:
        result = subprocess.run(
            ["git", *args],
            cwd=cwd or self.repo_root,
            capture_output=True,
            text=True,
        )
        if check and result.returncode != 0:
            detail = (result.stderr or result.stdout).strip()
            raise RuntimeError(f"git {' '.join(args)} failed: {detail}")
        return result

    @staticmethod
    def _write_result(run_dir: Path, result: IncrementalPortResult) -> None:
        atomic_write_json(run_dir / "result.json", result.model_dump(mode="json"))

    def _cleanup(self, worktree: Path, branch: str) -> None:
        removed = self._git(
            "worktree",
            "remove",
            "--force",
            str(worktree),
            check=False,
        )
        if removed.returncode == 0:
            self._git("branch", "-D", branch, check=False)

    def run(
        self,
        units: list[PortUnit],
        *,
        push_main: bool,
    ) -> IncrementalPortResult:
        if len(units) != 2:
            raise ValueError("the proof transaction requires exactly two units")

        run_id = f"{int(time.time())}-{uuid.uuid4().hex[:8]}"
        run_dir = self.run_root / run_id
        worktree = run_dir / "worktree"
        branch = f"codex/incremental-port-{uuid.uuid4().hex[:10]}"
        run_dir.mkdir(parents=True, exist_ok=False)

        base_commit: str | None = None
        commits: list[str] = []
        worktree_created = False
        try:
            self._git("fetch", "origin", "main")
            base_commit = self._git("rev-parse", "origin/main").stdout.strip()
            self._git(
                "worktree",
                "add",
                "-b",
                branch,
                str(worktree),
                base_commit,
            )
            worktree_created = True

            for index, unit in enumerate(units, start=1):
                unit_dir = run_dir / f"unit-{index:02d}-{unit.unit_id}"
                unit_dir.mkdir(parents=True)
                patch = self.patch_provider(unit, worktree, unit_dir)
                atomic_write_json(
                    unit_dir / "candidate.json",
                    patch.model_dump(mode="json"),
                )
                if patch.action != "edit":
                    raise RuntimeError(
                        f"{unit.unit_id} was excluded; POC units must be real edits"
                    )
                stats = apply_unified_diff(worktree, patch.diff)
                (unit_dir / "candidate.diff").write_text(
                    patch.diff,
                    encoding="utf-8",
                    newline="\n",
                )

                passed, gate_output = self.gate_runner(worktree, unit)
                (unit_dir / "gates.txt").write_text(
                    gate_output,
                    encoding="utf-8",
                    newline="\n",
                )
                if not passed:
                    raise RuntimeError(f"{unit.unit_id} failed verification")

                self._git("add", "--", *stats.files, cwd=worktree)
                staged = self._git(
                    "diff",
                    "--cached",
                    "--quiet",
                    cwd=worktree,
                    check=False,
                )
                if staged.returncode == 0:
                    raise RuntimeError(f"{unit.unit_id} produced no source change")
                self._git(
                    "commit",
                    "-m",
                    f"port: integrate {unit.unit_id}",
                    cwd=worktree,
                )
                commit = self._git("rev-parse", "HEAD", cwd=worktree).stdout.strip()
                commits.append(commit)

            if not push_main:
                result = IncrementalPortResult(
                    status="verified",
                    base_commit=base_commit,
                    commits=commits,
                    worktree=str(worktree),
                )
                self._write_result(run_dir, result)
                return result

            if self.before_push is not None:
                self.before_push()
            self._git("fetch", "origin", "main")
            remote_now = self._git("rev-parse", "origin/main").stdout.strip()
            if remote_now != base_commit:
                result = IncrementalPortResult(
                    status="push_race",
                    base_commit=base_commit,
                    commits=commits,
                    worktree=str(worktree),
                    error=(
                        f"origin/main advanced from {base_commit} to {remote_now}; "
                        "candidate retained"
                    ),
                )
                self._write_result(run_dir, result)
                return result

            push_command = [
                "git",
                "push",
                "origin",
                "HEAD:refs/heads/main",
            ]
            self._git(*push_command[1:], cwd=worktree)
            result = IncrementalPortResult(
                status="pushed",
                base_commit=base_commit,
                commits=commits,
                push_command=push_command,
            )
            self._write_result(run_dir, result)
            self._cleanup(worktree, branch)
            worktree_created = False
            return result
        except Exception as error:
            result = IncrementalPortResult(
                status="failed",
                base_commit=base_commit,
                commits=commits,
                error=f"{type(error).__name__}: {error}",
            )
            self._write_result(run_dir, result)
            if worktree_created:
                self._cleanup(worktree, branch)
            return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--unit", action="append", type=Path, required=True)
    parser.add_argument("--base", default="origin/main", choices=["origin/main"])
    parser.add_argument("--push-main", action="store_true")
    parser.add_argument("--repo-root", type=Path)
    parser.add_argument("--run-root", type=Path)
    args = parser.parse_args(argv)
    if len(args.unit) != 2:
        parser.error("--unit must be supplied exactly twice")

    from src.config import get_config
    from src.port_cli import _llm_for_config
    from src.port_run_controller import find_gotyaforce_root

    repo_root = (args.repo_root or find_gotyaforce_root()).resolve()
    run_root = (
        args.run_root
        or repo_root / "research" / "decomp" / "generated" / "incremental-port"
    ).resolve()
    units = []
    for path in args.unit:
        path = path.resolve()
        payload = json.loads(path.read_text(encoding="utf-8"))
        units.append(
            PortUnit(
                unit_id=str(payload.get("unit_id") or path.stem),
                evidence_path=path,
            )
        )
    config = get_config()
    result = IncrementalPortTransaction(
        repo_root=repo_root,
        run_root=run_root,
        patch_provider=QwenPatchProvider(lambda: _llm_for_config(config)),
        gate_runner=run_default_gates,
    ).run(units, push_main=args.push_main)
    print(result.model_dump_json(indent=2))
    return 0 if result.status in {"pushed", "verified"} else 3


if __name__ == "__main__":
    raise SystemExit(main())
