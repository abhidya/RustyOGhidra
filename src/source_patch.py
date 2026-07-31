"""Bounded unified-diff contract for model-generated browser-port changes."""

from __future__ import annotations

import re
import subprocess
import tempfile
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


ALLOWED_SOURCE_ROOTS = ("apps/game/", "packages/", "scripts/")
ALLOWED_SUFFIXES = {".ts", ".tsx", ".js", ".mjs", ".json"}
DIFF_HEADER = re.compile(r"^diff --git a/(?P<old>\S+) b/(?P<new>\S+)$")
PLACEHOLDER = re.compile(
    r"\b(?:TODO|FIXME|placeholder|not implemented|implement later|stub|assume)\b"
    r"|\bwe(?:'ll| will)\b",
    re.IGNORECASE,
)


class PatchValidationError(ValueError):
    """Raised before a candidate diff is allowed to mutate its worktree."""


class BrowserSourcePatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    summary: str = Field(min_length=1, max_length=240)
    action: Literal["edit", "exclude"] = "edit"
    semantics: list[str] = Field(default_factory=list, max_length=24)
    diff: str = Field(
        default="",
        max_length=80_000,
        description=(
            "Plain unified diff beginning every file section with "
            "'diff --git a/<path> b/<path>'; never complete file contents or Markdown"
        ),
    )

    @model_validator(mode="after")
    def require_diff_for_edit(self) -> "BrowserSourcePatch":
        if self.action == "edit" and not self.diff.strip():
            raise ValueError("action=edit requires a unified diff")
        if self.action == "exclude" and self.diff.strip():
            raise ValueError("action=exclude cannot include a diff")
        return self


class PatchStats(BaseModel):
    files: list[str]
    additions: int
    deletions: int


def _safe_relative_path(repo_root: Path, relative: str) -> Path:
    normalized = relative.replace("\\", "/").lstrip("/")
    path = Path(normalized)
    if (
        not normalized.startswith(ALLOWED_SOURCE_ROOTS)
        or path.suffix.lower() not in ALLOWED_SUFFIXES
        or ".." in path.parts
    ):
        raise PatchValidationError(f"diff contains a disallowed path: {relative}")
    target = (repo_root / path).resolve()
    if repo_root.resolve() not in target.parents:
        raise PatchValidationError(f"diff path escapes the repository: {relative}")
    return target


def _diff_sections(diff: str) -> list[tuple[str, list[str]]]:
    sections: list[tuple[str, list[str]]] = []
    current_path: str | None = None
    current_lines: list[str] = []
    for line in diff.splitlines():
        header = DIFF_HEADER.fullmatch(line)
        if header:
            if current_path is not None:
                sections.append((current_path, current_lines))
            old_path = header.group("old")
            new_path = header.group("new")
            if old_path != new_path:
                raise PatchValidationError("renames are not allowed in model diffs")
            current_path = new_path
            current_lines = [line]
        elif current_path is not None:
            current_lines.append(line)
    if current_path is not None:
        sections.append((current_path, current_lines))
    return sections


def validate_unified_diff(
    repo_root: Path,
    diff: str,
    *,
    max_files: int = 8,
    max_changed_lines: int = 400,
    max_deletions: int = 160,
) -> PatchStats:
    """Validate scope and size without applying the diff."""

    if "```" in diff:
        raise PatchValidationError("Markdown-wrapped patches are not accepted")
    if "\x00" in diff:
        raise PatchValidationError("binary patches are not accepted")

    sections = _diff_sections(diff)
    if not sections:
        raise PatchValidationError("response does not contain a unified diff")
    if len(sections) > max_files:
        raise PatchValidationError(f"diff changes more than {max_files} files")

    files: list[str] = []
    additions = 0
    deletions = 0
    for relative, lines in sections:
        target = _safe_relative_path(repo_root, relative)
        files.append(relative)
        file_additions = sum(
            1 for line in lines if line.startswith("+") and not line.startswith("+++")
        )
        file_deletions = sum(
            1 for line in lines if line.startswith("-") and not line.startswith("---")
        )
        additions += file_additions
        deletions += file_deletions

        added_text = "\n".join(
            line[1:]
            for line in lines
            if line.startswith("+") and not line.startswith("+++")
        )
        if PLACEHOLDER.search(added_text):
            raise PatchValidationError("diff adds a placeholder implementation")

        if target.is_file():
            original_lines = target.read_text(encoding="utf-8").splitlines()
            if original_lines and file_deletions >= len(original_lines):
                raise PatchValidationError(
                    f"complete-file replacement is not allowed: {relative}"
                )

    if additions + deletions > max_changed_lines:
        raise PatchValidationError(
            f"diff changes {additions + deletions} lines; limit is {max_changed_lines}"
        )
    if deletions > max_deletions:
        raise PatchValidationError(
            f"diff deletes {deletions} lines; limit is {max_deletions}"
        )
    return PatchStats(files=files, additions=additions, deletions=deletions)


def apply_unified_diff(repo_root: Path, diff: str) -> PatchStats:
    """Apply a diff after the same exact-context check exposed to model repair."""

    stats = check_unified_diff(repo_root, diff)
    repo_root = repo_root.resolve()
    with tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        newline="\n",
        suffix=".diff",
        delete=False,
    ) as handle:
        handle.write(diff)
        patch_path = Path(handle.name)
    try:
        applied = subprocess.run(
            ["git", "apply", "--whitespace=error-all", str(patch_path)],
            cwd=repo_root,
            capture_output=True,
            text=True,
        )
        if applied.returncode != 0:
            detail = (applied.stderr or applied.stdout).strip()
            raise PatchValidationError(f"git could not apply validated diff: {detail}")
        return stats
    finally:
        patch_path.unlink(missing_ok=True)


def check_unified_diff(repo_root: Path, diff: str) -> PatchStats:
    """Validate scope and require every hunk to match the current source."""

    repo_root = repo_root.resolve()
    stats = validate_unified_diff(repo_root, diff)
    with tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        newline="\n",
        suffix=".diff",
        delete=False,
    ) as handle:
        handle.write(diff)
        patch_path = Path(handle.name)
    try:
        check = subprocess.run(
            ["git", "apply", "--check", "--whitespace=error-all", str(patch_path)],
            cwd=repo_root,
            capture_output=True,
            text=True,
        )
        if check.returncode != 0:
            detail = (check.stderr or check.stdout).strip()
            raise PatchValidationError(
                f"diff does not match current source exactly: {detail}"
            )
        return stats
    finally:
        patch_path.unlink(missing_ok=True)
