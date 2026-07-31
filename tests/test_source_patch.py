from pathlib import Path

import pytest

from src.source_patch import (
    BrowserSourcePatch,
    PatchValidationError,
    apply_unified_diff,
    validate_unified_diff,
)


def _init_source(repo: Path) -> Path:
    source = repo / "packages/combat/src/combat.ts"
    source.parent.mkdir(parents=True)
    source.write_text(
        "export const STATE_IDLE = 0;\n"
        "export function tick(value: number): number {\n"
        "  return value;\n"
        "}\n",
        encoding="utf-8",
    )
    return source


def test_prior_complete_file_response_is_rejected_by_schema():
    raw = (
        Path(__file__).parent / "fixtures/broken_combat_response.txt"
    ).read_text(encoding="utf-8")
    with pytest.raises(Exception):
        BrowserSourcePatch.model_validate_json(raw)


def test_bounded_unified_diff_applies_with_exact_context(tmp_path: Path):
    source = _init_source(tmp_path)
    diff = """diff --git a/packages/combat/src/combat.ts b/packages/combat/src/combat.ts
--- a/packages/combat/src/combat.ts
+++ b/packages/combat/src/combat.ts
@@ -1,4 +1,5 @@
 export const STATE_IDLE = 0;
+export const STATE_ACTIVE = 1;
 export function tick(value: number): number {
   return value;
 }
"""
    stats = validate_unified_diff(tmp_path, diff)
    apply_unified_diff(tmp_path, diff)

    assert stats.files == ["packages/combat/src/combat.ts"]
    assert stats.additions == 1
    assert "STATE_ACTIVE" in source.read_text(encoding="utf-8")


def test_diff_rejects_disallowed_path_and_placeholder(tmp_path: Path):
    _init_source(tmp_path)
    outside = """diff --git a/.env b/.env
--- a/.env
+++ b/.env
@@ -0,0 +1 @@
+SECRET=no
"""
    with pytest.raises(PatchValidationError, match="disallowed"):
        validate_unified_diff(tmp_path, outside)

    placeholder = """diff --git a/packages/combat/src/combat.ts b/packages/combat/src/combat.ts
--- a/packages/combat/src/combat.ts
+++ b/packages/combat/src/combat.ts
@@ -1,4 +1,5 @@
 export const STATE_IDLE = 0;
+// TODO: implement original behavior
 export function tick(value: number): number {
   return value;
 }
"""
    with pytest.raises(PatchValidationError, match="placeholder"):
        validate_unified_diff(tmp_path, placeholder)

    stub = placeholder.replace(
        "// TODO: implement original behavior",
        "// We'll stub this behavior for now",
    )
    with pytest.raises(PatchValidationError, match="placeholder"):
        validate_unified_diff(tmp_path, stub)


def test_diff_rejects_complete_existing_file_replacement(tmp_path: Path):
    _init_source(tmp_path)
    replacement = """diff --git a/packages/combat/src/combat.ts b/packages/combat/src/combat.ts
--- a/packages/combat/src/combat.ts
+++ b/packages/combat/src/combat.ts
@@ -1,4 +1,4 @@
-export const STATE_IDLE = 0;
-export function tick(value: number): number {
-  return value;
-}
+export const STATE_NEW = 9;
+export function replacement(): number {
+  return 9;
+}
"""
    with pytest.raises(PatchValidationError, match="complete-file replacement"):
        validate_unified_diff(tmp_path, replacement)


def test_diff_rejects_markdown_and_bad_context(tmp_path: Path):
    _init_source(tmp_path)
    diff = """diff --git a/packages/combat/src/combat.ts b/packages/combat/src/combat.ts
--- a/packages/combat/src/combat.ts
+++ b/packages/combat/src/combat.ts
@@ -1 +1 @@
-not the current line
+replacement
"""
    with pytest.raises(PatchValidationError, match="exactly"):
        apply_unified_diff(tmp_path, diff)
    with pytest.raises(PatchValidationError, match="Markdown"):
        validate_unified_diff(tmp_path, f"```diff\n{diff}```")
