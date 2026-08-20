"""port_queue_fill.py — fill the wasm-unit queue with the remaining 1:1 chunk work.

Sweeps every research/decomp/ghidra-export/chunk_*.c, groups functions into
compile_only units of BATCH functions each (via port_unit_generator), and appends
them to wasm-units.json. Skips: gnt4_*/gnt4-* SDK functions (design stage 1:
never ported; ghidra-export markers use BOTH separators), names that are not
valid C identifiers (emcc cannot export them — truncated demangled C++ like
"cCameraManager::HasCamera(cBaseCamera"), and functions already exported by
existing queue units. Every skipped function is recorded (name, addr, chunk,
reason) in wasm-units-skipped.json next to the queue so nothing drops silently.
Idempotent: re-running skips units already queued. --rebuild drops all
generator-authored units first and resweeps (hand-authored units are kept and
their exports stay excluded).

    python -m src.port_queue_fill --repo D:/GotYaForce [--batch 8] [--rebuild]
        [--chunks chunk_0004 ...]
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from src.port_unit_generator import (
    QUEUE_DEFAULT,
    build_unit,
    is_c_identifier,
    scan_chunk,
)

SKIP_PREFIXES = ("gnt4_", "gnt4-")
SKIPPED_REPORT_DEFAULT = (
    "research/decomp/generated/finish-game-port/wasm-units-skipped.json"
)

REASON_SDK = "sdk_prefix"
REASON_NON_C_IDENTIFIER = "non_c_identifier"


def skip_reason(name: str) -> str | None:
    """Why `name` must never be queued, or None when it is portable.

    SDK check first: a hyphenated SDK name ("gnt4-memset") is also a non-C
    identifier, but the design-level reason (SDK is never ported) is the one
    worth recording.
    """
    if name.startswith(SKIP_PREFIXES):
        return REASON_SDK
    if not is_c_identifier(name):
        return REASON_NON_C_IDENTIFIER
    return None


def classify_blocks(
    blocks: list[dict[str, Any]], already_ported: set[str]
) -> tuple[list[str], list[dict[str, Any]]]:
    """(eligible function names, skipped-function report entries) for one chunk.

    Already-queued functions are neither eligible nor reported: they are in the
    queue, not dropped.
    """
    eligible: list[str] = []
    skipped: list[dict[str, Any]] = []
    for b in blocks:
        reason = skip_reason(b["name"])
        if reason is not None:
            skipped.append({"name": b["name"], "addr": b["addr"], "reason": reason})
        elif b["name"] not in already_ported:
            eligible.append(b["name"])
    return eligible, skipped


def write_skipped_report(
    report_path: Path, per_chunk: dict[str, list[dict[str, Any]]]
) -> dict[str, Any]:
    """Merge this sweep's skips into the report (entries keyed by chunk, so a
    subset --chunks run only replaces the chunks it actually swept)."""
    report: dict[str, Any] = {
        "note": (
            "Functions excluded from wasm-units.json at generation time "
            "(port_queue_fill). sdk_prefix: gnt4_*/gnt4-* SDK seam, never "
            "ported by design. non_c_identifier: emcc EXPORTED_FUNCTIONS "
            "cannot export the name (truncated demangled C++ etc.)."
        ),
        "skipped_by_chunk": {},
    }
    if report_path.exists():
        existing = json.loads(report_path.read_text(encoding="utf-8"))
        report["skipped_by_chunk"] = existing.get("skipped_by_chunk", {})
    for chunk, entries in per_chunk.items():
        if entries:
            report["skipped_by_chunk"][chunk] = entries
        else:
            report["skipped_by_chunk"].pop(chunk, None)
    report["skipped_by_chunk"] = dict(sorted(report["skipped_by_chunk"].items()))
    report["total_skipped"] = sum(
        len(v) for v in report["skipped_by_chunk"].values()
    )
    with open(report_path, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(report, fh, indent=1)
    return report


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--repo", default=r"D:\GotYaForce")
    ap.add_argument("--batch", type=int, default=8)
    ap.add_argument("--chunks", nargs="*", help="subset; default = all chunk_*.c")
    ap.add_argument(
        "--rebuild",
        action="store_true",
        help="drop all port_unit_generator units before sweeping (regenerate)",
    )
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    repo_root = Path(args.repo)
    queue_path = repo_root / QUEUE_DEFAULT
    queue = json.loads(queue_path.read_text(encoding="utf-8"))
    units = queue["units"] if isinstance(queue, dict) else queue
    dropped = 0
    if args.rebuild:
        keep = [u for u in units if u.get("generated_by") != "port_unit_generator"]
        dropped = len(units) - len(keep)
        units[:] = keep
    queued_names = {u["name"] for u in units}
    already_ported = {fn for u in units for fn in u.get("exported_functions", [])}

    chunk_dir = repo_root / "research/decomp/ghidra-export"
    chunks = args.chunks or sorted(p.stem for p in chunk_dir.glob("chunk_*.c"))

    added = 0
    skipped_by_chunk: dict[str, list[dict[str, Any]]] = {}
    for chunk in chunks:
        blocks = scan_chunk(chunk_dir / f"{chunk}.c")
        eligible, skipped = classify_blocks(blocks, already_ported)
        skipped_by_chunk[chunk] = skipped
        for i in range(0, len(eligible), args.batch):
            group = eligible[i : i + args.batch]
            name = f"auto-{chunk.replace('chunk_', 'c')}-{i // args.batch:03d}"
            if name in queued_names:
                continue
            unit = build_unit(repo_root, chunk, group, None, name)
            units.append(unit)
            queued_names.add(name)
            added += 1
    skipped_fns = sum(len(v) for v in skipped_by_chunk.values())
    if not args.dry_run:
        with open(queue_path, "w", encoding="utf-8", newline="\n") as fh:
            json.dump(queue, fh, indent=1)
        write_skipped_report(repo_root / SKIPPED_REPORT_DEFAULT, skipped_by_chunk)
    print(
        f"chunks={len(chunks)} units_dropped={dropped} units_added={added} "
        f"fns_skipped={skipped_fns} "
        f"queue_total={len(units)}{' (dry-run: not written)' if args.dry_run else ''}"
    )


if __name__ == "__main__":
    main()
