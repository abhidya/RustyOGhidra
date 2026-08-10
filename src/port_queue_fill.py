"""port_queue_fill.py — fill the wasm-unit queue with the remaining 1:1 chunk work.

Sweeps every research/decomp/ghidra-export/chunk_*.c, groups functions into
compile_only units of BATCH functions each (via port_unit_generator), and appends
them to wasm-units.json. Skips: gnt4_* SDK functions (design stage 1: never
ported), functions already exported by existing queue units, and chunks with no
eligible functions. Idempotent: re-running skips units already queued.

    python -m src.port_queue_fill --repo D:/GotYaForce [--batch 8] [--chunks chunk_0004 ...]
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from src.port_unit_generator import QUEUE_DEFAULT, build_unit, scan_chunk

SKIP_PREFIXES = ("gnt4_",)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--repo", default=r"D:\GotYaForce")
    ap.add_argument("--batch", type=int, default=8)
    ap.add_argument("--chunks", nargs="*", help="subset; default = all chunk_*.c")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    repo_root = Path(args.repo)
    queue_path = repo_root / QUEUE_DEFAULT
    queue = json.loads(queue_path.read_text(encoding="utf-8"))
    units = queue["units"] if isinstance(queue, dict) else queue
    queued_names = {u["name"] for u in units}
    already_ported = {fn for u in units for fn in u.get("exported_functions", [])}

    chunk_dir = repo_root / "research/decomp/ghidra-export"
    chunks = args.chunks or sorted(p.stem for p in chunk_dir.glob("chunk_*.c"))

    added = skipped_fns = 0
    for chunk in chunks:
        blocks = scan_chunk(chunk_dir / f"{chunk}.c")
        eligible = [
            b["name"]
            for b in blocks
            if not b["name"].startswith(SKIP_PREFIXES) and b["name"] not in already_ported
        ]
        skipped_fns += len(blocks) - len(eligible)
        for i in range(0, len(eligible), args.batch):
            group = eligible[i : i + args.batch]
            name = f"auto-{chunk.replace('chunk_', 'c')}-{i // args.batch:03d}"
            if name in queued_names:
                continue
            unit = build_unit(repo_root, chunk, group, None, name)
            units.append(unit)
            queued_names.add(name)
            added += 1
    if not args.dry_run:
        with open(queue_path, "w", encoding="utf-8", newline="\n") as fh:
            json.dump(queue, fh, indent=1)
    print(
        f"chunks={len(chunks)} units_added={added} fns_skipped={skipped_fns} "
        f"queue_total={len(units)}{' (dry-run: not written)' if args.dry_run else ''}"
    )


if __name__ == "__main__":
    main()
