#!/usr/bin/env python3
"""diff_against_gold.py -- accuracy of derived plans vs the hand-authored ones.

The hand-authored auto-c0020-007 plans are the quality bar (815 captured cases,
789 byte-exact, 0 unexplained). This compares a derivation run's plans against
them ENTRY BY ENTRY, on the thing that matters -- the byte range each entry
claims, not its id or its prose:

  matched      the derived set covers a byte range the gold set also declares
  missed       gold declares it, the derived set does not  (UNDER-declaration:
               the dangerous direction -- a spec built on this compares less)
  hallucinated the derived set declares it, gold does not  (over-declaration:
               noisy, and caught by the static validator, but not silent)

Ranges are compared as byte intervals per (root, offset..offset+width) so a
different-but-equivalent split (one 8-byte entry vs two 4-byte entries) scores
as matched rather than as a miss plus a hallucination.

  python tools/diff_against_gold.py --run report.json --unit auto-c0020-007
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.port_plan_derive import _reg_to_param, parse_addr  # noqa: E402
from src.port_trace_verify import load_registry_functions  # noqa: E402

GOLD_RELPATH = "research/tools/dolphin-trace/plans"


def byte_set(plan: dict, side: str, reg_param: dict[str, int]) -> dict[int, set]:
    """{root key: set of claimed byte addresses} for one side of a plan.

    Root key: (0, param) for a parameter-relative entry, (1, param, offset) for
    a pointer chase, (2, base) for an absolute ROM address.
    """
    out: dict = {}
    for entry in plan.get(side) or []:
        parsed = parse_addr(entry.get("addr", ""), reg_param)
        width = int(entry.get("width") or 0)
        if parsed.form == "direct":
            key = (0, parsed.param)
            start = parsed.offset
        elif parsed.form == "chase" and parsed.inner_loads:
            key = (1,) + tuple(parsed.inner_loads[0])
            start = parsed.offset
        elif parsed.form in ("absolute", "absolute_strided"):
            key = (2, parsed.base_addr)
            start = 0
        else:
            key = (3, entry.get("addr"))
            start = 0
        out.setdefault(key, set()).update(range(start, start + max(width, 1)))
    return out


def describe(key, offset: int) -> str:
    if key[0] == 0:
        return f"param_{key[1]}+{offset:#x}"
    if key[0] == 1:
        return f"[param_{key[1]}+{key[2]:#x}]+{offset:#x}"
    if key[0] == 2:
        return f"{key[1]:#x}"
    return str(key[1])


def compare(gold: dict, derived: dict) -> dict:
    keys = set(gold) | set(derived)
    matched = missed = extra = 0
    missed_at: list[str] = []
    extra_at: list[str] = []
    for key in keys:
        g = gold.get(key, set())
        d = derived.get(key, set())
        matched += len(g & d)
        for offset in sorted(g - d):
            missed += 1
            if len(missed_at) < 12:
                missed_at.append(describe(key, offset))
        for offset in sorted(d - g):
            extra += 1
            if len(extra_at) < 12:
                extra_at.append(describe(key, offset))
    return {"matched_bytes": matched, "missed_bytes": missed,
            "hallucinated_bytes": extra,
            "missed": _runs(missed_at), "hallucinated": _runs(extra_at)}


def _runs(items: list[str]) -> list[str]:
    seen = []
    for item in items:
        base = item.rsplit("+", 1)[0] if "+" in item else item
        if base not in seen:
            seen.append(base)
    return seen


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", default="D:/GotYaForce")
    parser.add_argument("--run", required=True)
    parser.add_argument("--unit", required=True)
    args = parser.parse_args()

    repo_root = Path(args.repo_root)
    registry = load_registry_functions(repo_root)
    run = json.loads(Path(args.run).read_text(encoding="utf-8"))
    exports = run["units"][args.unit]["exports"]

    totals = {"reads": [0, 0, 0], "writes": [0, 0, 0]}
    print(f"{'export':18s} {'verdict':9s} {'reads m/miss/hall':>20s} "
          f"{'writes m/miss/hall':>20s}")
    for fn, record in exports.items():
        gold_path = repo_root / GOLD_RELPATH / f"{args.unit}.{fn}.json"
        if not gold_path.is_file():
            print(f"{fn:18s} (no gold plan)")
            continue
        gold_plan = json.loads(gold_path.read_text(encoding="utf-8-sig"))
        entry = registry.get(fn) or {}
        reg_param = _reg_to_param(gold_plan, entry)
        derived_plan = record.get("plan")
        cells = []
        for side in ("reads", "writes"):
            gold_bytes = byte_set(gold_plan, side, reg_param)
            derived_bytes = (byte_set(derived_plan, side, reg_param)
                             if derived_plan else {})
            result = compare(gold_bytes, derived_bytes)
            record.setdefault("gold_diff", {})[side] = result
            totals[side][0] += result["matched_bytes"]
            totals[side][1] += result["missed_bytes"]
            totals[side][2] += result["hallucinated_bytes"]
            cells.append(f"{result['matched_bytes']}/"
                         f"{result['missed_bytes']}/{result['hallucinated_bytes']}")
        print(f"{fn:18s} {record['verdict']:9s} {cells[0]:>20s} {cells[1]:>20s}")
        for side in ("reads", "writes"):
            diff = record["gold_diff"][side]
            if diff["missed"]:
                print(f"     MISSED  {side}: {', '.join(diff['missed'])}")
            if diff["hallucinated"]:
                print(f"     EXTRA   {side}: {', '.join(diff['hallucinated'])}")

    print("\nTOTAL (bytes claimed)")
    for side in ("reads", "writes"):
        matched, missed, extra = totals[side]
        total = matched + missed
        recall = 100 * matched / total if total else 0.0
        precision = 100 * matched / (matched + extra) if (matched + extra) else 0.0
        print(f"  {side:7s} matched={matched:5d} missed={missed:4d} "
              f"hallucinated={extra:4d}   recall={recall:5.1f}%  "
              f"precision={precision:5.1f}%")

    Path(args.run).write_text(json.dumps(run, indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
