#!/usr/bin/env python3
"""survey_plan_tiers.py -- how much of the 1,396-unit corpus this can automate.

Runs the MODEL-FREE half of the derivation stage (src/port_c_evidence) over
every function in oracle-registry.json, slicing each one's verbatim C out of its
chunk file, and reports the tier it would land in. No LLM, no GPU: this is the
CEILING measurement -- the share of the corpus whose shape the generator can
even attempt, before the model's own accuracy is applied to it.

Usage:
  python tools/survey_plan_tiers.py --repo-root D:/GotYaForce [--json out.json]
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.port_c_evidence import analyse_function  # noqa: E402
from src.port_spec_emit import SDK_SHIMS, real_callees  # noqa: E402
from src.port_trace_verify import ORACLE_REGISTRY_RELPATH  # noqa: E402


def slice_c(repo_root: Path, entry: dict, cache: dict[str, list[str]]) -> str | None:
    chunk = entry.get("chunk_file")
    span = entry.get("line_range") or []
    if not chunk or len(span) != 2:
        return None
    lines = cache.get(chunk)
    if lines is None:
        path = repo_root / chunk
        if not path.is_file():
            cache[chunk] = []
            return None
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines(keepends=True)
        cache[chunk] = lines
    if not lines:
        return None
    start, end = int(span[0]), int(span[1])
    if not (1 <= start <= end <= len(lines)):
        return None
    return "".join(lines[start - 1:end])


def tier_of(evidence, entry: dict) -> tuple[str, str]:
    """(tier, reason) from the C alone -- the ceiling, ignoring model accuracy."""
    callees = real_callees(evidence)
    rom = sorted(c for c in callees if not c.startswith("gnt4_"))
    sdk = sorted(c for c in callees if c.startswith("gnt4_"))
    unknown_sdk = [c for c in sdk if c not in SDK_SHIMS]

    writes = evidence.direct_param_writes()
    local_writes = evidence.has_local_base_writes()

    if not writes and not local_writes:
        return "no_write_set", "function stores nothing a capture could compare"
    if evidence.indirect_calls:
        return "human", "dispatches through a ROM function-pointer table (replay traps)"
    if local_writes and not writes:
        return "human", "stores only through a non-argument base (allocator/stack)"
    if rom:
        return "human", f"calls external ROM callee(s) ({len(rom)})"
    if unknown_sdk:
        return "human", f"calls SDK helper(s) with no vetted shim ({unknown_sdk[:2]})"
    if local_writes:
        return "human", "some stores go through a non-argument base"
    return ("shimmed" if sdk else "mechanical"), ""


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", default="D:/GotYaForce")
    parser.add_argument("--json", default="")
    args = parser.parse_args()
    repo_root = Path(args.repo_root)

    payload = json.loads(
        (repo_root / ORACLE_REGISTRY_RELPATH).read_text(encoding="utf-8-sig"))
    functions = payload.get("functions") or []

    cache: dict[str, list[str]] = {}
    tiers = Counter()
    per_unit: dict[str, Counter] = defaultdict(Counter)
    reasons = Counter()
    plan_shape = Counter()

    for entry in functions:
        name = entry.get("name")
        unit = entry.get("unit") or "?"
        body = slice_c(repo_root, entry, cache)
        if body is None:
            tiers["no_source"] += 1
            per_unit[unit]["no_source"] += 1
            continue
        evidence = analyse_function(name, body, entry.get("params") or [])
        tier, reason = tier_of(evidence, entry)
        tiers[tier] += 1
        per_unit[unit][tier] += 1
        if reason:
            reasons[reason.split("(")[0].strip()] += 1
        # how big is the plan the model would have to get right?
        entries = len(evidence.direct_param_reads()) + len(evidence.direct_param_writes())
        plan_shape["<=4" if entries <= 4 else ("5-12" if entries <= 12 else ">12")] += 1

    # unit-level rollup: a unit is auto-speccable only if EVERY export is
    # (run-unit.mjs demands full export coverage for an oracle_green promotion)
    unit_tiers = Counter()
    for unit, counts in per_unit.items():
        auto = counts["mechanical"] + counts["shimmed"]
        total = sum(counts.values())
        if auto == total:
            unit_tiers["all_exports_auto"] += 1
        elif auto:
            unit_tiers["partially_auto"] += 1
        else:
            unit_tiers["none_auto"] += 1

    total_fn = sum(tiers.values())
    print(f"functions analysed: {total_fn}   units: {len(per_unit)}")
    print("\nPER-FUNCTION TIER (the shape the generator can attempt):")
    for tier, count in tiers.most_common():
        print(f"  {tier:14s} {count:6d}  {100 * count / total_fn:5.1f}%")
    print("\nHUMAN-tier reasons:")
    for reason, count in reasons.most_common(6):
        print(f"  {count:6d}  {reason}")
    print("\nPLAN SIZE the model must get right (declared direct entries):")
    for bucket, count in plan_shape.most_common():
        print(f"  {bucket:5s} {count:6d}  {100 * count / total_fn:5.1f}%")
    print("\nPER-UNIT rollup (full export coverage is required for oracle_green):")
    total_units = sum(unit_tiers.values())
    for kind, count in unit_tiers.most_common():
        print(f"  {kind:18s} {count:5d}  {100 * count / total_units:5.1f}%")

    if args.json:
        Path(args.json).write_text(json.dumps({
            "functions": total_fn, "units": len(per_unit),
            "per_function_tier": dict(tiers), "per_unit_rollup": dict(unit_tiers),
            "human_reasons": dict(reasons), "plan_size": dict(plan_shape),
        }, indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
