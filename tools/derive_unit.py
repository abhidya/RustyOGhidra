#!/usr/bin/env python3
"""derive_unit.py -- run the plan+spec derivation stage over staged units.

  python tools/derive_unit.py --unit auto-c0020-007 --out report.json \
      [--plans-out DIR] [--specs-out DIR] [--attempts 2] [--fn NAME]

Plans go to --plans-out (default: a scratch dir, NOT the repo) so an accuracy
measurement can never clobber a hand-authored plan. Pass
--plans-out research/tools/dolphin-trace/plans to publish for real; even then,
hand-authored plans are kept (port_plan_derive.write_plan).

Queues one request at a time against the shared model server. Never starts,
restarts or reconfigures it.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.port_c_evidence import analyse_function  # noqa: E402
from src.port_plan_derive import PlanDeriver, write_plan  # noqa: E402
from src.port_spec_emit import classify_export, emit_spec  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", default="D:/GotYaForce")
    parser.add_argument("--unit", action="append", required=True)
    parser.add_argument("--fn", action="append", default=[])
    parser.add_argument("--out", required=True)
    parser.add_argument("--plans-out", default="")
    parser.add_argument("--specs-out", default="")
    parser.add_argument("--attempts", type=int, default=2)
    parser.add_argument("--max-tokens", type=int, default=3072)
    args = parser.parse_args()

    repo_root = Path(args.repo_root)
    plans_out = Path(args.plans_out) if args.plans_out else None
    specs_out = Path(args.specs_out) if args.specs_out else None
    deriver = PlanDeriver(repo_root, max_tokens=args.max_tokens,
                          attempts=args.attempts)

    report: dict = {"units": {}, "started": time.strftime("%Y-%m-%dT%H:%M:%S")}
    for unit in args.unit:
        bodies = deriver.bodies(unit)
        targets = {fn: body for fn, body in bodies.items()
                   if not args.fn or fn in args.fn}
        unit_report: dict = {"exports": {}, "order": list(bodies)}
        plans: dict[str, dict] = {}
        evidences = {}
        tiers = {}

        for fn, body in targets.items():
            start = time.time()
            result = deriver.derive_function(unit, fn, body)
            entry = deriver.registry().get(fn) or {}
            evidence = analyse_function(fn, body, entry.get("params") or [])
            evidences[fn] = evidence
            tier = classify_export(fn, evidence, result.plan or {}, result.verdict)
            tiers[fn] = tier
            unit_report["exports"][fn] = {
                "verdict": result.verdict,
                "attempts": result.attempts,
                "seconds": round(time.time() - start, 1),
                "reasons": result.reasons,
                "tier": tier.tier,
                "tier_reasons": tier.reasons,
                "plan": result.plan,
                "entry_status": [
                    {"side": e.side, "id": e.entry_id, "status": e.status,
                     "detail": e.detail}
                    for e in (result.validation.entries if result.validation else [])
                ],
                "raw_reply_head": (result.raw_reply or "")[:400],
            }
            print(f"[{unit}] {fn:18s} {result.verdict:9s} tier={tier.tier:10s} "
                  f"{round(time.time() - start, 1)}s", flush=True)
            for reason in result.reasons:
                print(f"      ! {reason}", flush=True)

            if result.plan and result.verdict in ("validated", "flagged"):
                plans[fn] = result.plan
                if plans_out:
                    plans_out.mkdir(parents=True, exist_ok=True)
                    path = plans_out / f"{unit}.{fn}.json"
                    path.write_text(json.dumps(result.plan, indent=2) + "\n",
                                    encoding="utf-8", newline="\n")

        speccable = [fn for fn in plans if tiers[fn].tier in ("mechanical", "shimmed")]
        unit_report["speccable"] = speccable
        if speccable:
            source = emit_spec(unit, {fn: plans[fn] for fn in speccable},
                               evidences, tiers, list(bodies))
            unit_report["spec_chars"] = len(source)
            if specs_out:
                specs_out.mkdir(parents=True, exist_ok=True)
                (specs_out / f"{unit}.spec.mjs").write_text(
                    source, encoding="utf-8", newline="\n")
        else:
            unit_report["spec_refused"] = (
                "no export reached the mechanical/shimmed tier; emitting a spec "
                "here would compare nothing and pass everything")
        report["units"][unit] = unit_report

    Path(args.out).write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"\nreport -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
