#!/usr/bin/env python3
"""replay_recorded.py -- drive the derivation stage from RECORDED replies.

Exercises everything except the model itself: reply parsing -> plan assembly ->
static validation -> tiering -> spec emission. Two sources:

  --from-gold UNIT   synthesise a reply from each hand-authored plan of a unit
                     (the citation is filled in from the static index, since the
                     hand-authored plans predate the citation requirement). This
                     answers "if the model were perfect, what does the rest of
                     the stage do?" -- and produces a generated spec that can be
                     diffed against the hand-authored one.
  --replies FILE     a JSON map {fn: "raw model reply text"} captured from a real
                     run, replayed offline.

  python tools/replay_recorded.py --from-gold auto-c0020-007 --out replay.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.port_c_evidence import analyse_function, split_unit_functions  # noqa: E402
from src.port_plan_derive import (  # noqa: E402
    STAGING_RELPATH,
    assemble_plan,
    parse_addr,
    parse_reply,
    validate_plan,
)
from src.port_spec_emit import classify_export, emit_spec  # noqa: E402
from src.port_trace_verify import (  # noqa: E402
    PLANS_RELPATH,
    load_registry_functions,
    plan_args,
)


def cite_from_evidence(evidence, entry, reg_param) -> str:
    """The source line a hand-authored entry would have cited."""
    parsed = parse_addr(entry.get("addr", ""), reg_param)
    for access in evidence.accesses:
        if parsed.form == "direct" and access.kind == "param" \
                and access.param == parsed.param and access.offset == parsed.offset:
            return access.text
        if parsed.form == "chase" and access.kind == "chase" \
                and access.param == parsed.param and access.offset == parsed.offset:
            return access.text
        if parsed.form in ("absolute", "absolute_strided") \
                and access.kind == "absolute" and access.addr == parsed.base_addr:
            return access.text
    return ""


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", default="D:/GotYaForce")
    parser.add_argument("--from-gold", default="")
    parser.add_argument("--replies", default="")
    parser.add_argument("--unit", default="")
    parser.add_argument("--out", required=True)
    parser.add_argument("--spec-out", default="")
    args = parser.parse_args()

    repo_root = Path(args.repo_root)
    unit = args.from_gold or args.unit
    registry = load_registry_functions(repo_root)
    bodies = split_unit_functions(
        (repo_root / STAGING_RELPATH / unit / "unit.c").read_text(
            encoding="utf-8", errors="replace"))

    recorded: dict[str, str] = {}
    if args.replies:
        recorded = json.loads(Path(args.replies).read_text(encoding="utf-8"))

    report = {"unit": unit, "source": "gold" if args.from_gold else "replies",
              "exports": {}}
    plans: dict[str, dict] = {}
    evidences: dict = {}
    tiers: dict = {}

    for fn, body in bodies.items():
        entry = registry.get(fn) or {}
        evidence = analyse_function(fn, body, entry.get("params") or [])
        evidences[fn] = evidence

        if args.from_gold:
            gold_path = repo_root / PLANS_RELPATH / f"{unit}.{fn}.json"
            if not gold_path.is_file():
                continue
            gold = json.loads(gold_path.read_text(encoding="utf-8-sig"))
            args_list, _ = plan_args(entry.get("params") or [])
            reg_param = {}
            for arg in args_list:
                import re as _re
                match = _re.match(r"param_(\d+)", arg["name"])
                if match:
                    reg_param[arg["reg"]] = int(match.group(1))
            payload = {
                "reads": [{**e, "evidence": cite_from_evidence(evidence, e, reg_param)}
                          for e in gold.get("reads") or []],
                "writes": [{**e, "evidence": cite_from_evidence(evidence, e, reg_param)}
                           for e in gold.get("writes") or []],
                "uncapturable_writes": gold.get("uncapturable_writes") or [],
                "note": gold.get("note", "")[:300],
            }
        else:
            payload, shape = parse_reply(recorded.get(fn, ""))
            if payload is None:
                report["exports"][fn] = {"verdict": "error", "reason": shape}
                continue

        plan = assemble_plan(unit, fn, entry, payload)
        validation = validate_plan(plan, evidence, entry)
        tier = classify_export(fn, evidence, plan, validation.verdict)
        tiers[fn] = tier
        report["exports"][fn] = {
            "verdict": validation.verdict,
            "reasons": validation.reasons(),
            "tier": tier.tier,
            "tier_reasons": tier.reasons,
            "reads": len(plan.get("reads") or []),
            "writes": len(plan.get("writes") or []),
        }
        if validation.verdict in ("validated", "flagged"):
            plans[fn] = plan
        print(f"{fn:18s} {validation.verdict:9s} tier={tier.tier}")
        for reason in validation.reasons():
            print(f"     ! {reason}")

    speccable = [fn for fn in plans if tiers[fn].tier in ("mechanical", "shimmed")]
    report["speccable"] = speccable
    if speccable:
        source = emit_spec(unit, {fn: plans[fn] for fn in speccable},
                           evidences, tiers, list(bodies))
        report["spec_chars"] = len(source)
        if args.spec_out:
            Path(args.spec_out).write_text(source, encoding="utf-8", newline="\n")
            print(f"\nspec -> {args.spec_out} ({len(source)} chars)")
    else:
        report["spec_refused"] = "no export reached the mechanical/shimmed tier"
        print("\nNO SPEC EMITTED: no export reached the mechanical/shimmed tier")

    Path(args.out).write_text(json.dumps(report, indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
