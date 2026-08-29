#!/usr/bin/env python3
"""score_reads.py -- read-side accuracy of a derivation, including truncated replies.

`diff_against_gold.py` scores complete plans. On this rig the serving slot has
been ending replies early with finish_reason "stop" at varying lengths, so some
replies carry a COMPLETE `reads` array and a truncated `writes` array. Those are
correctly refused by the pipeline -- but the read set they did produce is still
real evidence about derivation quality, and throwing it away would understate
what was measured.

This salvages the `reads` array alone and scores it against the hand-authored
plan, byte range by byte range. It never writes a plan and never feeds the spec
generator: it is a measurement tool only.

  python tools/score_reads.py --replies real-replies.json --unit auto-c0020-007
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.port_plan_derive import _reg_to_param  # noqa: E402
from src.port_trace_verify import PLANS_RELPATH, load_registry_functions  # noqa: E402
from tools.diff_against_gold import byte_set, compare  # noqa: E402

def _objects(text: str, start: int) -> list[dict]:
    """Every complete top-level {...} object from `start`, scanned with STRING
    AWARENESS.

    A regex like `\\{[^{}]*\\}` looks adequate and silently drops any entry whose
    `evidence` text contains a brace -- and decompiled C is full of them
    (`if ((double)FLOAT_80438744 < dVar4) {`). That artefact cost this
    measurement two entries and would have been reported as the model missing
    two ROM constants it had in fact derived correctly.
    """
    entries: list[dict] = []
    index, depth, begin, in_string, escaped = start, 0, -1, False, False
    while index < len(text):
        char = text[index]
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
        elif char == '"':
            in_string = True
        elif char == "{":
            if depth == 0:
                begin = index
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0 and begin >= 0:
                try:
                    entries.append(json.loads(text[begin:index + 1]))
                except json.JSONDecodeError:
                    pass
                begin = -1
            elif depth < 0:
                break
        elif char == "]" and depth == 0:
            break
        index += 1
    return entries


def salvage_reads(reply: str) -> list[dict] | None:
    """The `reads` array of a possibly truncated reply, or None."""
    match = re.search(r'"reads"\s*:\s*\[', reply or "")
    if not match:
        return None
    return _objects(reply, match.end()) or None


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", default="D:/GotYaForce")
    parser.add_argument("--replies", required=True)
    parser.add_argument("--unit", required=True)
    args = parser.parse_args()

    repo_root = Path(args.repo_root)
    registry = load_registry_functions(repo_root)
    replies = json.loads(Path(args.replies).read_text(encoding="utf-8"))

    totals = [0, 0, 0]
    print(f"{'export':18s} {'reply':>7s} {'entries':>8s} "
          f"{'matched':>8s} {'missed':>7s} {'halluc':>7s}")
    for fn, reply in sorted(replies.items()):
        gold_path = repo_root / PLANS_RELPATH / f"{args.unit}.{fn}.json"
        if not gold_path.is_file():
            continue
        reads = salvage_reads(reply)
        if reads is None:
            print(f"{fn:18s} {len(reply):7d} {'-':>8s}   reply too short to carry a read set")
            continue
        gold = json.loads(gold_path.read_text(encoding="utf-8-sig"))
        reg_param = _reg_to_param(gold, registry.get(fn) or {})
        result = compare(byte_set(gold, "reads", reg_param),
                         byte_set({"reads": reads}, "reads", reg_param))
        totals[0] += result["matched_bytes"]
        totals[1] += result["missed_bytes"]
        totals[2] += result["hallucinated_bytes"]
        print(f"{fn:18s} {len(reply):7d} {len(reads):8d} "
              f"{result['matched_bytes']:8d} {result['missed_bytes']:7d} "
              f"{result['hallucinated_bytes']:7d}")
        if result["missed"]:
            print(f"     MISSED: {', '.join(result['missed'])}")
        if result["hallucinated"]:
            print(f"     EXTRA : {', '.join(result['hallucinated'])}")

    matched, missed, extra = totals
    denominator = matched + missed
    print(f"\nREAD SET totals: matched={matched} missed={missed} "
          f"hallucinated={extra}")
    if denominator:
        print(f"  recall    {100 * matched / denominator:5.1f}%  "
              f"(share of the hand-authored read bytes the model found)")
    if matched + extra:
        print(f"  precision {100 * matched / (matched + extra):5.1f}%  "
              f"(share of the model's read bytes that are in the gold plan)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
