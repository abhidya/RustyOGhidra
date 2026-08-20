"""port_queue_migrate.py — carry settled verdicts across a queue regeneration.

When the generator changes (skip rules, batching), auto-cNNNN-III unit names
shift and wasm-units-state.json verdicts would silently misattach to different
function sets. Settled verdicts — green, structural_ineligible — are facts
about a SPECIFIC set of exported functions, so they migrate by function set:

- old settled unit whose exported-function set is IDENTICAL to exactly one new
  unit's set: the full state record carries over to the new unit's name
  (disposition "carried");
- sets differ (batches shifted): the new units stay pending and the old
  verdict is recorded in the migration report (disposition
  "dropped_set_changed") — never applied to a set it was not earned on;
- unsettled non-pending statuses (red_retryable, porting) always reset to
  pending, recorded as "reset_unsettled".

Green units' committed artifacts in port-units/ and port-units-staging/ are
content-addressed by their own directories and are not touched here.

    python -m src.port_queue_migrate --repo D:/GotYaForce \
        --old-queue <backup of wasm-units.json taken BEFORE the refill>
"""
from __future__ import annotations

import argparse
import json
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from src.port_unit_generator import QUEUE_DEFAULT

STATE_DEFAULT = "research/decomp/generated/finish-game-port/wasm-units-state.json"
MIGRATION_REPORT_DEFAULT = (
    "research/decomp/generated/finish-game-port/wasm-units-migration.json"
)
SETTLED = ("green", "structural_ineligible")


def _units(queue: Any) -> list[dict[str, Any]]:
    return queue["units"] if isinstance(queue, dict) else queue


def _fnset(unit: dict[str, Any]) -> frozenset[str]:
    return frozenset(unit.get("exported_functions", []))


def migrate_state(
    old_queue: Any, old_state: dict[str, Any], new_queue: Any
) -> tuple[dict[str, Any], dict[str, Any]]:
    """(new state dict, migration report dict). Pure — no file IO."""
    old_by_name = {u["name"]: u for u in _units(old_queue)}
    new_units = _units(new_queue)
    new_by_set: dict[frozenset[str], list[str]] = {}
    for u in new_units:
        new_by_set.setdefault(_fnset(u), []).append(u["name"])

    new_state: dict[str, Any] = {
        "state_schema": old_state.get("state_schema", 1),
        "created_at": old_state.get("created_at"),
        "units": {u["name"]: {"status": "pending", "attempts": 0} for u in new_units},
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }
    entries: list[dict[str, Any]] = []
    carried = dropped = reset = 0
    for old_name, record in old_state.get("units", {}).items():
        status = record.get("status", "pending")
        if status == "pending":
            continue
        old_unit = old_by_name.get(old_name)
        old_set = _fnset(old_unit) if old_unit else frozenset()
        if status not in SETTLED:
            reset += 1
            entries.append(
                {
                    "old_unit": old_name,
                    "verdict": status,
                    "disposition": "reset_unsettled",
                }
            )
            continue
        targets = new_by_set.get(old_set, []) if old_set else []
        if len(targets) == 1:
            new_state["units"][targets[0]] = dict(record)
            carried += 1
            entries.append(
                {
                    "old_unit": old_name,
                    "verdict": status,
                    "disposition": "carried",
                    "new_unit": targets[0],
                }
            )
        else:
            # 0 targets: the set was re-batched. >1: ambiguous — never guess.
            dropped += 1
            overlapping = sorted(
                u["name"] for u in new_units if old_set & _fnset(u)
            )
            entries.append(
                {
                    "old_unit": old_name,
                    "verdict": status,
                    "disposition": "dropped_set_changed",
                    "new_units_overlapping": overlapping,
                }
            )
    report = {
        "note": (
            "Queue regeneration verdict migration: settled verdicts carry only "
            "onto a new unit with the IDENTICAL exported-function set; "
            "otherwise the new units stay pending and the old verdict is "
            "recorded here."
        ),
        "migrated_at": new_state["updated_at"],
        "summary": {
            "old_units": len(old_by_name),
            "new_units": len(new_units),
            "carried": carried,
            "dropped_set_changed": dropped,
            "reset_unsettled": reset,
        },
        "entries": entries,
    }
    return new_state, report


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--repo", default=r"D:\GotYaForce")
    ap.add_argument(
        "--old-queue",
        required=True,
        help="backup of wasm-units.json taken BEFORE the --rebuild refill",
    )
    ap.add_argument("--state", default=STATE_DEFAULT)
    ap.add_argument("--report", default=MIGRATION_REPORT_DEFAULT)
    args = ap.parse_args()

    repo_root = Path(args.repo)
    state_path = repo_root / args.state
    old_queue = json.loads(Path(args.old_queue).read_text(encoding="utf-8"))
    old_state = json.loads(state_path.read_text(encoding="utf-8"))
    new_queue = json.loads((repo_root / QUEUE_DEFAULT).read_text(encoding="utf-8"))

    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    backup = state_path.with_name(state_path.name + f".bak-{stamp}")
    shutil.copy2(state_path, backup)

    new_state, report = migrate_state(old_queue, old_state, new_queue)
    with open(state_path, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(new_state, fh, indent=1)
    report_path = repo_root / args.report
    with open(report_path, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(report, fh, indent=1)

    print(f"state backup: {backup}")
    print(json.dumps(report["summary"], indent=1))


if __name__ == "__main__":
    main()
