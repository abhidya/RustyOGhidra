"""Attach deterministic GotYaForce destination-gap evidence to a probe artifact."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from src.port_workflow import atomic_write_json


def annotate_family_unit(
    *,
    artifact_path: Path,
    repo_root: Path,
    borg_id: str,
    action_index: int,
) -> dict[str, Any]:
    repo_root = repo_root.resolve()
    artifact_path = artifact_path.resolve()
    artifact = json.loads(artifact_path.read_text(encoding="utf-8"))
    action_data = json.loads(
        (repo_root / "packages/combat/src/data/actionStreamTables.json").read_text(
            encoding="utf-8"
        )
    )
    move_data = json.loads(
        (repo_root / "packages/combat/src/data/borgMoveProperties.json").read_text(
            encoding="utf-8"
        )
    )
    coverage_path = (
        repo_root / "research/decomp/data/family-state-machine-coverage.json"
    )
    coverage = json.loads(coverage_path.read_text(encoding="utf-8"))

    borg = action_data["borgs"].get(borg_id)
    if borg is None:
        raise ValueError(f"unknown borg id: {borg_id}")
    action = borg.get("actions", {}).get(str(action_index))
    if action is None:
        raise ValueError(f"{borg_id} has no live action {action_index}")
    roots = {str(value).lower() for value in artifact.get("root_addresses", [])}
    if str(action.get("handler", "")).lower() not in roots:
        raise ValueError(
            f"probe root {sorted(roots)} does not match action handler {action.get('handler')}"
        )

    family = next(
        (
            item
            for item in coverage["families"]
            if item["constructorAddress"].lower()
            == str(borg["constructorAddress"]).lower()
        ),
        None,
    )
    if family is None:
        raise ValueError(f"coverage has no family for {borg['constructorAddress']}")
    slot = next(
        (
            item
            for item in family["actions"]
            if item["actionIndex"] == action_index
        ),
        None,
    )
    if slot is None or slot["status"] not in {"missing", "partial"}:
        status = slot["status"] if slot else "absent"
        raise ValueError(f"destination slot is not a gap: {status}")

    move = move_data.get(borg_id) or move_data.get("borgs", {}).get(borg_id, {})
    gap = {
        "borg_id": borg_id,
        "name": move.get("wikiTitle"),
        "constructor_address": borg["constructorAddress"],
        "action_index": action_index,
        "status": slot["status"],
        "members": family["members"],
        "implementation_members": family["implementationMembers"],
        "move_properties": move.get("moves", []),
        "rom_action": action,
        "audit_evidence": slot["romEvidence"],
    }
    artifact["destination_gap"] = gap
    artifact["destination_context_paths"] = [
        "packages/combat/src/bridge.ts",
        "packages/combat/src/families/shared-engine.ts",
        "packages/combat/src/families/wave-b-catch-all.ts",
        "packages/combat/src/rom/rom.selfcheck.ts",
    ]
    artifact["existing_destination_code"] = [
        f"deterministic audit status: {slot['status']}",
        f"implemented family members: {family['implementationMembers']}",
        f"presentation-only asset mapping exists for {borg_id}",
    ]
    artifact.setdefault("evidence", []).append(
        {
            "kind": "destination_audit",
            "source": (
                "research/decomp/data/family-state-machine-coverage.json:"
                f"{borg['constructorAddress']}:{action_index}"
            ),
            "detail": json.dumps(gap, sort_keys=True),
            "confidence": "confirmed",
        }
    )
    atomic_write_json(artifact_path, artifact)
    return artifact


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifact", type=Path, required=True)
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument("--borg", required=True)
    parser.add_argument("--action-index", type=int, required=True)
    args = parser.parse_args(argv)
    artifact = annotate_family_unit(
        artifact_path=args.artifact,
        repo_root=args.repo_root,
        borg_id=args.borg.lower(),
        action_index=args.action_index,
    )
    print(
        json.dumps(
            {
                "unit_id": artifact["unit_id"],
                "destination_gap": artifact["destination_gap"],
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
