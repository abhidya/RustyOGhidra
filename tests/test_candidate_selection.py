import json
from pathlib import Path

import pytest

from src.candidate_selection import annotate_family_unit


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")


def _fixture_repo(tmp_path: Path, status: str = "missing") -> Path:
    _write_json(
        tmp_path / "packages/combat/src/data/actionStreamTables.json",
        {
            "borgs": {
                "pl0a00": {
                    "constructorAddress": "0x80091824",
                    "actions": {
                        "0": {
                            "handler": "0x80091ab0",
                            "variantTable": "0x802db448",
                            "variants": {},
                        }
                    },
                }
            }
        },
    )
    _write_json(
        tmp_path / "packages/combat/src/data/borgMoveProperties.json",
        {
            "borgs": {
                "pl0a00": {
                    "wikiTitle": "Wing Soldier",
                    "moves": [{"name": "Wing Sword"}],
                }
            }
        },
    )
    _write_json(
        tmp_path / "research/decomp/data/family-state-machine-coverage.json",
        {
            "families": [
                {
                    "constructorAddress": "0x80091824",
                    "members": ["pl0a00"],
                    "implementationMembers": [],
                    "actions": [
                        {
                            "actionIndex": 0,
                            "status": status,
                            "romEvidence": ["confirmed command/root join"],
                        }
                    ],
                }
            ]
        },
    )
    return tmp_path


def test_selection_attaches_confirmed_missing_destination_gap(tmp_path: Path):
    repo = _fixture_repo(tmp_path)
    artifact = tmp_path / "probe.json"
    _write_json(
        artifact,
        {
            "unit_id": "state-machine-80091ab0",
            "root_addresses": ["0x80091ab0"],
            "evidence": [],
        },
    )

    selected = annotate_family_unit(
        artifact_path=artifact,
        repo_root=repo,
        borg_id="pl0a00",
        action_index=0,
    )

    assert selected["destination_gap"]["status"] == "missing"
    assert selected["destination_gap"]["name"] == "Wing Soldier"
    assert selected["destination_gap"]["move_properties"][0]["name"] == "Wing Sword"
    assert selected["evidence"][-1]["kind"] == "destination_audit"


def test_selection_rejects_already_ported_slot(tmp_path: Path):
    repo = _fixture_repo(tmp_path, status="ported")
    artifact = tmp_path / "probe.json"
    _write_json(
        artifact,
        {
            "unit_id": "state-machine-80091ab0",
            "root_addresses": ["0x80091ab0"],
            "evidence": [],
        },
    )

    with pytest.raises(ValueError, match="not a gap"):
        annotate_family_unit(
            artifact_path=artifact,
            repo_root=repo,
            borg_id="pl0a00",
            action_index=0,
        )
