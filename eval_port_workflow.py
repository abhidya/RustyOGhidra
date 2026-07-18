#!/usr/bin/env python3
"""Deterministic mechanics benchmark for candidate versus reviewed port dossiers."""

import argparse
import json
import sys
from pathlib import Path

from src.port_workflow import validate_dossier


def keyed(rows, *keys):
    out = {}
    for index, row in enumerate(rows or []):
        if not isinstance(row, dict):
            continue
        key = next((str(row.get(name)) for name in keys if row.get(name) is not None), str(index))
        out[key] = row
    return out


def score(candidate, gold):
    candidate_validation = validate_dossier(candidate)
    gold_validation = validate_dossier(gold)
    candidate_claims = keyed(candidate.get("claims"), "claimId")
    gold_claims = keyed(gold.get("claims"), "claimId")
    recovered = set(candidate_claims) & set(gold_claims)
    exact_status = sum(candidate_claims[key].get("status") == gold_claims[key].get("status") for key in recovered)
    exact_statement = sum(
        " ".join(str(candidate_claims[key].get("statement", "")).lower().split())
        == " ".join(str(gold_claims[key].get("statement", "")).lower().split())
        for key in recovered
    )
    phases = keyed(candidate.get("phases"), "phaseId", "id", "index")
    gold_phases = keyed(gold.get("phases"), "phaseId", "id", "index")
    variants = keyed(candidate.get("variants"), "variantId", "id", "index")
    gold_variants = keyed(gold.get("variants"), "variantId", "id", "index")

    def ratio(numerator, denominator):
        return round(numerator / denominator, 3) if denominator else 1.0

    return {
        "candidateValid": candidate_validation.valid,
        "candidateErrors": candidate_validation.errors,
        "goldValid": gold_validation.valid,
        "claimRecall": ratio(len(recovered), len(gold_claims)),
        "claimPrecision": ratio(len(recovered), len(candidate_claims)),
        "statusAccuracy": ratio(exact_status, len(recovered)),
        "exactStatementRate": ratio(exact_statement, len(recovered)),
        "phaseRecovery": ratio(len(set(phases) & set(gold_phases)), len(gold_phases)),
        "variantRecovery": ratio(len(set(variants) & set(gold_variants)), len(gold_variants)),
        "boundaryTests": len(candidate.get("tests") or []),
        "namedBlockers": len(candidate.get("blockers") or []),
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("candidate")
    parser.add_argument("gold")
    parser.add_argument("--minimum-claim-recall", type=float, default=0.9)
    args = parser.parse_args(argv)
    candidate = json.loads(Path(args.candidate).read_text(encoding="utf-8"))
    gold = json.loads(Path(args.gold).read_text(encoding="utf-8"))
    result = score(candidate, gold)
    result["passed"] = bool(
        result["candidateValid"]
        and result["goldValid"]
        and result["claimRecall"] >= args.minimum_claim_recall
        and result["statusAccuracy"] == 1.0
        and result["phaseRecovery"] == 1.0
        and result["variantRecovery"] == 1.0
    )
    print(json.dumps(result, indent=2))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())

