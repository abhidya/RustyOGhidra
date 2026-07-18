#!/usr/bin/env python3
"""Validate 1:1 port dossiers and compare ROM/port traces."""

import argparse
import json
import sys
from pathlib import Path

from src.port_workflow import atomic_write_json, build_evidence_bundle, compare_traces, load_trace, validate_dossier


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    validate = commands.add_parser("validate")
    validate.add_argument("dossier")
    compare = commands.add_parser("compare-traces")
    compare.add_argument("rom_trace")
    compare.add_argument("port_trace")
    compare.add_argument("--fields", nargs="*")
    compare.add_argument("--tolerance", type=float, default=1e-6)
    bundle = commands.add_parser("bundle")
    bundle.add_argument("--family", required=True)
    bundle.add_argument("--action-index", required=True, type=int)
    bundle.add_argument("--constructor")
    bundle.add_argument(
        "--source",
        action="append",
        default=[],
        metavar="TIER:KIND:PATH",
        help="Repeat for each source, e.g. authoritative:decompile:chunk_0047.c",
    )
    bundle.add_argument("--manifest-only", action="store_true")
    bundle.add_argument("--output", required=True)
    args = parser.parse_args(argv)

    if args.command == "validate":
        payload = json.loads(Path(args.dossier).read_text(encoding="utf-8"))
        result = validate_dossier(payload)
        print(json.dumps({"valid": result.valid, "errors": result.errors, "warnings": result.warnings}, indent=2))
        return 0 if result.valid else 1

    if args.command == "bundle":
        sources = []
        for value in args.source:
            try:
                tier, kind, path = value.split(":", 2)
            except ValueError:
                parser.error(f"invalid --source {value!r}; expected TIER:KIND:PATH")
            sources.append({"tier": tier, "kind": kind, "path": path})
        scope = {"family": args.family, "actionIndex": args.action_index}
        if args.constructor:
            scope["constructorAddress"] = args.constructor
        payload = build_evidence_bundle(scope, sources, include_content=not args.manifest_only)
        atomic_write_json(args.output, payload)
        print(json.dumps({"output": str(Path(args.output).resolve()), "sources": len(sources)}, indent=2))
        return 0

    result = compare_traces(
        load_trace(args.rom_trace),
        load_trace(args.port_trace),
        fields=args.fields,
        tolerance=args.tolerance,
    )
    print(json.dumps(result, indent=2))
    return 0 if result["match"] else 2


if __name__ == "__main__":
    sys.exit(main())
