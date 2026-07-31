"""CLI for exporting one validated function-level port artifact."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path

from src.config import get_config
from src.custom_api_client import CustomAPIClient
from src.external_client import ExternalClient
from src.ghidra_client import GhidraMCPClient, PyGhidraClient
from src.ollama_client import OllamaClient
from src.port_evidence import CollectedFunction, collect_function_evidence
from src.port_exporter import export_port_artifact, historical_summary


class FixtureLLM:
    default_model = "fixture"

    def __init__(self, response: str, mode: str = "fixture"):
        self.response = response
        self.mode = mode

    def generate_structured(self, **_kwargs):
        return self.response, self.mode


def _llm_for_config(config):
    provider = getattr(config, "llm_provider", "ollama")
    if provider == "custom_api":
        return CustomAPIClient(config.custom_api), "custom_api", config.custom_api.model
    if provider in {"external", "google"}:
        return ExternalClient(config=config.external), "external", getattr(config.external, "model", "configured")
    return OllamaClient(config=config.ollama), "ollama", getattr(config.ollama, "model", "configured")


def _ghidra_for_config(config, llm):
    if getattr(config.ghidra, "backend", "http") == "pyghidra":
        if PyGhidraClient is None:
            raise RuntimeError("pyGhidra backend requested but PyGhidraClient is unavailable")
        return PyGhidraClient(config=config.ghidra, ollama_client=llm)
    return GhidraMCPClient(config=config.ghidra, ollama_client=llm)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--address", required=True, help="Function address, e.g. 0x8012b458")
    parser.add_argument("--output", required=True, help="Versioned artifact JSON destination")
    parser.add_argument("--session", help="Historical session.json; read-only, with a sidecar reference written")
    parser.add_argument(
        "--requirements-file",
        help="Deterministic downstream requirements appended to the model prompt",
    )
    parser.add_argument("--evidence-file", help="Previously collected CollectedFunction JSON")
    parser.add_argument("--model-response", help="Saved structured model response for deterministic replay")
    parser.add_argument("--model", help="Override the configured generation model for this export")
    parser.add_argument(
        "--response-provider",
        help="Original provider provenance for --model-response (default: fixture)",
    )
    parser.add_argument(
        "--response-model",
        help="Original model provenance for --model-response (default: fixture)",
    )
    parser.add_argument(
        "--response-mode",
        choices=["tool_call", "json_schema", "plain_json", "fixture"],
        help="Original structured-output mode for --model-response (default: fixture)",
    )
    parser.add_argument("--binary", help="Optional local binary used only to record SHA-256 provenance")
    parser.add_argument("--ghidra-backend", choices=["http", "pyghidra"])
    parser.add_argument("--ghidra-install-dir", help="Ghidra installation directory for pyGhidra")
    parser.add_argument("--pyghidra-project", help="Existing .gpr/project path")
    parser.add_argument("--pyghidra-program", help="Program name or project path, e.g. boot.dol")
    args = parser.parse_args(argv)

    session_summary = historical_summary(args.session, args.address) if args.session else None
    config = get_config()
    if args.model:
        config.custom_api.model = args.model
        config.ollama.model = args.model
        config.external.model = args.model
    if args.ghidra_backend:
        config.ghidra.backend = args.ghidra_backend
    if args.ghidra_install_dir:
        os.environ["GHIDRA_INSTALL_DIR"] = str(Path(args.ghidra_install_dir).resolve())
    if args.pyghidra_project:
        config.ghidra.pyghidra_project_path = args.pyghidra_project
    if args.pyghidra_program:
        config.ghidra.pyghidra_program = args.pyghidra_program

    if args.model_response:
        llm = FixtureLLM(
            Path(args.model_response).read_text(encoding="utf-8"),
            mode=args.response_mode or "fixture",
        )
        provider = args.response_provider or "fixture"
        model_name = args.response_model or "fixture"
    else:
        llm, provider, model_name = _llm_for_config(config)

    if args.evidence_file:
        collected = CollectedFunction.model_validate_json(Path(args.evidence_file).read_text(encoding="utf-8"))
    else:
        ghidra = _ghidra_for_config(config, llm)
        try:
            if not ghidra.health_check():
                raise RuntimeError(
                    "Ghidra backend is unavailable. Start the configured Ghidra service or pass --evidence-file."
                )
            collected = collect_function_evidence(ghidra, args.address, session_summary=session_summary)
        finally:
            close = getattr(ghidra, "close", None)
            if callable(close):
                close()

    if args.binary:
        binary_path = Path(args.binary)
        collected.program.sha256 = hashlib.sha256(binary_path.read_bytes()).hexdigest()

    result = export_port_artifact(
        collected=collected,
        llm=llm,
        output_path=args.output,
        model_provider=provider,
        model_name=model_name,
        session_path=args.session,
        generation_requirements=(
            Path(args.requirements_file).read_text(encoding="utf-8")
            if args.requirements_file
            else None
        ),
    )
    print(
        json.dumps(
            {
                "artifact": str(result.output_path.resolve()),
                "function": result.artifact.function.address,
                "model": result.artifact.producer.model_name,
                "structured_output_mode": result.artifact.producer.structured_output_mode,
                "attempts": result.attempts,
                "passed": result.report.passed,
                "checks_passed": result.report.checks_passed,
                "checks_failed": result.report.checks_failed,
                "model_metrics": getattr(llm, "generation_metrics", {}),
                "collection_metrics": collected.collection_metrics,
            },
            indent=2,
        )
    )
    return 0 if result.report.passed else 2
