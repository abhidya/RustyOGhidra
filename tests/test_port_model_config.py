"""The single authoritative port-model configuration.

Regression source: on 2026-08-16 two components claimed ownership of the one
Unsloth serving slot because each carried its own model literal. These tests
pin the resolver's contract, and assert that no module-level model literal has
crept back into the code that resolves it.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from src import port_model_config
from src.port_model_config import (
    PortModelConfig,
    read_env_file,
    resolve_port_model_config,
)

ENV_BODY = """\
LLM_PROVIDER=custom_api
CUSTOM_API_URL=http://127.0.0.1:8888/v1/chat/completions
CUSTOM_API_KEY=sk-secret
CUSTOM_API_MODEL=vendor/Model-27B-GGUF
CUSTOM_API_GGUF_VARIANT=ud-q4_k_xl
CUSTOM_API_MAX_SEQ_LEN=32768
OGHIDRA_PORT_MODE=wasm_units
# a comment = not a key
"""


@pytest.fixture
def env_file(tmp_path: Path) -> Path:
    path = tmp_path / ".env"
    path.write_text(ENV_BODY, encoding="utf-8")
    return path


def test_resolves_every_field(env_file):
    config = resolve_port_model_config(env_file)
    assert config.model == "vendor/Model-27B-GGUF"
    assert config.gguf_variant == "ud-q4_k_xl"
    assert config.max_seq_length == 32768
    assert config.admin_base_url == "http://127.0.0.1:8888"
    assert config.chat_url == "http://127.0.0.1:8888/v1/chat/completions"
    assert config.port_mode == "wasm_units"
    assert config.source == str(env_file)


def test_env_file_wins_over_the_process_environment(env_file, monkeypatch):
    """config.py calls load_dotenv(override=True); anything that resolves
    env-first would disagree with what the port stack actually dials."""
    monkeypatch.setenv("CUSTOM_API_MODEL", "vendor/Something-Else")
    assert resolve_port_model_config(env_file).model == "vendor/Model-27B-GGUF"


def test_process_environment_fills_keys_absent_from_the_file(tmp_path, monkeypatch):
    path = tmp_path / ".env"
    path.write_text("CUSTOM_API_URL=http://127.0.0.1:8888/v1/chat/completions\n", encoding="utf-8")
    monkeypatch.setenv("CUSTOM_API_MODEL", "vendor/From-Env")
    assert resolve_port_model_config(path).model == "vendor/From-Env"


def test_context_falls_back_to_the_port_context_pin(tmp_path, monkeypatch):
    # Another test may have imported src.config, whose load_dotenv(override=True)
    # leaks the real .env into os.environ; the fallback under test is the
    # in-file one.
    monkeypatch.delenv("CUSTOM_API_MAX_SEQ_LEN", raising=False)
    path = tmp_path / ".env"
    path.write_text(
        "CUSTOM_API_URL=http://h/v1/chat/completions\nOGHIDRA_PORT_CONTEXT_TOKENS=131072\n",
        encoding="utf-8",
    )
    assert resolve_port_model_config(path).max_seq_length == 131072


def test_utf8_bom_does_not_corrupt_the_first_key(tmp_path):
    path = tmp_path / ".env"
    path.write_text(ENV_BODY, encoding="utf-8-sig")   # PowerShell-written files
    assert resolve_port_model_config(path).model == "vendor/Model-27B-GGUF"


def test_comments_and_quotes_are_handled(tmp_path):
    path = tmp_path / ".env"
    path.write_text(
        '# CUSTOM_API_MODEL=commented/out\nCUSTOM_API_MODEL="vendor/Quoted"\n',
        encoding="utf-8",
    )
    assert read_env_file(path)["CUSTOM_API_MODEL"] == "vendor/Quoted"


def test_public_dict_never_leaks_the_api_key(env_file):
    payload = resolve_port_model_config(env_file).to_public_dict()
    assert "api_key" not in payload
    assert payload["api_key_present"] is True


def test_missing_file_degrades_without_raising(tmp_path):
    config = resolve_port_model_config(tmp_path / "absent.env")
    assert isinstance(config, PortModelConfig)
    assert config.source == "process environment"


def test_the_resolver_source_contains_no_model_literal():
    """Structural guard: this module must not be able to name a model.

    Prose may (and does) recount the incident by name; executable code may not.
    So the check runs over string constants that are not docstrings.
    """
    import ast

    tree = ast.parse(Path(port_model_config.__file__).read_text(encoding="utf-8"))
    docstrings = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            body = getattr(node, "body", [])
            if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant):
                docstrings.add(id(body[0].value))
    literals = [
        node.value.lower()
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and id(node) not in docstrings
    ]
    for text in literals:
        for banned in ("qwen", "27b", "35b", "llama-", "mistral"):
            assert banned not in text, f"model literal {banned!r} leaked into {text!r}"


def test_the_live_env_is_the_configured_source_of_truth():
    """The real checkout resolves a usable configuration."""
    config = resolve_port_model_config()
    assert config.model
    assert config.admin_base_url.startswith("http")
    assert config.source.endswith(".env")
