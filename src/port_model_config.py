"""The single authoritative port-model configuration.

One place resolves which model the port stack serves, at which GGUF variant and
which served context. Everything else -- ``src/config.py``, the wasm-unit driver,
the machine contract (``src/port_contract.py``) and the rig supervisor -- reads
*this* answer instead of carrying its own literal.

Why this module exists (2026-08-16 incident): the retired RustyOGhidra watchdog
carried a hard-coded ``unsloth/Qwen3.6-35B-A3B-MTP-GGUF`` plus a
``"Qwen3.6-35B-A3B" in candidate`` recognition check, while the live pipeline had
moved to the 27B. Two components then believed they owned the single Unsloth
serving slot: the machine layer would evict a correct 27B to load its 35B, and a
correct 27B was reported as "wrong model". The fix is structural -- there is no
model literal anywhere in this file.

Resolution order matches ``src/config.py`` exactly. ``config.py`` calls
``load_dotenv(<oghidra_root>/.env, override=True)``, so **the .env file wins over
the process environment**; anything that resolves env-first would disagree with
what the port stack actually dials. Keys absent from the .env fall through to the
process environment.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any

# The .env that src/config.py loads (repo_root/.env, i.e. the OGhidra checkout
# root -- NOT src/.env, which is a dead LM Studio-era leftover).
OGHIDRA_ROOT = Path(__file__).resolve().parent.parent
ENV_PATH = OGHIDRA_ROOT / ".env"

_ASSIGNMENT = re.compile(r"^\s*(?!#)([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$")


def read_env_file(path: Path | str = ENV_PATH) -> dict[str, str]:
    """Parse a dotenv file the way python-dotenv does for our simple keys.

    utf-8-sig: pipeline files on this machine have carried a UTF-8 BOM (they were
    written by PowerShell), and a BOM on line 1 otherwise corrupts the first key.
    """
    try:
        text = Path(path).read_text(encoding="utf-8-sig")
    except OSError:
        return {}
    values: dict[str, str] = {}
    for line in text.splitlines():
        match = _ASSIGNMENT.match(line)
        if not match:
            continue
        key, raw = match.group(1), match.group(2)
        if len(raw) >= 2 and raw[0] == raw[-1] and raw[0] in "\"'":
            raw = raw[1:-1]
        values[key] = raw
    return values


@dataclass(frozen=True)
class PortModelConfig:
    """What the port stack serves. ``source`` names where the answer came from."""

    model: str
    gguf_variant: str
    max_seq_length: int
    chat_url: str
    admin_base_url: str
    api_key: str
    port_mode: str
    source: str

    @property
    def api_key_present(self) -> bool:
        return bool(self.api_key)

    def to_public_dict(self) -> dict[str, Any]:
        """Serialisable form with the API key redacted (this crosses a pipe)."""
        payload = asdict(self)
        payload.pop("api_key")
        payload["api_key_present"] = self.api_key_present
        return payload


def _admin_base_from_chat_url(chat_url: str) -> str:
    base = chat_url.strip()
    for suffix in ("/v1/chat/completions", "/chat/completions", "/v1"):
        if base.endswith(suffix):
            base = base[: -len(suffix)]
            break
    return base.rstrip("/")


def resolve_port_model_config(env_path: Path | str = ENV_PATH) -> PortModelConfig:
    """Resolve the one authoritative port-model configuration.

    .env wins over the process environment (see module docstring). Missing
    numeric values degrade to 0, which is the documented "serving-slot
    management is opt-out" signal in ``CustomAPIClient``.
    """
    env_path = Path(env_path)
    file_values = read_env_file(env_path)

    def value(key: str, default: str = "") -> str:
        if key in file_values:
            return file_values[key]
        return os.environ.get(key, default)

    try:
        max_seq_length = int(
            value("CUSTOM_API_MAX_SEQ_LEN") or value("OGHIDRA_PORT_CONTEXT_TOKENS") or 0
        )
    except ValueError:
        max_seq_length = 0

    chat_url = value("CUSTOM_API_URL")
    source = str(env_path) if file_values else "process environment"
    return PortModelConfig(
        model=value("CUSTOM_API_MODEL"),
        gguf_variant=value("CUSTOM_API_GGUF_VARIANT"),
        max_seq_length=max_seq_length,
        chat_url=chat_url,
        admin_base_url=_admin_base_from_chat_url(chat_url),
        api_key=value("CUSTOM_API_KEY"),
        port_mode=(value("OGHIDRA_PORT_MODE") or "chunks").strip().lower(),
        source=source,
    )
