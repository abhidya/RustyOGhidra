"""Append-only activity events for the Finish Game Port dashboard."""

from __future__ import annotations

import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class PortActivity:
    """Small JSONL event sink shared by the detached worker and GUI."""

    def __init__(self, path: str | Path, *, run_id: str | None = None):
        self.path = Path(path)
        self._lock = threading.Lock()
        self.run_id = run_id or os.getenv("OGHIDRA_PORT_RUN_ID") or f"manual:{os.getpid()}"

    def emit(
        self,
        kind: str,
        title: str,
        content: str = "",
        *,
        address: str | None = None,
        status: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "run_id": self.run_id,
            "kind": kind,
            "title": title,
            "content": content,
            "address": address,
            "status": status,
            "metadata": metadata or {},
        }
        line = json.dumps(event, ensure_ascii=False) + "\n"
        with self._lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8", newline="\n") as handle:
                handle.write(line)
                handle.flush()
