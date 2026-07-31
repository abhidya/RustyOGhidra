import json
import os

import pytest

from src import port_workflow


@pytest.mark.skipif(os.name != "nt", reason="Windows sharing-violation behavior")
def test_atomic_write_json_retries_transient_windows_file_lock(tmp_path, monkeypatch):
    target = tmp_path / "state.json"
    target.write_text('{"old":true}\n', encoding="utf-8")
    real_replace = os.replace
    attempts = 0

    def temporarily_locked(source, destination):
        nonlocal attempts
        attempts += 1
        if attempts < 3:
            raise PermissionError(5, "Access is denied")
        return real_replace(source, destination)

    monkeypatch.setattr(port_workflow.os, "replace", temporarily_locked)
    monkeypatch.setattr(port_workflow.time, "sleep", lambda _seconds: None)

    port_workflow.atomic_write_json(target, {"status": "running"})

    assert attempts == 3
    assert json.loads(target.read_text(encoding="utf-8")) == {"status": "running"}
