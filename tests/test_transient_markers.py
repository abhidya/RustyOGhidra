"""Migrated from tests/test_palworld_watchdog.py when machine supervision moved
to the rig (2026-08-16). This assertion is about the PORT stack's pause rule,
not about machine supervision, so it stays in RustyOGhidra."""


def test_http_error_body_reaches_transient_markers():
    # The client appends the response body to HTTPError messages; the workflow's
    # pause rule must match the unloaded-model body text.
    from src.port_chunk_workflow import TRANSIENT_MARKERS

    message = (
        "HTTPError: 400 Client Error: Bad Request for url: "
        "http://127.0.0.1:8888/v1/chat/completions | body: "
        '{"error": "No model loaded. Load a model first."}'
    )
    assert any(marker in message.lower() for marker in TRANSIENT_MARKERS)
