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


def test_the_empty_response_error_names_the_cause():
    """The bare symptom cost two misdiagnoses -- a reasoning spiral, then a
    context-budget theory. finish_reason separates the cases that need
    different fixes, so it must be in the message."""
    from src.custom_api_client import describe_empty_response

    spiral = describe_empty_response(
        {"choices": [{"message": {"content": ""}, "finish_reason": "length"}],
         "usage": {"prompt_tokens": 6955, "completion_tokens": 8192}},
        reasoning_text="x" * 40000,
    )
    assert "finish_reason='length'" in spiral
    assert "completion_tokens=8192" in spiral
    assert "reasoning_chars=40000" in spiral

    chose_silence = describe_empty_response(
        {"choices": [{"message": {"content": ""}, "finish_reason": "stop"}], "usage": {}}
    )
    assert "finish_reason='stop'" in chose_silence

    malformed = describe_empty_response({"choices": []})
    assert "finish_reason=None" in malformed
    assert "choices=0" in malformed

    assert "choices=absent" in describe_empty_response({})
    assert "choices=absent" in describe_empty_response(None)


def test_cancel_on_abandon_waits_for_the_slot_before_reloading(monkeypatch):
    """Retrying blind across the unload/reload window is what turned one slow
    generation into a cascade: three 1200s timeouts, then a stub response with
    finish_reason='stop' and prompt_tokens=0 -- a server that never processed a
    prompt because it was still reloading. That stub became the unit's verdict."""
    from src.custom_api_client import CustomAPIClient

    client = CustomAPIClient.__new__(CustomAPIClient)
    order: list[str] = []
    client.max_seq_length = 32768
    client.default_model = "vendor/model"
    client.verify_ssl = False
    client.logger = type("L", (), {"warning": lambda *a, **k: None,
                                   "info": lambda *a, **k: None})()
    client._log_llm_interaction = lambda *a, **k: None
    client._admin_base_url = lambda: "http://h"
    client._admin_headers = lambda: {}
    client._issue_serving_load = lambda: order.append("load")
    client._wait_for_slot_empty = lambda timeout: (order.append("wait-empty"), True)[1]
    client._wait_for_model_ready = lambda timeout: (order.append("wait-ready"), True)[1]

    import requests as _requests
    monkeypatch.setattr(
        _requests, "post", lambda *a, **k: order.append("unload") or type("R", (), {})()
    )

    client._cancel_abandoned_generation("ReadTimeout")

    # The slot must be proven empty before the reload, and the model proven
    # resident before the caller retries.
    assert order == ["unload", "wait-empty", "load", "wait-ready"]
