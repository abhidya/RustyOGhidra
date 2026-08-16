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
