import json
from types import SimpleNamespace

import requests

from src.custom_api_client import CustomAPIClient


def config():
    return SimpleNamespace(
        api_url="http://local.test/v1/chat/completions",
        api_key="test",
        model="qwen-test",
        request_delay=0,
        max_retries=0,
        adaptive_throttle_enabled=False,
        llm_logging_enabled=False,
        timeout=1,
        verify_ssl=False,
    )


class Response:
    status_code = 200

    def __init__(self, payload):
        self.payload = payload
        self.text = json.dumps(payload)

    def raise_for_status(self):
        return None

    def json(self):
        return self.payload


class StreamResponse(Response):
    def __init__(self, chunks):
        super().__init__({})
        self.chunks = chunks

    def iter_lines(self, decode_unicode=True):
        for chunk in self.chunks:
            yield f"data: {json.dumps(chunk)}"
        yield "data: [DONE]"


def test_generate_structured_uses_tool_call_arguments(monkeypatch):
    requests_seen = []

    def post(url, headers, json, timeout, verify):
        requests_seen.append(json)
        return Response(
            {
                "choices": [
                    {
                        "message": {
                            "content": None,
                            "tool_calls": [
                                {
                                    "function": {
                                        "name": "submit_port_model",
                                        "arguments": '{"analysis":{},"port_ir":null}',
                                    }
                                }
                            ],
                        }
                    }
                ]
            }
        )

    monkeypatch.setattr(requests, "post", post)
    client = CustomAPIClient(config())
    text, mode = client.generate_structured(
        prompt="port",
        schema={"type": "object"},
        tool_name="submit_port_model",
    )
    assert mode == "tool_call"
    assert json.loads(text)["port_ir"] is None
    assert requests_seen[0]["tool_choice"]["function"]["name"] == "submit_port_model"
    assert requests_seen[0]["tools"][0]["function"]["strict"] is True


def test_generate_structured_falls_back_to_json_schema(monkeypatch):
    requests_seen = []

    def post(url, headers, json, timeout, verify):
        requests_seen.append(json)
        if "tools" in json:
            response = Response({"error": "tools unsupported"})
            response.status_code = 400

            def fail():
                raise requests.exceptions.HTTPError("bad request", response=response)

            response.raise_for_status = fail
            return response
        return Response({"choices": [{"message": {"content": '{"analysis":{},"port_ir":null}'}}]})

    monkeypatch.setattr(requests, "post", post)
    client = CustomAPIClient(config())
    text, mode = client.generate_structured(
        prompt="port",
        schema={"type": "object"},
        tool_name="submit_port_model",
    )
    assert mode == "json_schema"
    assert json.loads(text)["analysis"] == {}
    assert requests_seen[1]["response_format"]["type"] == "json_schema"


def test_generate_structured_uses_json_schema_when_endpoint_ignores_tool_choice(monkeypatch):
    requests_seen = []

    def post(url, headers, json, timeout, verify):
        requests_seen.append(json)
        return Response({"choices": [{"message": {"content": '{"analysis":{},"port_ir":null}'}}]})

    monkeypatch.setattr(requests, "post", post)
    client = CustomAPIClient(config())
    text, mode = client.generate_structured(
        prompt="port",
        schema={"type": "object"},
        tool_name="submit_port_model",
    )
    assert mode == "json_schema"
    assert json.loads(text)["port_ir"] is None
    assert "tools" in requests_seen[0]
    assert requests_seen[1]["response_format"]["type"] == "json_schema"


def test_generate_structured_can_delegate_ignored_tool_plain_text_to_pydantic_caller(monkeypatch):
    requests_seen = []

    def post(url, headers, json, timeout, verify):
        requests_seen.append(json)
        return Response({"choices": [{"message": {"content": '{"analysis":{},"port_ir":null}'}}]})

    monkeypatch.setattr(requests, "post", post)
    client = CustomAPIClient(config())
    text, mode = client.generate_structured(
        prompt="port",
        schema={"type": "object"},
        tool_name="submit_port_model",
        accept_plain_tool_response=True,
    )
    assert mode == "plain_json"
    assert json.loads(text)["port_ir"] is None
    assert len(requests_seen) == 1


def test_generate_structured_can_prefer_json_schema_without_tool_probe(monkeypatch):
    requests_seen = []

    def post(url, headers, json, timeout, verify):
        requests_seen.append(json)
        return Response({"choices": [{"message": {"content": '{"analysis":{},"port_ir":null}'}}]})

    monkeypatch.setattr(requests, "post", post)
    client = CustomAPIClient(config())
    text, mode = client.generate_structured(
        prompt="port",
        schema={"type": "object"},
        tool_name="submit_port_model",
        prefer_json_schema=True,
    )
    assert mode == "json_schema"
    assert json.loads(text)["port_ir"] is None
    assert len(requests_seen) == 1
    assert "response_format" in requests_seen[0]
    assert "tools" not in requests_seen[0]


def test_generate_tracks_api_token_usage_and_throughput(monkeypatch, tmp_path):
    liveness = tmp_path / "llm-liveness.json"
    monkeypatch.setenv("OGHIDRA_PORT_LIVENESS_PATH", str(liveness))
    monkeypatch.setattr(
        requests,
        "post",
        lambda *args, **kwargs: Response(
            {
                "choices": [{"message": {"content": "model output"}}],
                "usage": {"prompt_tokens": 40, "completion_tokens": 10},
            }
        ),
    )

    client = CustomAPIClient(config())
    assert client.generate("test prompt") == "model output"

    metrics = json.loads(liveness.read_text())
    assert metrics["api_calls"] == 1
    assert metrics["prompt_tokens"] == 40
    assert metrics["completion_tokens"] == 10
    assert metrics["tokens_per_second"] > 0
    assert metrics["token_source"] == "api"
    assert metrics["active"] is False


def test_generate_estimates_tokens_when_api_omits_usage(monkeypatch, tmp_path):
    liveness = tmp_path / "llm-liveness.json"
    monkeypatch.setenv("OGHIDRA_PORT_LIVENESS_PATH", str(liveness))
    monkeypatch.setattr(
        requests,
        "post",
        lambda *args, **kwargs: Response(
            {"choices": [{"message": {"content": "hello world!"}}]}
        ),
    )

    client = CustomAPIClient(config())
    client.generate("one two")

    metrics = json.loads(liveness.read_text())
    assert metrics["completion_tokens"] == 3
    assert metrics["prompt_tokens"] >= 2
    assert metrics["tokens_per_second"] > 0
    assert metrics["token_source"] == "estimated"


def test_finish_game_structured_call_streams_tool_arguments_without_read_timeout(monkeypatch):
    request_seen = {}
    events = []

    def post(url, **kwargs):
        request_seen.update(kwargs)
        return StreamResponse(
            [
                {
                    "choices": [
                        {
                            "delta": {
                                "tool_calls": [
                                    {
                                        "function": {
                                            "name": "submit_browser_source_patch",
                                            "arguments": '{"summary":"done",',
                                        }
                                    }
                                ]
                            }
                        }
                    ]
                },
                {
                    "choices": [
                        {
                            "delta": {
                                "tool_calls": [
                                    {
                                        "function": {
                                            "arguments": '"action":"exclude","files":[]}'
                                        }
                                    }
                                ]
                            }
                        }
                    ]
                },
            ]
        )

    monkeypatch.setattr(requests, "post", post)
    client = CustomAPIClient(config())
    text, mode = client.generate_structured(
        prompt="port",
        schema={"type": "object"},
        tool_name="submit_browser_source_patch",
        phase="finish_game_source:0x80003100:attempt_1",
        stream_callback=lambda kind, payload: events.append((kind, payload)),
    )

    assert mode == "tool_call"
    assert json.loads(text)["action"] == "exclude"
    assert request_seen["timeout"] == (30, None)
    assert request_seen["stream"] is True
    assert request_seen["json"]["stream"] is True
    assert [kind for kind, _ in events] == [
        "tool_call_start",
        "tool_call_delta",
        "tool_call_delta",
    ]


def test_liveness_accumulates_across_clients_in_the_same_port_run(monkeypatch, tmp_path):
    liveness = tmp_path / "llm-liveness.json"
    monkeypatch.setenv("OGHIDRA_PORT_LIVENESS_PATH", str(liveness))
    monkeypatch.setenv("OGHIDRA_PORT_RUN_ID", "run-123")
    monkeypatch.setattr(
        requests,
        "post",
        lambda *args, **kwargs: Response(
            {
                "choices": [{"message": {"content": "ok"}}],
                "usage": {"prompt_tokens": 20, "completion_tokens": 5},
            }
        ),
    )

    CustomAPIClient(config()).generate("first")
    CustomAPIClient(config()).generate("second")

    metrics = json.loads(liveness.read_text())
    assert metrics["run_id"] == "run-123"
    assert metrics["api_calls"] == 2
    assert metrics["prompt_tokens"] == 40
    assert metrics["completion_tokens"] == 10
