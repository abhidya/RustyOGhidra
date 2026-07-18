#!/usr/bin/env python3
"""Minimal OpenAI-compatible chat adapter for DeepAI.

OGhidra's custom provider speaks /v1/chat/completions. DeepAI uses a different
API shape, so this local Flask service translates requests without patching
OGhidra itself.
"""

from __future__ import annotations

import os
import time
from typing import Any

import requests
from dotenv import load_dotenv
from flask import Flask, jsonify, request


load_dotenv(".env.deepai")

app = Flask(__name__)

DEEPAI_ENDPOINT = os.getenv("DEEPAI_ENDPOINT", "https://api.deepai.org/api/chat_response")
DEEPAI_API_KEY = os.getenv("DEEPAI_API_KEY", "")
DEFAULT_MODEL = os.getenv("DEEPAI_MODEL", "deepai-chat")
REQUEST_TIMEOUT = int(os.getenv("DEEPAI_TIMEOUT", "300"))


def _message_text(messages: list[dict[str, Any]]) -> str:
    parts: list[str] = []
    for message in messages:
        role = message.get("role", "user")
        content = message.get("content", "")
        if isinstance(content, list):
            content = "\n".join(str(item.get("text", item)) for item in content)
        parts.append(f"{role}: {content}")
    return "\n\n".join(parts)


def _extract_text(data: Any) -> str:
    if isinstance(data, dict):
        for key in ("output", "text", "response", "message", "result"):
            value = data.get(key)
            if isinstance(value, str):
                return value
        return str(data)
    return str(data)


@app.get("/v1/models")
def models():
    return jsonify({"object": "list", "data": [{"id": DEFAULT_MODEL, "object": "model"}]})


@app.post("/v1/chat/completions")
def chat_completions():
    if not DEEPAI_API_KEY:
        return jsonify({"error": "DEEPAI_API_KEY is not set"}), 500

    payload = request.get_json(force=True)
    model = payload.get("model") or DEFAULT_MODEL
    messages = payload.get("messages") or []
    prompt = _message_text(messages)

    response = requests.post(
        DEEPAI_ENDPOINT,
        headers={"api-key": DEEPAI_API_KEY},
        data={"text": prompt},
        timeout=REQUEST_TIMEOUT,
    )
    if response.status_code >= 400:
        return jsonify({"error": response.text, "status_code": response.status_code}), 502
    text = _extract_text(response.json())

    return jsonify(
        {
            "id": f"deepai-{int(time.time() * 1000)}",
            "object": "chat.completion",
            "created": int(time.time()),
            "model": model,
            "choices": [{"index": 0, "message": {"role": "assistant", "content": text}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        }
    )


if __name__ == "__main__":
    port = int(os.getenv("DEEPAI_ADAPTER_PORT", "5010"))
    app.run(host="127.0.0.1", port=port)
