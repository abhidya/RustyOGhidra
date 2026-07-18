#!/usr/bin/env python3
"""Smoke-test the DeepAI OpenAI-compatible adapter in-process."""

from __future__ import annotations

import json

import deepai_openai_adapter


payload = {
    "model": "deepai-chat",
    "messages": [{"role": "user", "content": "Reply with exactly OK."}],
    "max_tokens": 8,
    "temperature": 0,
}

client = deepai_openai_adapter.app.test_client()
response = client.post("/v1/chat/completions", json=payload)
print(response.status_code)
print(json.dumps(response.get_json(), indent=2))
