"""Provider-neutral client for OpenAI-compatible LLM endpoints."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Any

import requests


def _json_value(text: str) -> Any:
    value = text.strip()
    if value.startswith("```"):
        lines = value.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        value = "\n".join(lines).strip()
    return json.loads(value)


@dataclass(slots=True)
class OpenAICompatibleProvider:
    api_key: str
    model: str
    base_url: str
    wire_api: str = "chat_completions"
    temperature: float = 0.2
    timeout: int = 120

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

    def _request_responses_text(self, *, system_prompt: str, user_prompt: str) -> str:
        response = requests.post(
            self.base_url.rstrip("/") + "/responses",
            headers=self._headers(),
            json={
                "model": self.model,
                "instructions": system_prompt,
                "input": user_prompt,
                "stream": False,
            },
            timeout=self.timeout,
        )
        response.raise_for_status()
        data = response.json()
        if (data.get("error") or {}).get("message"):
            raise RuntimeError(str(data["error"]["message"]))
        pieces = [
            str(content["text"])
            for output in data.get("output") or []
            for content in output.get("content") or []
            if content.get("type") == "output_text" and content.get("text")
        ]
        if not pieces:
            raise RuntimeError("LLM endpoint returned no output text")
        return "".join(pieces).strip()

    def _request_chat_text(self, *, system_prompt: str, user_prompt: str) -> str:
        response = requests.post(
            self.base_url.rstrip("/") + "/chat/completions",
            headers=self._headers(),
            json={
                "model": self.model,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                "temperature": self.temperature,
                "stream": False,
            },
            timeout=self.timeout,
        )
        response.raise_for_status()
        data = response.json()
        content = (((data.get("choices") or [{}])[0].get("message") or {}).get("content"))
        if not content:
            raise RuntimeError("LLM endpoint returned no message content")
        return str(content).strip()

    def complete_text(self, *, system_prompt: str, user_prompt: str) -> str:
        if self.wire_api == "responses":
            return self._request_responses_text(
                system_prompt=system_prompt,
                user_prompt=user_prompt,
            )
        return self._request_chat_text(system_prompt=system_prompt, user_prompt=user_prompt)

    def complete_json(self, *, system_prompt: str, user_prompt: str) -> Any:
        return _json_value(
            self.complete_text(system_prompt=system_prompt, user_prompt=user_prompt)
        )


def openai_compatible_provider_from_env(
    *,
    model: str | None = None,
    temperature: float = 0.2,
) -> OpenAICompatibleProvider:
    api_key = (
        os.getenv("GRAFT_LLM_API_KEY")
        or os.getenv("OPENAI_API_KEY")
        or ""
    ).strip()
    if not api_key:
        raise RuntimeError(
            "missing API key: set GRAFT_LLM_API_KEY or OPENAI_API_KEY"
        )
    base_url = (
        os.getenv("GRAFT_LLM_BASE_URL")
        or os.getenv("OPENAI_BASE_URL")
        or "https://api.openai.com/v1"
    ).strip()
    chosen_model = (model or os.getenv("GRAFT_LLM_MODEL") or "").strip()
    if not chosen_model:
        raise RuntimeError("missing model: pass --llm-model or set GRAFT_LLM_MODEL")
    wire_api = os.getenv("GRAFT_LLM_WIRE_API", "chat_completions").strip().lower()
    if wire_api not in {"chat_completions", "responses"}:
        raise RuntimeError(
            "GRAFT_LLM_WIRE_API must be chat_completions or responses"
        )
    timeout = int(os.getenv("GRAFT_LLM_TIMEOUT", "120"))
    return OpenAICompatibleProvider(
        api_key=api_key,
        model=chosen_model,
        base_url=base_url,
        wire_api=wire_api,
        temperature=temperature,
        timeout=timeout,
    )
