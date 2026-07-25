from __future__ import annotations

import pytest

from graft.provider import openai_compatible_provider_from_env


def test_provider_requires_external_credential(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GRAFT_LLM_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)

    with pytest.raises(RuntimeError, match="missing API key"):
        openai_compatible_provider_from_env(model="test-model")
