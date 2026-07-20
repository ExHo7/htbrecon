"""Unit tests for the LLM provider resolution + helpers (no network)."""

from __future__ import annotations

import pytest

from htbrecon import llm


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    """Start each test from a known-empty LLM env."""
    monkeypatch.delenv("HTBRECON_LLM_PROVIDER", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)


def test_explicit_anthropic(monkeypatch):
    monkeypatch.setenv("HTBRECON_LLM_PROVIDER", "anthropic")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    assert llm.active_provider() == "anthropic"


def test_explicit_anthropic_without_key(monkeypatch):
    monkeypatch.setenv("HTBRECON_LLM_PROVIDER", "anthropic")
    assert llm.active_provider() is None


def test_explicit_ollama(monkeypatch):
    monkeypatch.setenv("HTBRECON_LLM_PROVIDER", "ollama")
    assert llm.active_provider() == "ollama"


def test_auto_with_key_prefers_anthropic(monkeypatch):
    monkeypatch.setenv("HTBRECON_LLM_PROVIDER", "auto")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    assert llm.active_provider() == "anthropic"


def test_auto_without_key_falls_back_to_ollama(monkeypatch):
    monkeypatch.setenv("HTBRECON_LLM_PROVIDER", "auto")
    assert llm.active_provider() == "ollama"


def test_default_is_auto(monkeypatch):
    # No HTBRECON_LLM_PROVIDER set at all.
    assert llm.active_provider() == "ollama"
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    assert llm.active_provider() == "anthropic"


def test_anthropic_model_defaults(monkeypatch):
    monkeypatch.delenv("HTBRECON_ANTHROPIC_MODEL_SMALL", raising=False)
    monkeypatch.delenv("HTBRECON_ANTHROPIC_MODEL_LARGE", raising=False)
    assert llm._anthropic_model("small") == "claude-haiku-4-5-20251001"
    assert llm._anthropic_model("large") == "claude-sonnet-5"


def test_anthropic_model_env_override(monkeypatch):
    monkeypatch.setenv("HTBRECON_ANTHROPIC_MODEL_SMALL", "claude-custom-small")
    monkeypatch.setenv("HTBRECON_ANTHROPIC_MODEL_LARGE", "claude-custom-large")
    assert llm._anthropic_model("small") == "claude-custom-small"
    assert llm._anthropic_model("large") == "claude-custom-large"


def test_anthropic_model_blank_falls_back(monkeypatch):
    monkeypatch.setenv("HTBRECON_ANTHROPIC_MODEL_SMALL", "   ")
    assert llm._anthropic_model("small") == "claude-haiku-4-5-20251001"


def test_strip_think():
    assert llm._strip_think("<think>reasoning here</think>\n{\"a\":1}") == '{"a":1}'
    assert llm._strip_think("no think tags") == "no think tags"
    multiline = "<think>\nline1\nline2\n</think>\nanswer"
    assert llm._strip_think(multiline) == "answer"
