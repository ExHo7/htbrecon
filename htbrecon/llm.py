"""Provider-agnostic LLM transport.

Centralises which LLM backend HTBRecon talks to (Anthropic cloud or a local
Ollama) and exposes a single ``complete`` coroutine. Call sites pass the same
system/user prompts regardless of provider — only the transport changes here.

Selection (env only):
    HTBRECON_LLM_PROVIDER = auto | anthropic | ollama   (default: auto)
        auto  -> anthropic if ANTHROPIC_API_KEY is set, else ollama
    ANTHROPIC_API_KEY      -> required for the anthropic provider
    OLLAMA_HOST            -> default http://localhost:11434
    HTBRECON_OLLAMA_MODEL  -> required for the ollama provider (no built-in default)
"""

from __future__ import annotations

import os
import re

from htbrecon.console import logger

_DEFAULT_OLLAMA_HOST = "http://localhost:11434"

# tier -> default Anthropic model id. "small" = fast structured tasks (tech
# normalisation, version filtering); "large" = the final attack-vector analysis.
# Each tier's model can be overridden from the environment / .env.
_ANTHROPIC_MODELS = {
    "small": "claude-haiku-4-5",
    "large": "claude-sonnet-5",
}
_ANTHROPIC_MODEL_ENV = {
    "small": "HTBRECON_ANTHROPIC_MODEL_SMALL",
    "large": "HTBRECON_ANTHROPIC_MODEL_LARGE",
}


def _anthropic_model(tier: str) -> str:
    """Resolve the Anthropic model id for a tier, honouring an env override."""
    default = _ANTHROPIC_MODELS.get(tier, _ANTHROPIC_MODELS["small"])
    env_var = _ANTHROPIC_MODEL_ENV.get(tier, "")
    return (os.environ.get(env_var, "").strip() if env_var else "") or default

# Thinking-capable Ollama models (e.g. qwen3.5) may emit <think>…</think> blocks
# before the real answer; strip them so JSON/Markdown consumers get clean text.
_THINK_RE = re.compile(r"<think>.*?</think>", re.DOTALL | re.IGNORECASE)


def active_provider() -> str | None:
    """Resolve the active LLM provider: "anthropic", "ollama", or None.

    None means no provider is usable and callers should skip AI / fall back.
    Availability of the chosen backend (key validity, ollama reachability,
    model configured) is verified lazily at call time, not here.
    """
    pref = os.environ.get("HTBRECON_LLM_PROVIDER", "auto").strip().lower()
    has_key = bool(os.environ.get("ANTHROPIC_API_KEY"))

    if pref == "anthropic":
        return "anthropic" if has_key else None
    if pref == "ollama":
        return "ollama"
    # auto
    return "anthropic" if has_key else "ollama"


async def complete(
    *,
    system: str,
    user: str,
    tier: str = "small",
    max_tokens: int = 1024,
    json_mode: bool = False,
) -> str | None:
    """Send a system+user chat to the active provider and return its text.

    Returns None when no provider is available or the call fails — never raises.
    ``json_mode`` hints the backend to emit JSON (Ollama: ``format=json``).
    """
    provider = active_provider()
    if provider == "anthropic":
        return await _complete_anthropic(system, user, tier, max_tokens)
    if provider == "ollama":
        return await _complete_ollama(system, user, max_tokens, json_mode)
    return None


def _strip_think(text: str) -> str:
    """Remove <think>…</think> blocks left by reasoning models."""
    return _THINK_RE.sub("", text).strip()


async def _complete_anthropic(
    system: str, user: str, tier: str, max_tokens: int
) -> str | None:
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        return None
    try:
        import anthropic
    except ImportError:
        logger.debug("anthropic package not installed")
        return None

    model = _anthropic_model(tier)
    try:
        client = anthropic.AsyncAnthropic(api_key=api_key)
        response = await client.messages.create(
            model=model,
            max_tokens=max_tokens,
            system=system,
            messages=[{"role": "user", "content": user}],
        )
        if not response.content:
            return None
        block = response.content[0]
        return block.text if hasattr(block, "text") else None
    except Exception as exc:
        logger.debug("anthropic completion failed: %s", exc)
        return None


async def _complete_ollama(
    system: str, user: str, max_tokens: int, json_mode: bool
) -> str | None:
    model = os.environ.get("HTBRECON_OLLAMA_MODEL", "").strip()
    if not model:
        logger.warning(
            "ollama: HTBRECON_OLLAMA_MODEL not set — define it in .env to enable the local LLM"
        )
        return None

    host = os.environ.get("OLLAMA_HOST", _DEFAULT_OLLAMA_HOST).strip().rstrip("/")
    if not host.startswith(("http://", "https://")):
        host = f"http://{host}"

    payload: dict = {
        "model": model,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        "stream": False,
        # Reasoning models otherwise spend the whole token budget on a <think>
        # block and never emit the answer; disable it so output is the answer.
        "think": False,
        "options": {"temperature": 0, "num_predict": max_tokens},
    }
    if json_mode:
        payload["format"] = "json"

    # Local generation is slow — a large-tier analysis on a 7-9B model can take
    # minutes. Generous default, overridable via HTBRECON_OLLAMA_TIMEOUT (seconds).
    try:
        timeout = float(os.environ.get("HTBRECON_OLLAMA_TIMEOUT", "600"))
    except ValueError:
        timeout = 600.0

    try:
        import httpx

        async with httpx.AsyncClient(timeout=timeout) as client:
            try:
                resp = await client.post(f"{host}/api/chat", json=payload)
                resp.raise_for_status()
            except httpx.HTTPStatusError:
                # Models without thinking support reject the option — retry without it.
                payload.pop("think", None)
                resp = await client.post(f"{host}/api/chat", json=payload)
                resp.raise_for_status()
            data = resp.json()
        content = (data.get("message") or {}).get("content", "")
        return _strip_think(content) if content else None
    except Exception as exc:
        # Some failures (e.g. ReadTimeout) stringify to "" — log the type too.
        logger.debug("ollama completion failed: %s: %s", type(exc).__name__, exc)
        return None
