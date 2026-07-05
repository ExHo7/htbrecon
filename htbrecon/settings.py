"""Optional user configuration for tool paths and wordlists.

Resolution never fails hard: a missing or malformed config file simply yields
no overrides. Environment variables always take precedence over the config
file so a one-off run can override without editing anything.

  Env:    HTBRECON_TOOL_<NAME>       e.g. HTBRECON_TOOL_WHATWEB=/opt/tools/WhatWeb/whatweb
          HTBRECON_WORDLIST_<KIND>   e.g. HTBRECON_WORDLIST_DIRECTORIES=/path/list.txt
  File:   ~/.config/htbrecon/config.toml
            [tools]
            whatweb = "/opt/tools/WhatWeb/whatweb"
            [wordlists]
            directories = "/path/to/common.txt"
"""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path

CONFIG_PATH = Path.home() / ".config" / "htbrecon" / "config.toml"


@lru_cache(maxsize=1)
def _load_config() -> dict:
    """Load the TOML config once. Returns {} if absent/unreadable/unsupported."""
    if not CONFIG_PATH.exists():
        return {}
    try:
        import tomllib
    except ModuleNotFoundError:
        return {}
    try:
        with CONFIG_PATH.open("rb") as fh:
            return tomllib.load(fh)
    except (OSError, tomllib.TOMLDecodeError):
        return {}


def _env_key(prefix: str, name: str) -> str:
    return f"{prefix}_{name.upper().replace('-', '_')}"


def tool_override(name: str) -> str | None:
    """Configured path/command override for a tool, or None.

    Priority: env ``HTBRECON_TOOL_<NAME>`` > config ``[tools].<name>``.
    """
    env = os.environ.get(_env_key("HTBRECON_TOOL", name))
    if env:
        return env
    val = _load_config().get("tools", {}).get(name)
    return val if isinstance(val, str) and val else None


def wordlist_override(kind: str) -> str | None:
    """Configured wordlist path override for a kind, or None.

    Priority: env ``HTBRECON_WORDLIST_<KIND>`` > config ``[wordlists].<kind>``.
    """
    env = os.environ.get(_env_key("HTBRECON_WORDLIST", kind))
    if env:
        return env
    val = _load_config().get("wordlists", {}).get(kind)
    return val if isinstance(val, str) and val else None
