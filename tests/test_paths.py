from __future__ import annotations

from htbrecon import paths, settings


def _clear() -> None:
    settings._load_config.cache_clear()


def test_env_override(monkeypatch, tmp_path):
    wl = tmp_path / "list.txt"
    wl.write_text("root\nadmin\n", encoding="utf-8")
    monkeypatch.setenv("HTBRECON_WORDLIST_DIRECTORIES", str(wl))
    _clear()
    assert paths.resolve_wordlist("directories") == wl


def test_override_missing_file_returns_none(monkeypatch):
    monkeypatch.setenv("HTBRECON_WORDLIST_DIRECTORIES", "/does/not/exist.txt")
    _clear()
    assert paths.resolve_wordlist("directories") is None


def test_first_existing_candidate(monkeypatch):
    monkeypatch.delenv("HTBRECON_WORDLIST_API", raising=False)
    monkeypatch.setattr(paths.Path, "exists", lambda self: str(self).endswith("objects.txt"))
    _clear()
    resolved = paths.resolve_wordlist("api")
    assert resolved is not None and resolved.name == "objects.txt"


def test_none_when_nothing_found(monkeypatch):
    monkeypatch.delenv("HTBRECON_WORDLIST_SUBDOMAINS", raising=False)
    monkeypatch.setattr(paths.Path, "exists", lambda self: False)
    _clear()
    assert paths.resolve_wordlist("subdomains") is None


def test_hint_is_actionable():
    hint = paths.wordlist_hint("directories")
    assert "directories" in hint
    assert "HTBRECON_WORDLIST_DIRECTORIES" in hint
