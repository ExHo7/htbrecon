from __future__ import annotations

from htbrecon import settings, tools


def _clear() -> None:
    settings._load_config.cache_clear()


def test_env_override_wins(monkeypatch):
    monkeypatch.setenv("HTBRECON_TOOL_FFUF", "/custom/ffuf")
    _clear()
    assert tools.resolve("ffuf") == ["/custom/ffuf"]


def test_env_override_dash_to_underscore(monkeypatch):
    monkeypatch.setenv("HTBRECON_TOOL_ENUM4LINUX_NG", "/opt/e4l/enum4linux-ng.py")
    _clear()
    assert tools.resolve("enum4linux-ng") == ["/opt/e4l/enum4linux-ng.py"]


def test_path_resolution(monkeypatch):
    monkeypatch.delenv("HTBRECON_TOOL_NMAP", raising=False)
    monkeypatch.setattr(tools.shutil, "which", lambda n: "/usr/bin/nmap" if n == "nmap" else None)
    _clear()
    assert tools.resolve("nmap") == ["/usr/bin/nmap"]


def test_fallback_when_not_on_path(monkeypatch):
    ruby = "/usr/local/rvm/gems/ruby-3.2.2@whatweb/wrappers/ruby"
    script = "/opt/tools/WhatWeb/whatweb"
    # whatweb not on PATH, but the Exegol ruby wrapper AND its script are present.
    monkeypatch.setattr(tools.shutil, "which", lambda n: n if n == ruby else None)
    monkeypatch.setattr(tools.Path, "exists", lambda self: str(self) in (ruby, script))
    monkeypatch.delenv("HTBRECON_TOOL_WHATWEB", raising=False)
    _clear()
    assert tools.resolve("whatweb") == [ruby, script]


def test_fallback_rejected_when_artifact_missing(monkeypatch):
    # python3 is on PATH but the EyeWitness script is not — must NOT resolve.
    monkeypatch.setattr(tools.shutil, "which", lambda n: "/usr/bin/python3" if n == "python3" else None)
    monkeypatch.setattr(tools.Path, "exists", lambda self: False)
    monkeypatch.delenv("HTBRECON_TOOL_EYEWITNESS", raising=False)
    _clear()
    assert tools.resolve("eyewitness") is None


def test_missing_returns_none(monkeypatch):
    monkeypatch.setattr(tools.shutil, "which", lambda n: None)
    monkeypatch.delenv("HTBRECON_TOOL_FFUF", raising=False)
    _clear()
    assert tools.resolve("ffuf") is None


def test_registry_specs_have_install():
    for spec in tools.all_specs():
        assert spec.install.kind in (tools.APT, tools.PIPX, tools.RELEASE)
        assert spec.install.describe()
