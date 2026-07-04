"""Registry and resolution for the external pentest tools HTBRecon shells out to.

This is the single source of truth that replaces the hardcoded Exegol paths that
used to live in ``executor.py``. For every tool we record:

  * how to detect it (``check`` — a binary name looked up on ``PATH``),
  * how to invoke it when it is NOT on ``PATH`` (``fallback_paths`` — full argv
    candidates, e.g. the Exegol ruby wrapper for WhatWeb),
  * how to install it (``install`` — apt / pipx / GitHub release).

Resolution priority for ``resolve(name)``:

  1. env/config override  (``settings.tool_override``)
  2. ``shutil.which(check)``            -> standard Debian/Kali install, incl. apt
  3. first existing ``fallback_paths`` candidate  -> Exegol/Kali legacy layout
  4. ``None``                           -> tool is missing

No ``/opt/tools`` path is ever privileged over ``PATH`` anymore; the Exegol
locations survive only as last-resort fallbacks.
"""

from __future__ import annotations

import shutil
from dataclasses import dataclass
from pathlib import Path

from htbrecon import settings

# apt package -> needs sudo; pipx/release -> user-scoped, no root.
APT = "apt"
PIPX = "pipx"
RELEASE = "release"


@dataclass(frozen=True)
class InstallMethod:
    kind: str  # APT | PIPX | RELEASE
    package: str = ""  # apt/pipx package name
    repo: str = ""  # "owner/name" for RELEASE (GitHub)
    binary: str = ""  # binary name inside the release archive (default: tool check name)

    def describe(self) -> str:
        if self.kind == APT:
            return f"apt install {self.package}"
        if self.kind == PIPX:
            return f"pipx install {self.package}"
        if self.kind == RELEASE:
            return f"github release {self.repo}"
        return self.kind


@dataclass(frozen=True)
class ToolSpec:
    name: str
    check: str  # binary looked up via shutil.which
    install: InstallMethod
    # Each fallback is a full argv; the first whose argv[0] exists wins. Used for
    # tools whose real invocation isn't a bare binary (Exegol ruby/venv wrappers).
    fallback_paths: tuple[tuple[str, ...], ...] = ()
    required: bool = True  # weighs the doctor exit code
    category: str = "recon"


def _spec(name, check, install, *, fallback_paths=(), required=True, category="recon"):
    return ToolSpec(
        name=name,
        check=check,
        install=install,
        fallback_paths=tuple(tuple(fp) for fp in fallback_paths),
        required=required,
        category=category,
    )


_REGISTRY: dict[str, ToolSpec] = {
    s.name: s
    for s in (
        # ── Port / web scanning ──────────────────────────────────────────
        _spec("nmap", "nmap", InstallMethod(APT, package="nmap")),
        _spec("rustscan", "rustscan", InstallMethod(RELEASE, repo="bee-san/RustScan"),
              required=False),  # nmap fallback exists in nmap.py
        _spec("ffuf", "ffuf", InstallMethod(RELEASE, repo="ffuf/ffuf")),
        _spec("nuclei", "nuclei", InstallMethod(RELEASE, repo="projectdiscovery/nuclei")),
        _spec("katana", "katana", InstallMethod(RELEASE, repo="projectdiscovery/katana"),
              required=False),
        _spec("vulnx", "vulnx", InstallMethod(RELEASE, repo="projectdiscovery/vulnx"),
              required=False),
        _spec(
            "whatweb", "whatweb", InstallMethod(APT, package="whatweb"),
            fallback_paths=[(
                "/usr/local/rvm/gems/ruby-3.2.2@whatweb/wrappers/ruby",
                "/opt/tools/WhatWeb/whatweb",
            )],
        ),
        _spec(
            "eyewitness", "eyewitness", InstallMethod(APT, package="eyewitness"),
            fallback_paths=[
                ("/opt/tools/EyeWitness/venv/bin/python3", "/opt/tools/EyeWitness/Python/EyeWitness.py"),
                ("python3", "/opt/tools/EyeWitness/Python/EyeWitness.py"),
            ],
            required=False,
        ),
        _spec("curl", "curl", InstallMethod(APT, package="curl")),
        # ── AD / SMB / LDAP ──────────────────────────────────────────────
        _spec("netexec", "nxc", InstallMethod(PIPX, package="netexec"), category="ad"),
        _spec("ldapsearch", "ldapsearch", InstallMethod(APT, package="ldap-utils"), category="ad"),
        _spec("smbclient", "smbclient", InstallMethod(APT, package="smbclient"), category="ad"),
        _spec("enum4linux-ng", "enum4linux-ng", InstallMethod(PIPX, package="enum4linux-ng"),
              category="ad", required=False),
        _spec("kerbrute", "kerbrute", InstallMethod(RELEASE, repo="ropnop/kerbrute"),
              category="ad", required=False),
        _spec("bloodhound-python", "bloodhound-python", InstallMethod(PIPX, package="bloodhound"),
              category="ad", required=False),
    )
}


def all_specs() -> list[ToolSpec]:
    """All registered tool specs, in registration order."""
    return list(_REGISTRY.values())


def get_spec(name: str) -> ToolSpec | None:
    return _REGISTRY.get(name)


def _candidate_ok(candidate: tuple[str, ...]) -> bool:
    """A fallback argv is usable only if its interpreter AND every path argument exist.

    This guards interpreter-prefixed fallbacks (e.g. ``["python3", ".../EyeWitness.py"]``):
    ``python3`` is always on PATH, so we must also confirm the actual script exists,
    otherwise a tool would be reported present when only the interpreter is.
    """
    if not candidate:
        return False
    exe = candidate[0]
    if not (Path(exe).exists() or shutil.which(exe)):
        return False
    return all("/" not in arg or Path(arg).exists() for arg in candidate[1:])


def resolve(name: str) -> list[str] | None:
    """Return the argv prefix to invoke ``name``, or None if unavailable.

    ``name`` is the command as written by a scanner (e.g. ``"nxc"`` scanners pass
    ``"nxc"`` as argv[0]); the returned list replaces that first element.
    """
    override = settings.tool_override(name)
    if override:
        return [override]

    spec = _REGISTRY.get(name)
    if spec is None:
        found = shutil.which(name)
        return [found] if found else None

    found = shutil.which(spec.check)
    if found:
        return [found]

    for candidate in spec.fallback_paths:
        if _candidate_ok(candidate):
            return list(candidate)

    return None


def status(name: str) -> tuple[bool, str | None]:
    """Return (found, display_path) for a tool — used by ``htbrecon doctor``."""
    resolved = resolve(name)
    if not resolved:
        return False, None
    return True, " ".join(resolved)
