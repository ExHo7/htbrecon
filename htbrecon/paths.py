"""Wordlist resolution — replaces the hardcoded Exegol/Kali ``/usr/share`` paths.

Generalises the candidate-list pattern that already lived in ``scanners/api.py``.
Resolution priority for ``resolve_wordlist(kind)``:

  1. env/config override  (``settings.wordlist_override``)
  2. first existing path among the known distro candidates
  3. ``None``  -> caller skips the scan with :func:`wordlist_hint`

No wordlist is ever downloaded or bundled; the user provides them (seclists/dirb
via apt, or a custom path via env/config).
"""

from __future__ import annotations

from pathlib import Path

from htbrecon import settings

# kind -> ordered candidate paths (Debian, Kali, and Exegol layouts).
_CANDIDATES: dict[str, list[str]] = {
    "subdomains": [
        "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
        "/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
    ],
    "directories": [
        "/usr/share/dirb/wordlists/common.txt",
        "/usr/share/wordlists/dirb/common.txt",
        "/usr/share/seclists/Discovery/Web-Content/common.txt",
    ],
    "usernames": [
        "/usr/share/seclists/Usernames/top-usernames-shortlist.txt",
        "/usr/share/wordlists/seclists/Usernames/top-usernames-shortlist.txt",
    ],
    "api": [
        "/usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt",
        "/usr/share/seclists/Discovery/Web-Content/api/objects.txt",
        "/usr/share/seclists/Discovery/Web-Content/raft-small-words-lowercase.txt",
    ],
}


def resolve_wordlist(kind: str) -> Path | None:
    """Resolve a wordlist path for ``kind`` (subdomains/directories/usernames/api).

    An explicit override that points at a missing file resolves to ``None`` (we
    do not silently fall back to the distro defaults — respect the user's intent
    and let the caller report it).
    """
    override = settings.wordlist_override(kind)
    if override:
        p = Path(override).expanduser()
        return p if p.exists() else None

    for candidate in _CANDIDATES.get(kind, []):
        p = Path(candidate)
        if p.exists():
            return p
    return None


def wordlist_hint(kind: str) -> str:
    """Actionable message when a wordlist can't be resolved."""
    return (
        f"Wordlist '{kind}' introuvable — installez seclists/dirb "
        f"(sudo apt install seclists dirb) ou définissez "
        f"HTBRECON_WORDLIST_{kind.upper()} (ou [wordlists].{kind} dans "
        f"~/.config/htbrecon/config.toml)"
    )
