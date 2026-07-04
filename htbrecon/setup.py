"""Tool installer + doctor for HTBRecon.

Cross-distribution (Debian-family) replacement for the old Exegol-only vulnx
installer. Installs the external tools HTBRecon needs, per architecture, into a
user-writable directory by default (``~/.local/bin``, no root), falling back to
``/usr/local/bin`` with ``--system``.

Install strategy per tool (see :mod:`htbrecon.tools`), ordered to minimise sudo:
  * RELEASE  -> download the GitHub release binary for the host arch (no root)
  * PIPX     -> ``pipx install`` (no root)
  * APT      -> ``apt install`` (needs root/sudo)
"""

from __future__ import annotations

import json
import os
import platform
import shutil
import subprocess
import tarfile
import tempfile
import urllib.request
import zipfile
from pathlib import Path

from htbrecon import tools
from htbrecon.console import (
    console,
    print_error,
    print_info,
    print_success,
    print_warning,
)
from htbrecon.tools import APT, PIPX, RELEASE, ToolSpec

_USER_BIN = Path.home() / ".local" / "bin"
_SYSTEM_BIN = Path("/usr/local/bin")

# arch tag -> tokens that may appear in a release asset name for that arch.
_ARCH_TOKENS: dict[str, tuple[str, ...]] = {
    "amd64": ("amd64", "x86_64"),
    "arm64": ("arm64", "aarch64"),
}
_ARCH_MAP = {
    "x86_64": "amd64",
    "amd64": "amd64",
    "aarch64": "arm64",
    "arm64": "arm64",
}

_SKIP_ASSET_EXT = (".deb", ".rpm", ".sha256", ".sha256sum", ".txt", ".sig", ".md5", ".asc", ".pem")


# ── Architecture ────────────────────────────────────────────────────────────
def detect_arch() -> str | None:
    """Return the arch tag ('amd64'/'arm64') for a supported Linux host, else None."""
    if platform.system() != "Linux":
        return None
    return _ARCH_MAP.get(platform.machine().lower())


def install_dir(system: bool = False) -> Path:
    """Destination for installed binaries."""
    return _SYSTEM_BIN if system else _USER_BIN


# ── GitHub release download ─────────────────────────────────────────────────
def _fetch_release_asset(repo: str, arch: str) -> tuple[str, str]:
    """Return (version, download_url) for the linux/<arch> asset of a repo's latest release."""
    api = f"https://api.github.com/repos/{repo}/releases/latest"
    req = urllib.request.Request(api, headers={"User-Agent": "htbrecon"})
    with urllib.request.urlopen(req, timeout=20) as resp:
        data = json.loads(resp.read())

    version = data.get("tag_name", "unknown")
    tokens = _ARCH_TOKENS[arch]
    candidates: list[tuple[int, str]] = []
    for asset in data.get("assets", []):
        name: str = asset["name"]
        low = name.lower()
        if "linux" not in low or not any(t in low for t in tokens):
            continue
        if low.endswith(_SKIP_ASSET_EXT):
            continue
        # Prefer archives over raw binaries (raw binaries are fine too).
        score = 2 if low.endswith((".tar.gz", ".tgz", ".zip", ".tar")) else 1
        candidates.append((score, asset["browser_download_url"]))

    if not candidates:
        raise RuntimeError(f"No linux/{arch} asset found in latest release of {repo}")

    candidates.sort(key=lambda c: c[0], reverse=True)
    return version, candidates[0][1]


def _extract_binary(archive: Path, workdir: Path, binary_name: str) -> Path:
    """Extract ``binary_name`` from a zip/tar archive (or return a raw binary)."""
    low = archive.name.lower()

    if low.endswith(".zip"):
        with zipfile.ZipFile(archive) as zf:
            names = [n for n in zf.namelist() if not n.endswith("/")]
            member = next((n for n in names if Path(n).name == binary_name), None)
            if member is None and len(names) == 1:
                member = names[0]
            if member is None:
                raise RuntimeError(f"'{binary_name}' not found in {archive.name}: {names}")
            zf.extract(member, workdir)
            return workdir / member

    if low.endswith((".tar.gz", ".tgz", ".tar")):
        with tarfile.open(archive) as tf:
            files = [m for m in tf.getmembers() if m.isfile()]
            tar_member = next((m for m in files if Path(m.name).name == binary_name), None)
            if tar_member is None and len(files) == 1:
                tar_member = files[0]
            if tar_member is None:
                raise RuntimeError(
                    f"'{binary_name}' not found in {archive.name}: {[m.name for m in files]}"
                )
            try:
                tf.extract(tar_member, workdir, filter="data")  # py>=3.12
            except TypeError:
                tf.extract(tar_member, workdir)
            return workdir / tar_member.name

    # Raw binary (e.g. kerbrute_linux_amd64) — use as-is.
    return archive


def install_release_binary(repo: str, arch: str, dest_dir: Path, binary_name: str) -> tuple[str, Path]:
    """Download the latest release binary for ``repo`` and install it as ``binary_name``."""
    version, url = _fetch_release_asset(repo, arch)
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        download = tmp_path / url.split("/")[-1]
        print_info(f"Downloading {url} ...")
        with console.status(f"[bold cyan]Downloading {binary_name}...", spinner="dots"):
            urllib.request.urlretrieve(url, download)

        extracted = _extract_binary(download, tmp_path, binary_name)
        dest_dir.mkdir(parents=True, exist_ok=True)
        dest = dest_dir / binary_name
        shutil.copy2(extracted, dest)
        dest.chmod(0o755)
    return version, dest


# ── pipx / apt ──────────────────────────────────────────────────────────────
def _run(cmd: list[str]) -> bool:
    print_info("$ " + " ".join(cmd))
    try:
        proc = subprocess.run(cmd, check=False)
    except FileNotFoundError:
        print_error(f"Command not found: {cmd[0]}")
        return False
    return proc.returncode == 0


def _install_pipx(package: str, force: bool) -> bool:
    if shutil.which("pipx") is None:
        print_error(
            "pipx introuvable — installez-le puis réessayez: "
            "sudo apt install pipx && pipx ensurepath"
        )
        return False
    cmd = ["pipx", "install", package]
    if force:
        cmd.append("--force")
    return _run(cmd)


def _apt_prefix() -> list[str]:
    return [] if os.geteuid() == 0 else ["sudo"]


def _install_apt(package: str) -> bool:
    return _run([*_apt_prefix(), "apt-get", "install", "-y", package])


def _install_one(spec: ToolSpec, arch: str | None, dest_dir: Path, force: bool) -> bool:
    method = spec.install
    if method.kind == RELEASE:
        if arch is None:
            print_error(
                f"{spec.name}: architecture non supportée "
                f"({platform.system()} {platform.machine()}) — installez manuellement."
            )
            return False
        try:
            binary = method.binary or spec.check
            version, dest = install_release_binary(method.repo, arch, dest_dir, binary)
            print_success(f"{spec.name} {version} installé -> {dest}")
            return True
        except Exception as exc:  # noqa: BLE001 — surface any download/extract failure
            print_error(f"{spec.name}: échec de l'installation ({exc})")
            return False
    if method.kind == PIPX:
        ok = _install_pipx(method.package, force)
        if ok:
            print_success(f"{spec.name} installé via pipx ({method.package})")
        return ok
    if method.kind == APT:
        ok = _install_apt(method.package)
        if ok:
            print_success(f"{spec.name} installé via apt ({method.package})")
        return ok
    print_error(f"{spec.name}: méthode d'installation inconnue '{method.kind}'")
    return False


# ── Public API (CLI) ────────────────────────────────────────────────────────
def check_vulnx() -> bool:
    """Return True if vulnx is available (kept for the pipeline's CVE phase)."""
    return tools.resolve("vulnx") is not None


def _warn_path(dest_dir: Path) -> None:
    path_entries = os.environ.get("PATH", "").split(os.pathsep)
    if str(dest_dir) not in path_entries:
        print_warning(
            f"{dest_dir} n'est pas dans votre PATH — ajoutez "
            f'\'export PATH="{dest_dir}:$PATH"\' à votre shell rc.'
        )


def run_doctor() -> int:
    """Print a diagnostic table of tool availability. Returns non-zero if a required tool is missing."""
    from htbrecon import paths
    from rich.table import Table

    table = Table(title="HTBRecon — Diagnostic des dépendances", border_style="cyan")
    table.add_column("Outil", style="bold")
    table.add_column("Statut")
    table.add_column("Chemin / méthode d'install", style="dim")

    missing_required = 0
    for spec in tools.all_specs():
        found, where = tools.status(spec.name)
        if found:
            table.add_row(spec.name, "[green]ok[/]", where or "")
        else:
            tag = "[red]MANQUANT[/]" if spec.required else "[yellow]absent (optionnel)[/]"
            table.add_row(spec.name, tag, spec.install.describe())
            if spec.required:
                missing_required += 1
    console.print(table)

    # Wordlists (resolved, not installed).
    wl_table = Table(title="Wordlists", border_style="cyan")
    wl_table.add_column("Type", style="bold")
    wl_table.add_column("Statut")
    wl_table.add_column("Chemin", style="dim")
    for kind in ("subdomains", "directories", "usernames", "api"):
        resolved = paths.resolve_wordlist(kind)
        if resolved:
            wl_table.add_row(kind, "[green]ok[/]", str(resolved))
        else:
            wl_table.add_row(kind, "[yellow]absente[/]", "apt install seclists dirb")
    console.print(wl_table)

    arch = detect_arch()
    console.print(f"\n[dim]Architecture: {arch or 'non supportée'} — install user: {_USER_BIN}[/]")
    if missing_required:
        print_warning(f"{missing_required} outil(s) requis manquant(s) — lancez [bold]htbrecon setup[/]")
    else:
        print_success("Tous les outils requis sont disponibles")
    _warn_path(_USER_BIN)
    return 1 if missing_required else 0


def run_setup(only: list[str] | None = None, force: bool = False, system: bool = False) -> None:
    """Install missing tools (or just those in ``only``) for this host's architecture."""
    arch = detect_arch()
    dest_dir = install_dir(system)

    specs = tools.all_specs()
    if only:
        wanted = {name.strip().lower() for name in only}
        # Match on tool name or its check binary (so --only nxc works for netexec).
        specs = [s for s in specs if s.name.lower() in wanted or s.check.lower() in wanted]
        unknown = wanted - {s.name.lower() for s in specs} - {s.check.lower() for s in specs}
        for u in sorted(unknown):
            print_warning(f"Outil inconnu ignoré: {u}")

    installed = skipped = failed = 0
    for spec in specs:
        found, where = tools.status(spec.name)
        if found and not force:
            print_info(f"{spec.name} déjà présent ({where}) — --force pour réinstaller")
            skipped += 1
            continue
        if _install_one(spec, arch, dest_dir, force):
            installed += 1
        else:
            failed += 1

    console.print()
    print_success(f"Terminé — {installed} installé(s), {skipped} déjà présent(s), {failed} échec(s)")
    if installed:
        _warn_path(dest_dir)
