from __future__ import annotations

import platform
import shutil
import tempfile
import urllib.request
import zipfile
from pathlib import Path

from htbrecon.console import console, print_error, print_info, print_success, print_warning

_GITHUB_API = "https://api.github.com/repos/projectdiscovery/vulnx/releases/latest"
_INSTALL_DIR = Path("/usr/local/bin")
_BINARY_NAME = "vulnx"


def _is_linux_amd64() -> bool:
    return platform.system() == "Linux" and platform.machine() in ("x86_64", "amd64")


def _get_latest_release_url() -> tuple[str, str]:
    """Fetch the latest release version and download URL for linux_amd64."""
    import json

    req = urllib.request.Request(_GITHUB_API, headers={"User-Agent": "htbrecon"})
    with urllib.request.urlopen(req, timeout=15) as resp:
        data = json.loads(resp.read())

    version = data.get("tag_name", "unknown")
    for asset in data.get("assets", []):
        name: str = asset["name"]
        if "linux_amd64" in name and name.endswith(".zip"):
            return version, asset["browser_download_url"]

    raise RuntimeError("No linux_amd64 asset found in latest vulnx release")


def _download_and_install(url: str) -> None:
    """Download zip, extract binary, install to /usr/local/bin."""
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        zip_path = tmp_path / "vulnx.zip"

        print_info(f"Downloading {url} ...")
        with console.status("[bold cyan]Downloading vulnx...", spinner="dots"):
            urllib.request.urlretrieve(url, zip_path)

        with zipfile.ZipFile(zip_path, "r") as zf:
            # Find the binary inside the zip (usually just "vulnx")
            names = [n for n in zf.namelist() if not n.endswith("/")]
            binary_in_zip = next(
                (n for n in names if Path(n).name == _BINARY_NAME), None
            )
            if not binary_in_zip:
                raise RuntimeError(f"Binary '{_BINARY_NAME}' not found in zip: {names}")
            zf.extract(binary_in_zip, tmp_path)
            extracted = tmp_path / binary_in_zip

        dest = _INSTALL_DIR / _BINARY_NAME
        shutil.copy2(extracted, dest)
        dest.chmod(0o755)


def check_vulnx() -> bool:
    """Return True if vulnx is available in PATH."""
    return shutil.which(_BINARY_NAME) is not None


def run_setup() -> None:
    """Download and install vulnx binary to /usr/local/bin."""
    if not _is_linux_amd64():
        print_error(
            f"Unsupported platform: {platform.system()} {platform.machine()}. "
            "Only linux/amd64 is supported. Install vulnx manually from "
            "https://github.com/projectdiscovery/vulnx/releases"
        )
        return

    if check_vulnx():
        existing = shutil.which(_BINARY_NAME)
        print_warning(f"vulnx already installed at {existing}")
        print_info("Run with --force to reinstall")
        return

    try:
        version, url = _get_latest_release_url()
        print_info(f"Latest version: {version}")
        _download_and_install(url)
        print_success(f"vulnx {version} installed to {_INSTALL_DIR / _BINARY_NAME}")
    except PermissionError:
        print_error(
            f"Permission denied writing to {_INSTALL_DIR}. "
            "Run htbrecon setup as root inside your Exegol container."
        )
    except Exception as e:
        print_error(f"Setup failed: {e}")


def run_setup_force() -> None:
    """Force reinstall vulnx even if already present."""
    existing = shutil.which(_BINARY_NAME)
    if existing:
        Path(existing).unlink(missing_ok=True)
        print_info(f"Removed existing {existing}")

    try:
        version, url = _get_latest_release_url()
        print_info(f"Latest version: {version}")
        _download_and_install(url)
        print_success(f"vulnx {version} installed to {_INSTALL_DIR / _BINARY_NAME}")
    except PermissionError:
        print_error(
            f"Permission denied writing to {_INSTALL_DIR}. "
            "Run htbrecon setup as root inside your Exegol container."
        )
    except Exception as e:
        print_error(f"Setup failed: {e}")
