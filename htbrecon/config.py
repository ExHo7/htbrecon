from pathlib import Path

from htbrecon.models import ReconConfig


def build_config(
    ip: str,
    name: str,
    domain: str = "htb",
    credentials: str | None = None,
    skip_ai: bool = False,
    debug: bool = False,
    base_dir: Path | None = None,
) -> ReconConfig:
    """Build a ReconConfig from CLI arguments."""
    name = name.lower().strip()
    domain = domain.lower().strip().lstrip(".")
    if base_dir is None:
        base_dir = Path.cwd()
    project_dir = base_dir / "results" / name

    creds: tuple[str, str] | None = None
    if credentials:
        if ":" not in credentials:
            raise ValueError("--credentials must be in user:password format")
        user, password = credentials.split(":", 1)
        creds = (user, password)

    return ReconConfig(
        ip=ip,
        name=name,
        domain=domain,
        credentials=creds,
        skip_ai=skip_ai,
        debug=debug,
        project_dir=project_dir,
    )
