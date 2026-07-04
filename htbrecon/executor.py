from __future__ import annotations

import asyncio
import shlex
import time
from dataclasses import dataclass
from pathlib import Path

from htbrecon import tools
from htbrecon.console import logger


def _resolve_cmd(cmd: list[str]) -> list[str]:
    """Resolve a command's first token to a concrete path/argv via the tool registry.

    Uses :func:`htbrecon.tools.resolve` (env override > PATH > known fallbacks).
    If the tool is unknown or unresolved, the command is left unchanged so the
    scanner's existing return-code-127 handling still fires.
    """
    if not cmd:
        return cmd
    resolved = tools.resolve(cmd[0])
    if resolved is not None:
        return resolved + cmd[1:]
    return cmd


@dataclass(frozen=True)
class ExecResult:
    command: str
    returncode: int
    stdout: str
    stderr: str
    duration: float
    timed_out: bool


async def run(
    cmd: list[str],
    timeout: int = 300,
    cwd: Path | None = None,
    output_file: Path | None = None,
) -> ExecResult:
    """Run a command asynchronously via bash login shell (resolves aliases).

    Commands are executed through ``bash -lc`` so that Exegol shell aliases
    (e.g. whatweb) and custom PATH entries are available.
    """
    cmd = _resolve_cmd(cmd)
    cmd_str = " ".join(shlex.quote(c) for c in cmd)
    logger.debug("Executing: %s (timeout=%ds)", cmd_str, timeout)
    start = time.monotonic()

    try:
        proc = await asyncio.create_subprocess_exec(
            "bash",
            "-lc",
            cmd_str,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=cwd,
        )
    except FileNotFoundError:
        duration = time.monotonic() - start
        msg = f"Command not found: {cmd[0]} — is the tool installed?"
        logger.warning(msg)
        return ExecResult(
            command=cmd_str,
            returncode=127,
            stdout="",
            stderr=msg,
            duration=duration,
            timed_out=False,
        )

    timed_out = False
    try:
        stdout_bytes, stderr_bytes = await asyncio.wait_for(
            proc.communicate(), timeout=timeout
        )
    except asyncio.TimeoutError:
        timed_out = True
        proc.kill()
        stdout_bytes, stderr_bytes = await proc.communicate()
        logger.warning("Command timed out after %ds: %s", timeout, cmd_str)

    duration = time.monotonic() - start
    stdout = stdout_bytes.decode("utf-8", errors="replace")
    stderr = stderr_bytes.decode("utf-8", errors="replace")

    if output_file:
        output_file.parent.mkdir(parents=True, exist_ok=True)
        output_file.write_text(stdout, encoding="utf-8")

    logger.debug(
        "Finished: %s (rc=%d, %.1fs%s)",
        cmd_str,
        proc.returncode or 0,
        duration,
        ", TIMEOUT" if timed_out else "",
    )

    return ExecResult(
        command=cmd_str,
        returncode=proc.returncode or 0,
        stdout=stdout,
        stderr=stderr,
        duration=duration,
        timed_out=timed_out,
    )
