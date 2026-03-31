from __future__ import annotations

from pathlib import Path

from htbrecon.console import logger, print_info, print_success, print_error

HOSTS_FILE = Path("/etc/hosts")


def _parse_hosts(content: str) -> list[tuple[str, list[str]]]:
    """Parse /etc/hosts into list of (ip, [hostnames])."""
    entries: list[tuple[str, list[str]]] = []
    for line in content.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        parts = stripped.split()
        if len(parts) >= 2:
            entries.append((parts[0], parts[1:]))
    return entries


def check_host(ip: str, hostname: str) -> tuple[str, str | None]:
    """Check status of hostname/ip in /etc/hosts.

    Returns:
        (status, message) where status is one of:
        - "exact_match": hostname already maps to this IP
        - "conflict": hostname maps to a different IP
        - "ip_exists": IP exists with other hostnames (can append)
        - "new": neither IP nor hostname found
    """
    content = HOSTS_FILE.read_text(encoding="utf-8")
    entries = _parse_hosts(content)

    for entry_ip, hostnames in entries:
        if hostname in hostnames:
            if entry_ip == ip:
                return "exact_match", None
            return "conflict", (
                f"Hostname '{hostname}' already maps to {entry_ip} (expected {ip})"
            )

    for entry_ip, hostnames in entries:
        if entry_ip == ip:
            return "ip_exists", f"IP {ip} exists with hostnames: {', '.join(hostnames)}"

    return "new", None


def add_host(ip: str, hostname: str) -> bool:
    """Add an entry to /etc/hosts with conflict detection.

    Returns True if the entry was added/already present, False on error.
    """
    try:
        status, message = check_host(ip, hostname)
    except PermissionError:
        print_error("Cannot read /etc/hosts — run with appropriate permissions")
        return False

    if status == "exact_match":
        print_info(f"{hostname} -> {ip} already in /etc/hosts")
        return True

    if status == "conflict":
        print_error(f"Conflict: {message}")
        return False

    try:
        content = HOSTS_FILE.read_text(encoding="utf-8")

        if status == "ip_exists":
            # Append hostname to existing IP line
            lines = content.splitlines(keepends=True)
            new_lines: list[str] = []
            for line in lines:
                stripped = line.strip()
                if stripped and not stripped.startswith("#"):
                    # Split off inline comment if present
                    code_part = line.split("#")[0] if "#" in line else line.rstrip("\n\r")
                    comment_part = "#" + line.split("#", 1)[1] if "#" in line else ""
                    parts = code_part.split()
                    if len(parts) >= 2 and parts[0] == ip:
                        if comment_part:
                            line = f"{code_part.rstrip()}\t{hostname}\t{comment_part}\n"
                        else:
                            line = f"{code_part.rstrip()}\t{hostname}\n"
                new_lines.append(line)
            new_content = "".join(new_lines)
            if not new_content.endswith("\n"):
                new_content += "\n"
            print_success(f"Appended {hostname} to existing entry for {ip}")
        else:
            # New entry
            new_content = content
            if not new_content.endswith("\n"):
                new_content += "\n"
            new_content += f"{ip}\t{hostname}\n"
            print_success(f"Added {hostname} -> {ip} to /etc/hosts")

        # Write directly (atomic rename fails on bind-mounted /etc/hosts in containers)
        HOSTS_FILE.write_text(new_content, encoding="utf-8")
        logger.info("Updated /etc/hosts: %s -> %s", ip, hostname)
        return True

    except PermissionError:
        print_error(
            "Cannot write to /etc/hosts — run with sudo or appropriate permissions"
        )
        return False
