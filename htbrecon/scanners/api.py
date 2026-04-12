from __future__ import annotations

import asyncio
import json
import re
from pathlib import Path

from htbrecon import executor
from htbrecon.console import print_finding, print_info, print_success, print_warning
from htbrecon.models import ApiResult, ReconContext

_API_WORDLIST_CANDIDATES = [
    "/usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt",
    "/usr/share/seclists/Discovery/Web-Content/api/objects.txt",
    "/usr/share/seclists/Discovery/Web-Content/raft-small-words-lowercase.txt",
]

_API_KEYWORDS = re.compile(
    r"(flowise|strapi|directus|hasura|graphql|fastapi|express|flask|django|"
    r"laravel|rails|spring|nestjs|gin|fiber|actix|fastify|hapi|restify|"
    r"swagger|openapi|apigee|kong|traefik)",
    re.IGNORECASE,
)

_SPEC_PATTERNS = ("swagger", "openapi", "api-docs", "api-doc")
_GRAPHQL_PATTERNS = ("graphql", "graphiql")


def _pick_wordlist() -> str | None:
    for p in _API_WORDLIST_CANDIDATES:
        if Path(p).exists():
            return p
    return None


def _detect_api_tech_from_whatweb(ctx: ReconContext) -> list[str]:
    hints: list[str] = []
    for ww in ctx.whatweb:
        for tech in ww.technologies:
            m = _API_KEYWORDS.search(tech)
            if m:
                hints.append(m.group(1).lower())
    return list(set(hints))


async def _ffuf_api(base_url: str, wordlist: str, out_file: str) -> list[tuple[str, int]]:
    """Fuzz API endpoints, return list of (path, status) tuples."""
    cmd = [
        "ffuf",
        "-u", f"{base_url}/FUZZ",
        "-w", wordlist,
        "-mc", "200,201,204,301,302,307,400,401,403,405,422",
        "-o", out_file,
        "-of", "json",
        "-t", "40",
        "-ac",
        "-H", "Content-Type: application/json",
        "-H", "Accept: application/json",
    ]
    await executor.run(cmd, timeout=180)

    hits: list[tuple[str, int]] = []
    try:
        data = json.loads(Path(out_file).read_text(encoding="utf-8"))
        for entry in data.get("results", []):
            path = "/" + entry.get("input", {}).get("FUZZ", "")
            status = entry.get("status", 0)
            hits.append((path, status))
    except (json.JSONDecodeError, FileNotFoundError, KeyError):
        pass
    return hits


async def run(ctx: ReconContext) -> None:
    """Fuzz API endpoints on all discovered HTTP targets using ffuf."""
    config = ctx.config
    out_dir = config.project_dir / "api"
    out_dir.mkdir(parents=True, exist_ok=True)

    if not ctx.http_ports:
        print_info("No HTTP ports — skipping API scan")
        return

    wordlist = _pick_wordlist()
    if not wordlist:
        print_warning("No API wordlist found — skipping API scan")
        ctx.api = ApiResult()
        return

    api_tech_hints = _detect_api_tech_from_whatweb(ctx)
    if api_tech_hints:
        print_info(f"API hints from WhatWeb: {', '.join(api_tech_hints)}")

    endpoints: list[str] = []
    graphql_endpoints: list[str] = []
    spec_urls: list[str] = []

    targets: list[tuple[str, str]] = []
    for hostname in ctx.all_hostnames:
        for _, url in ctx.web_urls(hostname):
            targets.append((hostname, url))

    fuzz_tasks = []
    for hostname, base_url in targets:
        safe_name = hostname.replace(".", "_")
        out_file = str(out_dir / f"api_{safe_name}.json")
        fuzz_tasks.append((base_url, wordlist, out_file))

    results = await asyncio.gather(
        *[_ffuf_api(base_url, wl, out) for base_url, wl, out in fuzz_tasks],
        return_exceptions=True,
    )

    for (base_url, _, _), result in zip(fuzz_tasks, results):
        if isinstance(result, BaseException):
            ctx.errors.append(f"API ffuf error on {base_url}: {result}")
            continue

        for path, status in result:
            full_url = base_url.rstrip("/") + path

            if any(kw in path for kw in _GRAPHQL_PATTERNS):
                if full_url not in graphql_endpoints:
                    graphql_endpoints.append(full_url)
                    print_finding("api", f"GraphQL endpoint: {full_url} [{status}]")
            elif any(kw in path for kw in _SPEC_PATTERNS):
                if full_url not in spec_urls:
                    spec_urls.append(full_url)
                    print_finding("api", f"API spec: {full_url} [{status}]")
            else:
                label = f"{full_url} [{status}]"
                if label not in endpoints:
                    endpoints.append(label)
                    print_success(f"API endpoint: {full_url} [{status}]")

    ctx.api = ApiResult(
        endpoints=endpoints,
        graphql_endpoints=graphql_endpoints,
        spec_urls=spec_urls,
        api_tech_hints=api_tech_hints,
    )

    total = len(endpoints) + len(graphql_endpoints) + len(spec_urls)
    if total:
        print_finding(
            "api",
            f"{total} API item(s) — {len(spec_urls)} spec(s), "
            f"{len(graphql_endpoints)} GraphQL, {len(endpoints)} endpoint(s)",
        )
    else:
        print_info("No API endpoints discovered")
