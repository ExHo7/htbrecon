from __future__ import annotations

import asyncio
import json
import re
from pathlib import Path

from htbrecon import executor
from htbrecon.console import print_finding, print_info, print_success, print_warning
from htbrecon.models import ApiResult, ReconContext

# Common API spec / discovery endpoints to probe before fuzzing
_API_PROBE_PATHS = [
    # OpenAPI / Swagger
    "/openapi.json",
    "/openapi.yaml",
    "/swagger.json",
    "/swagger.yaml",
    "/api-docs",
    "/api-docs/",
    "/api-docs.json",
    "/v2/api-docs",
    "/v3/api-docs",
    "/swagger-ui.html",
    "/swagger-ui/",
    "/swagger/index.html",
    # GraphQL
    "/graphql",
    "/graphiql",
    "/api/graphql",
    "/graphql/console",
    # Generic API roots
    "/api",
    "/api/",
    "/api/v1",
    "/api/v1/",
    "/api/v2",
    "/api/v2/",
    "/api/v3",
    "/rest",
    "/rest/",
    "/v1",
    "/v1/",
    "/v2",
    "/v2/",
    # Common frameworks
    "/actuator",           # Spring Boot
    "/actuator/health",
    "/actuator/env",
    "/actuator/mappings",
    "/_api",               # Directus
    "/items",              # Directus
    "/api/health",
    "/api/status",
    "/api/ping",
    "/api/me",
    "/api/user",
    "/api/users",
    # Flowise / LLM APIs
    "/api/v1/chatflows",
    "/api/v1/prediction",
    "/api/v1/tools",
    "/api/v1/credentials",
]

# Wordlist for deeper API fuzzing (relative path within seclists)
_API_WORDLIST_CANDIDATES = [
    "/usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt",
    "/usr/share/seclists/Discovery/Web-Content/api/objects.txt",
    "/usr/share/seclists/Discovery/Web-Content/raft-small-words-lowercase.txt",
]

# GraphQL introspection query
_GRAPHQL_INTROSPECTION = '{"query":"{ __schema { types { name } } }"}'

# Status codes that indicate a real endpoint (not pure 404/redirect noise)
_INTERESTING_STATUS = {200, 201, 204, 301, 302, 307, 400, 401, 403, 405, 422, 500}


def _pick_wordlist() -> str | None:
    for p in _API_WORDLIST_CANDIDATES:
        if Path(p).exists():
            return p
    return None


async def _probe_endpoint(url: str, path: str, session_headers: list[str]) -> tuple[str, int, int] | None:
    """Probe a single path, return (full_url, status, size) or None on error."""
    target = url.rstrip("/") + path
    cmd = [
        "curl", "-s", "-k",
        "-o", "/dev/null",
        "-w", "%{http_code}:%{size_download}",
        "--max-time", "5",
        "-L",  # follow redirects once
        *session_headers,
        target,
    ]
    result = await executor.run(cmd, timeout=10)
    if result.returncode != 0:
        return None
    parts = result.stdout.strip().split(":")
    if len(parts) < 2:
        return None
    try:
        status = int(parts[0])
        size = int(parts[1])
    except ValueError:
        return None
    if status in _INTERESTING_STATUS and status != 404:
        return target, status, size
    return None


async def _probe_graphql(url: str) -> bool:
    """Check if endpoint responds to GraphQL introspection."""
    target = url.rstrip("/") + "/graphql"
    cmd = [
        "curl", "-s", "-k",
        "-X", "POST",
        "-H", "Content-Type: application/json",
        "-d", _GRAPHQL_INTROSPECTION,
        "--max-time", "5",
        "-w", "\n%{http_code}",
        target,
    ]
    result = await executor.run(cmd, timeout=10)
    if result.returncode != 0:
        return False
    # Look for __schema in response body — confirms introspection enabled
    return "__schema" in result.stdout or '"data"' in result.stdout


async def _ffuf_api(base_url: str, wordlist: str, out_file: str) -> list[str]:
    """Fuzz API endpoints with ffuf using a dedicated API wordlist."""
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
    result = await executor.run(cmd, timeout=180)

    found: list[str] = []
    try:
        data = json.loads(Path(out_file).read_text(encoding="utf-8"))
        for entry in data.get("results", []):
            path = entry.get("input", {}).get("FUZZ", "")
            status = entry.get("status", 0)
            found.append(f"/{path} [{status}]")
    except (json.JSONDecodeError, FileNotFoundError, KeyError):
        pass
    return found


def _detect_api_tech_from_whatweb(ctx: ReconContext) -> list[str]:
    """Extract known API-framework hints from WhatWeb results."""
    hints: list[str] = []
    api_keywords = re.compile(
        r"(flowise|strapi|directus|hasura|graphql|fastapi|express|flask|django|"
        r"laravel|rails|spring|nestjs|gin|fiber|actix|fastify|hapi|restify|"
        r"swagger|openapi|apigee|kong|traefik)",
        re.IGNORECASE,
    )
    for ww in ctx.whatweb:
        for tech in ww.technologies:
            m = api_keywords.search(tech)
            if m:
                hints.append(m.group(1).lower())
    return list(set(hints))


async def run(ctx: ReconContext) -> None:
    """Detect and fuzz API endpoints on all discovered HTTP targets."""
    config = ctx.config
    out_dir = config.project_dir / "api"
    out_dir.mkdir(parents=True, exist_ok=True)

    if not ctx.http_ports:
        print_info("No HTTP ports — skipping API scan")
        return

    api_tech_hints = _detect_api_tech_from_whatweb(ctx)
    if api_tech_hints:
        print_info(f"API hints from WhatWeb: {', '.join(api_tech_hints)}")

    wordlist = _pick_wordlist()

    discovered_endpoints: list[str] = []
    graphql_endpoints: list[str] = []
    spec_urls: list[str] = []
    ffuf_results: list[str] = []

    # Build all (hostname, url) pairs to scan
    targets: list[tuple[str, str]] = []
    for hostname in ctx.all_hostnames:
        for _, url in ctx.web_urls(hostname):
            targets.append((hostname, url))

    # Baseline size per host: probe a guaranteed-404 path to detect wildcard 200s
    baselines: dict[str, int] = {}
    for hostname, base_url in targets:
        bl_result = await executor.run([
            "curl", "-s", "-k", "-o", "/dev/null",
            "-w", "%{http_code}:%{size_download}",
            "--max-time", "5",
            f"{base_url}/htbrecon-nonexistent-{hostname}",
        ], timeout=10)
        try:
            bl_parts = bl_result.stdout.strip().split(":")
            bl_status, bl_size = int(bl_parts[0]), int(bl_parts[1])
            # If server returns 200 on garbage path → it's a wildcard, record size to filter
            baselines[base_url] = bl_size if bl_status == 200 else -1
        except (ValueError, IndexError):
            baselines[base_url] = -1

    for hostname, base_url in targets:
        print_info(f"API probe: {base_url}")
        wildcard_size = baselines.get(base_url, -1)

        # Phase 1 — passive probe of known paths
        probe_tasks = [
            _probe_endpoint(base_url, path, [])
            for path in _API_PROBE_PATHS
        ]
        probe_results = await asyncio.gather(*probe_tasks, return_exceptions=True)

        for res in probe_results:
            if isinstance(res, BaseException) or res is None:
                continue
            endpoint_url, status, size = res

            # Filter wildcard responses: same size as baseline → likely fake 200
            if wildcard_size > 0 and size == wildcard_size:
                continue

            label = f"{endpoint_url} [{status}]"

            # Detect spec files — stored separately, NOT in endpoints
            if any(kw in endpoint_url for kw in ("swagger", "openapi", "api-docs")):
                if endpoint_url not in spec_urls:
                    spec_urls.append(endpoint_url)
                    print_finding("api", f"API spec found: {endpoint_url} [{status}]")
            else:
                if label not in discovered_endpoints:
                    discovered_endpoints.append(label)
                    print_success(f"API endpoint: {endpoint_url} [{status}]")

        # Phase 2 — GraphQL introspection
        gql_open = await _probe_graphql(base_url)
        if gql_open:
            gql_url = base_url.rstrip("/") + "/graphql"
            if gql_url not in graphql_endpoints:
                graphql_endpoints.append(gql_url)
                print_finding("api", f"GraphQL introspection OPEN: {gql_url}")

        # Phase 3 — ffuf fuzzing (only adds paths NOT already in probe results)
        if wordlist:
            safe_name = hostname.replace(".", "_")
            out_file = str(out_dir / f"api_{safe_name}.json")
            try:
                fuzz_hits = await _ffuf_api(base_url, wordlist, out_file)
                # Build set of already-known paths (without status tag) for dedup
                known_paths = {
                    e.split(" [")[0].replace(base_url, "")
                    for e in discovered_endpoints
                } | {s.replace(base_url, "") for s in spec_urls}

                new_hits = 0
                for hit in fuzz_hits:
                    path = hit.split(" [")[0]  # "/api/v1/foo"
                    if path not in known_paths:
                        full = f"{base_url}{hit}"
                        ffuf_results.append(full)
                        known_paths.add(path)
                        new_hits += 1
                if new_hits:
                    print_success(f"ffuf API fuzz on {hostname}: {new_hits} new endpoint(s)")
                    for h in ffuf_results[-new_hits:][:10]:
                        print_info(f"  {h}")
            except Exception as exc:
                ctx.errors.append(f"API ffuf error on {hostname}: {exc}")
        else:
            print_warning("API wordlist not found — skipping ffuf API fuzz")

    # Final merge: endpoints = probe hits + ffuf-only hits (specs kept separate)
    all_endpoints = list(dict.fromkeys(discovered_endpoints + ffuf_results))

    ctx.api = ApiResult(
        endpoints=all_endpoints,
        graphql_endpoints=graphql_endpoints,
        spec_urls=spec_urls,
        api_tech_hints=api_tech_hints,
    )

    total = len(all_endpoints) + len(graphql_endpoints) + len(spec_urls)
    if total:
        print_finding("api", f"{total} API item(s) — {len(spec_urls)} spec(s), {len(graphql_endpoints)} GraphQL, {len(all_endpoints)} endpoint(s)")
    else:
        print_info("No API endpoints discovered")
