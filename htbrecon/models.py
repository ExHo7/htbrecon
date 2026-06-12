from __future__ import annotations

import ipaddress
from pathlib import Path

from pydantic import BaseModel, ConfigDict, field_validator


class PortInfo(BaseModel):
    model_config = ConfigDict(frozen=True)

    port: int
    protocol: str
    state: str
    service: str
    version: str = ""
    product: str = ""        # nmap <service product=> e.g. "Apache httpd"
    cpe: list[str] = []      # nmap CPEs e.g. ["cpe:/a:apache:http_server:2.4.41"]


class NmapResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    ports: list[PortInfo]
    raw_output: str


class WhatWebResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    url: str
    technologies: list[str]
    raw_output: str


class FfufResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    target: str
    found_items: list[str]
    raw_output: str


class NucleiFinding(BaseModel):
    model_config = ConfigDict(frozen=True)

    template_id: str
    severity: str
    name: str
    matched_at: str


class NucleiResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    target: str
    findings: list[NucleiFinding]
    raw_output: str


class CveInfo(BaseModel):
    model_config = ConfigDict(frozen=True)

    cve_id: str
    severity: str
    cvss_score: float = 0.0
    epss_score: float = 0.0
    description: str = ""
    product: str = ""
    is_poc: bool = False
    is_kev: bool = False
    is_remote: bool = False
    has_nuclei_template: bool = False
    remediation: str = ""
    poc_urls: list[str] = []
    # Version applicability verdict vs. the detected version, derived from the
    # CVE description/remediation (vulnx exposes no structured version range):
    # "in" (detected version is affected), "unknown" (couldn't determine).
    # "out" findings are dropped before they reach the report.
    version_verdict: str = "unknown"


class VulnxResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    findings: list[CveInfo]
    searched_terms: list[str]


class SprayResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    lockout_threshold: int = 0  # 0 = no lockout policy
    users_tested: int = 0
    valid_creds: list[str] = []  # "user:password" format
    raw_output: str = ""


class SmbResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    shares: list[str]
    users: list[str]
    ntlm_reflection_vulnerable: bool = False
    av_products: list[str] = []
    nopac_vulnerable: bool = False
    coerce_vulns: list[str] = []
    rid_users: list[str] = []
    enum4linux_output: str
    nxc_output: str


class BloodHoundResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    ad_domain: str = ""
    func_level: str = ""
    users_count: int = 0
    groups_count: int = 0
    computers_count: int = 0
    admin_users: list[str] = []
    spn_users: list[str] = []
    asrep_users: list[str] = []
    unconstrained_users: list[str] = []
    dcsync_principals: list[str] = []
    summary_text: str = ""


class LdapResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    raw_output: str
    base_dn: str = ""
    entries_count: int = 0
    users: list[str] = []
    domain_admins: list[str] = []
    descriptions: list[str] = []             # "user: description" for non-generic entries
    unconstrained_delegation: list[str] = []
    domain_trusts: list[str] = []
    asreproast_hashes: list[str] = []
    kerberoast_hashes: list[str] = []
    adcs_cas: list[str] = []
    adcs_vulns: list[str] = []
    badsuccessor_dmsas: list[str] = []


class KerbruteResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    valid_users: list[str] = []
    tested_count: int = 0
    raw_output: str = ""


class SpiderResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    interesting_files: list[str] = []  # "SHARE/path/file.ext" format
    shares_spidered: list[str] = []
    output_dir: str = ""
    raw_output: str = ""


class WinRmResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    accessible: bool = False
    port: int = 5985
    raw_output: str = ""


class EyeWitnessResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    screenshots_count: int = 0
    output_dir: str = ""


class SshResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    accessible: bool = False
    port: int = 22
    raw_output: str = ""


class FtpResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    anonymous: bool = False
    accessible: bool = False
    port: int = 21
    raw_output: str = ""


class MssqlResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    accessible: bool = False
    sysadmin: bool = False
    xp_cmdshell: bool = False
    databases: list[str] = []
    port: int = 1433
    raw_output: str = ""


class KatanaResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    urls_found: list[str] = []
    interesting_urls: list[str] = []
    output_file: str = ""


class ApiResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    endpoints: list[str] = []          # "https://host/api/v1 [200]"
    graphql_endpoints: list[str] = []  # URLs with open introspection
    spec_urls: list[str] = []          # Swagger / OpenAPI spec URLs
    api_tech_hints: list[str] = []     # e.g. ["flowise", "fastapi"]


class ReconContext:
    """Mutable shared state accumulated across the pipeline."""

    def __init__(self, config: ReconConfig) -> None:
        self.config = config
        self.nmap: NmapResult | None = None
        self.whatweb: list[WhatWebResult] = []
        self.subdomains: list[str] = []
        self.directories: list[FfufResult] = []
        self.nuclei: NucleiResult | None = None
        self.https_redirect_ports: set[int] = set()  # ports that 301→https
        self.vulnx: VulnxResult | None = None
        self.smb: SmbResult | None = None
        self.ldap: LdapResult | None = None
        self.bloodhound: BloodHoundResult | None = None
        self.spray: SprayResult | None = None
        self.kerbrute: KerbruteResult | None = None
        self.spider: SpiderResult | None = None
        self.winrm: WinRmResult | None = None
        self.ssh: SshResult | None = None
        self.ftp: FtpResult | None = None
        self.mssql: MssqlResult | None = None
        self.eyewitness: EyeWitnessResult | None = None
        self.api: ApiResult | None = None
        self.katana: KatanaResult | None = None
        self.ai_analysis: str = ""
        self.errors: list[str] = []

    @property
    def open_ports(self) -> list[PortInfo]:
        if self.nmap is None:
            return []
        return [p for p in self.nmap.ports if p.state == "open"]

    @property
    def http_ports(self) -> list[PortInfo]:
        http_services = {"http", "https", "http-proxy", "http-alt", "https-alt"}
        return [p for p in self.open_ports if p.service in http_services]

    @property
    def has_smb(self) -> bool:
        return any(p.port in (139, 445) for p in self.open_ports)

    @property
    def has_ldap(self) -> bool:
        return any(p.port in (389, 636, 3268, 3269) for p in self.open_ports)

    @property
    def has_kerberos(self) -> bool:
        return any(p.port == 88 for p in self.open_ports)

    @property
    def has_winrm(self) -> bool:
        return any(p.port in (5985, 5986) for p in self.open_ports)

    @property
    def has_ssh(self) -> bool:
        return any(p.port in (22, 2222, 22222) for p in self.open_ports)

    @property
    def has_ftp(self) -> bool:
        return any(p.port in (21, 2121) for p in self.open_ports)

    @property
    def has_mssql(self) -> bool:
        return any(p.port in (1433, 1434) for p in self.open_ports)

    @property
    def all_hostnames(self) -> list[str]:
        return [self.config.hostname, *self.subdomains]

    def is_ssl(self, port: PortInfo) -> bool:
        """Determine if a port uses SSL/TLS based on nmap service info."""
        ssl_indicators = {"https", "https-alt", "ssl"}
        if port.service in ssl_indicators:
            return True
        if port.port in (443, 8443):
            return True
        if "ssl" in port.version.lower() or "tls" in port.version.lower():
            return True
        return False

    def build_url(self, hostname: str, port: PortInfo) -> str:
        """Build the correct URL (http/https) for a given hostname and port."""
        scheme = "https" if self.is_ssl(port) else "http"
        if (scheme == "http" and port.port == 80) or (scheme == "https" and port.port == 443):
            return f"{scheme}://{hostname}"
        return f"{scheme}://{hostname}:{port.port}"

    def web_urls(self, hostname: str | None = None) -> list[tuple[PortInfo, str]]:
        """Return (port, url) pairs for all HTTP ports and a given hostname.

        Ports that redirect to HTTPS are replaced by https://hostname
        (standard port 443) to avoid scanning http→https redirect loops.
        Deduplicates URLs so https://host isn't scanned twice.
        """
        host = hostname or self.config.hostname
        seen_urls: set[str] = set()
        result: list[tuple[PortInfo, str]] = []
        for p in self.http_ports:
            if p.port in self.https_redirect_ports:
                url = f"https://{host}"
            else:
                url = self.build_url(host, p)
            if url not in seen_urls:
                seen_urls.add(url)
                result.append((p, url))
        return result


class ReconConfig(BaseModel):
    model_config = ConfigDict(frozen=True)

    ip: str
    name: str
    domain: str = "htb"
    credentials: tuple[str, str] | None = None
    skip_ai: bool = False
    debug: bool = False
    html: bool = False
    project_dir: Path = Path(".")
    subdomain_wordlist: Path = Path(
        "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
    )
    directory_wordlist: Path = Path(
        "/usr/share/dirb/wordlists/common.txt"
    )

    @field_validator("ip")
    @classmethod
    def validate_ip(cls, v: str) -> str:
        try:
            ipaddress.ip_address(v)
        except ValueError:
            raise ValueError(f"Invalid IP address: {v!r}")
        return v

    @property
    def base_url(self) -> str:
        return f"http://{self.name}.{self.domain}"

    @property
    def hostname(self) -> str:
        return f"{self.name}.{self.domain}"
