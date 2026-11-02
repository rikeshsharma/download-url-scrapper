"""YAML configuration model.

Every option has a conservative default. Unknown keys are rejected so typos do
not silently fall back to defaults.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid")


class CollectionConfig(_Model):
    name: str = "default"
    data_dir: Path = Path("./data")
    # Identify the crawler honestly; robots.txt rules are matched on the product token.
    user_agent: str = "download-url-collector/0.1 (+research crawler; contact: unset)"
    robots_user_agent_token: str = "download-url-collector"


class ScopeConfig(_Model):
    include_subdomains: bool = False
    additional_domains: list[str] = Field(default_factory=list)
    # Verify explicitly linked download targets on other hosts (never crawled as pages).
    verify_external_downloads: bool = True
    # Follow redirects that leave crawl scope (e.g. CDN hand-offs) when probing/verifying.
    follow_external_redirects: bool = True
    # Optional local Public Suffix List file; the bundled snapshot is used otherwise.
    psl_file: Path | None = None


class LimitsConfig(_Model):
    max_depth: int = Field(2, ge=0)
    max_pages_per_seed: int = Field(50, ge=1)
    max_pages_total: int = Field(500, ge=1)
    max_candidates_per_seed: int = Field(100, ge=1)
    max_candidates_total: int = Field(1000, ge=1)
    max_requests_total: int = Field(3000, ge=1)
    max_elapsed_seconds: float = Field(1800, gt=0)
    max_download_bytes_total: int = Field(2 * 1024**3, ge=1)
    max_file_bytes: int = Field(200 * 1024**2, ge=1)
    max_html_bytes: int = Field(5 * 1024**2, ge=1024)
    probe_sniff_bytes: int = Field(65536, ge=512)
    concurrency: int = Field(4, ge=1)
    per_host_concurrency: int = Field(1, ge=1)
    per_host_min_interval_seconds: float = Field(1.0, ge=0)
    max_redirects: int = Field(10, ge=0)
    max_meta_refresh: int = Field(2, ge=0)
    max_sitemap_files: int = Field(10, ge=0)
    max_sitemap_urls: int = Field(2000, ge=0)
    request_timeout_seconds: float = Field(30, gt=0)


class PolitenessConfig(_Model):
    # robots.txt is always honoured; there is intentionally no switch to disable it.
    max_retries: int = Field(3, ge=0)
    backoff_base_seconds: float = Field(1.0, ge=0)
    backoff_max_seconds: float = Field(60.0, ge=0)
    max_retry_after_seconds: float = Field(300.0, ge=0)
    max_crawl_delay_seconds: float = Field(30.0, ge=0)
    use_head: bool = True


class TrapsConfig(_Model):
    max_url_length: int = 2048
    max_path_segments: int = 15
    max_repeated_segment: int = 2
    max_query_params: int = 8
    max_repeated_param: int = 1
    max_urls_per_pattern: int = 25
    max_urls_per_calendar_pattern: int = 5
    max_candidates_per_pattern: int = 200


DEFAULT_BLOCKED_HOSTNAMES = [
    "localhost",
    "localhost.localdomain",
    "ip6-localhost",
    "ip6-loopback",
    "metadata",
    "metadata.google.internal",
    "metadata.goog",
    "instance-data",
    "instance-data.ec2.internal",
]


class NetworkConfig(_Model):
    # CIDRs exempted from the non-global-address block. Leave empty in production;
    # the test-suite uses it to reach its loopback fixture server.
    allow_cidrs: list[str] = Field(default_factory=list)
    blocked_hostnames: list[str] = Field(default_factory=lambda: list(DEFAULT_BLOCKED_HOSTNAMES))
    blocked_hostname_suffixes: list[str] = Field(
        default_factory=lambda: [".localhost", ".local", ".internal", ".home.arpa"]
    )
    # None allows any port.
    allowed_ports: list[int] | None = Field(default_factory=lambda: [80, 443, 8080, 8443])


class InteractionConfig(_Model):
    enabled: bool = True
    max_controls_per_page: int = Field(5, ge=0)
    post_click_wait_seconds: float = Field(5.0, ge=0)


class BrowserConfig(_Model):
    enabled: bool = True
    executable_path: Path | None = None
    # "chromium" = full Chromium build (new headless mode). Without it Playwright
    # uses chrome-headless-shell, which has no PDF viewer and therefore downloads
    # PDFs that a real browser renders inline. Ignored when executable_path is set.
    channel: str | None = "chromium"
    headless: bool = True
    # Keep Chromium's OS sandbox on; some containers need it off (document why if so).
    chromium_sandbox: bool = True
    extra_args: list[str] = Field(default_factory=list)
    navigation_timeout_seconds: float = 30
    download_event_grace_seconds: float = 4.0
    download_timeout_seconds: float = 300
    verify_concurrency: int = Field(2, ge=1)
    render_seed_pages: bool = True
    render_pages_with_controls: bool = True
    # Probe failures with these HTTP statuses are still verified in the browser
    # (some servers answer non-browser clients differently).
    verify_probe_failure_statuses: list[int] = Field(default_factory=lambda: [401, 403, 406, 410, 429])
    interaction: InteractionConfig = Field(default_factory=InteractionConfig)
    # Route all browser traffic through the in-process egress-filtering proxy.
    # Disabling it removes browser network restrictions and is refused unless
    # allow_unfiltered_browser_network is also set.
    egress_proxy: bool = True
    allow_unfiltered_browser_network: bool = False
    # Optional "module:attribute" factory returning a FeatureCollectorHook.
    feature_collector: str | None = None


class ArchiveInspectionConfig(_Model):
    enabled: bool = False
    max_members: int = 1000
    max_total_uncompressed_bytes: int = 512 * 1024**2
    max_compression_ratio: float = 100.0
    max_listed_members: int = 50


class InspectionConfig(_Model):
    archives: ArchiveInspectionConfig = Field(default_factory=ArchiveInspectionConfig)


class StorageConfig(_Model):
    keep_files: bool = True
    max_storage_bytes: int = 5 * 1024**3


class CapsConfig(_Model):
    per_domain: int | None = 200
    per_publisher: int | None = 200
    per_content_hash: int | None = 3


class SamplingConfig(_Model):
    # Targets per dimension value, e.g. {"family": {"pe": 50, "zip": 50}}.
    targets: dict[str, dict[str, int]] = Field(default_factory=dict)
    caps: CapsConfig = Field(default_factory=CapsConfig)


class GitHubAdapterConfig(_Model):
    enabled: bool = False
    api_base: str = "https://api.github.com"
    web_hosts: list[str] = Field(default_factory=lambda: ["github.com"])
    token_env: str = "GITHUB_TOKEN"
    max_releases: int = 5
    max_assets: int = 50


class AdaptersConfig(_Model):
    github_releases: GitHubAdapterConfig = Field(default_factory=GitHubAdapterConfig)


class ScannerConfig(_Model):
    type: Literal["clamav", "mock", "none"] = "clamav"
    binary: str = "clamscan"
    timeout_seconds: float = 300
    # Mock scanner only: "clean", "detected", "unavailable", "error"; per-hash overrides.
    mock_default_verdict: str = "unavailable"
    mock_verdicts: dict[str, str] = Field(default_factory=dict)


class SignatureConfig(_Model):
    type: Literal["osslsigncode", "mock", "none"] = "none"
    binary: str = "osslsigncode"
    ca_file: Path | None = None
    timeout_seconds: float = 60
    mock_results: dict[str, dict[str, str]] = Field(default_factory=dict)


class ReputationConfig(_Model):
    enabled: bool = False
    provider: Literal["virustotal"] = "virustotal"
    api_key_env: str = "VT_API_KEY"
    base_url: str = "https://www.virustotal.com/api/v3"
    requests_per_minute: int = Field(4, ge=1)
    daily_quota: int = Field(500, ge=0)
    # The network policy applies to reputation lookups; tests point base_url at loopback.


class LabelingConfig(_Model):
    policy_file: Path = Path("config/labeling_policy.yaml")
    scanner: ScannerConfig = Field(default_factory=ScannerConfig)
    signature: SignatureConfig = Field(default_factory=SignatureConfig)
    reputation: ReputationConfig = Field(default_factory=ReputationConfig)
    checksum_discovery: bool = True


class DatasetConfig(_Model):
    test_fraction: float = Field(0.2, ge=0, le=1)
    unseen_domain_fraction: float = Field(0.15, ge=0, le=1)
    temporal_cutoff: str | None = None  # ISO-8601; samples first seen at/after it are temporal test
    split_salt: str = "duc-split-v1"


DEFAULT_SENSITIVE_PARAMS = [
    "token", "access_token", "id_token", "refresh_token", "auth", "authorization",
    "key", "apikey", "api_key", "secret", "password", "passwd", "pwd", "session",
    "sessionid", "sid", "sig", "signature", "code", "jwt", "credential",
    "x-amz-signature", "x-amz-credential", "x-amz-security-token",
    "x-goog-signature", "x-goog-credential", "googleaccessid",
    "policy", "key-pair-id", "se", "sp", "sv", "skoid", "sktid", "st", "hmac", "hash",
]


class PrivacyConfig(_Model):
    sensitive_params: list[str] = Field(default_factory=lambda: list(DEFAULT_SENSITIVE_PARAMS))
    # Long opaque query values are flagged as possible tokens.
    token_value_min_length: int = 32


class Config(_Model):
    collection: CollectionConfig = Field(default_factory=CollectionConfig)
    scope: ScopeConfig = Field(default_factory=ScopeConfig)
    limits: LimitsConfig = Field(default_factory=LimitsConfig)
    politeness: PolitenessConfig = Field(default_factory=PolitenessConfig)
    traps: TrapsConfig = Field(default_factory=TrapsConfig)
    network: NetworkConfig = Field(default_factory=NetworkConfig)
    browser: BrowserConfig = Field(default_factory=BrowserConfig)
    inspection: InspectionConfig = Field(default_factory=InspectionConfig)
    storage: StorageConfig = Field(default_factory=StorageConfig)
    sampling: SamplingConfig = Field(default_factory=SamplingConfig)
    adapters: AdaptersConfig = Field(default_factory=AdaptersConfig)
    labeling: LabelingConfig = Field(default_factory=LabelingConfig)
    dataset: DatasetConfig = Field(default_factory=DatasetConfig)
    privacy: PrivacyConfig = Field(default_factory=PrivacyConfig)

    @field_validator("browser")
    @classmethod
    def _proxy_guard(cls, v: BrowserConfig) -> BrowserConfig:
        if not v.egress_proxy and not v.allow_unfiltered_browser_network:
            raise ValueError(
                "browser.egress_proxy=false removes browser network restrictions; "
                "set browser.allow_unfiltered_browser_network=true only if an external "
                "egress proxy/firewall enforces the policy"
            )
        return v

    def fingerprint(self) -> str:
        """Stable hash of the effective configuration, recorded with every run."""
        blob = json.dumps(self.model_dump(mode="json"), sort_keys=True)
        return hashlib.sha256(blob.encode()).hexdigest()[:16]


def load_config(path: str | Path | None, overrides: dict[str, Any] | None = None) -> Config:
    data: dict[str, Any] = {}
    base_dir = Path.cwd()
    if path is not None:
        p = Path(path)
        with p.open("r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
        if not isinstance(data, dict):
            raise ValueError(f"{p}: top-level YAML value must be a mapping")
        base_dir = p.resolve().parent
    if overrides:
        data = _deep_merge(data, overrides)
    cfg = Config.model_validate(data)
    # Relative paths in a config file are relative to that file.
    if not cfg.collection.data_dir.is_absolute():
        cfg.collection.data_dir = (base_dir / cfg.collection.data_dir).resolve()
    if not cfg.labeling.policy_file.is_absolute():
        cfg.labeling.policy_file = (base_dir / cfg.labeling.policy_file).resolve()
    return cfg


def _deep_merge(a: dict[str, Any], b: dict[str, Any]) -> dict[str, Any]:
    out = dict(a)
    for k, v in b.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out
