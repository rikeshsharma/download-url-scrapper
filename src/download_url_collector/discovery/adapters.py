"""Optional source adapters for documented release APIs.

Adapters only *discover* candidates (plus publisher-provided metadata such as
checksums). Every request goes through the policy-enforcing client, honours
robots.txt for the API origin and the API's own rate-limit headers.
"""

from __future__ import annotations

import json
import logging
import os
import re
import time
from dataclasses import dataclass, field
from typing import Any, Protocol

from ..config import GitHubAdapterConfig
from ..http_client import PolicyHttpClient
from ..urls import URLError, hostname, normalize_observed

log = logging.getLogger(__name__)


@dataclass
class AdapterCandidate:
    url: str
    source_page: str
    publisher: str | None
    filename: str | None = None
    declared_size: int | None = None
    publisher_checksums: dict[str, str] = field(default_factory=dict)  # algo -> hex
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class AdapterResult:
    candidates: list[AdapterCandidate] = field(default_factory=list)
    errors: list[tuple[str, str]] = field(default_factory=list)  # (url, reason)


class SourceAdapter(Protocol):
    name: str

    def matches(self, seed_url: str) -> bool: ...

    async def discover(self, seed_url: str, client: PolicyHttpClient) -> AdapterResult: ...


_REPO_RE = re.compile(r"^/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?(?:/.*)?$")


class GitHubReleasesAdapter:
    """GitHub REST API: GET /repos/{owner}/{repo}/releases.

    Uses ``browser_download_url`` (the stable, documented replay URL) and the
    asset ``digest`` field when present as a publisher-platform checksum.
    """

    name = "github_releases"

    def __init__(self, cfg: GitHubAdapterConfig) -> None:
        self.cfg = cfg
        self._reset_at: float = 0.0

    def matches(self, seed_url: str) -> bool:
        from urllib.parse import urlsplit

        p = urlsplit(seed_url)
        return hostname(seed_url) in self.cfg.web_hosts and bool(_REPO_RE.match(p.path))

    async def discover(self, seed_url: str, client: PolicyHttpClient) -> AdapterResult:
        from urllib.parse import urlsplit

        out = AdapterResult()
        m = _REPO_RE.match(urlsplit(seed_url).path)
        if not m:
            return out
        owner, repo = m.group(1), m.group(2)
        if time.time() < self._reset_at:
            out.errors.append((seed_url, "api_rate_limited"))
            return out
        api = f"{self.cfg.api_base.rstrip('/')}/repos/{owner}/{repo}/releases?per_page={self.cfg.max_releases}"
        headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
        token = os.environ.get(self.cfg.token_env)
        if token:
            headers["Authorization"] = f"Bearer {token}"
        res = await client.fetch(api, max_bytes=5 * 1024**2, extra_headers=headers)
        remaining = res.header("x-ratelimit-remaining")
        if remaining is not None and remaining.strip() == "0":
            try:
                self._reset_at = float(res.header("x-ratelimit-reset") or 0)
            except ValueError:
                self._reset_at = time.time() + 3600
        if not res.ok:
            out.errors.append((api, f"adapter_http_error:{res.error or res.status}"))
            return out
        try:
            releases = json.loads(res.body)
        except ValueError:
            out.errors.append((api, "adapter_bad_json"))
            return out
        count = 0
        for rel in releases if isinstance(releases, list) else []:
            if rel.get("draft"):
                continue
            page = rel.get("html_url") or seed_url
            for asset in rel.get("assets") or []:
                if count >= self.cfg.max_assets:
                    return out
                raw = asset.get("browser_download_url")
                if not isinstance(raw, str):
                    continue
                try:
                    url = normalize_observed(raw)[0]
                except URLError as exc:
                    out.errors.append((raw, f"invalid_url:{exc}"))
                    continue
                checksums: dict[str, str] = {}
                digest = asset.get("digest")
                if isinstance(digest, str) and ":" in digest:
                    algo, hexval = digest.split(":", 1)
                    checksums[algo.lower()] = hexval.lower()
                out.candidates.append(AdapterCandidate(
                    url=url, source_page=page, publisher=f"github:{owner}",
                    filename=asset.get("name"), declared_size=asset.get("size"),
                    publisher_checksums=checksums,
                    metadata={"release_tag": rel.get("tag_name"),
                              "prerelease": rel.get("prerelease"),
                              "published_at": rel.get("published_at"),
                              "asset_content_type": asset.get("content_type")},
                ))
                count += 1
        return out


def build_adapters(cfg: Any) -> list[SourceAdapter]:
    adapters: list[SourceAdapter] = []
    if cfg.adapters.github_releases.enabled:
        adapters.append(GitHubReleasesAdapter(cfg.adapters.github_releases))
    return adapters
