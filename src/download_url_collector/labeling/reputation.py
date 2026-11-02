"""Optional hash-reputation lookups (VirusTotal v3 file report by SHA-256).

* Disabled by default; the API key comes only from an environment variable.
* Hash lookups only — files are never uploaded.
* Requests per minute and a persistent daily quota are enforced.
* "Not found" is recorded as absent, which is *not* evidence of benignness.
"""

from __future__ import annotations

import asyncio
import json
import os
import time
from dataclasses import dataclass, field
from typing import Any

from ..config import ReputationConfig
from ..http_client import PolicyHttpClient
from ..models import utcnow
from ..storage import Store


@dataclass
class ReputationResult:
    provider: str
    verdict: str  # "malicious" | "suspicious" | "clean" | "not_found" | "error" | "quota_exhausted" | "unavailable"
    malicious: int | None = None
    suspicious: int | None = None
    harmless: int | None = None
    undetected: int | None = None
    engines_total: int | None = None
    last_analysis_date: str | None = None
    detail: str | None = None
    queried_at: str = field(default_factory=utcnow)

    def to_details(self) -> dict[str, Any]:
        return {k: v for k, v in self.__dict__.items() if k not in ("provider", "verdict")}


class VirusTotalLookup:
    provider = "virustotal"

    def __init__(self, cfg: ReputationConfig, store: Store, client: PolicyHttpClient) -> None:
        self.cfg = cfg
        self.store = store
        self.client = client
        self.key = os.environ.get(cfg.api_key_env)
        self._last = 0.0

    async def lookup(self, sha256: str) -> ReputationResult:
        if not self.key:
            return ReputationResult(self.provider, "unavailable", detail=f"{self.cfg.api_key_env} not set")
        day = time.strftime("%Y-%m-%d", time.gmtime())
        if not self.store.quota_take(self.provider, day, self.cfg.daily_quota):
            return ReputationResult(self.provider, "quota_exhausted")
        gap = 60.0 / self.cfg.requests_per_minute
        wait = self._last + gap - time.monotonic()
        if wait > 0:
            await asyncio.sleep(wait)
        self._last = time.monotonic()
        url = f"{self.cfg.base_url.rstrip('/')}/files/{sha256}"
        res = await self.client.fetch(url, max_bytes=2 * 1024**2, check_robots=False,
                                      extra_headers={"x-apikey": self.key, "Accept": "application/json"})
        if res.status == 404:
            return ReputationResult(self.provider, "not_found")
        if res.status == 429:
            return ReputationResult(self.provider, "quota_exhausted", detail="http 429")
        if not res.ok:
            return ReputationResult(self.provider, "error", detail=f"{res.error or res.status}")
        try:
            attrs = json.loads(res.body)["data"]["attributes"]
            stats = attrs["last_analysis_stats"]
        except (ValueError, KeyError, TypeError) as exc:
            return ReputationResult(self.provider, "error", detail=f"bad response: {exc}")
        mal, sus = int(stats.get("malicious", 0)), int(stats.get("suspicious", 0))
        total = sum(int(v) for v in stats.values() if isinstance(v, int))
        ts = attrs.get("last_analysis_date")
        r = ReputationResult(
            self.provider, "clean", mal, sus, int(stats.get("harmless", 0)),
            int(stats.get("undetected", 0)), total,
            time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts)) if isinstance(ts, int) else None)
        if mal:
            r.verdict = "malicious"
        elif sus:
            r.verdict = "suspicious"
        return r
