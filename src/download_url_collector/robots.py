"""robots.txt handling per RFC 9309.

* 2xx: parse and obey (Crawl-delay raises the host interval).
* 4xx: "unavailable" — crawling is allowed.
* 5xx / network failure: "unreachable" — the whole origin is treated as disallowed.
* Robots fetches themselves follow up to 5 redirects and are subject to the
  network policy and budget like any other request.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field

from protego import Protego

from .http_client import PolicyHttpClient
from .urls import hostname, origin

log = logging.getLogger(__name__)

ROBOTS_MAX_BYTES = 500 * 1024  # RFC 9309 minimum parse limit


@dataclass
class RobotsEntry:
    status: str  # "parsed" | "unavailable" | "unreachable"
    parser: Protego | None = None
    sitemaps: list[str] = field(default_factory=list)


class RobotsCache:
    def __init__(self, client: PolicyHttpClient, user_agent_token: str,
                 max_crawl_delay: float) -> None:
        self.client = client
        self.token = user_agent_token
        self.max_crawl_delay = max_crawl_delay
        self._entries: dict[str, RobotsEntry] = {}
        self._locks: dict[str, asyncio.Lock] = {}

    async def entry(self, url: str) -> RobotsEntry:
        key = origin(url)
        lock = self._locks.setdefault(key, asyncio.Lock())
        async with lock:
            if key not in self._entries:
                self._entries[key] = await self._load(key)
            return self._entries[key]

    async def _load(self, key: str) -> RobotsEntry:
        res = await self.client.fetch(f"{key}/robots.txt", max_bytes=ROBOTS_MAX_BYTES,
                                      check_robots=False, max_redirects=5)
        if res.error or res.status is None:
            # Policy blocks are "unreachable" too: nothing on that origin is fetched.
            log.info("robots_unreachable", extra={"origin": key, "error": res.error})
            return RobotsEntry("unreachable")
        if 400 <= res.status < 500:
            return RobotsEntry("unavailable")
        if res.status >= 500 or not (200 <= res.status < 300):
            return RobotsEntry("unreachable")
        text = res.body.decode("utf-8", errors="replace")
        parser = Protego.parse(text)
        delay = parser.crawl_delay(self.token)
        if delay:
            self.client.limiter.set_interval(hostname(key + "/"), min(float(delay), self.max_crawl_delay))
        return RobotsEntry("parsed", parser, list(parser.sitemaps))

    async def allowed(self, url: str) -> bool:
        e = await self.entry(url)
        if e.status == "unavailable":
            return True
        if e.status == "unreachable" or e.parser is None:
            return False
        return bool(e.parser.can_fetch(url, self.token))
