"""Per-host politeness: concurrency, minimum interval, Retry-After and backoff."""

from __future__ import annotations

import asyncio
import email.utils
import random
import time
from collections import defaultdict
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager


def parse_retry_after(value: str | None, now: float | None = None) -> float | None:
    """Seconds to wait from a Retry-After header (delta-seconds or HTTP-date)."""
    if not value:
        return None
    value = value.strip()
    if value.isdigit():
        return float(value)
    try:
        dt = email.utils.parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return None
    if dt is None:
        return None
    now = time.time() if now is None else now
    return max(0.0, dt.timestamp() - now)


def backoff_delay(attempt: int, base: float, cap: float, rng: random.Random) -> float:
    """Exponential backoff with 'equal jitter'."""
    exp = min(cap, base * (2**attempt))
    return exp / 2 + rng.uniform(0, exp / 2)


class HostLimiter:
    def __init__(self, per_host_concurrency: int, min_interval: float) -> None:
        self._per_host = per_host_concurrency
        self._default_interval = min_interval
        self._sems: dict[str, asyncio.Semaphore] = {}
        self._last: dict[str, float] = defaultdict(float)
        self._interval: dict[str, float] = {}
        self._blocked_until: dict[str, float] = defaultdict(float)
        self._locks: dict[str, asyncio.Lock] = {}

    def set_interval(self, host: str, seconds: float) -> None:
        """Raise the interval for a host (e.g. robots.txt Crawl-delay)."""
        self._interval[host] = max(self._default_interval, seconds)

    def defer(self, host: str, seconds: float) -> None:
        """Pause a host (Retry-After, 429/503 backoff)."""
        self._blocked_until[host] = max(self._blocked_until[host], time.monotonic() + seconds)

    @asynccontextmanager
    async def slot(self, host: str) -> AsyncIterator[None]:
        sem = self._sems.setdefault(host, asyncio.Semaphore(self._per_host))
        lock = self._locks.setdefault(host, asyncio.Lock())
        async with sem:
            async with lock:
                interval = self._interval.get(host, self._default_interval)
                wait_until = max(self._last[host] + interval, self._blocked_until[host])
                delay = wait_until - time.monotonic()
                if delay > 0:
                    await asyncio.sleep(delay)
                self._last[host] = time.monotonic()
            yield
