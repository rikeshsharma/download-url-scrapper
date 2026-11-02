"""Run-wide resource budgets, checked before (and during) every costly action."""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from .config import LimitsConfig


class BudgetExceeded(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass
class Budget:
    limits: LimitsConfig
    requests: int = 0
    bytes: int = 0
    pages: int = 0
    candidates: int = 0
    started: float = field(default_factory=time.monotonic)
    exhausted: set[str] = field(default_factory=set)

    def _fail(self, reason: str) -> None:
        self.exhausted.add(reason)
        raise BudgetExceeded(reason)

    def check_time(self) -> None:
        if time.monotonic() - self.started > self.limits.max_elapsed_seconds:
            self._fail("max_elapsed_seconds")

    def take_request(self) -> None:
        self.check_time()
        if self.requests >= self.limits.max_requests_total:
            self._fail("max_requests_total")
        self.requests += 1

    def add_bytes(self, n: int) -> None:
        self.bytes += n
        if self.bytes > self.limits.max_download_bytes_total:
            self._fail("max_download_bytes_total")

    def remaining_bytes(self) -> int:
        return max(0, self.limits.max_download_bytes_total - self.bytes)

    def take_page(self) -> None:
        if self.pages >= self.limits.max_pages_total:
            self._fail("max_pages_total")
        self.pages += 1

    def take_candidate(self) -> None:
        if self.candidates >= self.limits.max_candidates_total:
            self._fail("max_candidates_total")
        self.candidates += 1

    def snapshot(self) -> dict[str, int]:
        return {"requests": self.requests, "bytes": self.bytes, "pages": self.pages,
                "candidates": self.candidates}

    def restore(self, snap: dict[str, int]) -> None:
        self.requests = int(snap.get("requests", 0))
        self.bytes = int(snap.get("bytes", 0))
        self.pages = int(snap.get("pages", 0))
        self.candidates = int(snap.get("candidates", 0))
