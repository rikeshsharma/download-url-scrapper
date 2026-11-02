"""Crawl-trap avoidance: calendars, faceted navigation, repeated parameters,
infinite / self-similar paths and overly long URLs."""

from __future__ import annotations

import re
from collections import Counter
from urllib.parse import urlsplit

from ..config import TrapsConfig

_DIGITS = re.compile(r"\d+")
_DATE_PATH = re.compile(r"(^|/)(19|20)\d{2}([/-])(0?[1-9]|1[0-2])(\3|/|$)")
_DATE_VALUE = re.compile(r"(19|20)\d{2}-(0[1-9]|1[0-2])(-\d{2})?")
_CAL_PARAMS = frozenset({"year", "month", "day", "date", "week", "cal", "calendar", "from",
                         "to", "start", "end", "ym", "yyyymm"})
_SESSIONISH = frozenset({"sid", "sessionid", "phpsessid", "jsessionid", "sort", "order", "page_size",
                         "view", "utm_source", "utm_medium", "utm_campaign"})


class TrapDetector:
    def __init__(self, cfg: TrapsConfig) -> None:
        self.cfg = cfg
        self._patterns: Counter[str] = Counter()

    @staticmethod
    def pattern_key(url: str) -> str:
        p = urlsplit(url)
        path = _DIGITS.sub("{n}", p.path)
        names = sorted({kv.split("=", 1)[0].lower() for kv in p.query.split("&") if kv})
        return f"{(p.hostname or '').lower()}{path}?{'&'.join(names)}"

    @staticmethod
    def is_calendar(url: str) -> bool:
        p = urlsplit(url)
        if _DATE_PATH.search(p.path):
            return True
        for kv in p.query.split("&"):
            if not kv:
                continue
            k, _, v = kv.partition("=")
            if k.lower() in _CAL_PARAMS or _DATE_VALUE.fullmatch(v):
                return True
        return False

    def static_reason(self, url: str) -> str | None:
        c = self.cfg
        if len(url) > c.max_url_length:
            return "trap_url_too_long"
        p = urlsplit(url)
        segments = [s for s in p.path.split("/") if s]
        if len(segments) > c.max_path_segments:
            return "trap_path_too_deep"
        if segments and max(Counter(segments).values()) > c.max_repeated_segment:
            return "trap_repeated_path_segment"
        params = [kv.split("=", 1)[0].lower() for kv in p.query.split("&") if kv]
        if len(params) > c.max_query_params:
            return "trap_too_many_query_params"
        if params and max(Counter(params).values()) > c.max_repeated_param:
            return "trap_repeated_query_param"
        return None

    def check_page(self, url: str) -> str | None:
        """Check a page URL and count it toward its pattern when accepted."""
        if reason := self.static_reason(url):
            return reason
        key = "page:" + self.pattern_key(url)
        limit = (self.cfg.max_urls_per_calendar_pattern if self.is_calendar(url)
                 else self.cfg.max_urls_per_pattern)
        if self._patterns[key] >= limit:
            return "trap_calendar_pattern" if self.is_calendar(url) else "trap_pattern_limit"
        self._patterns[key] += 1
        return None

    def check_candidate(self, url: str) -> str | None:
        if len(url) > self.cfg.max_url_length:
            return "trap_url_too_long"
        key = "cand:" + self.pattern_key(url)
        if self._patterns[key] >= self.cfg.max_candidates_per_pattern:
            return "trap_candidate_pattern_limit"
        self._patterns[key] += 1
        return None
