"""Policy-enforcing asynchronous HTTP client.

Every hop of every request (including redirects) is checked against the network
policy, robots.txt, the caller's scope rule and the run budget. Connections are
made to addresses validated at connect time (see ``netpolicy``). Bodies are
streamed and truncated at a byte bound; nothing is buffered unbounded.
"""

from __future__ import annotations

import asyncio
import logging
import random
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

import aiohttp

from .budget import Budget, BudgetExceeded
from .config import Config
from .netpolicy import NetworkPolicy, PolicyViolation, make_aiohttp_resolver
from .ratelimit import HostLimiter, backoff_delay, parse_retry_after
from .urls import URLError, hostname, port_of, resolve

log = logging.getLogger(__name__)

REDIRECT_STATUSES = {301, 302, 303, 307, 308}
RETRY_STATUSES = {429, 503}
# Headers recorded verbatim; Set-Cookie values are never stored.
RECORDED_HEADERS = (
    "content-type", "content-length", "content-disposition", "content-encoding",
    "content-range", "accept-ranges", "location", "last-modified", "etag",
    "cache-control", "expires", "server", "x-content-type-options", "retry-after",
    "refresh", "link", "content-location", "x-robots-tag",
)

ScopeCheck = Callable[[str], str | None]
RobotsCheck = Callable[[str], Awaitable[bool]]


@dataclass
class Hop:
    url: str
    status: int | None
    location: str | None = None
    method: str = "GET"

    def to_dict(self) -> dict[str, Any]:
        return {"url": self.url, "status": self.status, "location": self.location,
                "method": self.method}


@dataclass
class FetchResult:
    request_url: str
    method: str
    final_url: str | None = None
    status: int | None = None
    headers: dict[str, str] = field(default_factory=dict)
    set_cookie_names: list[str] = field(default_factory=list)
    redirect_chain: list[Hop] = field(default_factory=list)
    body: bytes = b""
    bytes_observed: int = 0
    truncated: bool = False
    range_requested: bool = False
    error: str | None = None
    error_detail: str | None = None
    attempts: int = 0

    @property
    def ok(self) -> bool:
        return self.error is None and self.status is not None and 200 <= self.status < 300

    def header(self, name: str) -> str | None:
        return self.headers.get(name.lower())

    def http_meta(self) -> dict[str, Any]:
        return {
            "method": self.method, "status": self.status, "final_url": self.final_url,
            "headers": self.headers, "set_cookie_names": self.set_cookie_names,
            "redirect_chain": [h.to_dict() for h in self.redirect_chain],
            "bytes_observed": self.bytes_observed, "truncated": self.truncated,
            "range_requested": self.range_requested, "error": self.error,
        }


class PolicyHttpClient:
    def __init__(self, cfg: Config, policy: NetworkPolicy, budget: Budget,
                 limiter: HostLimiter | None = None, rng_seed: int | None = None) -> None:
        self.cfg = cfg
        self.policy = policy
        self.budget = budget
        self.limiter = limiter or HostLimiter(
            cfg.limits.per_host_concurrency, cfg.limits.per_host_min_interval_seconds
        )
        self.robots_check: RobotsCheck | None = None
        self._rng = random.Random(rng_seed)
        self._global = asyncio.Semaphore(cfg.limits.concurrency)
        self._session: aiohttp.ClientSession | None = None

    async def __aenter__(self) -> PolicyHttpClient:
        connector = aiohttp.TCPConnector(
            resolver=make_aiohttp_resolver(self.policy),
            use_dns_cache=False,  # re-validate on every new connection
            limit=self.cfg.limits.concurrency * 2,
        )
        self._session = aiohttp.ClientSession(
            connector=connector,
            cookie_jar=aiohttp.DummyCookieJar(),  # never carry session state
            trust_env=False,  # never route via environment proxies
            timeout=aiohttp.ClientTimeout(total=None,
                                          sock_connect=self.cfg.limits.request_timeout_seconds,
                                          sock_read=self.cfg.limits.request_timeout_seconds),
            headers={"User-Agent": self.cfg.collection.user_agent, "Accept": "*/*"},
            auto_decompress=True,
        )
        return self

    async def __aexit__(self, *exc: object) -> None:
        if self._session is not None:
            await self._session.close()

    # ------------------------------------------------------------------
    async def precheck(self, url: str, *, check_robots: bool = True,
                       scope_check: ScopeCheck | None = None) -> str | None:
        """Return an exclusion reason for *url*, or None if it may be requested."""
        host = hostname(url)
        if reason := self.policy.check_hostname(host):
            return reason
        if reason := self.policy.check_port(port_of(url)):
            return reason
        if scope_check is not None and (reason := scope_check(url)):
            return reason
        try:
            await self.policy.resolve_and_check(host, port_of(url))
        except PolicyViolation as exc:
            return exc.reason
        if check_robots and self.robots_check is not None and not await self.robots_check(url):
            return "robots_disallowed"
        return None

    async def fetch(
        self,
        url: str,
        *,
        method: str = "GET",
        max_bytes: int,
        range_bytes: int | None = None,
        scope_check: ScopeCheck | None = None,
        check_robots: bool = True,
        max_redirects: int | None = None,
        extra_headers: dict[str, str] | None = None,
        body_limit: Callable[[dict[str, str]], int] | None = None,
    ) -> FetchResult:
        """Fetch *url* following redirects hop by hop.

        ``body_limit`` may lower ``max_bytes`` once response headers are known
        (e.g. read only a sniff sample of a non-HTML response).
        """
        assert self._session is not None, "use 'async with PolicyHttpClient(...)'"
        max_redirects = self.cfg.limits.max_redirects if max_redirects is None else max_redirects
        result = FetchResult(request_url=url, method=method)
        current = url
        cur_method = method
        for hop_index in range(max_redirects + 1):
            # The first hop is checked by the caller's scope rule as well: the
            # caller decides whether the initial URL is eligible.
            reason = await self.precheck(current, check_robots=check_robots,
                                         scope_check=scope_check if hop_index else None)
            if reason:
                result.redirect_chain.append(Hop(current, None, method=cur_method))
                result.error = "blocked" if hop_index == 0 else "redirect_blocked"
                result.error_detail = reason
                return result
            hop = await self._one_hop(current, cur_method, max_bytes, range_bytes,
                                      extra_headers, result, body_limit)
            result.redirect_chain.append(hop)
            if result.error:
                return result
            if hop.status in REDIRECT_STATUSES and hop.location:
                try:
                    nxt = resolve(current, hop.location)
                except URLError as exc:
                    result.error = "bad_redirect"
                    result.error_detail = str(exc)
                    return result
                if hop.status == 303 or (hop.status in (301, 302) and cur_method == "POST"):
                    cur_method = "GET"
                current = nxt
                result.body = b""
                continue
            result.final_url = current
            return result
        result.error = "too_many_redirects"
        result.error_detail = str(max_redirects)
        return result

    async def _one_hop(self, url: str, method: str, max_bytes: int, range_bytes: int | None,
                       extra_headers: dict[str, str] | None, result: FetchResult,
                       body_limit: Callable[[dict[str, str]], int] | None = None) -> Hop:
        assert self._session is not None
        host = hostname(url)
        headers = dict(extra_headers or {})
        if range_bytes is not None and method == "GET":
            headers["Range"] = f"bytes=0-{range_bytes - 1}"
            result.range_requested = True
        pol = self.cfg.politeness
        attempt = 0
        while True:
            attempt += 1
            result.attempts += 1
            try:
                self.budget.take_request()
            except BudgetExceeded as exc:
                result.error = "budget_exhausted"
                result.error_detail = exc.reason
                return Hop(url, None, method=method)
            try:
                async with self._global, self.limiter.slot(host):
                    async with self._session.request(
                        method, url, headers=headers, allow_redirects=False,
                    ) as resp:
                        status = resp.status
                        if status in RETRY_STATUSES and attempt <= pol.max_retries:
                            wait = parse_retry_after(resp.headers.get("Retry-After"))
                            if wait is None:
                                wait = backoff_delay(attempt - 1, pol.backoff_base_seconds,
                                                     pol.backoff_max_seconds, self._rng)
                            if wait <= pol.max_retry_after_seconds:
                                self.limiter.defer(host, wait)
                                log.info("retry_after", extra={"url": url, "status": status,
                                                               "wait_s": round(wait, 2)})
                                continue
                        self._record_response(resp, result)
                        location = resp.headers.get("Location")
                        if status in REDIRECT_STATUSES and location:
                            return Hop(url, status, location, method)
                        if method != "HEAD":
                            limit = max_bytes
                            if body_limit is not None:
                                limit = min(max_bytes, body_limit(result.headers))
                            await self._read_body(resp, limit, result)
                        return Hop(url, status, location, method)
            except PolicyViolation as exc:
                result.error, result.error_detail = "blocked", exc.reason
                return Hop(url, None, method=method)
            except aiohttp.ClientConnectorError as exc:
                cause = exc.os_error if isinstance(exc.os_error, PolicyViolation) else exc.__cause__
                if isinstance(cause, PolicyViolation):
                    result.error, result.error_detail = "blocked", cause.reason
                    return Hop(url, None, method=method)
                err: Exception = exc
            except BudgetExceeded as exc:
                result.error, result.error_detail = "budget_exhausted", exc.reason
                return Hop(url, None, method=method)
            except (TimeoutError, aiohttp.ClientError, OSError) as exc:
                err = exc
            if attempt > pol.max_retries:
                result.error = "network_error"
                result.error_detail = f"{type(err).__name__}: {err}"[:500]
                return Hop(url, None, method=method)
            await asyncio.sleep(backoff_delay(attempt - 1, pol.backoff_base_seconds,
                                              pol.backoff_max_seconds, self._rng))

    @staticmethod
    def _record_response(resp: aiohttp.ClientResponse, result: FetchResult) -> None:
        result.status = resp.status
        result.headers = {}
        for name in RECORDED_HEADERS:
            values = resp.headers.getall(name, [])
            if values:
                result.headers[name] = ", ".join(values)
        result.set_cookie_names = [
            c.split("=", 1)[0].strip() for c in resp.headers.getall("Set-Cookie", [])
        ]

    async def _read_body(self, resp: aiohttp.ClientResponse, max_bytes: int,
                         result: FetchResult) -> None:
        chunks: list[bytes] = []
        total = 0
        try:
            async for chunk in resp.content.iter_chunked(65536):
                take = chunk[: max(0, max_bytes - total)]
                chunks.append(take)
                total += len(chunk)
                self.budget.add_bytes(len(chunk))
                if total >= max_bytes:
                    result.truncated = total > max_bytes or not resp.content.at_eof()
                    break
        except BudgetExceeded:
            raise
        except (TimeoutError, aiohttp.ClientPayloadError, aiohttp.ClientError) as exc:
            result.error = "transfer_interrupted"
            result.error_detail = f"{type(exc).__name__}: {exc}"[:500]
        finally:
            result.body = b"".join(chunks)[:max_bytes]
            result.bytes_observed = total
            if result.truncated:
                resp.close()  # abort the transfer instead of draining it
