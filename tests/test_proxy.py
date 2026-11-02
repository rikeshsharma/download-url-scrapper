"""Egress proxy enforcement (the same proxy Chromium is routed through)."""

from __future__ import annotations

import aiohttp
from fixtures.server import FixtureSite

from download_url_collector.browser.proxy import EgressProxy
from download_url_collector.config import NetworkConfig
from download_url_collector.netpolicy import NetworkPolicy

POLICY = NetworkPolicy(NetworkConfig(allow_cidrs=["127.0.0.0/8", "::1/128"], blocked_hostnames=[],
                                     blocked_hostname_suffixes=[], allowed_ports=None))


async def _get(proxy: EgressProxy, url: str) -> tuple[int, bytes, dict[str, str]]:
    async with aiohttp.ClientSession(trust_env=False) as s:
        async with s.get(url, proxy=proxy.server_url, allow_redirects=False) as r:
            return r.status, await r.read(), dict(r.headers)


async def test_proxy_forwards_allowed_and_blocks_private(site: FixtureSite) -> None:
    proxy = EgressProxy(POLICY, 10**7, 10**8)
    await proxy.start()
    try:
        status, body, _ = await _get(proxy, f"{site.base}/docs/readme.txt")
        assert status == 200 and body == b"read me\n"
        status, _, headers = await _get(proxy, "http://169.254.169.254/latest/meta-data/")
        assert status == 403 and headers["X-Collector-Blocked"] == "blocked_metadata_or_link_local"
        status, _, headers = await _get(proxy, "http://10.0.0.1/")
        assert status == 403 and headers["X-Collector-Blocked"] == "blocked_private"
        assert [e.kind for e in proxy.drain_events() if e.kind == "blocked"] == ["blocked", "blocked"]
    finally:
        await proxy.stop()


async def test_proxy_enforces_byte_cap_during_transfer(site: FixtureSite) -> None:
    proxy = EgressProxy(POLICY, 100_000, 10**8)
    await proxy.start()
    try:
        try:
            status, body, _ = await _get(proxy, f"{site.base}/big.bin")
            assert len(body) < 3 * 1024 * 1024  # never the full payload
        except aiohttp.ClientError:
            pass
        assert any(e.kind == "byte_limit" for e in proxy.events)
        assert proxy.bytes_downstream <= 100_000 + 65536
    finally:
        await proxy.stop()
