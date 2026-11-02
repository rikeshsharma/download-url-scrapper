from __future__ import annotations

import socket

import pytest

from download_url_collector.config import NetworkConfig
from download_url_collector.netpolicy import NetworkPolicy, PolicyViolation

POL = NetworkPolicy(NetworkConfig())


@pytest.mark.parametrize("ip", [
    "127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.1.1", "169.254.169.254", "100.64.0.1",
    "0.0.0.0", "224.0.0.1", "240.0.0.1", "255.255.255.255", "100.100.100.200",
    "::1", "::", "fe80::1", "fc00::1", "fd00:ec2::254", "::ffff:127.0.0.1", "::ffff:10.0.0.1",
    "2002:a00:1::", "64:ff9b::a00:1", "2001:db8::1",
])
def test_blocks_non_global(ip: str) -> None:
    assert POL.check_ip(ip) is not None


@pytest.mark.parametrize("ip", ["93.184.216.34", "2606:4700::1111", "1.1.1.1"])
def test_allows_global(ip: str) -> None:
    assert POL.check_ip(ip) is None


def test_hostname_blocklist_and_ip_literal_hosts() -> None:
    assert POL.check_hostname("localhost") == "blocked_hostname"
    assert POL.check_hostname("metadata.google.internal") == "blocked_hostname"
    assert POL.check_hostname("foo.localhost") == "blocked_hostname_suffix"
    assert POL.check_hostname("[::1]") == "blocked_loopback"


def test_allow_cidrs_override_is_explicit() -> None:
    pol = NetworkPolicy(NetworkConfig(allow_cidrs=["127.0.0.0/8"]))
    assert pol.check_ip("127.0.0.1") is None
    assert pol.check_ip("::ffff:127.0.0.1") is None
    assert pol.check_ip("169.254.169.254") is not None


def test_ports() -> None:
    assert POL.check_port(22) == "blocked_port"
    assert POL.check_port(443) is None


async def test_dns_rebinding_any_private_answer_blocks(monkeypatch: pytest.MonkeyPatch) -> None:
    """A name resolving to public *and* private addresses is rejected outright,
    and every resolution is re-validated (no cached 'good' answer)."""
    import asyncio

    answers = [["93.184.216.34"], ["93.184.216.34", "10.0.0.5"], ["127.0.0.1"]]

    async def fake_getaddrinfo(host, port, **kw):  # type: ignore[no-untyped-def]
        ips = answers.pop(0)
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, port)) for ip in ips]

    loop = asyncio.get_running_loop()
    monkeypatch.setattr(loop, "getaddrinfo", fake_getaddrinfo)
    assert await POL.resolve_and_check("rebind.example", 80) == ["93.184.216.34"]
    with pytest.raises(PolicyViolation) as e1:
        await POL.resolve_and_check("rebind.example", 80)
    assert e1.value.reason == "blocked_private"
    with pytest.raises(PolicyViolation) as e2:
        await POL.resolve_and_check("rebind.example", 80)
    assert e2.value.reason == "blocked_loopback"
