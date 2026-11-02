"""Destination network policy shared by the HTTP client and the browser proxy.

Blocks loopback, private, link-local, CGNAT, multicast, reserved, unspecified
and other non-globally-routable destinations (IPv4 and IPv6, including
IPv4-mapped, 6to4, Teredo and NAT64 embeddings) plus well-known cloud metadata
names. Resolution happens immediately before connecting and the connection is
made to the validated address, so DNS rebinding between check and use is not
possible for connections made by this process.
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
from dataclasses import dataclass
from typing import Any

from .config import NetworkConfig

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address

_NAT64 = ipaddress.ip_network("64:ff9b::/96")
_EXTRA_BLOCKED = [
    ipaddress.ip_network("100.64.0.0/10"),  # CGNAT (also not is_global)
    ipaddress.ip_network("169.254.0.0/16"),  # link-local / metadata
    ipaddress.ip_network("fd00:ec2::/32"),  # AWS IMDS IPv6
    ipaddress.ip_network("100.100.100.200/32"),  # Alibaba metadata
]


class PolicyViolation(OSError):
    """Raised when a destination is not allowed. Subclasses OSError so it
    survives transport layers that only propagate OSError."""

    def __init__(self, reason: str, detail: str = "") -> None:
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason
        self.detail = detail


@dataclass
class NetworkPolicy:
    cfg: NetworkConfig

    def __post_init__(self) -> None:
        self._allow = [ipaddress.ip_network(c, strict=False) for c in self.cfg.allow_cidrs]
        self._blocked_names = {h.lower().rstrip(".") for h in self.cfg.blocked_hostnames}
        self._blocked_suffixes = tuple(s.lower() for s in self.cfg.blocked_hostname_suffixes)

    # -- checks -----------------------------------------------------------
    def check_hostname(self, host: str) -> str | None:
        h = host.lower().strip("[]").rstrip(".")
        if not h:
            return "empty_host"
        if h in self._blocked_names:
            return "blocked_hostname"
        if any(h.endswith(s) for s in self._blocked_suffixes):
            return "blocked_hostname_suffix"
        try:
            ip = ipaddress.ip_address(h)
        except ValueError:
            return None
        return self.check_ip(ip)

    def check_port(self, port: int) -> str | None:
        if self.cfg.allowed_ports is not None and port not in self.cfg.allowed_ports:
            return "blocked_port"
        return None

    def _allowed_override(self, ip: IPAddress) -> bool:
        return any(ip.version == n.version and ip in n for n in self._allow)

    def check_ip(self, ip: IPAddress | str) -> str | None:
        if isinstance(ip, str):
            ip = ipaddress.ip_address(ip.split("%", 1)[0])
        if self._allowed_override(ip):
            return None
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None \
                and self._allowed_override(ip.ipv4_mapped):
            return None  # ::ffff:a.b.c.d is the same destination as a.b.c.d
        candidates: list[IPAddress] = [ip]
        if isinstance(ip, ipaddress.IPv6Address):
            if ip.ipv4_mapped is not None:
                candidates.append(ip.ipv4_mapped)
            if ip.sixtofour is not None:
                candidates.append(ip.sixtofour)
            if ip.teredo is not None:
                candidates.extend(ip.teredo)
            if ip in _NAT64:
                candidates.append(ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF))
        for c in candidates:
            if c is not ip and self._allowed_override(c):
                continue
            if any(c.version == n.version and c in n for n in _EXTRA_BLOCKED):
                return "blocked_metadata_or_link_local"
            if c.is_loopback:
                return "blocked_loopback"
            if c.is_private:
                return "blocked_private"
            if c.is_link_local:
                return "blocked_link_local"
            if c.is_multicast:
                return "blocked_multicast"
            if c.is_unspecified:
                return "blocked_unspecified"
            if c.is_reserved:
                return "blocked_reserved"
            if not c.is_global:
                return "blocked_non_global"
        return None

    # -- resolution -------------------------------------------------------
    async def resolve_and_check(self, host: str, port: int) -> list[str]:
        """Resolve *host* and return validated addresses. Every address must
        pass; a single disallowed answer blocks the destination (prevents
        mixed public/private answers being raced)."""
        if reason := self.check_hostname(host):
            raise PolicyViolation(reason, host)
        if reason := self.check_port(port):
            raise PolicyViolation(reason, str(port))
        h = host.strip("[]")
        try:
            ipaddress.ip_address(h)
            return [h]
        except ValueError:
            pass
        loop = asyncio.get_running_loop()
        try:
            infos = await loop.getaddrinfo(h, port, type=socket.SOCK_STREAM)
        except socket.gaierror as exc:
            raise PolicyViolation("dns_resolution_failed", f"{h}: {exc}") from exc
        addrs: list[str] = []
        for _family, _type, _proto, _canon, sockaddr in infos:
            addr = str(sockaddr[0])
            if reason := self.check_ip(addr):
                raise PolicyViolation(reason, f"{h} -> {addr}")
            if addr not in addrs:
                addrs.append(addr)
        if not addrs:
            raise PolicyViolation("dns_resolution_failed", h)
        return addrs


def make_aiohttp_resolver(policy: NetworkPolicy) -> Any:
    """aiohttp resolver that validates every answer at connection time."""
    from aiohttp.abc import AbstractResolver

    class PolicyResolver(AbstractResolver):
        async def resolve(  # type: ignore[override]
            self, host: str, port: int = 0, family: socket.AddressFamily = socket.AF_INET
        ) -> list[dict[str, Any]]:
            addrs = await policy.resolve_and_check(host, port)
            out = []
            for a in addrs:
                fam = socket.AF_INET6 if ":" in a else socket.AF_INET
                out.append({"hostname": host, "host": a, "port": port, "family": fam,
                            "proto": 0, "flags": socket.AI_NUMERICHOST})
            return out

        async def close(self) -> None:
            return None

    return PolicyResolver()
