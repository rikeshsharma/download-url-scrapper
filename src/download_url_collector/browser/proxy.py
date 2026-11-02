"""In-process egress-filtering HTTP proxy for browser traffic.

Chromium is pointed at this proxy (with the implicit loopback bypass removed),
so every browser request — navigations, redirects, subresources, popups,
downloads — is resolved *here*, validated against the network policy and
connected to the validated address. This closes the DNS-rebinding gap that a
URL-level check inside the browser cannot close, and lets us cap bytes during
transfer (including browser downloads).

Limits: HTTPS is tunnelled (CONNECT) so caps are applied to encrypted bytes;
UDP (QUIC/WebRTC) is disabled with Chromium flags rather than proxied. A
production deployment should still run the browser in a network namespace /
container whose only egress is this proxy or an equivalent external proxy.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

from ..netpolicy import NetworkPolicy, PolicyViolation

log = logging.getLogger(__name__)

_MAX_HEADER_BYTES = 64 * 1024
_HOP_BY_HOP = {"proxy-connection", "proxy-authorization", "connection", "keep-alive", "te",
               "trailer", "upgrade"}


@dataclass
class ProxyEvent:
    kind: str  # "blocked" | "byte_limit" | "connect_error" | "connection"
    host: str
    port: int
    detail: str = ""
    ts: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {"kind": self.kind, "host": self.host, "port": self.port, "detail": self.detail}


class EgressProxy:
    def __init__(self, policy: NetworkPolicy, max_bytes_per_connection: int,
                 max_bytes_total: int, connect_timeout: float = 15.0) -> None:
        self.policy = policy
        self.max_conn = max_bytes_per_connection
        self.max_total = max_bytes_total
        self.connect_timeout = connect_timeout
        self.events: list[ProxyEvent] = []
        self.bytes_downstream = 0
        self._server: asyncio.base_events.Server | None = None
        self._tasks: set[asyncio.Task[None]] = set()
        self.port = 0

    async def start(self) -> int:
        self._server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        self.port = self._server.sockets[0].getsockname()[1]
        return self.port

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            for t in list(self._tasks):
                t.cancel()
            with contextlib.suppress(Exception):
                await asyncio.wait_for(self._server.wait_closed(), 5)
            self._server = None

    @property
    def server_url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def drain_events(self) -> list[ProxyEvent]:
        ev, self.events = self.events, []
        return ev

    # ------------------------------------------------------------------
    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        task = asyncio.current_task()
        if task is not None:
            self._tasks.add(task)
        try:
            await self._serve(reader, writer)
        except (ConnectionError, asyncio.IncompleteReadError, asyncio.LimitOverrunError,
                asyncio.CancelledError, ValueError):
            pass
        except Exception:  # pragma: no cover - defensive
            log.exception("proxy_error")
        finally:
            with contextlib.suppress(Exception):
                writer.close()
            if task is not None:
                self._tasks.discard(task)

    async def _read_head(self, reader: asyncio.StreamReader) -> bytes:
        data = await reader.readuntil(b"\r\n\r\n")
        if len(data) > _MAX_HEADER_BYTES:
            raise ValueError("header too large")
        return data

    async def _serve(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        head = await self._read_head(reader)
        lines = head.decode("latin-1").split("\r\n")
        method, target, version = lines[0].split(" ", 2)
        headers = [ln for ln in lines[1:] if ln]
        if method.upper() == "CONNECT":
            host, _, port_s = target.rpartition(":")
            port = int(port_s)
            upstream = await self._open(host, port, writer)
            if upstream is None:
                return
            up_reader, up_writer = upstream
            writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            await writer.drain()
            await self._pipe_both(reader, writer, up_reader, up_writer, host, port)
            return
        parts = urlsplit(target)
        if parts.scheme.lower() != "http" or not parts.hostname:
            await self._reject(writer, "unsupported_proxy_request", "")
            return
        host = parts.hostname
        port = parts.port or 80
        upstream = await self._open(host, port, writer)
        if upstream is None:
            return
        up_reader, up_writer = upstream
        path = parts.path or "/"
        if parts.query:
            path += "?" + parts.query
        out = [f"{method} {path} {version}"]
        for h in headers:
            name = h.split(":", 1)[0].strip().lower()
            if name not in _HOP_BY_HOP:
                out.append(h)
        # One request per upstream connection keeps the host binding unambiguous.
        out.append("Connection: close")
        up_writer.write(("\r\n".join(out) + "\r\n\r\n").encode("latin-1"))
        await up_writer.drain()
        await self._pipe_both(reader, writer, up_reader, up_writer, host, port)

    async def _open(self, host: str, port: int, writer: asyncio.StreamWriter
                    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter] | None:
        host = host.strip("[]")
        try:
            addrs = await self.policy.resolve_and_check(host, port)
        except PolicyViolation as exc:
            self.events.append(ProxyEvent("blocked", host, port, exc.reason))
            await self._reject(writer, exc.reason, host)
            return None
        last: Exception | None = None
        for addr in addrs:
            try:
                conn = await asyncio.wait_for(asyncio.open_connection(addr, port), self.connect_timeout)
                self.events.append(ProxyEvent("connection", host, port, addr))
                return conn
            except (TimeoutError, OSError) as exc:
                last = exc
        self.events.append(ProxyEvent("connect_error", host, port, str(last)))
        await self._reject(writer, "connect_failed", host, status=502)
        return None

    async def _reject(self, writer: asyncio.StreamWriter, reason: str, host: str,
                      status: int = 403) -> None:
        body = f"blocked by collector egress policy: {reason}\n".encode()
        writer.write(
            f"HTTP/1.1 {status} Blocked\r\nContent-Type: text/plain\r\nX-Collector-Blocked: {reason}\r\n"
            f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode() + body)
        with contextlib.suppress(Exception):
            await writer.drain()

    async def _pipe_both(self, c_reader: asyncio.StreamReader, c_writer: asyncio.StreamWriter,
                         u_reader: asyncio.StreamReader, u_writer: asyncio.StreamWriter,
                         host: str, port: int) -> None:
        async def up() -> None:
            try:
                while chunk := await c_reader.read(65536):
                    u_writer.write(chunk)
                    await u_writer.drain()
            finally:
                with contextlib.suppress(Exception):
                    u_writer.write_eof()

        async def down() -> bool:
            conn_bytes = 0
            while chunk := await u_reader.read(65536):
                conn_bytes += len(chunk)
                self.bytes_downstream += len(chunk)
                if conn_bytes > self.max_conn or self.bytes_downstream > self.max_total:
                    self.events.append(ProxyEvent("byte_limit", host, port,
                                                  f"connection={conn_bytes} total={self.bytes_downstream}"))
                    return True
                c_writer.write(chunk)
                await c_writer.drain()
            return False

        t_up = asyncio.create_task(up())
        limited = True
        try:
            limited = await down()
        finally:
            t_up.cancel()
            for w in (u_writer, c_writer):
                with contextlib.suppress(Exception):
                    if limited:
                        w.transport.abort()  # cut the transfer; the browser sees a network error
                    else:
                        w.close()
