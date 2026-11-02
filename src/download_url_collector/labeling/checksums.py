"""Publisher checksum discovery and parsing.

A matching publisher checksum establishes integrity *relative to the
publisher* — that the bytes are what the publisher lists — not that they are
benign. The policy therefore only uses it as an integrity qualifier for
provenance and treats a mismatch as suspicious.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import unquote, urlsplit, urlunsplit

from ..http_client import PolicyHttpClient

_LINE_GNU = re.compile(r"^([0-9a-fA-F]{64})\s+[ *]?(.+?)\s*$")
_LINE_BSD = re.compile(r"^SHA256\s*\((.+)\)\s*=\s*([0-9a-fA-F]{64})\s*$")
_LONE = re.compile(r"^\s*([0-9a-fA-F]{64})\s*$")


def parse_checksum_file(text: str) -> tuple[dict[str, str], str | None]:
    """Return ({filename: sha256}, lone_hash)."""
    entries: dict[str, str] = {}
    lone: str | None = None
    lines = [ln for ln in text.splitlines() if ln.strip()]
    for ln in lines:
        if m := _LINE_GNU.match(ln):
            entries[m.group(2).strip().lstrip("./")] = m.group(1).lower()
        elif m := _LINE_BSD.match(ln):
            entries[m.group(1).strip().lstrip("./")] = m.group(2).lower()
    if not entries and len(lines) == 1 and (m := _LONE.match(lines[0])):
        lone = m.group(1).lower()
    return entries, lone


@dataclass
class ChecksumFinding:
    verdict: str  # "match" | "mismatch"
    source_url: str
    filename: str
    listed_sha256: str


def sidecar_urls(download_url: str) -> list[str]:
    p = urlsplit(download_url)
    if p.query:
        return []  # sidecars of parameterised endpoints are not well defined
    base_dir = p.path.rsplit("/", 1)[0] + "/"
    out = [urlunsplit((p.scheme, p.netloc, p.path + suffix, "", ""))
           for suffix in (".sha256", ".sha256sum")]
    out += [urlunsplit((p.scheme, p.netloc, base_dir + name, "", ""))
            for name in ("SHA256SUMS", "SHA256SUMS.txt", "sha256sums.txt")]
    return out


async def find_publisher_checksum(client: PolicyHttpClient, download_url: str, sha256: str,
                                  filename_hint: str | None) -> list[ChecksumFinding]:
    p = urlsplit(download_url)
    names = {unquote(p.path.rsplit("/", 1)[-1])}
    if filename_hint:
        names.add(filename_hint)
    findings: list[ChecksumFinding] = []
    for url in sidecar_urls(download_url):
        res = await client.fetch(url, max_bytes=256 * 1024, max_redirects=3)
        if not res.ok:
            continue
        entries, lone = parse_checksum_file(res.body.decode("utf-8", errors="replace"))
        if lone and url.endswith((".sha256", ".sha256sum")):
            findings.append(ChecksumFinding("match" if lone == sha256 else "mismatch", url,
                                            next(iter(names)), lone))
            continue
        for name in names:
            listed = entries.get(name)
            if listed:
                findings.append(ChecksumFinding("match" if listed == sha256 else "mismatch",
                                                url, name, listed))
    return findings
