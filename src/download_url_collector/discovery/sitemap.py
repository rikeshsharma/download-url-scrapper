"""Sitemap and sitemap-index parsing (XML, gzip-compressed XML, plain text).

Parsing uses defusedxml to reject entity-expansion and external-entity
attacks; decompression is bounded.
"""

from __future__ import annotations

import gzip
import io
import zlib
from dataclasses import dataclass, field

from defusedxml import ElementTree as SafeET

from ..urls import URLError, resolve


@dataclass
class SitemapParse:
    urls: list[str] = field(default_factory=list)
    child_sitemaps: list[str] = field(default_factory=list)
    error: str | None = None


def _bounded_gunzip(data: bytes, max_bytes: int) -> bytes:
    with gzip.GzipFile(fileobj=io.BytesIO(data)) as gz:
        out = gz.read(max_bytes + 1)
    if len(out) > max_bytes:
        raise ValueError("decompressed sitemap exceeds limit")
    return out


def parse_sitemap(data: bytes, sitemap_url: str, max_bytes: int, max_urls: int) -> SitemapParse:
    res = SitemapParse()
    try:
        if data[:2] == b"\x1f\x8b":
            data = _bounded_gunzip(data, max_bytes)
    except (OSError, EOFError, ValueError, zlib.error) as exc:
        res.error = f"gzip: {exc}"
        return res
    head = data.lstrip()[:200].lower()
    if not head.startswith(b"<"):
        for line in data.decode("utf-8", errors="replace").splitlines():
            line = line.strip()
            if line and len(res.urls) < max_urls:
                try:
                    res.urls.append(resolve(sitemap_url, line))
                except URLError:
                    continue
        return res
    try:
        root = SafeET.fromstring(data)
    except Exception as exc:  # defusedxml raises several exception types
        res.error = f"xml: {type(exc).__name__}: {exc}"[:300]
        return res
    tag = root.tag.rsplit("}", 1)[-1].lower()
    for el in root.iter():
        if el.tag.rsplit("}", 1)[-1].lower() != "loc" or not el.text:
            continue
        try:
            loc = resolve(sitemap_url, el.text.strip())
        except URLError:
            continue
        if tag == "sitemapindex":
            res.child_sitemaps.append(loc)
        elif len(res.urls) < max_urls:
            res.urls.append(loc)
    return res
