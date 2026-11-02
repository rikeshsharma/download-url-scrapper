"""Bounded HTTP probing of download candidates.

HEAD is an optional, recorded optimisation and is never required to succeed.
A bounded (ranged) streaming GET always samples the leading bytes so that
misleading metadata can be compared with content. A probe result is a *hint*;
only browser verification establishes that a download completes.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import unquote

from .config import Config
from .discovery.hints import is_html_mime
from .http_client import FetchResult, PolicyHttpClient, ScopeCheck
from .inspection.filetype import detect_prefix
from .urls import filename_extension


@dataclass
class ContentDisposition:
    disposition: str | None
    filename: str | None
    raw: str | None


_PARAM_RE = re.compile(r';\s*([A-Za-z0-9_*.-]+)\s*=\s*("(?:[^"\\]|\\.)*"|[^;]*)')


def parse_content_disposition(value: str | None) -> ContentDisposition:
    if value is None:
        return ContentDisposition(None, None, None)
    disp = value.split(";", 1)[0].strip().lower() or None
    params: dict[str, str] = {}
    for m in _PARAM_RE.finditer(value):
        k = m.group(1).lower()
        v = m.group(2).strip()
        if v.startswith('"') and v.endswith('"') and len(v) >= 2:
            v = re.sub(r"\\(.)", r"\1", v[1:-1])
        params.setdefault(k, v)
    name: str | None = None
    if "filename*" in params:  # RFC 6266 / 8187: charset'lang'pct-encoded
        ext = params["filename*"]
        parts = ext.split("'", 2)
        if len(parts) == 3:
            charset = parts[0] or "utf-8"
            try:
                name = unquote(parts[2], encoding=charset, errors="strict")
            except (LookupError, UnicodeDecodeError):
                name = None
    if name is None and "filename" in params:
        name = params["filename"]
    return ContentDisposition(disp, name, value)


@dataclass
class ProbeResult:
    verdict: str  # "likely_download" | "html" | "failed"
    reason: str | None = None
    head: dict[str, Any] | None = None
    get: dict[str, Any] | None = None
    declared_mime: str | None = None
    content_disposition: str | None = None
    disposition_type: str | None = None
    filename: str | None = None
    filename_extension: str | None = None
    declared_length: int | None = None
    total_length: int | None = None
    range_honored: bool | None = None
    sniffed_family: str | None = None
    sniffed_mime: str | None = None
    head_status: int | None = None
    final_url: str | None = None
    status: int | None = None
    hints: list[str] = field(default_factory=list)
    body_sample: bytes = b""

    def to_dict(self) -> dict[str, Any]:
        d = {k: v for k, v in self.__dict__.items() if k != "body_sample"}
        return d


def _total_length(res: FetchResult) -> int | None:
    cr = res.header("content-range")
    if cr and "/" in cr:
        tail = cr.rsplit("/", 1)[1].strip()
        if tail.isdigit():
            return int(tail)
    if res.status == 200:
        cl = res.header("content-length")
        if cl and cl.strip().isdigit():
            return int(cl)
    return None


async def probe_url(client: PolicyHttpClient, url: str, cfg: Config,
                    scope_check: ScopeCheck | None) -> ProbeResult:
    out = ProbeResult(verdict="failed")
    if cfg.politeness.use_head:
        head = await client.fetch(url, method="HEAD", max_bytes=0, scope_check=scope_check)
        out.head = head.http_meta()
        out.head_status = head.status
        if head.error in ("blocked", "redirect_blocked", "budget_exhausted"):
            out.reason = f"{head.error}:{head.error_detail}"
            return out
    sniff = cfg.limits.probe_sniff_bytes
    get = await client.fetch(url, method="GET", max_bytes=sniff, range_bytes=sniff,
                             scope_check=scope_check)
    out.get = get.http_meta()
    out.status = get.status
    out.final_url = get.final_url
    out.body_sample = get.body
    if get.error and get.error != "transfer_interrupted":
        out.reason = f"{get.error}:{get.error_detail}"
        return out
    if get.status is None or not (200 <= get.status < 300):
        out.reason = f"http_status:{get.status}"
        return out
    out.declared_mime = get.header("content-type")
    cd = parse_content_disposition(get.header("content-disposition"))
    out.content_disposition = cd.raw
    out.disposition_type = cd.disposition
    out.filename = cd.filename
    out.filename_extension = filename_extension(cd.filename)
    cl = get.header("content-length")
    out.declared_length = int(cl) if cl and cl.strip().isdigit() else None
    out.total_length = _total_length(get)
    out.range_honored = get.status == 206 if get.range_requested else None
    ft = detect_prefix(get.body)
    out.sniffed_family, out.sniffed_mime = ft.family, ft.mime
    if cd.disposition == "attachment":
        out.hints.append("attachment_disposition")
    if (out.total_length or 0) > cfg.limits.max_file_bytes:
        out.hints.append("declared_size_over_limit")
    html_declared = is_html_mime(out.declared_mime)
    html_sniffed = ft.family == "html"
    if cd.disposition != "attachment" and (html_declared or (html_sniffed and not out.declared_mime)):
        out.verdict = "html"
        out.reason = "html_response"
        if html_declared and not html_sniffed and ft.family not in ("text", "empty", "xml", "unknown"):
            out.hints.append("html_declared_binary_sniffed")
            out.verdict = "likely_download"
        return out
    if get.error == "transfer_interrupted":
        out.hints.append("probe_transfer_interrupted")
    out.verdict = "likely_download"
    return out
