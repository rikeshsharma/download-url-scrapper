"""URL handling that preserves request semantics.

Rules:
* The replay URL is what was observed, resolved against the correct base, with
  only the minimal encoding a browser would apply (whitespace, non-ASCII,
  control characters). Query parameters are never removed, reordered or decoded
  and paths are never case-folded.
* Fragments are split off the request URL (they are never sent to the server)
  and kept separately by callers that need them.
* Deduplication uses a *separate*, conservative key; it is never used as a
  request target.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from urllib.parse import SplitResult, urljoin, urlsplit, urlunsplit

import tldextract

ALLOWED_SCHEMES = ("http", "https")
_DEFAULT_PORTS = {"http": 80, "https": 443}
# Characters a browser percent-encodes in paths/queries; '%' and reserved
# characters are deliberately absent so existing escapes stay untouched.
_ENCODE_RE = re.compile(r"[\x00-\x20\x7f\"<>\\^`{|}]|[^\x00-\x7f]")
_STRIP_CHARS = "\t\n\r"


class URLError(ValueError):
    pass


def _encode_char(m: re.Match[str]) -> str:
    return "".join(f"%{b:02X}" for b in m.group(0).encode("utf-8"))


def minimal_encode(component: str) -> str:
    return _ENCODE_RE.sub(_encode_char, component)


def _idna_host(host: str) -> str:
    if not host:
        return host
    if host.startswith("["):
        return host
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    try:
        return host.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise URLError(f"invalid hostname: {host!r}") from exc


def normalize_observed(url: str) -> tuple[str, str]:
    """Return (request_url, fragment) for an absolute URL.

    Leading/trailing C0/space and embedded tab/newline characters are removed,
    as the WHATWG URL parser does. The host is IDNA-encoded and the scheme
    lowercased because both are case-insensitive. Nothing else changes.
    """
    url = url.strip("\x00\x01\x02\x03\x04\x05\x06\x07\x08\x0b\x0c\x0e\x0f "
                    "\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\t\n\r")
    for ch in _STRIP_CHARS:
        url = url.replace(ch, "")
    try:
        parts = urlsplit(url)
    except ValueError as exc:
        raise URLError(str(exc)) from exc
    scheme = parts.scheme.lower()
    if scheme not in ALLOWED_SCHEMES:
        raise URLError(f"unsupported scheme: {parts.scheme or '(none)'}")
    try:
        hostname = parts.hostname
        port = parts.port
    except ValueError as exc:
        raise URLError(str(exc)) from exc
    if not hostname:
        raise URLError("missing host")
    host = _idna_host(hostname)
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    netloc = host
    if parts.username is not None or parts.password is not None:
        # Credentials are preserved verbatim (they are part of the observed URL)
        # but flagged by has_sensitive_content().
        userinfo = parts.netloc.rsplit("@", 1)[0]
        netloc = f"{userinfo}@{netloc}"
    if port is not None:
        netloc = f"{netloc}:{port}"
    path = minimal_encode(parts.path) or "/"
    query = minimal_encode(parts.query)
    request_url = urlunsplit(SplitResult(scheme, netloc, path, query, ""))
    # urlunsplit drops a bare '?'; keep it because it is part of the observed URL.
    if url.split("#", 1)[0].endswith("?") and not query:
        request_url += "?"
    return request_url, parts.fragment


def resolve(base_url: str, href: str) -> str:
    """Resolve *href* against *base_url* and normalise minimally."""
    href = href.strip()
    for ch in _STRIP_CHARS:
        href = href.replace(ch, "")
    joined = urljoin(base_url, href)
    return normalize_observed(joined)[0]


def dedup_key(url: str) -> str:
    """Conservative identity key: case-folds scheme/host, drops default port and
    fragment. Path and query are kept byte-for-byte."""
    p = urlsplit(url)
    scheme = p.scheme.lower()
    host = (p.hostname or "").lower()
    if ":" in host:
        host = f"[{host}]"
    port = p.port
    netloc = host if port in (None, _DEFAULT_PORTS.get(scheme)) else f"{host}:{port}"
    return urlunsplit((scheme, netloc, p.path or "/", p.query, ""))


def hostname(url: str) -> str:
    return (urlsplit(url).hostname or "").lower()


def port_of(url: str) -> int:
    p = urlsplit(url)
    return p.port or _DEFAULT_PORTS.get(p.scheme.lower(), 0)


def origin(url: str) -> str:
    p = urlsplit(url)
    return f"{p.scheme.lower()}://{p.netloc.rsplit('@', 1)[-1].lower()}"


_extractor: tldextract.TLDExtract | None = None


def configure_psl(psl_file: Path | None) -> None:
    """Use the bundled Public Suffix List snapshot (no network fetch), or a local file."""
    global _extractor
    if psl_file is not None:
        _extractor = tldextract.TLDExtract(
            suffix_list_urls=(Path(psl_file).resolve().as_uri(),),
            cache_dir=None,
            fallback_to_snapshot=False,
        )
    else:
        _extractor = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)
    registrable_domain.cache_clear()


@lru_cache(maxsize=65536)
def registrable_domain(host: str) -> str:
    """eTLD+1 per the Public Suffix List (including private suffixes such as
    github.io). IP literals and single-label hosts are returned unchanged."""
    host = host.strip("[]").lower().rstrip(".")
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    if _extractor is None:
        configure_psl(None)
    assert _extractor is not None
    ext = _extractor(host, include_psl_private_domains=True)
    if ext.domain and ext.suffix:
        return f"{ext.domain}.{ext.suffix}"
    return host


def path_extension(url: str) -> str | None:
    """Lower-cased extension of the last path segment, for reporting only."""
    last = urlsplit(url).path.rsplit("/", 1)[-1]
    return filename_extension(last)


_MULTI_EXT = ("tar.gz", "tar.bz2", "tar.xz", "tar.zst", "tar.lz")


def filename_extension(name: str | None) -> str | None:
    if not name or "." not in name.strip("."):
        return None
    lower = name.lower()
    for multi in _MULTI_EXT:
        if lower.endswith("." + multi):
            return multi
    ext = lower.rsplit(".", 1)[1]
    if not ext or len(ext) > 12 or not re.fullmatch(r"[a-z0-9_+-]+", ext):
        return None
    return ext


@dataclass(frozen=True)
class SensitivityPolicy:
    sensitive_params: frozenset[str]
    token_value_min_length: int = 32


_TOKENISH = re.compile(r"^[A-Za-z0-9_\-+/=.~%]+$")


def _split_query(query: str) -> list[tuple[str, str | None]]:
    out: list[tuple[str, str | None]] = []
    for piece in query.split("&") if query else []:
        if "=" in piece:
            k, v = piece.split("=", 1)
            out.append((k, v))
        else:
            out.append((piece, None))
    return out


def sensitive_findings(url: str, policy: SensitivityPolicy) -> list[str]:
    """Reasons a URL may carry credentials or bearer tokens (it is never altered)."""
    p = urlsplit(url)
    reasons: list[str] = []
    if p.username is not None or p.password is not None:
        reasons.append("userinfo")
    for k, v in _split_query(p.query):
        name = k.lower()
        if name in policy.sensitive_params:
            reasons.append(f"param:{k}")
        elif v and len(v) >= policy.token_value_min_length and _TOKENISH.match(v):
            reasons.append(f"opaque_value:{k}")
    return reasons


def redact_url(url: str, policy: SensitivityPolicy) -> str:
    """Shareable form: credentials and sensitive/opaque parameter values replaced.

    Parameter order and names are preserved so the redacted form stays readable.
    Only for logs and shareable reports — never use the result as a request URL.
    """
    try:
        p = urlsplit(url)
    except ValueError:
        return "<unparseable-url>"
    netloc = p.netloc
    if "@" in netloc:
        netloc = "REDACTED@" + netloc.rsplit("@", 1)[1]
    pieces: list[str] = []
    for k, v in _split_query(p.query):
        if v is None:
            pieces.append(k)
            continue
        name = k.lower()
        if name in policy.sensitive_params or (
            len(v) >= policy.token_value_min_length and _TOKENISH.match(v)
        ):
            pieces.append(f"{k}=REDACTED")
        else:
            pieces.append(f"{k}={v}")
    return urlunsplit((p.scheme, netloc, p.path, "&".join(pieces), ""))


_URL_IN_TEXT = re.compile(r"https?://[^\s\"'<>]+")


def redact_text(text: str, policy: SensitivityPolicy) -> str:
    return _URL_IN_TEXT.sub(lambda m: redact_url(m.group(0), policy), text)
