"""Static HTML link extraction.

Relative references are resolved against the document base URL: the first
``<base href>`` (itself resolved against the final response URL), otherwise the
final response URL after redirects.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from bs4 import BeautifulSoup

from ..models import DiscoveryMethod
from ..urls import URLError, resolve

_REFRESH_RE = re.compile(r"^\s*(\d+(?:\.\d+)?)?\s*[;,]?\s*(?:url\s*=\s*)?(['\"]?)(.*?)\2\s*$",
                         re.IGNORECASE | re.DOTALL)
_DOWNLOAD_WORD = re.compile(r"\bdownload", re.IGNORECASE)
_DATA_URL_ATTRS = ("data-href", "data-url", "data-download-url", "data-download", "data-file")
_DIR_TITLE = re.compile(r"^\s*(index of|directory listing for)\s+/", re.IGNORECASE)
_SORT_QUERY = re.compile(r"^\?C=[NMSD](;|&|&amp;)O=[AD]$", re.IGNORECASE)


@dataclass
class ExtractedLink:
    url: str
    raw_href: str
    method: DiscoveryMethod
    text: str = ""
    download_attr: str | None = None
    tag: str = "a"
    rel: str | None = None


@dataclass
class DownloadControl:
    """An element that explicitly looks like a download trigger but has no
    plain navigable href (button, onclick, javascript: link)."""

    tag: str
    text: str
    attrs: dict[str, str]


@dataclass
class PageExtraction:
    document_url: str
    base_url: str
    title: str | None = None
    links: list[ExtractedLink] = field(default_factory=list)
    meta_refresh: tuple[float, str] | None = None
    is_directory_listing: bool = False
    controls: list[DownloadControl] = field(default_factory=list)
    invalid_hrefs: list[tuple[str, str]] = field(default_factory=list)


def parse_refresh(content: str, base_url: str) -> tuple[float, str] | None:
    m = _REFRESH_RE.match(content or "")
    if not m or not m.group(3):
        return None
    try:
        delay = float(m.group(1) or 0)
        return delay, resolve(base_url, m.group(3).strip())
    except (URLError, ValueError):
        return None


def _text(el) -> str:  # type: ignore[no-untyped-def]
    txt = " ".join(el.get_text(" ", strip=True).split())
    for attr in ("aria-label", "title", "value", "alt"):
        if not txt and el.get(attr):
            txt = str(el.get(attr))
    return txt[:300]


def extract_links(html: bytes | str, document_url: str, encoding: str | None = None) -> PageExtraction:
    soup = BeautifulSoup(html, "html.parser", from_encoding=encoding if isinstance(html, bytes) else None)
    base_url = document_url
    base = soup.find("base", href=True)
    if base is not None:
        try:
            base_url = resolve(document_url, str(base["href"]))
        except URLError:
            pass
    out = PageExtraction(document_url=document_url, base_url=base_url)
    if soup.title and soup.title.string:
        out.title = soup.title.string.strip()[:300]
    h1 = soup.find("h1")
    out.is_directory_listing = bool(
        (out.title and _DIR_TITLE.match(out.title))
        or (h1 is not None and _DIR_TITLE.match(h1.get_text(" ", strip=True)))
    )

    for meta in soup.find_all("meta"):
        if str(meta.get("http-equiv", "")).lower() == "refresh" and meta.get("content"):
            out.meta_refresh = parse_refresh(str(meta["content"]), base_url)
            break

    def add(href: str, method: DiscoveryMethod, **kw: object) -> None:
        href = href.strip()
        if not href or href.startswith("#"):
            return
        low = href.lower()
        if low.startswith(("javascript:", "mailto:", "tel:", "data:", "blob:", "about:")):
            return
        if out.is_directory_listing and (_SORT_QUERY.match(href) or href in ("../", "..")):
            return
        try:
            url = resolve(base_url, href)
        except URLError as exc:
            out.invalid_hrefs.append((href[:500], str(exc)))
            return
        out.links.append(ExtractedLink(url=url, raw_href=href, method=method, **kw))  # type: ignore[arg-type]

    for a in soup.find_all(["a", "area"]):
        href = a.get("href")
        text = _text(a)
        if href is None or str(href).strip().lower().startswith("javascript:"):
            if a.name == "a" and (_DOWNLOAD_WORD.search(text) or a.get("onclick")):
                out.controls.append(DownloadControl("a", text, _attrs(a)))
            continue
        dl = a.get("download")
        if a.name == "area":
            method = DiscoveryMethod.AREA
        elif out.is_directory_listing:
            method = DiscoveryMethod.DIRECTORY_LISTING
        elif dl is not None:
            method = DiscoveryMethod.ANCHOR_DOWNLOAD_ATTR
        else:
            method = DiscoveryMethod.ANCHOR
        rel = a.get("rel")
        add(str(href), method, text=text, tag=a.name,
            download_attr=(str(dl) if dl is not None else None),
            rel=" ".join(rel) if isinstance(rel, list) else rel)

    for tag, attr in (("iframe", "src"), ("embed", "src"), ("object", "data")):
        for el in soup.find_all(tag):
            if el.get(attr):
                add(str(el[attr]), DiscoveryMethod.EMBED, tag=tag)

    for el in soup.find_all(True):
        for attr in _DATA_URL_ATTRS:
            v = el.get(attr)
            if v and isinstance(v, str) and ("/" in v or "." in v):
                add(v, DiscoveryMethod.DATA_ATTRIBUTE, text=_text(el), tag=el.name)
        if el.name in ("button", "input") and (
            _DOWNLOAD_WORD.search(_text(el)) or any(k.startswith("data-download") for k in el.attrs)
        ):
            out.controls.append(DownloadControl(el.name, _text(el), _attrs(el)))
        elif el.get("onclick") and _DOWNLOAD_WORD.search(str(el.get("onclick")) + _text(el)):
            if el.name != "a":
                out.controls.append(DownloadControl(el.name, _text(el), _attrs(el)))
    return out


def _attrs(el) -> dict[str, str]:  # type: ignore[no-untyped-def]
    return {k: (" ".join(v) if isinstance(v, list) else str(v))[:300] for k, v in el.attrs.items()}


def sniff_html_charset(content_type: str | None) -> str | None:
    if not content_type:
        return None
    m = re.search(r"charset=([\w.:-]+)", content_type, re.IGNORECASE)
    return m.group(1) if m else None
