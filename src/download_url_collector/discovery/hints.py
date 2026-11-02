"""Heuristic download hints. These are *hints* for prioritising probing, never
evidence that something is a download."""

from __future__ import annotations

import re
from urllib.parse import urlsplit

from ..urls import path_extension

DOWNLOAD_EXTENSIONS = frozenset({
    # executables / installers / packages
    "exe", "msi", "msix", "msixbundle", "appx", "appxbundle", "dll", "scr", "com", "bat", "cmd",
    "ps1", "vbs", "js", "jse", "wsf", "hta", "lnk", "jar", "apk", "aab", "xapk", "ipa",
    "dmg", "pkg", "mpkg", "app", "deb", "rpm", "appimage", "snap", "flatpak", "run", "bin", "sh",
    "whl", "egg", "gem", "nupkg", "crx", "xpi", "vsix", "msp", "cab",
    # archives / images
    "zip", "7z", "rar", "tar", "gz", "tgz", "bz2", "xz", "zst", "lz", "lzma", "iso", "img", "vhd",
    "vhdx", "tar.gz", "tar.bz2", "tar.xz", "tar.zst", "tar.lz",
    # documents frequently delivered as downloads
    "pdf", "doc", "docx", "docm", "xls", "xlsx", "xlsm", "xlsb", "ppt", "pptx", "pptm", "rtf",
    "odt", "ods", "odp", "one", "chm", "epub",
    # misc data
    "csv", "torrent", "ics", "vcf", "dat", "db", "sqlite",
})
PAGE_EXTENSIONS = frozenset({"html", "htm", "xhtml", "php", "asp", "aspx", "jsp", "cfm", "shtml"})
NON_DOWNLOAD_ASSET_EXTENSIONS = frozenset({
    "css", "png", "jpg", "jpeg", "gif", "svg", "webp", "ico", "woff", "woff2", "ttf", "otf", "eot",
    "map", "mp4", "webm", "mp3",
})
_PATH_HINT = re.compile(
    r"/(download|downloads|dl|get|file|files|attachment|attachments|release|releases|dist|"
    r"pub|mirror|mirrors|binaries|installer|installers|setup)(/|$)",
    re.IGNORECASE,
)
_QUERY_HINT = re.compile(r"(^|&)(download|dl|file|filename|attachment|fileid|file_id|get)=",
                         re.IGNORECASE)
_TEXT_HINT = re.compile(r"\b(download|installer|setup|get the app|\.exe|\.msi|\.zip|\.dmg)\b",
                        re.IGNORECASE)


def link_hints(url: str, text: str = "", download_attr: str | None = None) -> list[str]:
    hints: list[str] = []
    ext = path_extension(url)
    if ext in DOWNLOAD_EXTENSIONS:
        hints.append(f"ext:{ext}")
    if download_attr is not None:
        hints.append("download_attribute")
    parts = urlsplit(url)
    if _PATH_HINT.search(parts.path):
        hints.append("path_keyword")
    if parts.query and _QUERY_HINT.search(parts.query):
        hints.append("query_keyword")
    if text and _TEXT_HINT.search(text):
        hints.append("link_text")
    return hints


def url_kind(url: str) -> str:
    """'download' | 'page' | 'asset' | 'ambiguous' — purely from the URL."""
    ext = path_extension(url)
    if ext in DOWNLOAD_EXTENSIONS:
        return "download"
    if ext in NON_DOWNLOAD_ASSET_EXTENSIONS:
        return "asset"
    if ext in PAGE_EXTENSIONS or urlsplit(url).path.endswith("/"):
        return "page"
    return "ambiguous"


HTML_MIMES = ("text/html", "application/xhtml+xml")


def is_html_mime(content_type: str | None) -> bool:
    if not content_type:
        return False
    return content_type.split(";", 1)[0].strip().lower() in HTML_MIMES
