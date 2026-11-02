"""Magic-byte file-type detection (pure Python, deterministic).

``detect_prefix`` works on a leading byte sample (used during probing);
``detect_file`` can also look at the file trailer and ZIP directory for
container subtypes (OOXML, JAR, APK, …).
"""

from __future__ import annotations

import struct
import zipfile
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class FileType:
    family: str
    mime: str

    def to_dict(self) -> dict[str, str]:
        return {"family": self.family, "mime": self.mime}


UNKNOWN = FileType("unknown", "application/octet-stream")

# Families considered archives for inspection purposes.
ARCHIVE_FAMILIES = frozenset({"zip", "jar", "apk", "ooxml_document", "ooxml_spreadsheet",
                              "ooxml_presentation", "opendocument", "msix", "gzip", "bzip2", "xz",
                              "zstd", "7z", "rar", "cab", "tar", "iso", "dmg", "deb", "rpm",
                              "xpi_crx", "nupkg"})
EXECUTABLE_FAMILIES = frozenset({"pe", "elf", "macho", "script", "msi_or_ole", "jar", "apk", "msix",
                                 "wasm"})

_SIMPLE: list[tuple[int, bytes, FileType]] = [
    (0, b"%PDF-", FileType("pdf", "application/pdf")),
    (0, b"\x7fELF", FileType("elf", "application/x-elf")),
    (0, b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", FileType("msi_or_ole", "application/x-ole-storage")),
    (0, b"\x1f\x8b", FileType("gzip", "application/gzip")),
    (0, b"BZh", FileType("bzip2", "application/x-bzip2")),
    (0, b"\xfd7zXZ\x00", FileType("xz", "application/x-xz")),
    (0, b"\x28\xb5\x2f\xfd", FileType("zstd", "application/zstd")),
    (0, b"7z\xbc\xaf\x27\x1c", FileType("7z", "application/x-7z-compressed")),
    (0, b"Rar!\x1a\x07", FileType("rar", "application/vnd.rar")),
    (0, b"MSCF", FileType("cab", "application/vnd.ms-cab-compressed")),
    (0, b"!<arch>\ndebian-binary", FileType("deb", "application/vnd.debian.binary-package")),
    (0, b"\xed\xab\xee\xdb", FileType("rpm", "application/x-rpm")),
    (0, b"\x89PNG\r\n\x1a\n", FileType("image", "image/png")),
    (0, b"\xff\xd8\xff", FileType("image", "image/jpeg")),
    (0, b"GIF87a", FileType("image", "image/gif")),
    (0, b"GIF89a", FileType("image", "image/gif")),
    (0, b"\x00asm", FileType("wasm", "application/wasm")),
    (0, b"{\\rtf", FileType("rtf", "application/rtf")),
    (0, b"Cr24", FileType("xpi_crx", "application/x-chrome-extension")),
]
_MACHO = {b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe"}


def detect_prefix(data: bytes) -> FileType:
    if not data:
        return FileType("empty", "application/x-empty")
    for off, magic, ft in _SIMPLE:
        if data[off:off + len(magic)] == magic:
            return ft
    if data[:2] == b"MZ":
        if len(data) >= 0x40:
            (pe_off,) = struct.unpack_from("<I", data, 0x3C)
            if pe_off + 4 <= len(data) and data[pe_off:pe_off + 4] == b"PE\x00\x00":
                return FileType("pe", "application/vnd.microsoft.portable-executable")
        return FileType("pe", "application/x-msdownload")  # MZ stub; PE header beyond sample
    if data[:4] in _MACHO:
        return FileType("macho", "application/x-mach-binary")
    if data[:4] == b"\xca\xfe\xba\xbe" and len(data) >= 8:
        # Fat Mach-O (small arch count) vs Java class (major version >= 45).
        (n,) = struct.unpack_from(">I", data, 4)
        if n < 45:
            return FileType("macho", "application/x-mach-binary")
        return FileType("java_class", "application/java-vm")
    if data[:4] in (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"):
        return FileType("zip", "application/zip")
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return FileType("image", "image/webp")
    if data[4:8] == b"ftyp":
        return FileType("media", "video/mp4")
    for off in (0x8001, 0x8801, 0x9001):
        if data[off:off + 5] == b"CD001":
            return FileType("iso", "application/x-iso9660-image")
    if len(data) >= 262 and data[257:262] == b"ustar":
        return FileType("tar", "application/x-tar")
    if data[:2] == b"#!":
        return FileType("script", "text/x-shellscript")
    head = data[:1024].lstrip(b"\xef\xbb\xbf \t\r\n").lower()
    if head.startswith((b"<!doctype html", b"<html", b"<head", b"<body")) or b"<html" in head[:512]:
        return FileType("html", "text/html")
    if head.startswith(b"<?xml") or head.startswith(b"<svg"):
        return FileType("xml", "image/svg+xml" if b"<svg" in head else "application/xml")
    if head.startswith((b"{", b"[")) and _is_text(data):
        return FileType("text", "application/json")
    if _is_text(data):
        return FileType("text", "text/plain")
    return UNKNOWN


def _is_text(data: bytes) -> bool:
    sample = data[:8192]
    if b"\x00" in sample:
        return False
    try:
        sample.decode("utf-8")
        return True
    except UnicodeDecodeError as exc:
        # A multi-byte sequence may be cut at the sample boundary.
        return exc.start >= len(sample) - 4


def _zip_subtype(path: Path) -> FileType | None:
    try:
        with zipfile.ZipFile(path) as zf:
            names = set(zf.namelist()[:5000])
    except (zipfile.BadZipFile, OSError, ValueError):
        return None
    if "[Content_Types].xml" in names:
        if any(n.startswith("word/") for n in names):
            return FileType("ooxml_document", "application/vnd.openxmlformats-officedocument.wordprocessingml.document")
        if any(n.startswith("xl/") for n in names):
            return FileType("ooxml_spreadsheet", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
        if any(n.startswith("ppt/") for n in names):
            return FileType("ooxml_presentation", "application/vnd.openxmlformats-officedocument.presentationml.presentation")
        if "AppxManifest.xml" in names or "AppxMetadata/AppxBundleManifest.xml" in names:
            return FileType("msix", "application/msix")
        if any(n.endswith(".nuspec") for n in names):
            return FileType("nupkg", "application/zip")
    if "AndroidManifest.xml" in names and "classes.dex" in names:
        return FileType("apk", "application/vnd.android.package-archive")
    if "META-INF/MANIFEST.MF" in names:
        return FileType("jar", "application/java-archive")
    if "mimetype" in names:
        return FileType("opendocument", "application/vnd.oasis.opendocument")
    if "manifest.json" in names and any(n.startswith("META-INF/mozilla") for n in names):
        return FileType("xpi_crx", "application/x-xpinstall")
    return None


def detect_file(path: Path) -> FileType:
    with path.open("rb") as fh:
        head = fh.read(0x9010)
        size = path.stat().st_size
        trailer = b""
        if size >= 512:
            fh.seek(size - 512)
            trailer = fh.read(512)
    ft = detect_prefix(head)
    if ft.family == "zip":
        return _zip_subtype(path) or ft
    if ft.family in ("unknown", "text") and trailer[:4] == b"koly":
        return FileType("dmg", "application/x-apple-diskimage")
    return ft


# Declared MIME / extension -> family, for discrepancy checks.
MIME_FAMILY = {
    "application/pdf": "pdf",
    "application/zip": "zip", "application/x-zip-compressed": "zip",
    "application/x-msdownload": "pe", "application/x-msdos-program": "pe",
    "application/vnd.microsoft.portable-executable": "pe", "application/x-dosexec": "pe",
    "application/x-msi": "msi_or_ole", "application/x-ole-storage": "msi_or_ole",
    "application/msword": "msi_or_ole", "application/vnd.ms-excel": "msi_or_ole",
    "application/gzip": "gzip", "application/x-gzip": "gzip", "application/x-tar": "tar",
    "application/x-7z-compressed": "7z", "application/vnd.rar": "rar", "application/x-rar-compressed": "rar",
    "application/x-apple-diskimage": "dmg", "application/vnd.android.package-archive": "apk",
    "application/java-archive": "jar", "application/x-iso9660-image": "iso",
    "text/html": "html", "text/plain": "text", "application/json": "text",
    "image/png": "image", "image/jpeg": "image", "image/gif": "image", "image/webp": "image",
    "application/x-elf": "elf", "application/x-executable": "elf",
    "application/x-mach-binary": "macho",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": "ooxml_document",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": "ooxml_spreadsheet",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation": "ooxml_presentation",
}
GENERIC_MIMES = frozenset({"application/octet-stream", "binary/octet-stream",
                           "application/download", "application/force-download",
                           "application/x-download", "application/unknown"})
EXT_FAMILY = {
    "exe": "pe", "dll": "pe", "scr": "pe", "sys": "pe", "msi": "msi_or_ole", "doc": "msi_or_ole",
    "xls": "msi_or_ole", "ppt": "msi_or_ole", "zip": "zip", "jar": "jar", "apk": "apk",
    "docx": "ooxml_document", "docm": "ooxml_document", "xlsx": "ooxml_spreadsheet",
    "xlsm": "ooxml_spreadsheet", "pptx": "ooxml_presentation", "pdf": "pdf", "gz": "gzip",
    "tgz": "gzip", "tar.gz": "gzip", "tar.bz2": "bzip2", "bz2": "bzip2", "tar.xz": "xz", "xz": "xz",
    "7z": "7z", "rar": "rar", "dmg": "dmg", "iso": "iso", "deb": "deb", "rpm": "rpm", "cab": "cab",
    "tar": "tar", "png": "image", "jpg": "image", "jpeg": "image", "gif": "image", "txt": "text",
    "csv": "text", "json": "text", "html": "html", "htm": "html", "sh": "script", "msix": "msix",
    "appx": "msix", "nupkg": "nupkg", "whl": "zip", "xpi": "xpi_crx", "crx": "xpi_crx",
    "odt": "opendocument", "ods": "opendocument", "odp": "opendocument", "elf": "elf",
}
# Families that are legitimately also seen as their container family.
COMPATIBLE = {
    ("zip", "jar"), ("zip", "apk"), ("zip", "ooxml_document"), ("zip", "ooxml_spreadsheet"),
    ("zip", "ooxml_presentation"), ("zip", "msix"), ("zip", "opendocument"), ("zip", "nupkg"),
    ("zip", "xpi_crx"), ("gzip", "tar"), ("text", "script"), ("text", "html"), ("text", "xml"),
}


def families_compatible(declared: str, detected: str) -> bool:
    return declared == detected or (declared, detected) in COMPATIBLE or (detected, declared) in COMPATIBLE


def mime_family(mime: str | None) -> str | None:
    if not mime:
        return None
    base = mime.split(";", 1)[0].strip().lower()
    if base in GENERIC_MIMES:
        return None
    return MIME_FAMILY.get(base)
