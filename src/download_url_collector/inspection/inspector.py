"""Inspect a completed download: hash, size, content type, discrepancies and
(optionally) bounded archive inspection. Files are stored under their
SHA-256, never under a server-supplied name, with no execute permission."""

from __future__ import annotations

import hashlib
import os
import shutil
import stat
import tarfile
import zipfile
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from ..config import ArchiveInspectionConfig
from .filetype import (
    ARCHIVE_FAMILIES,
    EXT_FAMILY,
    GENERIC_MIMES,
    detect_file,
    families_compatible,
    mime_family,
)


@dataclass
class InspectionResult:
    sha256: str
    size: int
    detected_family: str
    detected_mime: str
    status: str  # "complete" | "unresolved"
    unresolved_reasons: list[str] = field(default_factory=list)
    discrepancies: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    archive: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def sha256_file(path: Path) -> tuple[str, int]:
    h = hashlib.sha256()
    size = 0
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
            size += len(chunk)
    return h.hexdigest(), size


def evidence_discrepancies(detected_family: str, declared_mime: str | None, url_ext: str | None,
                           filename_ext: str | None) -> tuple[list[str], list[str]]:
    """Compare independently recorded type evidence. Returns (discrepancies, notes)."""
    disc: list[str] = []
    notes: list[str] = []
    if declared_mime:
        base = declared_mime.split(";", 1)[0].strip().lower()
        if base in GENERIC_MIMES:
            notes.append("generic_declared_mime")
        else:
            fam = mime_family(base)
            if fam is None:
                notes.append("unmapped_declared_mime")
            elif detected_family not in ("unknown",) and not families_compatible(fam, detected_family):
                disc.append(f"declared_mime:{base}!=detected:{detected_family}")
    for label, ext in (("url_extension", url_ext), ("filename_extension", filename_ext)):
        if not ext:
            continue
        fam = EXT_FAMILY.get(ext)
        if fam and detected_family != "unknown" and not families_compatible(fam, detected_family):
            disc.append(f"{label}:{ext}!=detected:{detected_family}")
    if url_ext and filename_ext and url_ext != filename_ext:
        notes.append(f"url_extension:{url_ext}!=filename_extension:{filename_ext}")
    return disc, notes


def inspect_archive(path: Path, family: str, cfg: ArchiveInspectionConfig) -> tuple[dict[str, Any], list[str]]:
    """Bounded listing of ZIP-family and TAR archives. Nothing is extracted to disk."""
    info: dict[str, Any] = {"members": 0, "listed": [], "encrypted_members": 0,
                            "declared_uncompressed_bytes": 0, "nested_archives": 0}
    unresolved: list[str] = []
    size = max(1, path.stat().st_size)
    nested_ext = (".zip", ".7z", ".rar", ".gz", ".tgz", ".xz", ".bz2", ".cab", ".iso", ".jar", ".tar")
    try:
        if family in ("zip", "jar", "apk", "ooxml_document", "ooxml_spreadsheet", "ooxml_presentation",
                      "opendocument", "msix", "nupkg", "xpi_crx"):
            with zipfile.ZipFile(path) as zf:
                infos = zf.infolist()
                info["members"] = len(infos)
                if len(infos) > cfg.max_members:
                    return info, ["archive_too_many_members"]
                total = sum(i.file_size for i in infos)
                info["declared_uncompressed_bytes"] = total
                if total > cfg.max_total_uncompressed_bytes:
                    return info, ["archive_uncompressed_too_large"]
                if total / size > cfg.max_compression_ratio:
                    return info, ["archive_compression_ratio_exceeded"]
                for i in infos:
                    if i.flag_bits & 0x1:
                        info["encrypted_members"] += 1
                    if i.filename.lower().endswith(nested_ext):
                        info["nested_archives"] += 1
                    if len(info["listed"]) < cfg.max_listed_members:
                        info["listed"].append({"name": i.filename[:300], "size": i.file_size})
                if info["encrypted_members"]:
                    return info, ["archive_encrypted"]
                # CRC check reads every member (bounded by the limits above).
                bad = zf.testzip()
                if bad is not None:
                    unresolved.append("archive_crc_error")
        elif family in ("tar", "gzip", "bzip2", "xz"):
            read_total = 0
            try:
                with tarfile.open(path, mode="r:*") as tf:
                    for m in tf:
                        info["members"] += 1
                        if info["members"] > cfg.max_members:
                            return info, ["archive_too_many_members"]
                        read_total += m.size
                        if read_total > cfg.max_total_uncompressed_bytes:
                            return info, ["archive_uncompressed_too_large"]
                        if len(info["listed"]) < cfg.max_listed_members:
                            info["listed"].append({"name": m.name[:300], "size": m.size})
                info["declared_uncompressed_bytes"] = read_total
            except tarfile.ReadError:
                if family == "tar":
                    raise
                # A single compressed stream that is not a tar: we cannot bound
                # its expansion cheaply here, so leave it unresolved.
                return info, ["compressed_stream_not_inspected"]
        else:
            return info, [f"archive_format_unsupported:{family}"]
    except (zipfile.BadZipFile, tarfile.ReadError, EOFError) as exc:
        return info, [f"archive_truncated_or_corrupt:{type(exc).__name__}"]
    except (RuntimeError, NotImplementedError) as exc:  # e.g. unsupported compression
        return info, [f"archive_unsupported_feature:{type(exc).__name__}"]
    except OSError as exc:
        return info, [f"archive_read_error:{type(exc).__name__}"]
    return info, unresolved


def inspect_file(path: Path, *, declared_mime: str | None, url_ext: str | None,
                 filename_ext: str | None, archive_cfg: ArchiveInspectionConfig,
                 expected_size: int | None = None) -> InspectionResult:
    digest, size = sha256_file(path)
    ft = detect_file(path)
    disc, notes = evidence_discrepancies(ft.family, declared_mime, url_ext, filename_ext)
    res = InspectionResult(sha256=digest, size=size, detected_family=ft.family,
                           detected_mime=ft.mime, status="complete", discrepancies=disc, notes=notes)
    if expected_size is not None and expected_size != size:
        res.unresolved_reasons.append("size_mismatch_with_declared_length")
    if ft.family in ARCHIVE_FAMILIES:
        if not archive_cfg.enabled:
            res.unresolved_reasons.append("archive_inspection_disabled")
        else:
            info, reasons = inspect_archive(path, ft.family, archive_cfg)
            res.archive = info
            res.unresolved_reasons.extend(reasons)
    if res.unresolved_reasons:
        res.status = "unresolved"
    return res


class FileStore:
    """Content-addressed storage under generated identifiers."""

    def __init__(self, root: Path, keep_files: bool, max_bytes: int) -> None:
        self.root = root
        self.keep_files = keep_files
        self.max_bytes = max_bytes
        (root / "tmp").mkdir(parents=True, exist_ok=True)
        (root / "objects").mkdir(parents=True, exist_ok=True)

    def temp_path(self, token: str) -> Path:
        return self.root / "tmp" / f"{token}.part"

    def commit(self, tmp: Path, sha256: str, size: int, stored_bytes: int) -> tuple[str | None, bool, str | None]:
        """Move *tmp* into the object store. Returns (relative_path, stored, reason_if_not)."""
        if not self.keep_files:
            tmp.unlink(missing_ok=True)
            return None, False, "keep_files_disabled"
        rel = Path("objects") / sha256[:2] / f"{sha256}.bin"
        dest = self.root / rel
        if dest.exists():
            tmp.unlink(missing_ok=True)
            return str(rel), True, None
        if stored_bytes + size > self.max_bytes:
            tmp.unlink(missing_ok=True)
            return None, False, "storage_limit_reached"
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(tmp), dest)
        # Read-only, never executable.
        os.chmod(dest, stat.S_IRUSR)
        return str(rel), True, None
