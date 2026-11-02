from __future__ import annotations

import io
import os
import stat
import struct
import tarfile
import zipfile
from pathlib import Path

from download_url_collector.config import ArchiveInspectionConfig
from download_url_collector.inspection.filetype import detect_file, detect_prefix
from download_url_collector.inspection.inspector import FileStore, inspect_file

ARCH = ArchiveInspectionConfig(enabled=True, max_members=10, max_total_uncompressed_bytes=10_000,
                               max_compression_ratio=50)


def _zip(tmp: Path, name: str, members: dict[str, bytes], encrypt_flag: bool = False) -> Path:
    p = tmp / name
    with zipfile.ZipFile(p, "w", zipfile.ZIP_DEFLATED) as zf:
        for n, data in members.items():
            zf.writestr(n, data)
    if encrypt_flag:  # set the general-purpose "encrypted" bit in both headers
        raw = bytearray(p.read_bytes())
        for sig, off in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
            i = raw.find(sig)
            flags = struct.unpack_from("<H", raw, i + off)[0] | 1
            struct.pack_into("<H", raw, i + off, flags)
        p.write_bytes(bytes(raw))
    return p


def test_magic_detection() -> None:
    pe = bytearray(b"MZ" + b"\0" * 0x3A + struct.pack("<I", 0x40) + b"PE\0\0")
    assert detect_prefix(bytes(pe)).family == "pe"
    assert detect_prefix(b"%PDF-1.7").family == "pdf"
    assert detect_prefix(b"\x7fELF\x02").family == "elf"
    assert detect_prefix(b"<!DOCTYPE html><html>").family == "html"
    assert detect_prefix(b"\xca\xfe\xba\xbe\x00\x00\x00\x02").family == "macho"
    assert detect_prefix(b"\xca\xfe\xba\xbe\x00\x00\x00\x34").family == "java_class"
    assert detect_prefix(b"").family == "empty"


def test_zip_subtypes(tmp_path: Path) -> None:
    docx = _zip(tmp_path, "d.zip", {"[Content_Types].xml": b"x", "word/document.xml": b"x"})
    assert detect_file(docx).family == "ooxml_document"
    jar = _zip(tmp_path, "j.zip", {"META-INF/MANIFEST.MF": b"x"})
    assert detect_file(jar).family == "jar"


def test_discrepancies_are_recorded_separately(tmp_path: Path) -> None:
    z = _zip(tmp_path, "z.bin", {"a.txt": b"a"})
    res = inspect_file(z, declared_mime="application/pdf", url_ext="pdf", filename_ext="zip", archive_cfg=ARCH)
    assert res.detected_family == "zip"
    assert "declared_mime:application/pdf!=detected:zip" in res.discrepancies
    assert "url_extension:pdf!=detected:zip" in res.discrepancies
    assert not any(d.startswith("filename_extension") for d in res.discrepancies)
    generic = inspect_file(z, declared_mime="application/octet-stream", url_ext=None, filename_ext=None,
                           archive_cfg=ARCH)
    assert generic.discrepancies == [] and "generic_declared_mime" in generic.notes


def test_archive_inspection_outcomes(tmp_path: Path) -> None:
    ok = inspect_file(_zip(tmp_path, "ok.zip", {"a.txt": b"hello"}), declared_mime=None, url_ext=None,
                      filename_ext=None, archive_cfg=ARCH)
    assert ok.status == "complete" and ok.archive and ok.archive["members"] == 1
    enc = inspect_file(_zip(tmp_path, "e.zip", {"a.txt": b"x"}, encrypt_flag=True), declared_mime=None,
                       url_ext=None, filename_ext=None, archive_cfg=ARCH)
    assert enc.status == "unresolved" and "archive_encrypted" in enc.unresolved_reasons
    big = inspect_file(_zip(tmp_path, "b.zip", {"a.txt": b"\0" * 20_000}), declared_mime=None,
                       url_ext=None, filename_ext=None, archive_cfg=ARCH)
    assert big.status == "unresolved"
    many = inspect_file(_zip(tmp_path, "m.zip", {f"{i}.txt": b"x" for i in range(11)}), declared_mime=None,
                        url_ext=None, filename_ext=None, archive_cfg=ARCH)
    assert "archive_too_many_members" in many.unresolved_reasons
    trunc = tmp_path / "t.zip"
    trunc.write_bytes((tmp_path / "ok.zip").read_bytes()[:40])
    t = inspect_file(trunc, declared_mime=None, url_ext=None, filename_ext=None, archive_cfg=ARCH)
    assert t.status == "unresolved" and any("truncated" in r for r in t.unresolved_reasons)
    off = inspect_file(tmp_path / "ok.zip", declared_mime=None, url_ext=None, filename_ext=None,
                       archive_cfg=ArchiveInspectionConfig(enabled=False))
    assert off.unresolved_reasons == ["archive_inspection_disabled"]
    seven = tmp_path / "x.7z"
    seven.write_bytes(b"7z\xbc\xaf\x27\x1c" + b"\0" * 32)
    s = inspect_file(seven, declared_mime=None, url_ext=None, filename_ext=None, archive_cfg=ARCH)
    assert s.unresolved_reasons == ["archive_format_unsupported:7z"]


def test_tar_gz_listing(tmp_path: Path) -> None:
    p = tmp_path / "a.tar.gz"
    with tarfile.open(p, "w:gz") as tf:
        data = b"hi"
        info = tarfile.TarInfo("dir/hi.txt")
        info.size = len(data)
        tf.addfile(info, io.BytesIO(data))
    res = inspect_file(p, declared_mime="application/gzip", url_ext="tar.gz", filename_ext=None, archive_cfg=ARCH)
    assert res.status == "complete" and res.archive and res.archive["listed"][0]["name"] == "dir/hi.txt"


def test_file_store_uses_generated_names_and_no_exec(tmp_path: Path) -> None:
    fs = FileStore(tmp_path / "files", keep_files=True, max_bytes=100)
    tmp = fs.temp_path("abc")
    tmp.write_bytes(b"x" * 10)
    rel, stored, why = fs.commit(tmp, "ab" * 32, 10, 0)
    assert stored and rel == f"objects/ab/{'ab' * 32}.bin" and why is None
    mode = os.stat(tmp_path / "files" / rel).st_mode
    assert not mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    tmp2 = fs.temp_path("def")
    tmp2.write_bytes(b"y" * 10)
    assert fs.commit(tmp2, "cd" * 32, 10, 95) == (None, False, "storage_limit_reached")
