"""Local antivirus scanner adapters.

Scanners only *read* files. Nothing is uploaded. The engine and signature
database versions are captured with each result so stale databases can be
detected by the labeling policy.
"""

from __future__ import annotations

import datetime as _dt
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

from ..config import ScannerConfig
from ..models import utcnow


@dataclass
class ScanResult:
    scanner: str
    verdict: str  # "clean" | "detected" | "error" | "unavailable"
    engine_version: str | None = None
    signature_version: str | None = None
    signature_date: str | None = None  # ISO-8601 when known
    detections: list[str] = field(default_factory=list)
    detail: str | None = None
    scanned_at: str = field(default_factory=utcnow)


class Scanner(Protocol):
    name: str

    def scan(self, path: Path, sha256: str) -> ScanResult: ...


class UnavailableScanner:
    name = "none"

    def scan(self, path: Path, sha256: str) -> ScanResult:
        return ScanResult(self.name, "unavailable", detail="no scanner configured")


_CLAM_VER = re.compile(r"ClamAV\s+([\w.\-]+)(?:/(\d+)/(.+))?")


class ClamAVScanner:
    """ClamAV via ``clamscan`` or ``clamdscan`` (no file is executed)."""

    name = "clamav"

    def __init__(self, cfg: ScannerConfig) -> None:
        self.cfg = cfg
        self.binary = shutil.which(cfg.binary)

    def version(self) -> tuple[str | None, str | None, str | None]:
        if not self.binary:
            return None, None, None
        try:
            out = subprocess.run([self.binary, "--version"], capture_output=True, text=True,
                                 timeout=30, check=False).stdout.strip()
        except (OSError, subprocess.TimeoutExpired):
            return None, None, None
        m = _CLAM_VER.search(out)
        if not m:
            return out[:100] or None, None, None
        date: str | None = None
        if m.group(3):
            try:
                date = _dt.datetime.strptime(m.group(3).strip(), "%a %b %d %H:%M:%S %Y") \
                    .replace(tzinfo=_dt.UTC).isoformat().replace("+00:00", "Z")
            except ValueError:
                date = None
        return m.group(1), m.group(2), date

    def scan(self, path: Path, sha256: str) -> ScanResult:
        if not self.binary:
            return ScanResult(self.name, "unavailable", detail=f"{self.cfg.binary} not found on PATH")
        engine, db, db_date = self.version()
        try:
            proc = subprocess.run(
                [self.binary, "--no-summary", "--stdout", "--infected", str(path)],
                capture_output=True, text=True, timeout=self.cfg.timeout_seconds, check=False)
        except subprocess.TimeoutExpired:
            return ScanResult(self.name, "error", engine, db, db_date, detail="timeout")
        except OSError as exc:
            return ScanResult(self.name, "error", engine, db, db_date, detail=str(exc))
        if proc.returncode == 0:
            return ScanResult(self.name, "clean", engine, db, db_date)
        if proc.returncode == 1:
            names = [ln.rsplit(":", 1)[-1].replace("FOUND", "").strip()
                     for ln in proc.stdout.splitlines() if ln.endswith("FOUND")]
            return ScanResult(self.name, "detected", engine, db, db_date, detections=names)
        return ScanResult(self.name, "error", engine, db, db_date,
                          detail=(proc.stderr or proc.stdout)[:300])


class MockScanner:
    """Deterministic scanner for tests and dry runs."""

    name = "mock"

    def __init__(self, default_verdict: str = "unavailable",
                 verdicts: dict[str, str] | None = None,
                 engine_version: str = "mock-1.0", signature_version: str = "1",
                 signature_date: str | None = None) -> None:
        self.default = default_verdict
        self.verdicts = verdicts or {}
        self.engine_version = engine_version
        self.signature_version = signature_version
        self.signature_date = signature_date

    def scan(self, path: Path, sha256: str) -> ScanResult:
        verdict = self.verdicts.get(sha256, self.default)
        if verdict == "unavailable":
            return ScanResult(self.name, "unavailable", detail="mock scanner unavailable")
        return ScanResult(self.name, verdict, self.engine_version, self.signature_version,
                          self.signature_date or utcnow(),
                          detections=["Mock.Test.Detection"] if verdict == "detected" else [])


def build_scanner(cfg: ScannerConfig) -> Scanner:
    if cfg.type == "clamav":
        return ClamAVScanner(cfg)
    if cfg.type == "mock":
        return MockScanner(cfg.mock_default_verdict, cfg.mock_verdicts)
    return UnavailableScanner()
