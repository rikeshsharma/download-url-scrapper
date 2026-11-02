"""Code-signature validation adapters (where supported).

Only Authenticode (PE/MSI/CAB) via ``osslsigncode`` is implemented. Validity
depends on the configured trust store; an unsigned or unsupported file is
recorded as such, never as a negative or positive verdict on its own.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from ..config import SignatureConfig

SUPPORTED_FAMILIES = frozenset({"pe", "msi_or_ole", "cab"})


@dataclass
class SignatureResult:
    status: str  # "valid" | "invalid" | "unsigned" | "unsupported" | "error" | "unavailable"
    signer: str | None = None
    tool: str = "none"
    tool_version: str | None = None
    detail: str | None = None


class SignatureVerifier(Protocol):
    def verify(self, path: Path, family: str, sha256: str) -> SignatureResult: ...


class NoSignatureVerifier:
    def verify(self, path: Path, family: str, sha256: str) -> SignatureResult:
        return SignatureResult("unavailable", detail="no signature verifier configured")


class OsslsigncodeVerifier:
    def __init__(self, cfg: SignatureConfig) -> None:
        self.cfg = cfg
        self.binary = shutil.which(cfg.binary)

    def verify(self, path: Path, family: str, sha256: str) -> SignatureResult:
        if family not in SUPPORTED_FAMILIES:
            return SignatureResult("unsupported", tool="osslsigncode", detail=family)
        if not self.binary:
            return SignatureResult("unavailable", tool="osslsigncode", detail="binary not found")
        cmd = [self.binary, "verify", "-in", str(path)]
        if self.cfg.ca_file:
            cmd += ["-CAfile", str(self.cfg.ca_file)]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True,
                                  timeout=self.cfg.timeout_seconds, check=False)
        except (OSError, subprocess.TimeoutExpired) as exc:
            return SignatureResult("error", tool="osslsigncode", detail=str(exc)[:200])
        out = proc.stdout + proc.stderr
        ver = re.search(r"osslsigncode\s+([\d.]+)", out)
        signer = re.search(r"Subject:\s*(.+)", out)
        if "No signature found" in out:
            status = "unsigned"
        elif proc.returncode == 0 and re.search(r"Signature verification:\s*ok", out):
            status = "valid"
        else:
            status = "invalid"
        return SignatureResult(status, signer.group(1).strip() if signer else None, "osslsigncode",
                               ver.group(1) if ver else None, out[-300:] if status != "valid" else None)


class MockSignatureVerifier:
    def __init__(self, results: dict[str, dict[str, str]]) -> None:
        self.results = results

    def verify(self, path: Path, family: str, sha256: str) -> SignatureResult:
        r = self.results.get(sha256)
        if not r:
            return SignatureResult("unsigned", tool="mock")
        return SignatureResult(r.get("status", "unsigned"), r.get("signer"), "mock", "1")


def build_signature_verifier(cfg: SignatureConfig) -> SignatureVerifier:
    if cfg.type == "osslsigncode":
        return OsslsigncodeVerifier(cfg)
    if cfg.type == "mock":
        return MockSignatureVerifier(cfg.mock_results)
    return NoSignatureVerifier()
