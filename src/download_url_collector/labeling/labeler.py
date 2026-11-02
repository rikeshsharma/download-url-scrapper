"""Labeling stage: gather evidence per file hash, then apply the policy.

Evidence and labels are append-only and keyed by SHA-256. A re-label adds a
new label row (with the policy version) and never rewrites history.
"""

from __future__ import annotations

import datetime as _dt
import json
import logging
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from ..config import Config
from ..http_client import PolicyHttpClient
from ..models import parse_ts
from ..storage import Store
from ..urls import hostname, registrable_domain
from .checksums import find_publisher_checksum
from .policy import Decision, EvidenceItem, LabelingPolicy, evaluate
from .reputation import VirusTotalLookup
from .scanners import Scanner
from .signatures import SUPPORTED_FAMILIES, SignatureVerifier

log = logging.getLogger(__name__)


def _domain_match(host: str, domains: list[str]) -> bool:
    host = host.lower()
    return any(host == d.lower() or host.endswith("." + d.lower()) for d in domains)


class Labeler:
    def __init__(self, cfg: Config, store: Store, policy: LabelingPolicy, scanner: Scanner,
                 signer: SignatureVerifier, client: PolicyHttpClient | None = None,
                 reputation: VirusTotalLookup | None = None) -> None:
        self.cfg = cfg
        self.store = store
        self.policy = policy
        self.scanner = scanner
        self.signer = signer
        self.client = client
        self.reputation = reputation
        self.files_root = cfg.collection.data_dir / "files"

    def _fresh(self, sha256: str, kind: str, max_days: float, source: str | None = None) -> bool:
        now = _dt.datetime.now(_dt.UTC)
        for r in self.store.evidence_for(sha256):
            if r["kind"] == kind and (source is None or r["source"] == source):
                if (now - parse_ts(r["observed_at"])).total_seconds() / 86400 <= max_days \
                        and r["verdict"] not in ("unavailable", "error", "quota_exhausted"):
                    return True
        return False

    async def label_run(self, run_id: str, *, force: bool = False) -> dict[str, int]:
        rows = self.store.query(
            "SELECT DISTINCT sha256 FROM observations WHERE run_id=? AND sha256 IS NOT NULL", [run_id])
        counts: dict[str, int] = {}
        for r in rows:
            decision = await self.label_hash(r["sha256"], run_id=run_id, force=force)
            counts[str(decision.label)] = counts.get(str(decision.label), 0) + 1
        return counts

    async def label_hash(self, sha256: str, *, run_id: str | None = None, force: bool = False) -> Decision:
        f = self.store.get_file(sha256)
        if f is None:
            raise KeyError(sha256)
        path = self.files_root / f["storage_path"] if f["stored"] and f["storage_path"] else None
        age = self.policy.max_evidence_age_days
        family = f["detected_family"] or "unknown"

        # 1. Local AV (never uploads).
        if force or not self._fresh(sha256, "av_scan", age.av_scan, self.scanner.name):
            if path is not None and path.exists():
                res = self.scanner.scan(path, sha256)
            else:
                from .scanners import ScanResult

                res = ScanResult(self.scanner.name, "unavailable", detail="file_not_stored")
            self.store.add_evidence(
                sha256, "av_scan", res.scanner, res.verdict,
                {"detections": res.detections, "detail": res.detail},
                res.engine_version, res.signature_version, res.signature_date, res.scanned_at)

        # 2. Code signature (where supported).
        if family in SUPPORTED_FAMILIES and path is not None and \
                (force or not self._fresh(sha256, "signature", age.signature)):
            s = self.signer.verify(path, family, sha256)
            self.store.add_evidence(sha256, "signature", s.tool, s.status,
                                    {"signer": s.signer, "detail": s.detail}, s.tool_version)

        # 3. Optional hash reputation (lookup by hash only).
        if self.reputation is not None and (force or not self._fresh(sha256, "reputation", age.reputation)):
            rep = await self.reputation.lookup(sha256)
            self.store.add_evidence(sha256, "reputation", rep.provider, rep.verdict, rep.to_details(),
                                    observed_at=rep.queried_at)

        # 4. Publisher checksums and provenance, per observed URL of this content.
        obs = self.store.query(
            "SELECT o.*, c.publisher_checksums_json, c.adapter_metadata_json FROM observations o "
            "LEFT JOIN candidates c ON c.candidate_id = o.candidate_id WHERE o.sha256=?"
            + (" AND o.run_id=?" if run_id else ""), [sha256, run_id] if run_id else [sha256])
        existing = {(r["kind"], r["source"], r["verdict"]) for r in self.store.evidence_for(sha256)}
        for o in obs:
            await self._checksum_evidence(sha256, o, existing, force)
            self._provenance_evidence(sha256, o, existing)

        evidence = [EvidenceItem.from_row(r) for r in self.store.evidence_for(sha256)]
        inspection = json.loads(f["inspection_json"] or "{}")
        decision = evaluate(self.policy, evidence, inspection_status=f["inspection_status"],
                            detected_family=f["detected_family"],
                            discrepancies=inspection.get("discrepancies") or [])
        self.store.add_label(sha256, decision.label, self.policy.policy_version,
                             decision.reasons, decision.evidence_ids)
        return decision

    async def _checksum_evidence(self, sha256: str, o: Any, existing: set[tuple[str, str, str]],
                                 force: bool) -> None:
        provided = json.loads(o["publisher_checksums_json"] or "{}") if o["publisher_checksums_json"] else {}
        if "sha256" in provided:
            meta = json.loads(o["adapter_metadata_json"] or "{}") if o["adapter_metadata_json"] else {}
            src = f"adapter:{meta.get('adapter', 'unknown')}"
            verdict = "match" if provided["sha256"] == sha256 else "mismatch"
            if (("publisher_checksum", src, verdict) not in existing) or force:
                self.store.add_evidence(sha256, "publisher_checksum", src, verdict,
                                        {"listed_sha256": provided["sha256"], "url": o["initiating_url"]})
                existing.add(("publisher_checksum", src, verdict))
        if not (self.cfg.labeling.checksum_discovery and self.client is not None):
            return
        url = o["final_url"] if o["final_url"] and o["final_url"].startswith("http") else o["initiating_url"]
        urls = [o["initiating_url"]] + ([url] if url != o["initiating_url"] else [])
        for u in urls:
            if not u or not u.startswith("http"):
                continue
            for finding in await find_publisher_checksum(self.client, u, sha256, o["suggested_filename"]):
                key = ("publisher_checksum", finding.source_url, finding.verdict)
                if key in existing and not force:
                    continue
                existing.add(key)
                self.store.add_evidence(sha256, "publisher_checksum", finding.source_url, finding.verdict,
                                        {"filename": finding.filename, "listed_sha256": finding.listed_sha256,
                                         "download_url": u})

    def _provenance_evidence(self, sha256: str, o: Any, existing: set[tuple[str, str, str]]) -> None:
        page = o["source_page"] or o["initiating_url"]
        dl_url = o["final_url"] if o["final_url"] and o["final_url"].startswith("http") else o["initiating_url"]
        if not page or not dl_url:
            return
        page_host, dl_host = hostname(page), hostname(dl_url)
        init_host = hostname(o["initiating_url"])
        https = all(urlsplit(u).scheme == "https" for u in (page, o["initiating_url"], dl_url))
        for pub in self.policy.trusted_publishers:
            dl_domains = pub.download_domains or pub.page_domains
            ok = (https and _domain_match(page_host, pub.page_domains)
                  and _domain_match(init_host, pub.page_domains + dl_domains)
                  and _domain_match(dl_host, dl_domains + pub.page_domains))
            verdict = "trusted_publisher" if ok else "no_match"
            if not ok:
                continue
            src = f"policy:{pub.name}"
            if ("provenance", src, verdict) in existing:
                continue
            existing.add(("provenance", src, verdict))
            self.store.add_evidence(sha256, "provenance", src, verdict, {
                "publisher": pub.name, "source_page": page, "initiating_url": o["initiating_url"],
                "download_url": dl_url, "page_domain": registrable_domain(page_host),
                "download_domain": registrable_domain(dl_host), "https": https,
                "observation_id": o["observation_id"]})


def add_manual_review(store: Store, sha256: str, verdict: str, reviewer: str, notes: str) -> str:
    if verdict not in ("benign", "suspicious", "malicious"):
        raise ValueError("verdict must be benign, suspicious or malicious")
    if store.get_file(sha256) is None:
        raise KeyError(f"unknown sha256 {sha256}")
    return store.add_evidence(sha256, "manual_review", f"reviewer:{reviewer}", verdict, {"notes": notes})


def files_root(cfg: Config) -> Path:
    return cfg.collection.data_dir / "files"
