"""Versioned, declarative labeling policy.

The policy maps *independently recorded evidence* to one of five labels.
It is evaluated per file hash, so verdicts stay tied to exact content.

Facts derived from evidence (each computed with freshness limits):

  av_scan_clean               latest local AV result is clean, scan and signature DB fresh
  av_detection                latest result of any local AV scanner is a detection
  inspection_complete         content inspection finished without unresolved items
  type_discrepancy_executable executable content disagrees with declared MIME/extension
  publisher_provenance        served from a configured trusted publisher's domains over
                              HTTPS (with publisher checksum match when required)
  publisher_checksum_match    publisher-listed checksum equals the file hash (integrity only)
  publisher_checksum_mismatch publisher-listed checksum differs
  trusted_signature           valid code signature by a signer configured for a trusted publisher
  signature_invalid           signature present but fails validation
  reputation_clean            fresh hash report: zero malicious/suspicious, enough engines
  reputation_suspicious       fresh hash report with suspicious engines over threshold
  reputation_malicious        hash report with malicious engines over threshold
  manual_review_benign|suspicious|malicious   latest manual review verdict, fresh

Only facts listed in ``positive_evidence`` count toward benign labels, each at
most once. ``av_scan_clean`` and ``inspection_complete`` are *requirements*,
never positive evidence, and ``benign_validated`` needs at least two distinct
positive facts — so no single signal (zero detections, an absent threat-feed
entry, a valid signature, a known domain) can produce it.
"""

from __future__ import annotations

import datetime as _dt
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator

from ..inspection.filetype import EXECUTABLE_FAMILIES
from ..models import Label, parse_ts

POSITIVE_FACTS = frozenset({"publisher_provenance", "trusted_signature", "reputation_clean",
                            "manual_review_benign"})
NEGATIVE_FACTS = frozenset({"av_detection", "reputation_malicious", "manual_review_malicious",
                            "publisher_checksum_mismatch", "signature_invalid",
                            "reputation_suspicious", "manual_review_suspicious",
                            "type_discrepancy_executable"})
REQUIREMENT_FACTS = frozenset({"av_scan_clean", "inspection_complete"})


class _M(BaseModel):
    model_config = ConfigDict(extra="forbid")


class TrustedPublisher(_M):
    name: str
    page_domains: list[str]
    download_domains: list[str] = Field(default_factory=list)
    signers: list[str] = Field(default_factory=list)
    require_publisher_checksum: bool = True


class ReputationThresholds(_M):
    malicious_min_engines: int = 2
    suspicious_min_engines: int = 1
    clean_min_engines: int = 50


class MaxAge(_M):
    av_scan: float = 7
    av_signature_db: float = 3  # DB date must be within N days before the scan
    reputation: float = 30
    signature: float = 365
    publisher_checksum: float = 365
    provenance: float = 365
    manual_review: float = 365


class StateRule(_M):
    required: list[str] = Field(default_factory=list)
    min_independent_positive: int


class LabelingPolicy(_M):
    policy_version: str
    description: str = ""
    max_evidence_age_days: MaxAge = Field(default_factory=MaxAge)
    positive_evidence: list[str]
    benign_validated: StateRule
    benign_candidate: StateRule
    malicious_evidence_if: list[str]
    suspicious_if: list[str]
    reputation: ReputationThresholds = Field(default_factory=ReputationThresholds)
    trusted_publishers: list[TrustedPublisher] = Field(default_factory=list)

    @model_validator(mode="after")
    def _validate(self) -> LabelingPolicy:
        unknown = set(self.positive_evidence) - POSITIVE_FACTS
        if unknown:
            raise ValueError(f"positive_evidence has non-positive facts: {sorted(unknown)}")
        if self.benign_validated.min_independent_positive < 2:
            raise ValueError("benign_validated.min_independent_positive must be >= 2 so that no "
                             "single signal can validate a sample")
        if "av_scan_clean" not in self.benign_validated.required:
            raise ValueError("benign_validated.required must include av_scan_clean")
        bad_req = set(self.benign_validated.required) - REQUIREMENT_FACTS
        if bad_req:
            raise ValueError(f"unknown requirement facts: {sorted(bad_req)}")
        if self.benign_candidate.min_independent_positive < 1:
            raise ValueError("benign_candidate.min_independent_positive must be >= 1")
        for name, facts in (("malicious_evidence_if", self.malicious_evidence_if),
                            ("suspicious_if", self.suspicious_if)):
            bad = set(facts) - NEGATIVE_FACTS
            if bad:
                raise ValueError(f"{name} has unknown facts: {sorted(bad)}")
        return self

    def fingerprint(self) -> str:
        import hashlib

        return hashlib.sha256(json.dumps(self.model_dump(mode="json"), sort_keys=True)
                              .encode()).hexdigest()[:12]


def load_policy(path: Path) -> LabelingPolicy:
    with path.open("r", encoding="utf-8") as fh:
        return LabelingPolicy.model_validate(yaml.safe_load(fh))


@dataclass
class EvidenceItem:
    evidence_id: str
    kind: str
    source: str
    verdict: str
    observed_at: str
    details: dict[str, Any] = field(default_factory=dict)
    tool_version: str | None = None
    db_version: str | None = None
    db_date: str | None = None

    @classmethod
    def from_row(cls, r: Any) -> EvidenceItem:
        return cls(r["evidence_id"], r["kind"], r["source"], r["verdict"], r["observed_at"],
                   json.loads(r["details_json"] or "{}"), r["tool_version"],
                   r["signature_db_version"], r["signature_db_date"])


@dataclass
class Decision:
    label: Label
    reasons: list[str]
    evidence_ids: list[str]
    facts: dict[str, bool]


def _age_days(ts: str, now: _dt.datetime) -> float:
    return (now - parse_ts(ts)).total_seconds() / 86400


def evaluate(policy: LabelingPolicy, evidence: list[EvidenceItem], *, inspection_status: str | None,
             detected_family: str | None, discrepancies: list[str],
             now: _dt.datetime | None = None) -> Decision:
    now = now or _dt.datetime.now(_dt.UTC)
    age = policy.max_evidence_age_days
    facts: dict[str, bool] = {}
    used: dict[str, list[str]] = {}
    reasons: list[str] = []

    def fresh(e: EvidenceItem, limit: float) -> bool:
        return _age_days(e.observed_at, now) <= limit

    def latest(kind: str, source: str | None = None) -> EvidenceItem | None:
        items = [e for e in evidence if e.kind == kind and (source is None or e.source == source)]
        return max(items, key=lambda e: e.observed_at) if items else None

    def setf(name: str, value: bool, *ids: str) -> None:
        facts[name] = facts.get(name, False) or value
        if value:
            used.setdefault(name, []).extend(ids)

    # Antivirus: latest result per scanner.
    av_sources = {e.source for e in evidence if e.kind == "av_scan"}
    av_clean_any = False
    for src in sorted(av_sources):
        e = latest("av_scan", src)
        assert e is not None
        if e.verdict == "detected":
            setf("av_detection", True, e.evidence_id)
        elif e.verdict == "clean":
            if not fresh(e, age.av_scan):
                reasons.append(f"stale:av_scan:{src}")
            elif not e.db_date:
                reasons.append(f"unknown_signature_db_date:{src}")
            elif (parse_ts(e.observed_at) - parse_ts(e.db_date)).total_seconds() / 86400 > age.av_signature_db:
                reasons.append(f"stale:av_signature_db:{src}")
            else:
                av_clean_any = True
                used.setdefault("av_scan_clean", []).append(e.evidence_id)
        else:
            reasons.append(f"av_scan_{e.verdict}:{src}")
    facts["av_scan_clean"] = av_clean_any and not facts.get("av_detection", False)
    if not av_sources:
        reasons.append("missing:av_scan")

    facts["inspection_complete"] = inspection_status == "complete"
    if not facts["inspection_complete"]:
        reasons.append(f"inspection_{inspection_status or 'missing'}")
    setf("type_discrepancy_executable",
         bool(discrepancies) and (detected_family or "") in EXECUTABLE_FAMILIES)

    for e in evidence:
        if e.kind == "publisher_checksum":
            if e.verdict == "mismatch":
                setf("publisher_checksum_mismatch", True, e.evidence_id)
            elif e.verdict == "match" and fresh(e, age.publisher_checksum):
                setf("publisher_checksum_match", True, e.evidence_id)

    trusted_signers: set[str] = set()
    for e in evidence:
        if e.kind == "provenance" and e.verdict == "trusted_publisher" and fresh(e, age.provenance):
            pub = next((p for p in policy.trusted_publishers if p.name == e.details.get("publisher")), None)
            if pub is None:
                reasons.append("provenance_publisher_not_in_policy")
                continue
            if pub.require_publisher_checksum and not facts.get("publisher_checksum_match"):
                reasons.append(f"provenance_without_checksum:{pub.name}")
                continue
            setf("publisher_provenance", True, e.evidence_id, *used.get("publisher_checksum_match", []))
            trusted_signers.update(pub.signers)
    if not trusted_signers:
        trusted_signers = {s for p in policy.trusted_publishers for s in p.signers}

    sig = latest("signature")
    if sig is not None:
        if sig.verdict == "invalid":
            setf("signature_invalid", True, sig.evidence_id)
        elif sig.verdict == "valid" and fresh(sig, age.signature):
            signer = sig.details.get("signer")
            if signer and signer in trusted_signers:
                setf("trusted_signature", True, sig.evidence_id)
            else:
                reasons.append("signature_valid_signer_not_trusted")

    rep = latest("reputation")
    if rep is not None:
        d = rep.details
        mal, sus, tot = d.get("malicious") or 0, d.get("suspicious") or 0, d.get("engines_total") or 0
        th = policy.reputation
        if mal >= th.malicious_min_engines:
            setf("reputation_malicious", True, rep.evidence_id)
        elif sus + mal >= th.suspicious_min_engines and rep.verdict in ("suspicious", "malicious"):
            setf("reputation_suspicious", True, rep.evidence_id)
        elif rep.verdict == "clean":
            if not fresh(rep, age.reputation):
                reasons.append("stale:reputation")
            elif tot < th.clean_min_engines:
                reasons.append("reputation_insufficient_engines")
            else:
                setf("reputation_clean", True, rep.evidence_id)
        else:
            reasons.append(f"reputation_{rep.verdict}")

    mr = latest("manual_review")
    if mr is not None:
        if mr.verdict in ("malicious", "suspicious"):
            setf(f"manual_review_{mr.verdict}", True, mr.evidence_id)
        elif mr.verdict == "benign":
            if fresh(mr, age.manual_review):
                setf("manual_review_benign", True, mr.evidence_id)
            else:
                reasons.append("stale:manual_review")

    def ids_for(names: list[str]) -> list[str]:
        return sorted({i for n in names for i in used.get(n, [])})

    hit = [f for f in policy.malicious_evidence_if if facts.get(f)]
    if hit:
        return Decision(Label.MALICIOUS_EVIDENCE, [f"fact:{f}" for f in hit] + reasons, ids_for(hit), facts)
    hit = [f for f in policy.suspicious_if if facts.get(f)]
    if hit:
        return Decision(Label.SUSPICIOUS, [f"fact:{f}" for f in hit] + reasons, ids_for(hit), facts)

    positives = [f for f in policy.positive_evidence if facts.get(f)]
    pos_reasons = [f"positive:{f}" for f in positives]
    missing = [r for r in policy.benign_validated.required if not facts.get(r)]
    if not missing and len(positives) >= policy.benign_validated.min_independent_positive:
        return Decision(Label.BENIGN_VALIDATED, pos_reasons + [f"required:{r}" for r in
                                                               policy.benign_validated.required],
                        ids_for(positives + policy.benign_validated.required), facts)
    blockers = [f"missing_required:{m}" for m in missing]
    if len(positives) < policy.benign_validated.min_independent_positive:
        blockers.append(f"insufficient_positive:{len(positives)}<"
                        f"{policy.benign_validated.min_independent_positive}")
    cand_missing = [r for r in policy.benign_candidate.required if not facts.get(r)]
    if not cand_missing and len(positives) >= policy.benign_candidate.min_independent_positive:
        return Decision(Label.BENIGN_CANDIDATE, pos_reasons + blockers + reasons,
                        ids_for(positives), facts)
    return Decision(Label.UNKNOWN, pos_reasons + blockers + reasons, ids_for(positives), facts)
