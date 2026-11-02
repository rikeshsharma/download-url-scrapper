"""Labeling policy semantics. No single signal may produce benign_validated."""

from __future__ import annotations

import datetime as dt
from pathlib import Path

import pytest
import yaml

from download_url_collector.labeling.policy import EvidenceItem, LabelingPolicy, evaluate, load_policy
from download_url_collector.models import Label

POLICY_FILE = Path(__file__).resolve().parents[1] / "config" / "labeling_policy.yaml"
NOW = dt.datetime(2026, 10, 25, tzinfo=dt.UTC)


def ts(days_ago: float) -> str:
    return (NOW - dt.timedelta(days=days_ago)).isoformat().replace("+00:00", "Z")


def policy(**extra: object) -> LabelingPolicy:
    data = yaml.safe_load(POLICY_FILE.read_text())
    data["trusted_publishers"] = [{"name": "Pub", "page_domains": ["pub.example"],
                                   "signers": ["Pub Inc."], "require_publisher_checksum": True}]
    data.update(extra)
    return LabelingPolicy.model_validate(data)


_n = 0


def ev(kind: str, verdict: str, days: float = 0, source: str = "s", db_days: float | None = 0,
       **details: object) -> EvidenceItem:
    global _n
    _n += 1
    return EvidenceItem(f"ev{_n}", kind, source, verdict, ts(days), dict(details),
                        "1.0", "db1", ts(days + db_days) if db_days is not None else None)


AV_CLEAN = ev("av_scan", "clean", source="clamav")
PROV = ev("provenance", "trusted_publisher", publisher="Pub")
CHECKSUM = ev("publisher_checksum", "match")
SIG = ev("signature", "valid", signer="Pub Inc.")
REP = ev("reputation", "clean", malicious=0, suspicious=0, engines_total=70)
MANUAL = ev("manual_review", "benign")


def run(evidence: list[EvidenceItem], inspection: str = "complete", family: str = "pe",
        disc: list[str] | None = None, pol: LabelingPolicy | None = None) -> tuple[Label, list[str]]:
    d = evaluate(pol or policy(), evidence, inspection_status=inspection, detected_family=family,
                 discrepancies=disc or [], now=NOW)
    return d.label, d.reasons


def test_default_policy_file_loads() -> None:
    assert load_policy(POLICY_FILE).policy_version


def test_no_evidence_is_unknown() -> None:
    assert run([])[0] == Label.UNKNOWN


@pytest.mark.parametrize("single", [AV_CLEAN, PROV, SIG, REP, MANUAL, CHECKSUM,
                                    ev("reputation", "not_found")])
def test_no_single_signal_validates(single: EvidenceItem) -> None:
    label, _ = run([single])
    assert label != Label.BENIGN_VALIDATED


def test_av_clean_plus_one_positive_is_only_candidate() -> None:
    label, reasons = run([AV_CLEAN, SIG])
    assert label == Label.BENIGN_CANDIDATE
    assert "insufficient_positive:1<2" in reasons


def test_two_independent_positives_plus_requirements_validate() -> None:
    label, reasons = run([AV_CLEAN, SIG, REP])
    assert label == Label.BENIGN_VALIDATED
    assert "positive:trusted_signature" in reasons and "positive:reputation_clean" in reasons


def test_provenance_requires_checksum_when_configured() -> None:
    assert run([AV_CLEAN, PROV, REP])[0] == Label.BENIGN_CANDIDATE
    assert run([AV_CLEAN, PROV, CHECKSUM, REP])[0] == Label.BENIGN_VALIDATED


def test_checksum_alone_is_integrity_not_benignness() -> None:
    assert run([AV_CLEAN, CHECKSUM, REP])[0] == Label.BENIGN_CANDIDATE


def test_missing_scanner_blocks_promotion() -> None:
    unavailable = ev("av_scan", "unavailable", source="mock")
    label, reasons = run([unavailable, SIG, REP, MANUAL])
    assert label == Label.BENIGN_CANDIDATE
    assert "missing_required:av_scan_clean" in reasons


@pytest.mark.parametrize("stale", [
    ev("av_scan", "clean", days=30, source="clamav"),               # old scan
    ev("av_scan", "clean", days=0, db_days=10, source="clamav"),    # old signature DB
    ev("av_scan", "clean", days=0, db_days=None, source="clamav"),  # unknown DB date
])
def test_stale_av_blocks_promotion(stale: EvidenceItem) -> None:
    assert run([stale, SIG, REP])[0] == Label.BENIGN_CANDIDATE


def test_stale_reputation_not_counted() -> None:
    old = ev("reputation", "clean", days=90, malicious=0, suspicious=0, engines_total=70)
    assert run([AV_CLEAN, SIG, old])[0] == Label.BENIGN_CANDIDATE


def test_incomplete_inspection_blocks_promotion() -> None:
    label, reasons = run([AV_CLEAN, SIG, REP], inspection="unresolved")
    assert label == Label.BENIGN_CANDIDATE and "missing_required:inspection_complete" in reasons


def test_untrusted_signer_does_not_count() -> None:
    assert run([AV_CLEAN, ev("signature", "valid", signer="Someone Else"), REP])[0] == Label.BENIGN_CANDIDATE


def test_negative_evidence_wins() -> None:
    assert run([AV_CLEAN, SIG, REP, ev("av_scan", "detected", source="other")])[0] == Label.MALICIOUS_EVIDENCE
    assert run([AV_CLEAN, SIG, REP, ev("reputation", "malicious", days=-1, malicious=5,
                                       suspicious=0, engines_total=70)])[0] == Label.MALICIOUS_EVIDENCE
    assert run([AV_CLEAN, SIG, REP, ev("publisher_checksum", "mismatch")])[0] == Label.SUSPICIOUS
    assert run([AV_CLEAN, SIG, REP], disc=["declared_mime:image/png!=detected:pe"])[0] == Label.SUSPICIOUS


def test_policy_rejects_single_signal_validation() -> None:
    data = yaml.safe_load(POLICY_FILE.read_text())
    data["benign_validated"]["min_independent_positive"] = 1
    with pytest.raises(ValueError):
        LabelingPolicy.model_validate(data)
    data = yaml.safe_load(POLICY_FILE.read_text())
    data["positive_evidence"].append("av_scan_clean")
    with pytest.raises(ValueError):
        LabelingPolicy.model_validate(data)
    data = yaml.safe_load(POLICY_FILE.read_text())
    data["benign_validated"]["required"] = ["inspection_complete"]
    with pytest.raises(ValueError):
        LabelingPolicy.model_validate(data)
