"""Export stage: CSV/JSONL outputs from the SQLite state.

Controlled outputs (exact replay URLs, may contain tokens — handle as sensitive):
  download_candidates.csv, verified_direct_download_urls.csv, benign_download_urls.csv,
  download_observations.csv, replay_manifest.jsonl, crawl_errors.csv,
  dataset_metadata.csv, detector_features.csv, labels.csv
Shareable outputs (credentials/tokens redacted): coverage_report.json, coverage_summary.md
"""

from __future__ import annotations

import json
import logging
import sqlite3
from pathlib import Path
from typing import Any

from .config import Config
from .crawler import sensitivity
from .csvio import write_csv
from .dataset import assign_splits
from .labeling.policy import LabelingPolicy, load_policy
from .models import Classification, Label
from .storage import Store, loads
from .urls import hostname, registrable_domain, sensitive_findings

log = logging.getLogger(__name__)

HOSTING_PROVIDERS = [
    ("githubusercontent.com", "github"), ("github.com", "github"),
    ("amazonaws.com", "aws"), ("cloudfront.net", "aws_cloudfront"),
    ("storage.googleapis.com", "google_cloud_storage"), ("googleusercontent.com", "google"),
    ("blob.core.windows.net", "azure_blob"), ("azureedge.net", "azure_cdn"),
    ("akamaized.net", "akamai"), ("akamaihd.net", "akamai"), ("fastly.net", "fastly"),
    ("r2.dev", "cloudflare_r2"), ("sourceforge.net", "sourceforge"), ("dropboxusercontent.com", "dropbox"),
    ("gitlab.com", "gitlab"), ("bitbucket.org", "bitbucket"), ("b-cdn.net", "bunny_cdn"),
]


def hosting_provider(host: str | None) -> str | None:
    if not host:
        return None
    for suffix, name in HOSTING_PROVIDERS:
        if host == suffix or host.endswith("." + suffix):
            return name
    return None


OBSERVATION_COLUMNS = [
    "observation_id", "run_id", "candidate_id", "seed_id", "seed_url", "source_page",
    "initiating_url", "final_url", "redirect_chain", "redirect_count",
    "source_registrable_domain", "initiating_registrable_domain", "destination_registrable_domain",
    "hosting_provider", "publisher", "discovery_method", "verification_mode", "classification",
    "started_at", "completed_at", "browser_config_id", "http_status", "declared_mime",
    "content_disposition", "content_disposition_filename", "suggested_filename", "url_extension",
    "final_url_extension", "suggested_filename_extension", "detected_family", "detected_mime",
    "type_discrepancies", "size", "sha256", "download_state", "download_trigger",
    "navigation_aborted_for_download", "inspection_status", "inspection_unresolved", "file_stored",
    "label", "policy_version", "label_reasons", "evidence_ids", "replay_status", "failure_reason",
    "capped_reason", "content_changed", "previous_observation_id", "url_has_token",
    "url_sensitive_reasons", "feature_ref",
]


class Exporter:
    def __init__(self, cfg: Config, store: Store, run_id: str, out_dir: Path | None = None) -> None:
        self.cfg = cfg
        self.store = store
        self.run_id = run_id
        self.out = out_dir or Path(".")
        self.sens = sensitivity(cfg)
        self.policy: LabelingPolicy | None
        try:
            self.policy = load_policy(cfg.labeling.policy_file)
        except (OSError, ValueError) as exc:
            log.warning("policy_unavailable", extra={"error": str(exc)})
            self.policy = None
        self._seed_urls = {s["seed_id"]: s["url"] for s in store.seeds(run_id)}
        self._cands = {c["candidate_id"]: c for c in store.candidates(run_id)}

    def _label(self, sha256: str | None) -> sqlite3.Row | None:
        if not sha256 or self.policy is None:
            return None
        return self.store.current_label(sha256, self.policy.policy_version)

    def latest_direct_by_url(self) -> dict[str, sqlite3.Row]:
        latest: dict[str, sqlite3.Row] = {}
        for o in self.store.observations(self.run_id):
            if o["verification_mode"] not in ("direct_navigation", "revalidation"):
                continue
            prev = latest.get(o["initiating_url"])
            if prev is None or (o["completed_at"] or "") >= (prev["completed_at"] or ""):
                latest[o["initiating_url"]] = o
        return latest

    def run(self) -> dict[str, int]:
        self.out.mkdir(parents=True, exist_ok=True)
        counts: dict[str, int] = {}
        counts["download_candidates.csv"] = self.candidates_csv()
        counts["download_observations.csv"] = self.observations_csv()
        verified, benign = self.url_lists()
        counts["verified_direct_download_urls.csv"] = verified
        counts["benign_download_urls.csv"] = benign
        counts["replay_manifest.jsonl"] = self.replay_manifest()
        counts["crawl_errors.csv"] = self.errors_csv()
        counts["labels.csv"] = self.labels_csv()
        counts["dataset_metadata.csv"] = self.dataset_csv()
        counts["detector_features.csv"] = self.features_csv()
        self.run_manifest()
        return counts

    # ------------------------------------------------------------------
    def candidates_csv(self) -> int:
        latest_cls: dict[str, str] = {}
        for o in self.store.observations(self.run_id):
            if o["candidate_id"]:
                latest_cls[o["candidate_id"]] = o["classification"]
        header = ["candidate_id", "run_id", "seed_id", "seed_url", "source_page", "url", "raw_href",
                  "dedup_key", "discovery_method", "depth", "is_external", "link_text", "download_attr",
                  "hints", "publisher", "status", "status_reason", "probe_http_status",
                  "probe_declared_mime", "probe_content_disposition", "probe_filename",
                  "probe_sniffed_family", "probe_range_honored", "head_status",
                  "verification_classification", "url_has_token", "url_sensitive_reasons", "created_at"]
        rows = []
        for c in self._cands.values():
            p = loads(c["probe_json"]) or {}
            sens = loads(c["url_sensitive_json"]) or []
            rows.append([
                c["candidate_id"], c["run_id"], c["seed_id"], self._seed_urls.get(c["seed_id"]),
                c["source_page"], c["url"], c["raw_href"], c["dedup_key"], c["discovery_method"],
                c["depth"], bool(c["is_external"]), c["link_text"], c["download_attr"],
                loads(c["hints_json"]), c["publisher"], c["status"], c["status_reason"],
                p.get("status"), p.get("declared_mime"), p.get("content_disposition"), p.get("filename"),
                p.get("sniffed_family"), p.get("range_honored"), p.get("head_status"),
                latest_cls.get(c["candidate_id"]), bool(sens), sens, c["created_at"]])
        return write_csv(self.out / "download_candidates.csv", header, rows)

    def _obs_row(self, o: sqlite3.Row) -> list[Any]:
        extra = loads(o["extra_json"]) or {}
        chain = loads(o["redirect_chain_json"])
        http = loads(o["http_json"]) or {}
        cand = self._cands.get(o["candidate_id"]) if o["candidate_id"] else None
        lbl = self._label(o["sha256"])
        final_http = o["final_url"] if o["final_url"] and o["final_url"].startswith("http") else None
        sens = sensitive_findings(o["initiating_url"], self.sens) + (
            [f"final:{r}" for r in sensitive_findings(final_http, self.sens)] if final_http else [])
        src = o["source_page"]
        if o["sha256"] is None:
            label_value = None  # not applicable: no file
        else:
            label_value = lbl["label"] if lbl else Label.UNKNOWN.value
        return [
            o["observation_id"], o["run_id"], o["candidate_id"], o["seed_id"],
            self._seed_urls.get(o["seed_id"]), src, o["initiating_url"], o["final_url"], chain,
            len(chain) - 1 if chain else None,
            registrable_domain(hostname(src)) if src else None,
            registrable_domain(hostname(o["initiating_url"])),
            registrable_domain(hostname(final_http)) if final_http else None,
            hosting_provider(hostname(final_http) if final_http else hostname(o["initiating_url"])),
            cand["publisher"] if cand else None,
            cand["discovery_method"] if cand else ("page_interaction" if o["verification_mode"] == "page_interaction" else None),
            o["verification_mode"], o["classification"], o["started_at"], o["completed_at"],
            o["browser_config_id"], http.get("status"), extra.get("declared_mime"),
            extra.get("content_disposition"), extra.get("content_disposition_filename"),
            o["suggested_filename"], extra.get("url_extension"), extra.get("final_url_extension"),
            extra.get("suggested_filename_extension"), extra.get("detected_family"),
            extra.get("detected_mime"), loads(o["discrepancies_json"]), o["size"], o["sha256"],
            o["download_state"], extra.get("download_trigger"),
            extra.get("navigation_aborted_for_download"), extra.get("inspection_status"),
            extra.get("inspection_unresolved"), extra.get("stored"),
            label_value, lbl["policy_version"] if lbl else (self.policy.policy_version if self.policy and o["sha256"] else None),
            loads(lbl["reasons_json"]) if lbl else None, loads(lbl["evidence_ids_json"]) if lbl else None,
            o["replay_status"], o["failure_reason"], o["capped_reason"],
            None if o["content_changed"] is None else bool(o["content_changed"]),
            o["previous_observation_id"], bool(sens), sens, o["feature_ref"],
        ]

    def observations_csv(self) -> int:
        return write_csv(self.out / "download_observations.csv", OBSERVATION_COLUMNS,
                         (self._obs_row(o) for o in self.store.observations(self.run_id)))

    def url_lists(self) -> tuple[int, int]:
        verified: list[str] = []
        benign: list[str] = []
        for url, o in self.latest_direct_by_url().items():
            if o["classification"] != Classification.DIRECT_DOWNLOAD:
                continue
            verified.append(url)
            lbl = self._label(o["sha256"])
            if lbl is not None and lbl["label"] == Label.BENIGN_VALIDATED:
                benign.append(url)
        n1 = write_csv(self.out / "verified_direct_download_urls.csv", ["url"],
                       ([u] for u in sorted(set(verified))))
        n2 = write_csv(self.out / "benign_download_urls.csv", ["url"], ([u] for u in sorted(set(benign))))
        return n1, n2

    def replay_manifest(self) -> int:
        n = 0
        with (self.out / "replay_manifest.jsonl").open("w", encoding="utf-8") as fh:
            for o in self.store.observations(self.run_id):
                if o["classification"] not in (Classification.INTERACTION_DOWNLOAD,
                                               Classification.SESSION_DEPENDENT,
                                               Classification.GENERATED_DOWNLOAD):
                    continue
                replay = loads(o["replay_json"]) or {}
                rec = {
                    "observation_id": o["observation_id"], "classification": o["classification"],
                    "source_page": o["source_page"], "steps": replay.get("steps", []),
                    "control": replay.get("control"),
                    "download_url": o["final_url"],
                    "download_url_is_context_bound": bool(o["final_url"] and not o["final_url"].startswith("http")),
                    "requires": replay.get("requires", []),
                    "request_context": replay.get("request_context"),
                    "target_direct_replay_verified": replay.get("target_direct_replay_verified"),
                    "sha256": o["sha256"], "browser_config_id": o["browser_config_id"],
                    "observed_at": o["completed_at"], "replay_status": o["replay_status"],
                }
                fh.write(json.dumps(rec, sort_keys=True) + "\n")
                n += 1
        return n

    def errors_csv(self) -> int:
        header = ["error_id", "run_id", "stage", "seed_id", "url", "reason", "details", "created_at"]
        rows = ([e["error_id"], e["run_id"], e["stage"], e["seed_id"], e["url"], e["reason"],
                 e["details"], e["created_at"]] for e in self.store.errors(self.run_id))
        return write_csv(self.out / "crawl_errors.csv", header, rows)

    def labels_csv(self) -> int:
        """Label history and evidence references — kept apart from model features."""
        header = ["sha256", "label", "policy_version", "decided_at", "reasons", "evidence_ids"]
        shas = [r["sha256"] for r in self.store.query(
            "SELECT DISTINCT sha256 FROM observations WHERE run_id=? AND sha256 IS NOT NULL", [self.run_id])]
        rows = []
        for sha in sorted(shas):
            for lbl in self.store.query("SELECT * FROM labels WHERE sha256=? ORDER BY decided_at, rowid", [sha]):
                rows.append([sha, lbl["label"], lbl["policy_version"], lbl["decided_at"],
                             loads(lbl["reasons_json"]), loads(lbl["evidence_ids_json"])])
        return write_csv(self.out / "labels.csv", header, rows)

    def _group_domain(self, o: sqlite3.Row) -> str:
        cand = self._cands.get(o["candidate_id"]) if o["candidate_id"] else None
        if cand is not None and cand["publisher"]:
            return f"publisher:{cand['publisher']}"
        seed_url = self._seed_urls.get(o["seed_id"])
        if seed_url:
            return registrable_domain(hostname(seed_url))
        return registrable_domain(hostname(o["source_page"] or o["initiating_url"]))

    def dataset_csv(self) -> int:
        samples = []
        rows_by_obs: dict[str, sqlite3.Row] = {}
        for o in self.store.observations(self.run_id):
            if o["classification"] != Classification.DIRECT_DOWNLOAD or not o["sha256"]:
                continue
            f = self.store.get_file(o["sha256"])
            samples.append({"observation_id": o["observation_id"], "sha256": o["sha256"],
                            "group_domain": self._group_domain(o),
                            "first_seen": f["first_seen"] if f else o["completed_at"]})
            rows_by_obs[o["observation_id"]] = o
        ds = self.cfg.dataset
        metas = assign_splits(samples, test_fraction=ds.test_fraction, unseen_fraction=ds.unseen_domain_fraction,
                              salt=ds.split_salt, temporal_cutoff=ds.temporal_cutoff)
        header = ["observation_id", "sha256", "initiating_url", "group_domain", "payload_component",
                  "first_seen_payload", "observed_at", "payload_split", "unseen_domain_split",
                  "temporal_split", "in_sample", "capped_reason"]
        rows = []
        for m in metas:
            o = rows_by_obs[m.observation_id]
            rows.append([m.observation_id, m.sha256, o["initiating_url"], m.group_domain, m.component_id,
                         m.first_seen, o["completed_at"], m.payload_split, m.unseen_domain_split,
                         m.temporal_split, o["capped_reason"] is None, o["capped_reason"]])
        return write_csv(self.out / "dataset_metadata.csv", header, rows)

    def features_csv(self) -> int:
        """Features available at the detector's decision point (download start).
        Excludes hashes, file content, labels and collection artefacts."""
        header = ["observation_id", "initiating_url", "final_url", "referrer_page", "redirect_count",
                  "initiating_registrable_domain", "final_registrable_domain", "referrer_registrable_domain",
                  "cross_domain_redirect", "http_status", "declared_mime", "content_disposition",
                  "suggested_filename", "url_extension", "suggested_filename_extension",
                  "declared_content_length", "download_trigger", "url_has_token"]
        rows = []
        for o in self.store.observations(self.run_id):
            if o["classification"] not in (Classification.DIRECT_DOWNLOAD, Classification.INTERACTION_DOWNLOAD,
                                           Classification.SESSION_DEPENDENT):
                continue
            extra = loads(o["extra_json"]) or {}
            http = loads(o["http_json"]) or {}
            headers = http.get("headers") or {}
            chain = loads(o["redirect_chain_json"]) or []
            final_http = o["final_url"] if o["final_url"] and o["final_url"].startswith("http") else None
            i_dom = registrable_domain(hostname(o["initiating_url"]))
            f_dom = registrable_domain(hostname(final_http)) if final_http else None
            cl = headers.get("content-length")
            rows.append([o["observation_id"], o["initiating_url"], o["final_url"], o["source_page"],
                         max(0, len(chain) - 1) if chain else None, i_dom, f_dom,
                         registrable_domain(hostname(o["source_page"])) if o["source_page"] else None,
                         (f_dom != i_dom) if f_dom else None, http.get("status"), extra.get("declared_mime"),
                         extra.get("content_disposition"), o["suggested_filename"], extra.get("url_extension"),
                         extra.get("suggested_filename_extension"),
                         int(cl) if cl and cl.isdigit() else None, extra.get("download_trigger"),
                         bool(extra.get("initiating_url_sensitive"))])
        return write_csv(self.out / "detector_features.csv", header, rows)

    def run_manifest(self) -> None:
        run = self.store.get_run(self.run_id)
        assert run is not None
        cfg_ids = {o["browser_config_id"] for o in self.store.observations(self.run_id) if o["browser_config_id"]}
        browsers = [loads(r["identity_json"]) for r in self.store.query(
            "SELECT * FROM browser_configs") if r["browser_config_id"] in cfg_ids]
        manifest = {
            "run_id": self.run_id, "created_at": run["created_at"], "status": run["status"],
            "config_fingerprint": run["config_fingerprint"], "config": loads(run["config_json"]),
            "seeds_file": run["seeds_file"], "counters": loads(run["counters_json"]),
            "budget_exhausted": loads(run["budget_exhausted_json"]),
            "labeling_policy_version": self.policy.policy_version if self.policy else None,
            "labeling_policy_fingerprint": self.policy.fingerprint() if self.policy else None,
            "browser_configs": browsers,
            "notice": ("Discovery and download verification do not establish that a file is benign. "
                       "Only benign_download_urls.csv reflects the labeling policy. Coverage is not "
                       "exhaustive."),
        }
        (self.out / "run_manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True, default=str))
