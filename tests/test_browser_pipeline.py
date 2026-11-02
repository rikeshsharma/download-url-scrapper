"""End-to-end: crawl → Chromium verification → labeling → export, on the local fixture.

Skipped automatically when Playwright's Chromium is not installed.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
from pathlib import Path
from typing import Any

import pytest
from conftest import make_config, requires_browser
from fixtures.server import SAMPLE_ZIP, FixtureSite

from download_url_collector import pipeline
from download_url_collector.browser.verifier import BrowserVerifier
from download_url_collector.config import Config
from download_url_collector.csvio import read_csv_nullable
from download_url_collector.export import Exporter
from download_url_collector.inspection.inspector import FileStore
from download_url_collector.labeling.labeler import add_manual_review
from download_url_collector.netpolicy import NetworkPolicy
from download_url_collector.report import write_report
from download_url_collector.storage import Store, loads

pytestmark = [requires_browser, pytest.mark.browser]


class Run:
    def __init__(self, cfg: Config, store: Store, rid: str, out: Path, site: FixtureSite) -> None:
        self.cfg, self.store, self.rid, self.out, self.site = cfg, store, rid, out, site

    def obs(self, path: str, mode: str | None = None) -> list[Any]:
        url = self.site.base + path
        return [o for o in self.store.observations(self.rid)
                if (o["initiating_url"] == url or o["source_page"] == url and o["verification_mode"] == "page_interaction")
                and (mode is None or o["verification_mode"] == mode)]

    def direct(self, path: str, base: str | None = None) -> Any:
        url = (base or self.site.base) + path
        rows = [o for o in self.store.observations(self.rid)
                if o["initiating_url"] == url and o["verification_mode"] == "direct_navigation"]
        assert rows, f"no direct observation for {path}"
        return rows[-1]

    def interaction(self, page: str) -> Any:
        rows = [o for o in self.store.observations(self.rid)
                if o["verification_mode"] == "page_interaction" and o["source_page"] == self.site.base + page]
        assert rows, f"no interaction observation for {page}"
        return rows[-1]

    def csv(self, name: str) -> list[dict[str, str | None]]:
        return read_csv_nullable(self.out / name)


@pytest.fixture(scope="module")
def run(site: FixtureSite, tmp_path_factory: pytest.TempPathFactory) -> Run:
    tmp = tmp_path_factory.mktemp("e2e")
    cfg = make_config(tmp)
    seeds = tmp / "seeds.csv"
    seeds.write_text(f"url\n{site.base}/\n")
    store = pipeline.open_store(cfg)
    rid = pipeline.start_run(cfg, store, seeds)
    asyncio.run(pipeline.crawl(cfg, store, rid))
    asyncio.run(pipeline.verify(cfg, store, rid))
    asyncio.run(pipeline.label(cfg, store, rid))  # mock scanner reports "unavailable"
    out = tmp / "out"
    Exporter(cfg, store, rid, out).run()
    write_report(cfg, store, rid, out)
    return Run(cfg, store, rid, out, site)


# -- direct downloads -----------------------------------------------------------

@pytest.mark.parametrize("path", [
    "/files/sample.zip", "/download?id=1", "/download?id=2", "/download?lang=en&id=1", "/go/latest",
    "/nohead/file.bin", "/misleading/data.bin", "/dup/copy-of-sample.zip", "/dir/listed-a.zip",
    "/files/meta-target.bin", "/files/from-sitemap.zip",
])
def test_direct_downloads(run: Run, path: str) -> None:
    o = run.direct(path)
    assert o["classification"] == "direct_download", o["failure_reason"]
    assert o["download_state"] == "completed" and o["sha256"] and o["size"]
    assert o["replay_status"] == "url_replayable"


def test_download_navigation_abort_handled(run: Run) -> None:
    extra = loads(run.direct("/files/sample.zip")["extra_json"])
    assert extra["navigation_aborted_for_download"] is True
    assert extra["download_trigger"] == "navigation_response"


def test_redirect_preserves_initiating_and_final_url(run: Run) -> None:
    o = run.direct("/go/latest")
    assert o["initiating_url"] == run.site.base + "/go/latest"
    assert o["final_url"] == run.site.base + "/files/release-1.0.bin"
    assert [h["status"] for h in loads(o["redirect_chain_json"])] == [302, 200]


def test_external_target_verified(run: Run) -> None:
    o = run.direct("/ext/tool.zip", base=run.site.external_base)
    assert o["classification"] == "direct_download"


def test_query_dependent_payloads_differ_and_duplicates_tracked(run: Run) -> None:
    a, b, a2 = run.direct("/download?id=1"), run.direct("/download?id=2"), run.direct("/download?lang=en&id=1")
    assert a["sha256"] != b["sha256"] and a["sha256"] == a2["sha256"]
    sample = hashlib.sha256(SAMPLE_ZIP).hexdigest()
    assert run.direct("/files/sample.zip")["sha256"] == sample
    assert run.direct("/dup/copy-of-sample.zip")["sha256"] == sample
    meta = {r["initiating_url"]: r for r in run.csv("dataset_metadata.csv")}
    splits = {meta[run.site.base + p]["payload_split"] for p in ("/files/sample.zip", "/dup/copy-of-sample.zip",
                                                                "/misleading/data.bin")}
    assert len(splits) == 1  # identical payloads never straddle train/test


def test_misleading_mime_recorded_separately(run: Run) -> None:
    o = run.direct("/misleading/data.bin")
    extra = loads(o["extra_json"])
    assert extra["declared_mime"].startswith("text/plain")
    assert extra["detected_family"] == "zip"
    assert extra["suggested_filename_extension"] == "txt" and extra["url_extension"] == "bin"
    assert any("declared_mime:text/plain" in d for d in loads(o["discrepancies_json"]))


def test_files_stored_under_generated_names(run: Run) -> None:
    o = run.direct("/files/sample.zip")
    f = run.store.get_file(o["sha256"])
    path = run.cfg.collection.data_dir / "files" / f["storage_path"]
    assert path.name == f"{o['sha256']}.bin" and "sample" not in str(path)
    assert hashlib.sha256(path.read_bytes()).hexdigest() == o["sha256"]


# -- non-direct outcomes -------------------------------------------------------------

def test_inline_resources_not_forced_to_download(run: Run) -> None:
    for path in ("/docs/manual.pdf", "/docs/readme.txt"):
        o = run.direct(path)
        assert o["classification"] == "inline_resource" and o["sha256"] is None


def test_download_attribute_click_is_interaction_only(run: Run) -> None:
    rows = [o for o in run.obs("/", "page_interaction") if "manual.pdf" in (o["final_url"] or "")]
    assert rows and rows[-1]["classification"] == "interaction_download"
    replay = loads(rows[-1]["replay_json"])
    assert replay["target_direct_replay_verified"] is False and replay["requires"] == ["interaction"]


def test_js_and_popup_downloads(run: Run) -> None:
    js = run.interaction("/js-download.html")
    assert js["classification"] == "interaction_download"
    assert loads(js["replay_json"])["target_direct_replay_verified"] is True
    assert run.direct("/files/js-target.bin")["classification"] == "direct_download"
    pop = run.interaction("/popup.html")
    assert pop["classification"] == "interaction_download"
    assert loads(pop["replay_json"])["request_context"]["popup"] is True


def test_blob_download_is_generated_and_not_url_output(run: Run) -> None:
    o = run.interaction("/blob.html")
    assert o["classification"] == "generated_download" and o["final_url"].startswith("blob:")
    urls = {r["url"] for r in run.csv("verified_direct_download_urls.csv")}
    assert not any(u.startswith(("blob:", "data:")) for u in urls)


def test_session_dependent_post_and_cookie(run: Run) -> None:
    form = run.interaction("/form.html")
    assert form["classification"] == "session_dependent"
    assert set(loads(form["replay_json"])["requires"]) >= {"method:POST", "post_data"}
    ck = run.interaction("/cookie.html")
    assert ck["classification"] == "session_dependent"
    assert "cookies" in loads(ck["replay_json"])["requires"]
    assert run.direct("/needs-cookie.bin")["failure_reason"] == "http_status:403"


def test_failures_recorded_accurately(run: Run) -> None:
    expired = run.direct("/expired?token=abcdefabcdefabcdefabcdefabcdefabcdef&expires=1")
    assert expired["failure_reason"] == "http_status:410"
    interrupted = run.direct("/interrupted.bin")
    assert interrupted["classification"] == "failed_or_unverified"
    assert interrupted["download_state"] == "failed" and interrupted["failure_reason"].startswith("download_failed")
    big = run.direct("/big.bin")
    assert big["failure_reason"] == "byte_limit_exceeded" and big["sha256"] is None


def test_robots_and_private_redirect_never_reach_browser(run: Run) -> None:
    assert not run.obs("/private/secret.zip") and not run.obs("/redirect-private")


def test_browser_blocks_private_redirect_and_records_identity(run: Run) -> None:
    async def go() -> Any:
        files = FileStore(run.cfg.collection.data_dir / "files", True, 10**9)
        async with BrowserVerifier(run.cfg, NetworkPolicy(run.cfg.network), files) as v:
            assert v.identity is not None and v.identity.browser_version
            return await v.verify_direct(run.site.base + "/redirect-private", candidate_id=None, source_page=None)

    obs = asyncio.run(go())
    assert obs.classification == "failed_or_unverified"
    assert obs.failure_reason == "blocked_destination:blocked_metadata_or_link_local"
    ids = {o["browser_config_id"] for o in run.store.observations(run.rid)}
    assert len(ids) == 1
    ident = loads(run.store.one("SELECT identity_json FROM browser_configs WHERE browser_config_id=?",
                                [ids.pop()])["identity_json"])
    assert ident["settings"]["headless_mode"] == "new_headless" and ident["os"]


# -- exports and labeling independence -------------------------------------------------

def test_exports_present_and_consistent(run: Run) -> None:
    for name in ("download_candidates.csv", "verified_direct_download_urls.csv", "benign_download_urls.csv",
                 "download_observations.csv", "replay_manifest.jsonl", "crawl_errors.csv",
                 "coverage_report.json", "coverage_summary.md", "dataset_metadata.csv",
                 "detector_features.csv", "labels.csv", "run_manifest.json"):
        assert (run.out / name).exists(), name
    verified = [r["url"] for r in run.csv("verified_direct_download_urls.csv")]
    assert len(verified) == len(set(verified)) >= 11
    assert run.site.base + "/download?lang=en&id=1" in verified
    obs = run.csv("download_observations.csv")
    row = next(r for r in obs if r["initiating_url"] == run.site.base + "/files/sample.zip"
               and r["verification_mode"] == "direct_navigation")
    assert row["label"] == "unknown" and row["policy_version"]
    inline = next(r for r in obs if r["initiating_url"] == run.site.base + "/docs/readme.txt")
    assert inline["sha256"] is None and inline["label"] is None  # unknown/not applicable, not ""
    manifest = [json.loads(line) for line in (run.out / "replay_manifest.jsonl").read_text().splitlines()]
    assert {m["classification"] for m in manifest} >= {"interaction_download", "session_dependent",
                                                       "generated_download"}
    report = json.loads((run.out / "coverage_report.json").read_text())
    assert report["verified_direct_download_urls"] == len(verified)
    shareable = (run.out / "coverage_report.json").read_text() + (run.out / "coverage_summary.md").read_text()
    assert "abcdefabcdef" not in shareable  # token value never in shareable reports
    assert "token=REDACTED" in shareable
    # ...but the controlled observation output keeps the exact replay URL, flagged.
    exp = next(r for r in obs if (r["initiating_url"] or "").endswith("expires=1"))
    assert "token=abcdefabcdefabcdefabcdefabcdefabcdef" in exp["initiating_url"]
    assert exp["url_has_token"] == "true"
    features = run.csv("detector_features.csv")
    assert "sha256" not in features[0] and "label" not in features[0]


def test_verified_but_unscanned_is_not_benign(run: Run) -> None:
    """Direct-download verification and benign validation are independent."""
    assert run.csv("benign_download_urls.csv") == []
    labels = {r["label"] for r in run.csv("labels.csv")}
    assert labels == {"unknown"}
    reasons = json.loads(run.csv("labels.csv")[0]["reasons"] or "[]")
    assert any("av_scan_unavailable" in r or "missing_required:av_scan_clean" in r for r in reasons)
    # The publisher checksum sidecar matched: integrity evidence is recorded, yet no promotion.
    sha = run.direct("/files/sample.zip")["sha256"]
    ev = [(e["kind"], e["verdict"]) for e in run.store.evidence_for(sha)]
    assert ("publisher_checksum", "match") in ev and ("av_scan", "unavailable") in ev
    assert run.store.current_label(sha)["label"] == "unknown"


def test_promotion_requires_independent_evidence(run: Run, tmp_path: Path) -> None:
    sha = run.direct("/download?id=1")["sha256"]
    # Fresh clean scan + manual review = one positive -> still not benign_validated.
    cfg = make_config(Path(str(run.cfg.collection.data_dir.parent)),
                      labeling={"scanner": {"type": "mock", "mock_default_verdict": "clean"}})
    add_manual_review(run.store, sha, "benign", "analyst-1", "fixture review")
    asyncio.run(pipeline.label(cfg, run.store, run.rid, force=True))
    assert run.store.current_label(sha)["label"] == "benign_candidate"
    # A second, independent positive (fresh clean reputation report) validates it.
    run.store.add_evidence(sha, "reputation", "virustotal", "clean",
                           {"malicious": 0, "suspicious": 0, "engines_total": 70})
    asyncio.run(pipeline.label(cfg, run.store, run.rid))
    assert run.store.current_label(sha)["label"] == "benign_validated"
    out = tmp_path / "out2"
    Exporter(cfg, run.store, run.rid, out).run()
    benign = [r["url"] for r in read_csv_nullable(out / "benign_download_urls.csv")]
    verified = [r["url"] for r in read_csv_nullable(out / "verified_direct_download_urls.csv")]
    # Identical payload at two URLs: both validated, and benign is a subset of verified.
    assert set(benign) == {run.site.base + "/download?id=1", run.site.base + "/download?lang=en&id=1"}
    assert set(benign) <= set(verified)
    history = [r["label"] for r in run.store.query("SELECT label FROM labels WHERE sha256=? ORDER BY rowid", [sha])]
    assert history[0] == "unknown" and history[-1] == "benign_validated"  # history kept


def test_revalidation_creates_new_observation_on_content_change(site: FixtureSite, tmp_path: Path) -> None:
    cfg = make_config(tmp_path, browser={"render_seed_pages": False})
    seeds = tmp_path / "seeds.csv"
    seeds.write_text(f"url\n{site.base}/mutable.bin\n")
    store = pipeline.open_store(cfg)
    rid = pipeline.start_run(cfg, store, seeds)
    asyncio.run(pipeline.crawl(cfg, store, rid))
    asyncio.run(pipeline.verify(cfg, store, rid))
    asyncio.run(pipeline.label(cfg, store, rid))
    first = store.latest_direct_observation(site.base + "/mutable.bin")
    assert first["classification"] == "direct_download"
    stats = asyncio.run(pipeline.revalidate(cfg, store, rid))
    assert stats.get("content_changed") == 1
    second = store.latest_direct_observation(site.base + "/mutable.bin")
    assert second["observation_id"] != first["observation_id"]
    assert second["previous_observation_id"] == first["observation_id"] and second["content_changed"] == 1
    assert store.current_label(first["sha256"]) is not None  # historical verdict stays with old hash
    assert store.current_label(second["sha256"]) is None  # new content is unlabeled until `label` runs
