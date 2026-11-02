"""Discovery + HTTP probing against the local fixture site (no browser)."""

from __future__ import annotations

import asyncio
import time
from pathlib import Path
from typing import Any

import pytest
from conftest import make_config
from fixtures.server import FixtureSite

from download_url_collector import pipeline
from download_url_collector.budget import Budget
from download_url_collector.http_client import PolicyHttpClient
from download_url_collector.netpolicy import NetworkPolicy
from download_url_collector.ratelimit import parse_retry_after
from download_url_collector.storage import Store, loads


def _crawl(site: FixtureSite, tmp: Path, seed_path: str = "/", **overrides: Any) -> tuple[Store, str]:
    cfg = make_config(tmp, **overrides)
    seeds = tmp / "seeds.csv"
    seeds.write_text(f"url\n{site.base}{seed_path}\n")
    store = pipeline.open_store(cfg)
    rid = pipeline.start_run(cfg, store, seeds)
    asyncio.run(pipeline.crawl(cfg, store, rid))
    return store, rid


@pytest.fixture(scope="module")
def crawled(site: FixtureSite, tmp_path_factory: pytest.TempPathFactory) -> tuple[Store, str, dict[str, Any]]:
    store, rid = _crawl(site, tmp_path_factory.mktemp("crawl"))
    by_path = {c["url"].split(str(site.port), 1)[1]: c for c in store.candidates(rid)}
    return store, rid, by_path


def probe(c: Any) -> dict[str, Any]:
    return loads(c["probe_json"]) or {}


def test_robots_exclusion_without_fetching(crawled: Any, site: FixtureSite) -> None:
    _, _, c = crawled
    assert c["/private/secret.zip"]["status"] == "excluded"
    assert c["/private/secret.zip"]["status_reason"] == "robots_disallowed"
    assert not any(path.startswith("/private/") for _, path in site.hits)


def test_sitemap_and_directory_and_meta_refresh(crawled: Any) -> None:
    _, _, c = crawled
    assert c["/files/from-sitemap.zip"]["discovery_method"] == "sitemap"
    assert c["/dir/listed-a.zip"]["discovery_method"] == "directory_listing"
    assert c["/files/meta-target.bin"]["discovery_method"] == "meta_refresh"


def test_extensionless_and_query_dependent_urls_preserved(crawled: Any) -> None:
    _, _, c = crawled
    assert "/download?id=1" in c and "/download?id=2" in c
    assert "/download?lang=en&id=1" in c  # parameter order preserved exactly
    assert probe(c["/download?id=1"])["filename"] == "build-1.bin"
    assert probe(c["/download?id=2"])["filename"] == "build-2.bin"
    assert probe(c["/download?id=2"])["declared_length"] is None  # chunked, no Content-Length


def test_redirect_chain_recorded(crawled: Any, site: FixtureSite) -> None:
    _, _, c = crawled
    p = probe(c["/go/latest"])
    assert p["final_url"] == f"{site.base}/files/release-1.0.bin"
    assert [h["status"] for h in p["get"]["redirect_chain"]] == [302, 200]


def test_external_target_verified_not_crawled(crawled: Any) -> None:
    store, rid, c = crawled
    ext = c["/ext/tool.zip"]
    assert ext["url"].startswith("http://localhost:") and ext["is_external"] == 1
    assert ext["status"] == "probed_likely_download"
    assert not [p for p in store.query("SELECT url FROM pages WHERE run_id=?", [rid])
                if p["url"].startswith("http://localhost")]


def test_rejected_head_falls_back_to_get(crawled: Any) -> None:
    _, _, c = crawled
    p = probe(c["/nohead/file.bin"])
    assert p["head_status"] == 405 and p["status"] == 200 and p["verdict"] == "likely_download"


def test_range_ignored_and_misleading_mime_recorded(crawled: Any) -> None:
    _, _, c = crawled
    p = probe(c["/misleading/data.bin"])
    assert p["range_honored"] is False
    assert p["declared_mime"].startswith("text/plain") and p["sniffed_family"] == "zip"


def test_expired_link_and_blocked_private_redirect(crawled: Any) -> None:
    _, _, c = crawled
    exp = c["/expired?token=abcdefabcdefabcdefabcdefabcdefabcdef&expires=1"]
    assert exp["status"] == "probe_failed" and exp["status_reason"] == "http_status:410"
    assert loads(exp["url_sensitive_json"]) == ["param:token"]
    red = c["/redirect-private"]
    assert red["status"] == "excluded" and red["status_reason"] == "blocked_metadata_or_link_local"


def test_probe_reads_bounded_bytes(crawled: Any) -> None:
    _, _, c = crawled
    p = probe(c["/big.bin"])
    assert p["get"]["truncated"] is True
    assert p["get"]["bytes_observed"] < 200_000


def test_invalid_seed_rows_do_not_abort(site: FixtureSite, tmp_path: Path) -> None:
    cfg = make_config(tmp_path)
    seeds = tmp_path / "s.csv"
    seeds.write_text(f"url\nnot-a-url\n{site.base}/sitemap-only.html\n")
    store = pipeline.open_store(cfg)
    rid = pipeline.start_run(cfg, store, seeds)
    asyncio.run(pipeline.crawl(cfg, store, rid))
    statuses = [s["status"] for s in store.seeds(rid)]
    assert statuses == ["invalid", "crawled"]
    assert any(e["stage"] == "input" for e in store.errors(rid))


def test_calendar_trap_capped(site: FixtureSite, tmp_path: Path) -> None:
    store, rid = _crawl(site, tmp_path, "/calendar?month=2026-01", limits={"max_depth": 20})
    pages = store.query("SELECT url, status, reason FROM pages WHERE run_id=?", [rid])
    fetched = [p for p in pages if p["status"] == "fetched" and "/calendar" in p["url"]]
    assert len(fetched) <= 4  # seed + calendar pattern cap (3)
    assert any(p["reason"] == "trap_calendar_pattern" for p in pages)


def test_budget_exhaustion_then_resume(site: FixtureSite, tmp_path: Path) -> None:
    store, rid = _crawl(site, tmp_path, limits={"max_requests_total": 8})
    run = store.get_run(rid)
    assert "max_requests_total" in loads(run["budget_exhausted_json"])
    assert store.seeds(rid)[0]["status"] == "crawling"
    unfinished = store.query("SELECT 1 FROM pages WHERE run_id=? AND status='queued' UNION ALL "
                             "SELECT 1 FROM candidates WHERE run_id=? AND status='discovered'", [rid, rid])
    assert unfinished  # work was left pending, not marked failed
    before = len(store.candidates(rid))
    cfg = make_config(tmp_path, limits={"max_requests_total": 3000})
    asyncio.run(pipeline.resume(cfg, store, rid, with_browser=False))
    assert store.seeds(rid)[0]["status"] == "crawled"
    assert len(store.candidates(rid)) >= before
    assert not store.query("SELECT 1 FROM pages WHERE run_id=? AND status='queued'", [rid])
    assert not store.candidates(rid, ("discovered",))
    probed = {c["url"].rsplit("/", 1)[-1] for c in store.candidates(rid, ("probed_likely_download",))}
    assert probed >= {"sample.zip", "tool.zip", "latest"}


async def test_retry_after_is_honoured(site: FixtureSite, tmp_path: Path) -> None:
    cfg = make_config(tmp_path)
    async with PolicyHttpClient(cfg, NetworkPolicy(cfg.network), Budget(cfg.limits)) as client:
        t0 = time.monotonic()
        res = await client.fetch(f"{site.base}/ratelimited?case=1", max_bytes=1000)
        assert res.status == 200 and res.attempts == 2
        assert time.monotonic() - t0 >= 0.9


def test_parse_retry_after() -> None:
    assert parse_retry_after("5") == 5
    assert parse_retry_after("Wed, 21 Oct 2015 07:28:00 GMT", now=1445412480 - 10) == pytest.approx(10, abs=1)
    assert parse_retry_after("garbage") is None
