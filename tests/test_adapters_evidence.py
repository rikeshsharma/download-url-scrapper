"""Source adapter, publisher checksum discovery, reputation client and PSL config."""

from __future__ import annotations

import asyncio
import hashlib
from pathlib import Path

import pytest
from conftest import make_config
from fixtures.server import SAMPLE_ZIP, FixtureSite

from download_url_collector import pipeline
from download_url_collector.budget import Budget
from download_url_collector.http_client import PolicyHttpClient
from download_url_collector.labeling.checksums import find_publisher_checksum, parse_checksum_file
from download_url_collector.labeling.reputation import VirusTotalLookup
from download_url_collector.netpolicy import NetworkPolicy
from download_url_collector.storage import Store, loads
from download_url_collector.urls import configure_psl, registrable_domain

SHA = hashlib.sha256(SAMPLE_ZIP).hexdigest()


def test_github_releases_adapter_discovers_assets_with_digest(site: FixtureSite, tmp_path: Path) -> None:
    cfg = make_config(tmp_path, adapters={"github_releases": {
        "enabled": True, "api_base": f"{site.base}/api", "web_hosts": ["127.0.0.1"]}})
    seeds = tmp_path / "s.csv"
    seeds.write_text(f"url\n{site.base}/acme/tool\n")
    store = pipeline.open_store(cfg)
    rid = pipeline.start_run(cfg, store, seeds)
    asyncio.run(pipeline.crawl(cfg, store, rid))
    adapter = [c for c in store.candidates(rid) if c["discovery_method"] == "source_adapter"]
    assert len(adapter) == 1  # draft release skipped
    c = adapter[0]
    assert c["url"] == f"{site.base}/files/sample.zip" and c["publisher"] == "github:acme"
    assert loads(c["publisher_checksums_json"]) == {"sha256": SHA}
    assert loads(c["adapter_metadata_json"])["release_tag"] == "v1.0"


def test_checksum_file_formats() -> None:
    entries, lone = parse_checksum_file(f"{SHA}  sample.zip\n{'b' * 64} *other.bin\n")
    assert entries == {"sample.zip": SHA, "other.bin": "b" * 64} and lone is None
    entries, _ = parse_checksum_file(f"SHA256 (./sample.zip) = {SHA}\n")
    assert entries == {"sample.zip": SHA}
    assert parse_checksum_file(f"{SHA}\n") == ({}, SHA)


async def test_sidecar_checksum_match_and_mismatch(site: FixtureSite, tmp_path: Path) -> None:
    cfg = make_config(tmp_path)
    async with PolicyHttpClient(cfg, NetworkPolicy(cfg.network), Budget(cfg.limits)) as client:
        ok = await find_publisher_checksum(client, f"{site.base}/files/sample.zip", SHA, None)
        assert [(f.verdict, f.source_url.rsplit("/", 1)[-1]) for f in ok] == [("match", "sample.zip.sha256")]
        bad = await find_publisher_checksum(client, f"{site.base}/files/sample.zip", "f" * 64, None)
        assert [f.verdict for f in bad] == ["mismatch"]


async def test_reputation_hash_lookup_quota_and_not_found(site: FixtureSite, tmp_path: Path,
                                                          monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TEST_VT_KEY", "test-key")
    cfg = make_config(tmp_path, labeling={"reputation": {
        "enabled": True, "api_key_env": "TEST_VT_KEY", "base_url": f"{site.base}/vt",
        "requests_per_minute": 600, "daily_quota": 2}})
    store = Store(tmp_path / "db.sqlite3")
    async with PolicyHttpClient(cfg, NetworkPolicy(cfg.network), Budget(cfg.limits)) as client:
        vt = VirusTotalLookup(cfg.labeling.reputation, store, client)
        r1 = await vt.lookup(SHA)
        assert r1.verdict == "clean" and r1.engines_total == 70
        r2 = await vt.lookup("0" * 64)
        assert r2.verdict == "not_found"  # absent is not benign
        r3 = await vt.lookup(SHA)
        assert r3.verdict == "quota_exhausted"
    assert not any(m == "POST" for m, p in site.hits if p.startswith("/vt"))  # never uploads


async def test_reputation_without_key_is_unavailable(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("VT_API_KEY", raising=False)
    cfg = make_config(tmp_path)
    async with PolicyHttpClient(cfg, NetworkPolicy(cfg.network), Budget(cfg.limits)) as client:
        r = await VirusTotalLookup(cfg.labeling.reputation, Store(tmp_path / "d.sqlite3"), client).lookup(SHA)
    assert r.verdict == "unavailable"


def test_custom_public_suffix_list(tmp_path: Path) -> None:
    psl = tmp_path / "psl.dat"
    psl.write_text("// test list\ncom\nexample.com\n")
    try:
        configure_psl(psl)
        assert registrable_domain("a.b.example.com") == "b.example.com"
    finally:
        configure_psl(None)
    assert registrable_domain("a.b.example.com") == "example.com"
