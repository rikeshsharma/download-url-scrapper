from __future__ import annotations

import gzip

from download_url_collector.config import TrapsConfig
from download_url_collector.discovery.hints import link_hints, url_kind
from download_url_collector.discovery.html import extract_links
from download_url_collector.discovery.sitemap import parse_sitemap
from download_url_collector.discovery.traps import TrapDetector
from download_url_collector.models import DiscoveryMethod
from download_url_collector.probe import parse_content_disposition


def test_extracts_anchors_download_attr_meta_refresh_and_controls() -> None:
    html = """<html><head><meta http-equiv="Refresh" content="3; URL='/dl/file.msi'"></head><body>
    <a href="/a.zip">A</a><a href="b.bin" download="x.bin">B</a>
    <a href="javascript:void(0)" onclick="go()">Download now</a>
    <button data-download-url="/c.exe">Get it</button>
    <area href="/map.zip"><iframe src="/frame.pdf"></iframe>
    <a href="mailto:x@y">mail</a><a href="#top">top</a></body></html>"""
    ext = extract_links(html, "https://h/p/index.html")
    by_url = {link.url: link for link in ext.links}
    assert by_url["https://h/a.zip"].method == DiscoveryMethod.ANCHOR
    assert by_url["https://h/p/b.bin"].method == DiscoveryMethod.ANCHOR_DOWNLOAD_ATTR
    assert by_url["https://h/p/b.bin"].download_attr == "x.bin"
    assert by_url["https://h/c.exe"].method == DiscoveryMethod.DATA_ATTRIBUTE
    assert by_url["https://h/map.zip"].method == DiscoveryMethod.AREA
    assert by_url["https://h/frame.pdf"].method == DiscoveryMethod.EMBED
    assert ext.meta_refresh == (3.0, "https://h/dl/file.msi")
    assert len(ext.controls) == 2
    assert not any(u.startswith(("mailto", "javascript")) for u in by_url)


def test_directory_listing_skips_sort_and_parent_links() -> None:
    html = '<title>Index of /pub/</title><a href="?C=N;O=D">Name</a><a href="../">Parent</a><a href="x.tar.gz">x</a>'
    ext = extract_links(html, "https://h/pub/")
    assert ext.is_directory_listing
    assert [link.url for link in ext.links] == ["https://h/pub/x.tar.gz"]
    assert ext.links[0].method == DiscoveryMethod.DIRECTORY_LISTING


def test_sitemap_index_urlset_gzip_and_xxe_rejected() -> None:
    idx = b'<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><sitemap><loc>https://h/s1.xml.gz</loc></sitemap></sitemapindex>'
    r = parse_sitemap(idx, "https://h/sitemap.xml", 10**6, 100)
    assert r.child_sitemaps == ["https://h/s1.xml.gz"]
    us = gzip.compress(b'<urlset><url><loc>https://h/a.zip</loc></url><url><loc>/rel.html</loc></url></urlset>')
    r = parse_sitemap(us, "https://h/s1.xml.gz", 10**6, 100)
    assert r.urls == ["https://h/a.zip", "https://h/rel.html"]
    bomb = b'<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "aaaa">]><urlset><url><loc>&a;</loc></url></urlset>'
    r = parse_sitemap(bomb, "https://h/s.xml", 10**6, 100)
    assert r.error and not r.urls


def test_traps() -> None:
    t = TrapDetector(TrapsConfig(max_urls_per_calendar_pattern=2, max_urls_per_pattern=3))
    assert t.check_page("https://h/cal?month=2026-01") is None
    assert t.check_page("https://h/cal?month=2026-02") is None
    assert t.check_page("https://h/cal?month=2026-03") == "trap_calendar_pattern"
    assert t.check_page("https://h/a/b/a/b/a/x") == "trap_repeated_path_segment"
    assert t.check_page("https://h/s?a=1&a=2") == "trap_repeated_query_param"
    assert t.check_page("https://h/s?" + "&".join(f"f{i}=1" for i in range(9))) == "trap_too_many_query_params"
    for i in range(3):
        assert t.check_page(f"https://h/item/{i}") is None
    assert t.check_page("https://h/item/99") == "trap_pattern_limit"


def test_hints_are_hints() -> None:
    assert url_kind("https://h/x.exe") == "download"
    assert url_kind("https://h/download?id=1") == "ambiguous"
    assert url_kind("https://h/x.html") == "page"
    assert "query_keyword" in link_hints("https://h/get?file=1")
    assert link_hints("https://h/x", "Download installer") == ["link_text"]


def test_content_disposition_parsing() -> None:
    cd = parse_content_disposition("attachment; filename=\"a b.zip\"; filename*=UTF-8''%E2%82%AC%20rates.zip")
    assert cd.disposition == "attachment" and cd.filename == "€ rates.zip"
    assert parse_content_disposition("inline").filename is None
    assert parse_content_disposition(None).disposition is None
