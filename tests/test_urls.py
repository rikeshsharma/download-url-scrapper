from __future__ import annotations

import pytest

from download_url_collector.config import DEFAULT_SENSITIVE_PARAMS
from download_url_collector.discovery.html import extract_links
from download_url_collector.urls import (
    SensitivityPolicy,
    URLError,
    dedup_key,
    normalize_observed,
    path_extension,
    redact_url,
    registrable_domain,
    resolve,
    sensitive_findings,
)

POL = SensitivityPolicy(frozenset(DEFAULT_SENSITIVE_PARAMS))


def test_query_order_case_and_encoding_preserved() -> None:
    url = "https://Example.COM/Path/File.EXE?b=2&a=1&A=%2F&empty=&flag"
    out, frag = normalize_observed(url + "#frag")
    assert out == "https://example.com/Path/File.EXE?b=2&a=1&A=%2F&empty=&flag"
    assert frag == "frag"


def test_reserved_escapes_not_decoded_and_minimal_encoding() -> None:
    assert normalize_observed("http://h/a%2Fb/c d?q=x y&r=%26")[0] == "http://h/a%2Fb/c%20d?q=x%20y&r=%26"
    assert normalize_observed("http://h/ünï")[0] == "http://h/%C3%BCn%C3%AF"


def test_trailing_question_mark_kept() -> None:
    assert normalize_observed("http://h/dl?")[0] == "http://h/dl?"


def test_idna_host() -> None:
    assert normalize_observed("http://bücher.example/x")[0] == "http://xn--bcher-kva.example/x"


@pytest.mark.parametrize("bad", ["ftp://h/x", "javascript:alert(1)", "file:///etc/passwd", "http:///nohost", "nope"])
def test_rejects_non_http(bad: str) -> None:
    with pytest.raises(URLError):
        normalize_observed(bad)


def test_relative_resolution_query_only_and_dot_segments() -> None:
    base = "https://h/dir/page.html?x=1"
    assert resolve(base, "?id=2") == "https://h/dir/page.html?id=2"
    assert resolve(base, "../f.zip") == "https://h/f.zip"
    assert resolve(base, "//cdn.example/f.zip") == "https://cdn.example/f.zip"


def test_base_href_used_for_resolution() -> None:
    html = b'<html><head><base href="/downloads/v2/"></head><body><a href="tool.zip">t</a></body></html>'
    ext = extract_links(html, "https://h/some/page")
    assert ext.base_url == "https://h/downloads/v2/"
    assert ext.links[0].url == "https://h/downloads/v2/tool.zip"


def test_dedup_key_is_conservative() -> None:
    assert dedup_key("HTTP://Host:80/A?b=1&a=2") == "http://host/A?b=1&a=2"
    assert dedup_key("http://host/A?b=1&a=2") != dedup_key("http://host/A?a=2&b=1")
    assert dedup_key("http://host/a") != dedup_key("http://host/A")


def test_registrable_domain_uses_psl_private_suffixes() -> None:
    assert registrable_domain("a.b.example.co.uk") == "example.co.uk"
    assert registrable_domain("user.github.io") == "user.github.io"
    assert registrable_domain("127.0.0.1") == "127.0.0.1"


def test_redaction_and_token_flags_do_not_alter_original() -> None:
    url = "https://user:pw@h/f.zip?X-Amz-Signature=abc&name=ok&blob=" + "A" * 40
    assert sensitive_findings(url, POL) == ["userinfo", "param:X-Amz-Signature", "opaque_value:blob"]
    red = redact_url(url, POL)
    assert red == "https://REDACTED@h/f.zip?X-Amz-Signature=REDACTED&name=ok&blob=REDACTED"
    assert normalize_observed(url)[0] == url  # replay URL untouched


def test_path_extension() -> None:
    assert path_extension("http://h/a/pkg.tar.gz?x=1") == "tar.gz"
    assert path_extension("http://h/download") is None
