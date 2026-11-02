from __future__ import annotations

from pathlib import Path
import json

import pytest

from download_url_collector.csvio import read_csv_nullable, write_csv
from download_url_collector.inputs import SeedFileError, read_seeds


def test_seed_validation_reports_invalid_rows(tmp_path: Path) -> None:
    p = tmp_path / "s.csv"
    p.write_text("note,URL\na,https://example.com/x?b=1&a=2\nb,\nc,ftp://x/y\nd,https://example.com/x?b=1&a=2\ne,http://ok.example\n",
                 encoding="utf-8")
    rows = read_seeds(p)
    assert [r.error for r in rows] == [None, "empty_url", "invalid_url: unsupported scheme: ftp",
                                       "duplicate_seed", None]
    assert rows[0].url == "https://example.com/x?b=1&a=2"


def test_seed_file_requires_url_column(tmp_path: Path) -> None:
    p = tmp_path / "s.csv"
    p.write_text("link\nhttp://x\n")
    with pytest.raises(SeedFileError):
        read_seeds(p)


def test_seed_file_must_be_utf8(tmp_path: Path) -> None:
    p = tmp_path / "s.csv"
    p.write_bytes(b"url\nhttp://x/\xff\n")
    with pytest.raises(SeedFileError):
        read_seeds(p)


def test_csv_distinguishes_unknown_from_empty(tmp_path: Path) -> None:
    p = tmp_path / "o.csv"
    write_csv(p, ["a", "b", "c", "d", "e"], [[None, "", [], True, 'x,"y"\nz']])
    text = p.read_text()
    assert text.splitlines()[1].startswith(',"",[],true,')
    row = read_csv_nullable(p)[0]
    assert row == {"a": None, "b": "", "c": "[]", "d": "true", "e": 'x,"y"\nz'}


def test_csv_exports_malformed_unicode_without_losing_rows(tmp_path: Path) -> None:
    p = tmp_path / "unicode.csv"
    bad = "file_\udcf1.zip"
    url = "https://example.com/mañana.zip?b=2&a=1"
    count = write_csv(p, ["url", "filename", "metadata", "empty", "unknown"], [
        [url, bad, {"filename": bad, "title": "日本語"}, "", None],
        ["https://example.com/next.zip", "valid_😀.zip", {}, "", None],
    ])
    assert count == 2
    text = p.read_bytes().decode("utf-8", errors="strict")
    assert "\\udcf1" in text
    rows = read_csv_nullable(p)
    assert rows[0]["url"] == url
    assert rows[0]["filename"] == r"file_\udcf1.zip"
    assert json.loads(rows[0]["metadata"]) == {"filename": bad, "title": "日本語"}
    assert rows[0]["empty"] == ""
    assert rows[0]["unknown"] is None
    assert rows[1]["filename"] == "valid_😀.zip"
