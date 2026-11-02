"""Seed CSV reading and validation. Invalid rows are reported, never fatal."""

from __future__ import annotations

import csv
from dataclasses import dataclass
from pathlib import Path

from .urls import URLError, normalize_observed


@dataclass
class SeedRow:
    row_number: int  # 1-based data row number (header is row 0)
    raw_url: str
    url: str | None
    error: str | None


class SeedFileError(ValueError):
    pass


def read_seeds(path: Path) -> list[SeedRow]:
    try:
        text = path.read_bytes().decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise SeedFileError(f"{path}: not valid UTF-8 ({exc})") from exc
    reader = csv.DictReader(text.splitlines())
    if reader.fieldnames is None or "url" not in [f.strip().lower() for f in reader.fieldnames]:
        raise SeedFileError(f"{path}: missing required 'url' column")
    url_field = next(f for f in reader.fieldnames if f.strip().lower() == "url")
    rows: list[SeedRow] = []
    seen: set[str] = set()
    for i, rec in enumerate(reader, start=1):
        raw = (rec.get(url_field) or "").strip()
        if not raw:
            rows.append(SeedRow(i, raw, None, "empty_url"))
            continue
        try:
            url, _frag = normalize_observed(raw)
        except URLError as exc:
            rows.append(SeedRow(i, raw, None, f"invalid_url: {exc}"))
            continue
        if url in seen:
            rows.append(SeedRow(i, raw, None, "duplicate_seed"))
            continue
        seen.add(url)
        rows.append(SeedRow(i, raw, url, None))
    return rows
