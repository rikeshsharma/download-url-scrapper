"""CSV writing/reading that distinguishes unknown from empty.

Convention (documented in docs/schemas.md):
* unknown / not applicable (NULL)  -> empty, unquoted cell:   a,,c
* known empty string               -> quoted empty cell:      a,"",c
* lists / objects                  -> compact JSON ("[]" is a known-empty list)
* booleans                         -> true / false
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import Any


def _cell(v: Any) -> str:
    if v is None:
        return ""
    if isinstance(v, bool):
        s = "true" if v else "false"
    elif isinstance(v, (list, dict)):
        s = json.dumps(v, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    else:
        s = str(v)
    if s == "" or any(ch in s for ch in ',"\r\n') or s != s.strip():
        return '"' + s.replace('"', '""') + '"'
    return s


def write_csv(path: Path, header: Sequence[str], rows: Iterable[Sequence[Any]]) -> int:
    n = 0
    # Malformed source metadata can contain lone surrogates. Preserve their
    # code points as visible escapes instead of aborting or dropping data.
    with path.open("w", encoding="utf-8", errors="backslashreplace", newline="") as fh:
        fh.write(",".join(_cell(h) for h in header) + "\n")
        for row in rows:
            fh.write(",".join(_cell(v) for v in row) + "\n")
            n += 1
    return n


def read_csv_nullable(path: Path) -> list[dict[str, str | None]]:
    """Parse files written by write_csv, returning None for unquoted empty cells."""
    text = path.read_text(encoding="utf-8")
    records: list[list[str | None]] = []
    row: list[str | None] = []
    i, n = 0, len(text)
    field: list[str] = []
    quoted = False
    at_start = True
    while i < n:
        ch = text[i]
        if at_start and ch == '"':
            quoted, at_start = True, False
            i += 1
            while i < n:
                if text[i] == '"':
                    if i + 1 < n and text[i + 1] == '"':
                        field.append('"')
                        i += 2
                        continue
                    i += 1
                    break
                field.append(text[i])
                i += 1
            continue
        if ch == ",":
            row.append("".join(field) if (field or quoted) else None)
            field, quoted, at_start = [], False, True
        elif ch == "\n":
            row.append("".join(field) if (field or quoted) else None)
            records.append(row)
            row, field, quoted, at_start = [], [], False, True
        elif ch != "\r":
            field.append(ch)
            at_start = False
        i += 1
    if field or quoted or row:
        row.append("".join(field) if (field or quoted) else None)
        records.append(row)
    if not records:
        return []
    header = [h or "" for h in records[0]]
    return [dict(zip(header, r, strict=False)) for r in records[1:]]
