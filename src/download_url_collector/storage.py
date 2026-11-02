"""SQLite persistence: crawl frontier, candidates, probes, observations, files,
evidence and labels. All state needed to resume an interrupted run lives here.

Structured values are stored as JSON text. SQL NULL means "unknown"; an empty
JSON list/object or empty string means "known to be empty".
"""

from __future__ import annotations

import json
import sqlite3
import threading
from collections.abc import Iterable, Iterator
from pathlib import Path
from typing import Any

from .models import new_id, utcnow

SCHEMA_VERSION = 1

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS runs (
    run_id TEXT PRIMARY KEY, created_at TEXT, updated_at TEXT, status TEXT,
    config_json TEXT, config_fingerprint TEXT, seeds_file TEXT, counters_json TEXT,
    budget_exhausted_json TEXT
);
CREATE TABLE IF NOT EXISTS seeds (
    seed_id TEXT PRIMARY KEY, run_id TEXT, row_number INTEGER, raw_url TEXT, url TEXT,
    status TEXT, error TEXT, registrable_domain TEXT, created_at TEXT
);
CREATE INDEX IF NOT EXISTS seeds_run ON seeds(run_id);
CREATE TABLE IF NOT EXISTS pages (
    page_id TEXT PRIMARY KEY, run_id TEXT, seed_id TEXT, url TEXT, dedup_key TEXT, depth INTEGER,
    discovered_from TEXT, discovery_method TEXT, status TEXT, reason TEXT, http_json TEXT,
    has_download_controls INTEGER DEFAULT 0, controls_json TEXT, rendered INTEGER DEFAULT 0,
    meta_refresh_hops INTEGER DEFAULT 0, created_at TEXT, fetched_at TEXT,
    UNIQUE(run_id, dedup_key)
);
CREATE INDEX IF NOT EXISTS pages_run_status ON pages(run_id, status);
CREATE INDEX IF NOT EXISTS pages_run_seed_status ON pages(run_id, seed_id, status);
CREATE TABLE IF NOT EXISTS candidates (
    candidate_id TEXT PRIMARY KEY, run_id TEXT, seed_id TEXT, url TEXT, dedup_key TEXT,
    raw_href TEXT, source_page TEXT, discovery_method TEXT, depth INTEGER, is_external INTEGER,
    link_text TEXT, download_attr TEXT, hints_json TEXT, publisher TEXT,
    publisher_checksums_json TEXT, adapter_metadata_json TEXT,
    status TEXT, status_reason TEXT, probe_json TEXT, url_sensitive_json TEXT,
    created_at TEXT, updated_at TEXT,
    UNIQUE(run_id, dedup_key)
);
CREATE INDEX IF NOT EXISTS cand_run_status ON candidates(run_id, status);
CREATE INDEX IF NOT EXISTS candidates_run_seed_status ON candidates(run_id, seed_id, status);
CREATE TABLE IF NOT EXISTS browser_configs (
    browser_config_id TEXT PRIMARY KEY, identity_json TEXT, created_at TEXT
);
CREATE TABLE IF NOT EXISTS files (
    sha256 TEXT PRIMARY KEY, size INTEGER, storage_path TEXT, stored INTEGER,
    detected_family TEXT, detected_mime TEXT, inspection_status TEXT, inspection_json TEXT,
    first_seen TEXT, last_seen TEXT
);
CREATE TABLE IF NOT EXISTS observations (
    observation_id TEXT PRIMARY KEY, run_id TEXT, candidate_id TEXT, seed_id TEXT,
    verification_mode TEXT, classification TEXT, initiating_url TEXT, final_url TEXT,
    source_page TEXT, redirect_chain_json TEXT, http_json TEXT, browser_config_id TEXT,
    started_at TEXT, completed_at TEXT, download_state TEXT, suggested_filename TEXT,
    sha256 TEXT, size INTEGER, failure_reason TEXT, replay_json TEXT,
    replay_status TEXT, discrepancies_json TEXT, feature_ref TEXT,
    previous_observation_id TEXT, content_changed INTEGER, capped_reason TEXT,
    extra_json TEXT
);
CREATE INDEX IF NOT EXISTS obs_run ON observations(run_id);
CREATE INDEX IF NOT EXISTS obs_url ON observations(initiating_url);
CREATE INDEX IF NOT EXISTS obs_sha ON observations(sha256);
CREATE TABLE IF NOT EXISTS evidence (
    evidence_id TEXT PRIMARY KEY, sha256 TEXT, kind TEXT, source TEXT, verdict TEXT,
    tool_version TEXT, signature_db_version TEXT, signature_db_date TEXT,
    details_json TEXT, observed_at TEXT
);
CREATE INDEX IF NOT EXISTS ev_sha ON evidence(sha256);
CREATE TABLE IF NOT EXISTS labels (
    label_id TEXT PRIMARY KEY, sha256 TEXT, label TEXT, policy_version TEXT,
    reasons_json TEXT, evidence_ids_json TEXT, decided_at TEXT
);
CREATE INDEX IF NOT EXISTS labels_sha ON labels(sha256);
CREATE TABLE IF NOT EXISTS errors (
    error_id TEXT PRIMARY KEY, run_id TEXT, stage TEXT, url TEXT, seed_id TEXT, reason TEXT,
    details TEXT, created_at TEXT
);
CREATE INDEX IF NOT EXISTS errors_run ON errors(run_id);
CREATE TABLE IF NOT EXISTS api_quota (
    provider TEXT, day TEXT, count INTEGER, PRIMARY KEY(provider, day)
);
"""


def dumps(v: Any) -> str | None:
    return None if v is None else json.dumps(v, sort_keys=True, default=str)


def loads(v: str | None) -> Any:
    return None if v is None else json.loads(v)


class Store:
    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        self._conn = sqlite3.connect(str(path), isolation_level=None, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._lock = threading.RLock()
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.executescript(SCHEMA)
        self._conn.execute("INSERT OR IGNORE INTO meta VALUES ('schema_version', ?)",
                           (str(SCHEMA_VERSION),))

    def close(self) -> None:
        self._conn.close()

    # -- low level ---------------------------------------------------------
    def execute(self, sql: str, params: Iterable[Any] = ()) -> sqlite3.Cursor:
        with self._lock:
            return self._conn.execute(sql, tuple(params))

    def query(self, sql: str, params: Iterable[Any] = ()) -> list[sqlite3.Row]:
        with self._lock:
            return list(self._conn.execute(sql, tuple(params)))

    def one(self, sql: str, params: Iterable[Any] = ()) -> sqlite3.Row | None:
        rows = self.query(sql, params)
        return rows[0] if rows else None

    def _insert(self, table: str, row: dict[str, Any], or_ignore: bool = False) -> bool:
        cols = ", ".join(row)
        qs = ", ".join("?" for _ in row)
        verb = "INSERT OR IGNORE" if or_ignore else "INSERT"
        cur = self.execute(f"{verb} INTO {table} ({cols}) VALUES ({qs})", row.values())
        return cur.rowcount > 0

    def _update(self, table: str, key: str, key_value: Any, fields: dict[str, Any]) -> None:
        sets = ", ".join(f"{k} = ?" for k in fields)
        self.execute(f"UPDATE {table} SET {sets} WHERE {key} = ?", [*fields.values(), key_value])

    # -- runs ----------------------------------------------------------------
    def create_run(self, config_json: dict[str, Any], fingerprint: str, seeds_file: str,
                   run_id: str | None = None) -> str:
        run_id = run_id or new_id("run")
        now = utcnow()
        self._insert("runs", {"run_id": run_id, "created_at": now, "updated_at": now,
                              "status": "created", "config_json": dumps(config_json),
                              "config_fingerprint": fingerprint, "seeds_file": seeds_file,
                              "counters_json": dumps({}), "budget_exhausted_json": dumps([])})
        return run_id

    def get_run(self, run_id: str) -> sqlite3.Row | None:
        return self.one("SELECT * FROM runs WHERE run_id = ?", [run_id])

    def latest_run_id(self) -> str | None:
        r = self.one("SELECT run_id FROM runs ORDER BY created_at DESC, rowid DESC LIMIT 1")
        return r["run_id"] if r else None

    def update_run(self, run_id: str, **fields: Any) -> None:
        fields["updated_at"] = utcnow()
        for k in ("counters_json", "budget_exhausted_json"):
            if k in fields and not isinstance(fields[k], str):
                fields[k] = dumps(fields[k])
        self._update("runs", "run_id", run_id, fields)

    # -- seeds -----------------------------------------------------------------
    def add_seed(self, run_id: str, row_number: int, raw_url: str, url: str | None,
                 status: str, error: str | None, domain: str | None) -> str:
        seed_id = new_id("seed")
        self._insert("seeds", {"seed_id": seed_id, "run_id": run_id, "row_number": row_number,
                               "raw_url": raw_url, "url": url, "status": status, "error": error,
                               "registrable_domain": domain, "created_at": utcnow()})
        return seed_id

    def seeds(self, run_id: str, status: str | None = None) -> list[sqlite3.Row]:
        if status:
            return self.query("SELECT * FROM seeds WHERE run_id=? AND status=? ORDER BY row_number",
                              [run_id, status])
        return self.query("SELECT * FROM seeds WHERE run_id=? ORDER BY row_number", [run_id])

    def set_seed_status(self, seed_id: str, status: str, error: str | None = None) -> None:
        self._update("seeds", "seed_id", seed_id, {"status": status, "error": error})

    # -- pages -----------------------------------------------------------------
    def add_page(self, run_id: str, seed_id: str, url: str, key: str, depth: int,
                 discovered_from: str | None, method: str, status: str = "queued",
                 reason: str | None = None, meta_refresh_hops: int = 0) -> str | None:
        page_id = new_id("page")
        ok = self._insert("pages", {
            "page_id": page_id, "run_id": run_id, "seed_id": seed_id, "url": url,
            "dedup_key": key, "depth": depth, "discovered_from": discovered_from,
            "discovery_method": method, "status": status, "reason": reason,
            "meta_refresh_hops": meta_refresh_hops, "created_at": utcnow()}, or_ignore=True)
        return page_id if ok else None

    def page_exists(self, run_id: str, key: str) -> bool:
        return self.one("SELECT 1 FROM pages WHERE run_id=? AND dedup_key=?", [run_id, key]) is not None

    def queued_pages(self, run_id: str, seed_id: str) -> list[sqlite3.Row]:
        return self.query("SELECT * FROM pages WHERE run_id=? AND seed_id=? AND status='queued' "
                          "ORDER BY depth, created_at, rowid", [run_id, seed_id])

    def count_pages(self, run_id: str, seed_id: str, statuses: tuple[str, ...]) -> int:
        q = ",".join("?" for _ in statuses)
        r = self.one(f"SELECT COUNT(*) c FROM pages WHERE run_id=? AND seed_id=? AND status IN ({q})",
                     [run_id, seed_id, *statuses])
        return int(r["c"]) if r else 0

    def update_page(self, page_id: str, **fields: Any) -> None:
        for k in ("http_json", "controls_json"):
            if k in fields and not isinstance(fields[k], str | None):
                fields[k] = dumps(fields[k])
        self._update("pages", "page_id", page_id, fields)

    # -- candidates ------------------------------------------------------------
    def add_candidate(self, row: dict[str, Any]) -> str | None:
        row = dict(row)
        row.setdefault("candidate_id", new_id("cand"))
        row.setdefault("status", "discovered")
        row["created_at"] = row["updated_at"] = utcnow()
        for k in ("hints_json", "publisher_checksums_json", "adapter_metadata_json",
                  "probe_json", "url_sensitive_json"):
            if k in row and not isinstance(row[k], str | None):
                row[k] = dumps(row[k])
        return row["candidate_id"] if self._insert("candidates", row, or_ignore=True) else None

    def candidate_by_key(self, run_id: str, key: str) -> sqlite3.Row | None:
        return self.one("SELECT * FROM candidates WHERE run_id=? AND dedup_key=?", [run_id, key])

    def get_candidate(self, candidate_id: str) -> sqlite3.Row | None:
        return self.one("SELECT * FROM candidates WHERE candidate_id=?", [candidate_id])

    def candidates(self, run_id: str, statuses: tuple[str, ...] | None = None,
                   seed_id: str | None = None) -> list[sqlite3.Row]:
        sql = "SELECT * FROM candidates WHERE run_id=?"
        params: list[Any] = [run_id]
        if statuses:
            sql += f" AND status IN ({','.join('?' for _ in statuses)})"
            params += list(statuses)
        if seed_id:
            sql += " AND seed_id=?"
            params.append(seed_id)
        return self.query(sql + " ORDER BY created_at, rowid", params)

    def count_candidates(self, run_id: str, seed_id: str) -> int:
        r = self.one("SELECT COUNT(*) c FROM candidates WHERE run_id=? AND seed_id=?", [run_id, seed_id])
        return int(r["c"]) if r else 0

    def update_candidate(self, candidate_id: str, **fields: Any) -> None:
        fields["updated_at"] = utcnow()
        for k in ("hints_json", "probe_json", "url_sensitive_json"):
            if k in fields and not isinstance(fields[k], str | None):
                fields[k] = dumps(fields[k])
        self._update("candidates", "candidate_id", candidate_id, fields)

    # -- browser configs / files / observations --------------------------------
    def upsert_browser_config(self, config_id: str, identity: dict[str, Any]) -> None:
        self._insert("browser_configs", {"browser_config_id": config_id,
                                         "identity_json": dumps(identity),
                                         "created_at": utcnow()}, or_ignore=True)

    def upsert_file(self, sha256: str, size: int, storage_path: str | None, stored: bool,
                    family: str | None, mime: str | None, inspection_status: str,
                    inspection: dict[str, Any]) -> None:
        now = utcnow()
        if self.one("SELECT 1 FROM files WHERE sha256=?", [sha256]):
            self._update("files", "sha256", sha256, {"last_seen": now})
            if stored:
                self._update("files", "sha256", sha256, {"storage_path": storage_path, "stored": 1})
            return
        self._insert("files", {"sha256": sha256, "size": size, "storage_path": storage_path,
                               "stored": int(stored), "detected_family": family,
                               "detected_mime": mime, "inspection_status": inspection_status,
                               "inspection_json": dumps(inspection), "first_seen": now,
                               "last_seen": now})

    def get_file(self, sha256: str) -> sqlite3.Row | None:
        return self.one("SELECT * FROM files WHERE sha256=?", [sha256])

    def stored_bytes(self) -> int:
        r = self.one("SELECT COALESCE(SUM(size),0) s FROM files WHERE stored=1")
        return int(r["s"]) if r else 0

    def add_observation(self, row: dict[str, Any]) -> str:
        row = dict(row)
        row.setdefault("observation_id", new_id("obs"))
        for k in ("redirect_chain_json", "http_json", "replay_json", "discrepancies_json",
                  "extra_json"):
            if k in row and not isinstance(row[k], str | None):
                row[k] = dumps(row[k])
        self._insert("observations", row)
        return row["observation_id"]

    def observations(self, run_id: str | None = None) -> list[sqlite3.Row]:
        if run_id is None:
            return self.query("SELECT * FROM observations ORDER BY started_at, rowid")
        return self.query("SELECT * FROM observations WHERE run_id=? ORDER BY started_at, rowid",
                          [run_id])

    def latest_direct_observation(self, url: str) -> sqlite3.Row | None:
        return self.one(
            "SELECT * FROM observations WHERE initiating_url=? AND verification_mode IN "
            "('direct_navigation','revalidation') ORDER BY completed_at DESC, rowid DESC LIMIT 1",
            [url])

    def count_observations_for_hash(self, run_id: str, sha256: str) -> int:
        r = self.one("SELECT COUNT(*) c FROM observations WHERE run_id=? AND sha256=?",
                     [run_id, sha256])
        return int(r["c"]) if r else 0

    # -- evidence / labels -------------------------------------------------------
    def add_evidence(self, sha256: str, kind: str, source: str, verdict: str,
                     details: dict[str, Any] | None = None, tool_version: str | None = None,
                     db_version: str | None = None, db_date: str | None = None,
                     observed_at: str | None = None) -> str:
        eid = new_id("ev")
        self._insert("evidence", {"evidence_id": eid, "sha256": sha256, "kind": kind,
                                  "source": source, "verdict": verdict,
                                  "tool_version": tool_version, "signature_db_version": db_version,
                                  "signature_db_date": db_date, "details_json": dumps(details or {}),
                                  "observed_at": observed_at or utcnow()})
        return eid

    def evidence_for(self, sha256: str) -> list[sqlite3.Row]:
        return self.query("SELECT * FROM evidence WHERE sha256=? ORDER BY observed_at, rowid", [sha256])

    def add_label(self, sha256: str, label: str, policy_version: str, reasons: list[str],
                  evidence_ids: list[str]) -> str:
        lid = new_id("lbl")
        self._insert("labels", {"label_id": lid, "sha256": sha256, "label": label,
                                "policy_version": policy_version, "reasons_json": dumps(reasons),
                                "evidence_ids_json": dumps(evidence_ids), "decided_at": utcnow()})
        return lid

    def current_label(self, sha256: str, policy_version: str | None = None) -> sqlite3.Row | None:
        if policy_version:
            return self.one("SELECT * FROM labels WHERE sha256=? AND policy_version=? "
                            "ORDER BY decided_at DESC, rowid DESC LIMIT 1", [sha256, policy_version])
        return self.one("SELECT * FROM labels WHERE sha256=? ORDER BY decided_at DESC, rowid DESC LIMIT 1",
                        [sha256])

    # -- errors / quota ------------------------------------------------------
    def add_error(self, run_id: str, stage: str, url: str | None, reason: str,
                  details: str | None = None, seed_id: str | None = None) -> None:
        self._insert("errors", {"error_id": new_id("err"), "run_id": run_id, "stage": stage,
                                "url": url, "seed_id": seed_id, "reason": reason,
                                "details": details, "created_at": utcnow()})

    def errors(self, run_id: str) -> list[sqlite3.Row]:
        return self.query("SELECT * FROM errors WHERE run_id=? ORDER BY created_at, rowid", [run_id])

    def quota_take(self, provider: str, day: str, limit: int) -> bool:
        with self._lock:
            r = self.one("SELECT count FROM api_quota WHERE provider=? AND day=?", [provider, day])
            used = int(r["count"]) if r else 0
            if used >= limit:
                return False
            self.execute("INSERT INTO api_quota VALUES (?,?,1) ON CONFLICT(provider, day) "
                         "DO UPDATE SET count = count + 1", [provider, day])
            return True


def iter_rows_as_dicts(rows: Iterable[sqlite3.Row]) -> Iterator[dict[str, Any]]:
    for r in rows:
        yield dict(r)
