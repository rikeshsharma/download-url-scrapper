"""Indexed seed queries and cached crawl counts preserve persisted limits."""

import pytest

from download_url_collector import pipeline
from download_url_collector.budget import Budget, BudgetExceeded
from download_url_collector.crawler import Crawler, SeedState
from download_url_collector.discovery.traps import TrapDetector
from download_url_collector.scope import Scope
from download_url_collector.storage import Store


def setup_crawler(cfg, tmp_path):
    path = tmp_path / "seeds.csv"
    path.write_text("url\nhttps://example.com/\nhttps://other.example/\n")
    store = pipeline.open_store(cfg)
    rid = pipeline.start_run(cfg, store, path)
    seed = store.seeds(rid)[0]
    crawler = Crawler(cfg, store, rid, None, None, Budget(cfg.limits), [])
    state = SeedState(seed, Scope.for_seed(seed["url"], cfg.scope), TrapDetector(cfg.traps))
    return store, rid, crawler, state


def test_existing_database_gets_seed_indexes_without_changing_records(tmp_path):
    path = tmp_path / "existing.sqlite3"
    store = Store(path)
    rid = store.create_run({}, "test", "seeds.csv")
    sid = store.add_seed(rid, 1, "https://example.com/", "https://example.com/", "crawling", None, "example.com")
    store.add_page(rid, sid, "https://example.com/", "key", 0, None, "seed", status="fetched")
    store.add_candidate({"run_id": rid, "seed_id": sid, "url": "https://example.com/file.zip", "dedup_key": "file"})
    # Recreate the pre-upgrade index layout on a populated database.
    store.execute("DROP INDEX pages_run_seed_status")
    store.execute("DROP INDEX candidates_run_seed_status")
    before = {table: [tuple(r) for r in store.query(f"SELECT * FROM {table}")]
              for table in ("runs", "seeds", "pages", "candidates")}
    store.close()
    for _ in range(2):  # Reopening and index installation are idempotent.
        store = Store(path)
        try:
            for table, rows in before.items():
                assert [tuple(r) for r in store.query(f"SELECT * FROM {table}")] == rows
            for table in ("pages", "candidates"):
                plan = store.query(f"EXPLAIN QUERY PLAN SELECT status,COUNT(*) FROM {table} "
                                   "WHERE run_id=? AND seed_id=? GROUP BY status", [rid, sid])
                assert any("run_id=? AND seed_id=?" in r["detail"] for r in plan)
            assert store.count_pages(rid, sid, ("fetched",)) == 1
            assert store.count_candidates(rid, sid) == 1
            assert store.one("PRAGMA integrity_check")[0] == "ok"
        finally:
            store.close()


def test_candidate_limit_cache_handles_duplicates_exclusions_and_resume(cfg, tmp_path, monkeypatch):
    cfg.limits.max_candidates_per_seed = 2
    store, rid, crawler, st = setup_crawler(cfg, tmp_path)
    calls = 0
    original = store.count_candidates

    def count(*args):
        nonlocal calls
        calls += 1
        return original(*args)

    monkeypatch.setattr(store, "count_candidates", count)
    try:
        # Existing persisted candidate must count toward the limit on resume.
        store.add_candidate({"run_id": rid, "seed_id": st.seed["seed_id"],
                             "url": "https://example.com/old.zip", "dedup_key": "https://example.com/old.zip"})

        def add(state, name):
            url = f"https://example.com/{name}.zip"
            return crawler._add_candidate(state, url, url, st.seed["url"], "html_anchor", 1)

        first = add(st, "new")
        assert store.get_candidate(first)["status"] == "discovered"
        assert add(st, "new") is None
        excluded = add(st, "excess")
        assert store.get_candidate(excluded)["status_reason"] == "max_candidates_per_seed"
        assert calls == 1
        assert st.candidate_count == 3  # Includes exclusions, matching existing semantics.
        resumed = SeedState(st.seed, st.scope, TrapDetector(cfg.traps))
        again = add(resumed, "after-resume")
        assert store.get_candidate(again)["status_reason"] == "max_candidates_per_seed"
        assert calls == 2
        assert resumed.candidate_count == 4
    finally:
        store.close()


@pytest.mark.asyncio
async def test_page_count_once_per_drain_and_reloaded_after_interruption(cfg, tmp_path, monkeypatch):
    cfg.limits.max_pages_per_seed = 3
    store, rid, crawler, st = setup_crawler(cfg, tmp_path)
    for i in range(8):
        store.add_page(rid, st.seed["seed_id"], f"https://example.com/{i}", str(i), 1, None, "html_anchor")
    calls = 0
    original = store.count_pages

    def count(*args):
        nonlocal calls
        calls += 1
        return original(*args)

    monkeypatch.setattr(store, "count_pages", count)
    processed = 0

    async def interrupted(state, page):
        nonlocal processed
        if processed == 1:
            raise BudgetExceeded("max_elapsed_seconds")
        store.update_page(page["page_id"], status="fetched")
        processed += 1

    monkeypatch.setattr(crawler, "_process_page", interrupted)
    try:
        with pytest.raises(BudgetExceeded):
            await crawler._drain_pages(st)
        assert calls == 1
        assert original(rid, st.seed["seed_id"], ("fetched",)) == 1

        async def complete(state, page):
            store.update_page(page["page_id"], status="failed")

        monkeypatch.setattr(crawler, "_process_page", complete)
        await crawler._drain_pages(st)
        assert calls == 2
        assert original(rid, st.seed["seed_id"], ("fetched", "failed", "not_html")) == 3
        assert original(rid, st.seed["seed_id"], ("excluded",)) == 5
        assert store.queued_pages(rid, st.seed["seed_id"]) == []
    finally:
        store.close()
