"""Progress counts distinguish completed seeds from budget-limited attempts."""

import asyncio
import logging
import io

from download_url_collector import pipeline
from download_url_collector.budget import Budget
from download_url_collector.crawler import Crawler
from download_url_collector.progress import TerminalProgress, progress_bar
from download_url_collector.logging_setup import ProgressStreamHandler


class TerminalBuffer(io.StringIO):
    def isatty(self):
        return True


def test_progress_counts_valid_completed_and_limited_seeds(cfg, tmp_path, monkeypatch, caplog):
    terminal = TerminalBuffer()
    monkeypatch.setattr("download_url_collector.crawler.TerminalProgress", lambda: TerminalProgress(terminal))
    seeds = tmp_path / "seeds.csv"
    seeds.write_text("url\nhttps://example.com/a\nhttps://example.com/b\n"
                     "https://example.com/c\nftp://example.com/invalid\n")
    store = pipeline.open_store(cfg)
    try:
        rid = pipeline.start_run(cfg, store, seeds)
        valid = [s for s in store.seeds(rid) if s["url"]]
        store.set_seed_status(valid[0]["seed_id"], "crawled")
        crawler = Crawler(cfg, store, rid, None, None, Budget(cfg.limits), [])

        async def crawl_seed(seed):
            status = "crawled" if seed["seed_id"] == valid[1]["seed_id"] else "crawling"
            store.set_seed_status(seed["seed_id"], status)

        monkeypatch.setattr(crawler, "_crawl_seed", crawl_seed)
        caplog.set_level(logging.INFO, logger="download_url_collector.crawler")
        asyncio.run(crawler.run())
        progress = [r for r in caplog.records if hasattr(r, "seeds_processed")]
        assert progress[0].seeds_processed == 1
        assert progress[0].seeds_total == 3
        assert progress[-1].seeds_processed == 2
        assert progress[-1].seeds_budget_limited == 1
        assert progress[-1].elapsed_seconds >= 0
        assert "elapsed 00:00:00" in progress[-1].getMessage()
        output = terminal.getvalue()
        assert "2/3 | elapsed" in output
        assert "| done | example.com" in output
        assert "| budget-limited | example.com" in output
        assert TerminalProgress.active is None
    finally:
        store.close()


def test_progress_reports_on_cancellation(cfg, tmp_path, monkeypatch, caplog):
    terminal = TerminalBuffer()
    monkeypatch.setattr("download_url_collector.crawler.TerminalProgress", lambda: TerminalProgress(terminal))
    seeds = tmp_path / "seeds.csv"
    seeds.write_text("url\nhttps://example.com/\n")
    store = pipeline.open_store(cfg)
    try:
        rid = pipeline.start_run(cfg, store, seeds)
        crawler = Crawler(cfg, store, rid, None, None, Budget(cfg.limits), [])

        async def crawl_seed(seed):
            raise asyncio.CancelledError

        monkeypatch.setattr(crawler, "_crawl_seed", crawl_seed)
        caplog.set_level(logging.INFO, logger="download_url_collector.crawler")

        async def run():
            try:
                await crawler.run()
            except asyncio.CancelledError:
                pass
            else:
                raise AssertionError("Cancellation must propagate")
            assert not [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]

        asyncio.run(run())
        progress = [r for r in caplog.records if hasattr(r, "seeds_processed")]
        assert len(progress) == 2
        assert progress[-1].seeds_processed == 0
        assert "| interrupted | example.com" in terminal.getvalue()
        assert TerminalProgress.active is None
    finally:
        store.close()


def test_unknown_work_and_completion():
    assert "  0%" in progress_bar(0, 0)
    assert " 99%" in progress_bar(5, 5)
    assert " 25%" in progress_bar(5, 20)
    assert "100%" in progress_bar(5, 5, complete=True)


def test_redirected_output_has_no_terminal_sequences():
    output = io.StringIO()
    display = TerminalProgress(output)
    display.update(["Seeds [###---]"])
    display.close()
    assert output.getvalue() == ""


def test_logs_are_written_above_bars():
    output = TerminalBuffer()
    display = TerminalProgress(output)
    try:
        display.update(["Seeds [###---]"])
        handler = ProgressStreamHandler(output)
        record = logging.LogRecord("test", logging.INFO, "", 0, "page fetched", (), None)
        handler.emit(record)
        assert "page fetched\nSeeds [###---]\n" in output.getvalue()
    finally:
        display.close()
