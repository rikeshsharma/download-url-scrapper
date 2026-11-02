from __future__ import annotations

import asyncio
import io
import json
import logging
from pathlib import Path

import yaml
from click.testing import CliRunner
from conftest import make_config, requires_browser
from fixtures.server import FixtureSite

from download_url_collector.browser.integration import load_feature_collector
from download_url_collector.browser.verifier import BrowserVerifier
from download_url_collector.cli import main
from download_url_collector.crawler import sensitivity
from download_url_collector.inspection.inspector import FileStore
from download_url_collector.logging_setup import JsonFormatter
from download_url_collector.netpolicy import NetworkPolicy


def _write_cfg(tmp_path: Path, **overrides: object) -> Path:
    cfg = make_config(tmp_path, **overrides)
    p = tmp_path / "cfg.yaml"
    p.write_text(yaml.safe_dump(cfg.model_dump(mode="json")))
    return p


def test_cli_crawl_export_report(site: FixtureSite, tmp_path: Path) -> None:
    cfg = _write_cfg(tmp_path)
    seeds = tmp_path / "seeds.csv"
    seeds.write_text(f"url\n{site.base}/sitemap-only.html\nmailto:x@y\n")
    runner = CliRunner()
    res = runner.invoke(main, ["-c", str(cfg), "--log-level", "WARNING", "crawl", str(seeds)])
    assert res.exit_code == 0, res.output
    rid = res.output.strip().splitlines()[-1]
    out = tmp_path / "out"
    res = runner.invoke(main, ["-c", str(cfg), "export", "--run-id", rid, "--out", str(out)])
    assert res.exit_code == 0, res.output
    assert json.loads(res.output)["rows"]["download_candidates.csv"] >= 1
    res = runner.invoke(main, ["-c", str(cfg), "report", "--run-id", rid, "--out", str(out)])
    assert res.exit_code == 0 and "Collection summary" in res.output
    res = runner.invoke(main, ["-c", str(cfg), "runs"])
    assert rid in res.output


def test_cli_rejects_bad_config(tmp_path: Path) -> None:
    p = tmp_path / "bad.yaml"
    p.write_text("limits:\n  max_depht: 3\n")
    res = CliRunner().invoke(main, ["-c", str(p), "runs"])
    assert res.exit_code != 0 and "invalid configuration" in res.output


def test_cli_fails_clearly_for_uncontrollable_browser(tmp_path: Path) -> None:
    fake = tmp_path / "not-a-browser"
    fake.write_text("#!/bin/sh\nexit 1\n")
    fake.chmod(0o755)
    cfg = _write_cfg(tmp_path, browser={"executable_path": str(fake), "navigation_timeout_seconds": 5})
    res = CliRunner().invoke(main, ["-c", str(cfg), "browser-info"])
    assert res.exit_code == 3
    assert "browser unavailable" in res.output and "not-a-browser" in res.output


def test_log_redaction() -> None:
    cfg = make_config(Path("/tmp"))
    buf = io.StringIO()
    h = logging.StreamHandler(buf)
    h.setFormatter(JsonFormatter(sensitivity(cfg)))
    log = logging.getLogger("redaction-test")
    log.addHandler(h)
    log.setLevel(logging.INFO)
    log.info("fetch https://u:p@h/x?sig=SECRET&a=1", extra={"url": "https://h/y?token=T0K",
                                                          "headers": {"Authorization": "Bearer X"}})
    rec = json.loads(buf.getvalue())
    assert "SECRET" not in buf.getvalue() and "T0K" not in buf.getvalue() and "Bearer" not in buf.getvalue()
    assert rec["event"] == "fetch https://REDACTED@h/x?sig=REDACTED&a=1"


@requires_browser
def test_feature_collector_hook_called_before_navigation(site: FixtureSite, tmp_path: Path) -> None:
    import hook_impl

    cfg = make_config(tmp_path, browser={"feature_collector": "hook_impl:factory"})
    hook = load_feature_collector(cfg.browser.feature_collector, cfg)

    async def go():  # type: ignore[no-untyped-def]
        files = FileStore(tmp_path / "files", True, 10**9)
        async with BrowserVerifier(cfg, NetworkPolicy(cfg.network), files, hook) as v:
            return await v.verify_direct(site.base + "/files/sample.zip", candidate_id=None, source_page=None)

    obs = asyncio.run(go())
    kinds = [k for k, _ in hook_impl.CALLS]
    assert kinds[0] == "context" and hook_impl.CALLS[0][1] == 0
    assert "download" in kinds and kinds[-1] == "close"
    assert obs.feature_ref and obs.feature_ref.startswith("feature-record:")
