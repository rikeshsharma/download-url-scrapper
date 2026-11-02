from __future__ import annotations

import os
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).parent))

from fixtures.server import FixtureSite  # noqa: E402

from download_url_collector.config import Config, load_config  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / "config" / "labeling_policy.yaml"


@pytest.fixture(scope="session")
def site() -> Iterator[FixtureSite]:
    s = FixtureSite().start()
    yield s
    s.stop()


def make_config(tmp_path: Path, **overrides: Any) -> Config:
    """Test configuration: the loopback fixture is explicitly allowed, all other
    non-global destinations (e.g. 169.254.169.254) stay blocked."""
    base: dict[str, Any] = {
        "collection": {"data_dir": str(tmp_path / "data")},
        "limits": {"per_host_min_interval_seconds": 0, "max_file_bytes": 1024 * 1024,
                   "max_depth": 2, "request_timeout_seconds": 10, "max_elapsed_seconds": 600},
        "politeness": {"max_retries": 1, "backoff_base_seconds": 0.05, "backoff_max_seconds": 0.2},
        "traps": {"max_urls_per_calendar_pattern": 3},
        "network": {"allow_cidrs": ["127.0.0.0/8", "::1/128"], "blocked_hostnames": ["metadata.google.internal"],
                    "blocked_hostname_suffixes": [], "allowed_ports": None},
        "browser": {"navigation_timeout_seconds": 15, "download_event_grace_seconds": 2.0,
                    "download_timeout_seconds": 30, "verify_concurrency": 2,
                    "interaction": {"post_click_wait_seconds": 3}},
        "labeling": {"policy_file": str(POLICY), "scanner": {"type": "mock", "mock_default_verdict": "unavailable"},
                     "checksum_discovery": True},
        "inspection": {"archives": {"enabled": True}},
    }
    return load_config(None, _merge(base, overrides))


def _merge(a: dict[str, Any], b: dict[str, Any]) -> dict[str, Any]:
    out = dict(a)
    for k, v in b.items():
        out[k] = _merge(out[k], v) if isinstance(v, dict) and isinstance(out.get(k), dict) else v
    return out


@pytest.fixture
def cfg(tmp_path: Path) -> Config:
    return make_config(tmp_path)


def browser_available() -> bool:
    if os.environ.get("DUC_SKIP_BROWSER"):
        return False
    try:
        from playwright.sync_api import sync_playwright

        with sync_playwright() as pw:
            return Path(pw.chromium.executable_path).exists()
    except Exception:
        return False


BROWSER = browser_available()
requires_browser = pytest.mark.skipif(not BROWSER, reason="Playwright Chromium not installed")
