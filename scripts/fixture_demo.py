"""Small end-to-end run against the local fixture site, through the real CLI.

    .venv/bin/python scripts/fixture_demo.py [--out DIR]

Starts the deterministic fixture server on 127.0.0.1, writes a config that
allows only loopback (needed to reach the fixture) and uses the mock scanner in
"unavailable" mode, then runs `duc run`. Nothing touches the public internet.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
import tempfile
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))

from fixtures.server import FixtureSite  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", type=Path, default=None)
    args = ap.parse_args()
    work = args.out or Path(tempfile.mkdtemp(prefix="duc-demo-"))
    work.mkdir(parents=True, exist_ok=True)
    site = FixtureSite().start()
    try:
        cfg = {
            "collection": {"data_dir": str(work / "data")},
            "limits": {"per_host_min_interval_seconds": 0, "max_file_bytes": 1048576},
            "network": {"allow_cidrs": ["127.0.0.0/8", "::1/128"], "blocked_hostnames": [],
                        "blocked_hostname_suffixes": [], "allowed_ports": None},
            "browser": {"download_event_grace_seconds": 2, "interaction": {"post_click_wait_seconds": 3}},
            "inspection": {"archives": {"enabled": True}},
            "labeling": {"policy_file": str(ROOT / "config" / "labeling_policy.yaml"),
                         "scanner": {"type": "mock", "mock_default_verdict": "unavailable"}},
        }
        (work / "config.yaml").write_text(yaml.safe_dump(cfg))
        (work / "seeds.csv").write_text(f"url\n{site.base}/\nnot-a-url\n")
        out = work / "out"
        duc = [sys.executable, "-m", "download_url_collector.cli", "-c", str(work / "config.yaml"),
               "--log-level", "WARNING"]
        subprocess.run([*duc, "run", str(work / "seeds.csv"), "--out", str(out)], check=True)
        print((out / "coverage_summary.md").read_text())
        for name in ("verified_direct_download_urls.csv", "benign_download_urls.csv"):
            lines = (out / name).read_text().splitlines()
            print(f"{name}: {len(lines) - 1} rows")
        print(f"\nOutputs in {out}")
    finally:
        site.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
