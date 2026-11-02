# download-url-collector

Collects HTTP(S) download URLs for training a malicious-download detector integrated
into a modified Chromium browser. It crawls a bounded scope around seed pages,
probes candidates over HTTP, **verifies actual download behaviour in Chromium**,
inspects completed files, and labels them through a **separate, versioned,
auditable policy**.

> **What this tool does not claim.** Discovery is not exhaustive: it finds what is
> reachable within the configured scope, limits, robots.txt and network policy.
> A verified download is **not** evidence that a file is benign. Only
> `benign_download_urls.csv` reflects the labeling policy, and even
> `benign_validated` is a policy outcome over recorded evidence, not a guarantee
> of safety.

## Pipeline

```
seeds.csv ─► crawl (HTTP: pages, sitemaps, listings, adapters) ─► probe (HEAD optional + bounded GET)
          ─► verify (Chromium: direct navigation in fresh contexts, recorded interactions)
          ─► inspect (SHA-256, magic bytes, discrepancies, bounded archive listing)
          ─► label (local AV, signatures, checksums, provenance, optional reputation, manual review)
          ─► export / report
```

| Module | Responsibility |
| --- | --- |
| `discovery/` | HTML extraction (base URL aware), sitemaps, directory listings, hints, crawl-trap detection, source adapters |
| `netpolicy.py`, `browser/proxy.py` | Destination policy (private/reserved/metadata blocks, DNS-rebinding-safe), egress proxy for browser traffic |
| `http_client.py`, `robots.py`, `ratelimit.py`, `budget.py` | Hop-by-hop policy enforcement, robots.txt (RFC 9309), per-host politeness, Retry-After, backoff, run budgets |
| `probe.py` | Bounded HEAD/GET probing; Content-Disposition parsing; content sniffing |
| `browser/` | Launch + identity recording, verification, interaction replay, feature-collector hook |
| `inspection/` | File typing, discrepancy detection, archive inspection, content-addressed storage |
| `labeling/` | Scanners, signature verifiers, checksums, reputation, policy, labeler |
| `storage.py` | SQLite state for resumable runs |
| `export.py`, `report.py`, `dataset.py` | Outputs, coverage, leakage-safe splits |

## Installation

Python ≥ 3.11.

```bash
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"
.venv/bin/playwright install chromium      # full Chromium + headless shell
# optional, for labeling:
brew install clamav  # or apt-get install clamav; then run freshclam
```

## Quick start

```bash
cp config/example.yaml my.yaml           # edit contact UA, scope, limits, scanner
.venv/bin/duc -c my.yaml browser-info    # confirm the browser can be controlled
.venv/bin/duc -c my.yaml crawl examples/seeds.csv     # prints the run id
.venv/bin/duc -c my.yaml verify          # latest run by default; --run-id to choose
.venv/bin/duc -c my.yaml label
.venv/bin/duc -c my.yaml export --out out/
.venv/bin/duc -c my.yaml report --out out/
# or all at once:
.venv/bin/duc -c my.yaml run examples/seeds.csv --out out/
```

The seeds in `examples/seeds.csv` are starting points for discovery, **not**
prevalidated benign labels. One row is intentionally invalid to show that bad rows
are reported (in `crawl_errors.csv`) without aborting the run.

During crawling, INFO logs show elapsed time (`HH:MM:SS`) and processed/total
valid seeds at startup, every 10 seconds, after each seed, and when crawling stops.
Processed seeds have finished crawling under the configured scope and limits;
seeds interrupted by a global budget are counted separately as budget-limited.
On resume, the processed count includes seeds completed earlier, while elapsed
time measures the current crawl invocation. This also applies to `run` and `resume`.

In an interactive terminal, live bars additionally show overall seed completion
and the pages/probes processed for each active seed, refreshed every second.
Per-seed percentages cover currently discovered work and may decrease when more
links are found. Only finished seeds show 100%; budget-limited or interrupted
seeds remain incomplete. Invalid seed rows are excluded from the total. Bars
are disabled when stderr is redirected; JSON logs and `--log-file` stay unchanged.

Per-seed page and candidate lookups use indexes on `(run_id, seed_id, status)`.
Existing databases receive these indexes automatically when opened by the CLI;
the first open may take longer while SQLite builds them. Crawl counters are
initialized from saved records and reused during each seed's processing to avoid
recounting for every link or page. Limits and excluded-record retention are unchanged.

## Commands

| Command | Purpose |
| --- | --- |
| `crawl SEEDS.csv` | Create a run, validate seeds, crawl and probe. |
| `verify [--run-id]` | Render seed pages / pages with download controls, click recorded controls, then verify each candidate by direct navigation in a fresh context. |
| `label [--run-id] [--force]` | Collect evidence per file hash and apply the policy. |
| `review --sha256 --verdict --reviewer` | Record a manual review as evidence. |
| `revalidate [--run-id] [--limit]` | Re-verify direct-download URLs; each attempt is a new observation; content changes are flagged; labels stay with their hash. Re-labels by default. |
| `export [--run-id] [--out]` | Write CSV/JSONL outputs. |
| `report [--run-id] [--out]` | Write `coverage_report.json` + `coverage_summary.md` (redacted, shareable). |
| `resume [--run-id] [--no-browser]` | Continue an interrupted or budget-limited run. |
| `run SEEDS.csv` | crawl → verify → label → export → report. |
| `browser-info` | Launch the configured browser and print its identity; exits with code 3 and an explanation if it cannot be controlled. |
| `runs` | List runs. |

Global options: `-c/--config`, `--log-level`, `--log-file` (JSON lines, URLs and
credentials redacted).

## Outputs

| File | Audience | Content |
| --- | --- | --- |
| `download_candidates.csv` | controlled | Every discovered candidate with status/reason and probe metadata |
| `verified_direct_download_urls.csv` | controlled | Single `url` column: unique URLs whose latest direct-navigation check in a fresh context completed a download — **regardless of label** |
| `benign_download_urls.csv` | controlled | Single `url` column: subset of the above whose payload is `benign_validated` under the current policy version |
| `download_observations.csv` | controlled | One row per browser observation (all six classes) |
| `replay_manifest.jsonl` | controlled | Interaction, session-dependent and generated downloads with structured replay steps |
| `crawl_errors.csv` | controlled | Input errors, exclusions (robots, scope, policy, traps, budgets) and failures |
| `labels.csv` | controlled | Full label history per SHA-256 with reasons and evidence ids |
| `dataset_metadata.csv` | controlled | Payload/unseen-domain/temporal splits and sampling caps |
| `detector_features.csv` | controlled | Only features available at the detector's decision point |
| `run_manifest.json` | controlled | Config, policy version, browser identities, budgets |
| `coverage_report.json`, `coverage_summary.md` | shareable | Coverage, unmet sampling targets, errors — URLs redacted |

"Controlled" outputs contain exact replay URLs, which may embed tokens. They are
flagged (`url_has_token`, `url_sensitive_reasons`), never silently altered. See
[docs/schemas.md](docs/schemas.md).

## Observation classes

| Class | Meaning | In URL-only output? |
| --- | --- | --- |
| `direct_download` | Direct navigation in a fresh context completed a download | yes |
| `interaction_download` | A recorded click on the source page triggered a download | no (replay manifest) |
| `session_dependent` | Replay needs cookies, POST data, non-GET method or similar | no (replay manifest) |
| `generated_download` | A `blob:`/`data:` URL produced the file | no (replay manifest) |
| `inline_resource` | Chromium rendered the response instead of downloading | no |
| `failed_or_unverified` | Errors, HTTP failures, blocked destinations, byte limits, truncation | no |

## End-to-end fixture run

`scripts/fixture_demo.py` starts the deterministic local fixture site and runs the
real CLI (`duc run`) against it — no public websites involved:

```bash
.venv/bin/python scripts/fixture_demo.py --out /tmp/duc-demo
```

Actual output from a run on macOS 27 (arm64), Chromium 156.0.8078.4, Playwright 1.64.1:

```
- Seeds: 1 valid, 1 invalid
- Pages: fetched=12
- Candidates: excluded=2, probed_html=5, verified=21
- Observations: inline_resource=2, interaction_download=3, direct_download=15,
  generated_download=1, session_dependent=2, failed_or_unverified=4
- Verified direct-download URLs: 15 (12 unique payloads; 2 payloads seen at >1 URL)
...
verified_direct_download_urls.csv: 15 rows
benign_download_urls.csv: 0 rows
```

`benign_download_urls.csv` is empty because the demo's scanner reports
"unavailable": verified downloads without a fresh clean scan can never be
`benign_validated`.

## Tests

```bash
.venv/bin/pytest -q                 # all tests; browser tests auto-skip without Chromium
DUC_SKIP_BROWSER=1 .venv/bin/pytest -q   # force-skip browser tests
```

The suite uses only local fixtures (`tests/fixtures/server.py`) with harmless
generated payloads. It covers direct downloads, extensionless and query-dependent
endpoints, redirects, external targets, rejected HEAD, ignored Range, inline PDF and
text, misleading MIME types, JavaScript, popup, blob, POST- and cookie-dependent
downloads, expired links, interrupted transfers, byte limits, duplicate payloads,
robots exclusions, blocked private-network redirects (HTTP client, proxy and
browser), crawl traps, budget exhaustion + resume, revalidation, labeling policy
semantics, CLI behaviour and log redaction.

## Documentation

- [docs/configuration.md](docs/configuration.md) — every option and its default
- [docs/schemas.md](docs/schemas.md) — output columns, conventions, SQLite tables
- [docs/labeling.md](docs/labeling.md) — label states, evidence, policy, limitations
- [docs/browser-integration.md](docs/browser-integration.md) — custom Chromium, identity, compatibility, feature-collector hook
- [docs/security.md](docs/security.md) — network restrictions, isolation, file handling, what needs external controls
- [docs/dataset.md](docs/dataset.md) — coverage, sampling, splits, CDN grouping, decision-point features
