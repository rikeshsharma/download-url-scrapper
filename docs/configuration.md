# Configuration

YAML, validated strictly (unknown keys are errors). Every key is optional; the
defaults below are conservative. Relative paths resolve against the config file's
directory. `config/example.yaml` lists every section.

The effective configuration is hashed (`config_fingerprint`) and stored with the
run; it is reproduced in `run_manifest.json`.

## `collection`
| Key | Default | Notes |
| --- | --- | --- |
| `name` | `default` | Label only. |
| `data_dir` | `./data` | SQLite DB (`collector.sqlite3`), stored files (`files/`), default exports. |
| `user_agent` | `download-url-collector/0.1 (...)` | Used by the HTTP client. Put a real contact address here. The browser keeps its own UA. |
| `robots_user_agent_token` | `download-url-collector` | Token matched against robots.txt groups. |

## `scope`
| Key | Default | Notes |
| --- | --- | --- |
| `include_subdomains` | `false` | Crawl pages on any host with the seed's registrable domain (Public Suffix List). |
| `additional_domains` | `[]` | Extra domains (and their subdomains) whose pages may be crawled. |
| `verify_external_downloads` | `true` | Probe/verify download-hinted links on other hosts. They are never crawled for more links. |
| `follow_external_redirects` | `true` | Allow candidate redirects to leave scope (CDN hand-offs). Page fetches never leave crawl scope; an in-scope page that redirects off-site becomes a candidate. |
| `psl_file` | `null` | Local PSL file. `null` uses the snapshot bundled with `tldextract` (no network fetch). |

## `limits`
| Key | Default | Notes |
| --- | --- | --- |
| `max_depth` | 2 | Link depth from the seed. |
| `max_pages_per_seed` / `max_pages_total` | 50 / 500 | |
| `max_candidates_per_seed` / `max_candidates_total` | 100 / 1000 | Excess candidates are recorded as excluded. |
| `max_requests_total` | 3000 | All HTTP requests including robots, sitemaps, retries. |
| `max_elapsed_seconds` | 1800 | Per CLI invocation (resets on `resume`). |
| `max_download_bytes_total` | 2 GiB | HTTP bodies + browser traffic through the egress proxy. |
| `max_file_bytes` | 200 MiB | Per download, enforced during transfer by the proxy (with 256 KiB framing slack) and re-checked after. |
| `max_html_bytes` | 5 MiB | Page bodies. Non-HTML responses read only `probe_sniff_bytes`. |
| `probe_sniff_bytes` | 64 KiB | Ranged GET sample size. |
| `concurrency` | 4 | Global HTTP concurrency and concurrent seeds. |
| `per_host_concurrency` | 1 | |
| `per_host_min_interval_seconds` | 1.0 | Raised by robots.txt `Crawl-delay` (capped by `politeness.max_crawl_delay_seconds`). |
| `max_redirects` | 10 | Per request. |
| `max_meta_refresh` | 2 | Chained meta-refresh / `Refresh` header hops. |
| `max_sitemap_files` / `max_sitemap_urls` | 10 / 2000 | Seed origin only. |
| `request_timeout_seconds` | 30 | Connect and read timeouts. |

## `politeness`
`max_retries` (3), `backoff_base_seconds` (1), `backoff_max_seconds` (60): exponential
backoff with jitter on 429/503 without `Retry-After` and on connection errors.
`max_retry_after_seconds` (300): a longer `Retry-After` is not waited for; the
response is recorded instead. `use_head` (true): optional HEAD before the bounded
GET. robots.txt is always honoured; there is no option to disable it.

## `traps`
`max_url_length`, `max_path_segments`, `max_repeated_segment`, `max_query_params`,
`max_repeated_param`, `max_urls_per_pattern` (pages per host+path-shape+param-names
pattern), `max_urls_per_calendar_pattern` (stricter for date-like URLs),
`max_candidates_per_pattern`.

## `network`
| Key | Default | Notes |
| --- | --- | --- |
| `allow_cidrs` | `[]` | Exemptions from the non-global-address block. **Leave empty in production.** Tests use `127.0.0.0/8` to reach the fixture. |
| `blocked_hostnames` | localhost, metadata names | Exact names. |
| `blocked_hostname_suffixes` | `.localhost .local .internal .home.arpa` | |
| `allowed_ports` | `[80, 443, 8080, 8443]` | `null` allows any port. |

## `browser`
| Key | Default | Notes |
| --- | --- | --- |
| `enabled` | true | `verify` refuses to run when false. |
| `executable_path` | null | Path to the modified Chromium build. Overrides `channel`. |
| `channel` | `chromium` | Full Chromium in new-headless mode. Set `null` to use `chrome-headless-shell`, which **downloads PDFs instead of rendering them** — see docs/browser-integration.md. |
| `headless` | true | |
| `chromium_sandbox` | true | Keep on. Some containers require disabling; document the reason. |
| `extra_args` | `[]` | Appended to the base flags. Do not add flags that change download behaviour. |
| `navigation_timeout_seconds` | 30 | |
| `download_event_grace_seconds` | 4 | Wait after load for script-initiated downloads. |
| `download_timeout_seconds` | 300 | Then the download is cancelled and recorded as `download_timeout`. |
| `verify_concurrency` | 2 | Parallel fresh contexts. |
| `render_seed_pages` / `render_pages_with_controls` | true / true | Which pages are rendered for DOM links and controls. |
| `verify_probe_failure_statuses` | `[401,403,406,410,429]` | Probe failures with these statuses are still checked in the browser (results recorded honestly; no auth bypass). |
| `interaction.enabled` / `max_controls_per_page` / `post_click_wait_seconds` | true / 5 / 5 | |
| `egress_proxy` | true | Route all browser traffic through the in-process filtering proxy. |
| `allow_unfiltered_browser_network` | false | Required to set `egress_proxy: false`; only with an external egress filter. |
| `feature_collector` | null | `module:factory` for the custom feature collector hook. |

## `inspection.archives`
`enabled` (false), `max_members` (1000), `max_total_uncompressed_bytes` (512 MiB),
`max_compression_ratio` (100), `max_listed_members` (50). When disabled, archive
files are `unresolved` (and so cannot become `benign_validated` under the default
policy).

## `storage`
`keep_files` (true), `max_storage_bytes` (5 GiB). Beyond the limit, files are hashed
and inspected but not kept (`file_stored=false`, `storage_note`).

## `sampling`
`targets`: `{dimension: {value: count}}` over the coverage dimensions (`family`,
`declared_mime`, `extension`, `size`, `domain`, `destination_domain`, `publisher`,
`hosting_provider`, `discovery_method`, `label`). Unmet targets are reported, never
filled artificially. `caps.per_domain` / `caps.per_publisher` stop verifying more
candidates once that many direct downloads exist (status `capped`).
`caps.per_content_hash` marks additional observations of an identical payload
`capped_reason=per_content_hash` (`in_sample=false` in `dataset_metadata.csv`); they
remain in the verified URL list because URL diversity is preserved.

## `adapters.github_releases`
`enabled` (false), `api_base`, `web_hosts` (`[github.com]`), `token_env`
(`GITHUB_TOKEN`, optional), `max_releases`, `max_assets`. Respects
`X-RateLimit-Remaining/Reset` and robots.txt of the API origin.

## `labeling`
`policy_file` (see docs/labeling.md); `scanner.type` `clamav|mock|none`,
`scanner.binary`, `scanner.timeout_seconds`, `scanner.mock_default_verdict`,
`scanner.mock_verdicts`; `signature.type` `osslsigncode|mock|none`, `signature.ca_file`;
`reputation.enabled` (false), `reputation.api_key_env` (`VT_API_KEY`),
`reputation.base_url`, `reputation.requests_per_minute` (4), `reputation.daily_quota`
(500); `checksum_discovery` (true).

## `dataset`
`test_fraction` (0.2), `unseen_domain_fraction` (0.15), `temporal_cutoff` (ISO-8601 or
null), `split_salt`.

## `privacy`
`sensitive_params`: parameter names whose values are redacted in logs and shareable
reports and which flag a URL as token-bearing. `token_value_min_length` (32): long
opaque values are flagged too.
