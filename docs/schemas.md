# Output schemas

## Conventions

* **Unknown vs empty.** An unquoted empty cell (`a,,c`) means unknown / not
  applicable (SQL `NULL`). A quoted empty cell (`a,"",c`) is a known empty string.
  `[]` / `{}` are known-empty lists/objects. `csvio.read_csv_nullable` parses this
  convention; standard CSV readers return `""` for both.
* **Structured values** (lists, objects) are compact JSON with sorted keys.
* **Malformed Unicode.** CSV exports represent unpaired surrogate code points
  from source data as literal backslash escapes (for example `\udcf1`) so one
  malformed value cannot abort an export. Valid Unicode is preserved, and the
  original database values remain unchanged.
* **Booleans** are `true` / `false`. **Timestamps** are UTC ISO-8601 (`...Z`).
* **URLs are exact.** Replay URLs are written as observed (resolved against the
  document base, minimal browser-style percent-encoding of spaces/non-ASCII, fragment
  removed). Query parameters are never removed, reordered or decoded; paths are never
  case-folded. `dedup_key` (candidates) is a separate conservative identity key.
* **Token-bearing URLs** are flagged (`url_has_token`, `url_sensitive_reasons`), not
  altered. Controlled outputs keep them exact; shareable reports and logs redact them.

## `verified_direct_download_urls.csv` / `benign_download_urls.csv`
Single column `url`, sorted, unique. *Verified* = latest direct-navigation or
revalidation observation of that exact URL is `direct_download`. *Benign* = verified
**and** the payload's current label (current policy version) is `benign_validated`.

## `download_candidates.csv`
`candidate_id, run_id, seed_id, seed_url, source_page, url, raw_href, dedup_key,
discovery_method, depth, is_external, link_text, download_attr, hints, publisher,
status, status_reason, probe_http_status, probe_declared_mime,
probe_content_disposition, probe_filename, probe_sniffed_family, probe_range_honored,
head_status, verification_classification, url_has_token, url_sensitive_reasons,
created_at`

`status`: `discovered`, `probed_likely_download`, `probed_html`, `probe_failed`,
`excluded` (reason: `robots_disallowed`, `blocked_*`, `redirect_out_of_scope`,
`trap_*`, `max_candidates_*`, `external_verification_disabled`), `capped`,
`verified`. `discovery_method`: `seed`, `html_anchor`,
`html_anchor_download_attr`, `html_area`, `html_embed`, `html_data_attribute`,
`meta_refresh`, `redirect`, `sitemap`, `directory_listing`, `page_fetch_non_html`,
`rendered_dom`, `browser_interaction_target`, `source_adapter`. `hints` are
discovery hints only (`ext:*`, `download_attribute`, `path_keyword`,
`query_keyword`, `link_text`).

## `download_observations.csv`
| Column | Meaning |
| --- | --- |
| `observation_id`, `run_id`, `candidate_id`, `seed_id`, `seed_url` | identifiers |
| `source_page` | page that linked the candidate / page interacted with |
| `initiating_url` | URL navigated to (direct) or page URL (interaction) |
| `final_url` | URL of the response that became the download (after redirects); `blob:`/`data:` for generated downloads |
| `redirect_chain`, `redirect_count` | `[{url,status,method,location[,blocked]}]` from the browser's network log |
| `source_registrable_domain`, `initiating_registrable_domain`, `destination_registrable_domain` | PSL eTLD+1 |
| `hosting_provider`, `publisher` | known CDN/storage provider of the final host; adapter publisher |
| `discovery_method`, `verification_mode` (`direct_navigation`, `page_interaction`, `revalidation`), `classification` | |
| `started_at`, `completed_at`, `browser_config_id` | |
| `http_status`, `declared_mime`, `content_disposition`, `content_disposition_filename` | from the browser-observed response |
| `suggested_filename` | Chromium's suggested filename |
| `url_extension`, `final_url_extension`, `suggested_filename_extension` | recorded separately |
| `detected_family`, `detected_mime` | from content (magic bytes / container inspection) |
| `type_discrepancies` | e.g. `declared_mime:text/plain!=detected:zip` |
| `size`, `sha256` | over the complete file |
| `download_state` | `completed`, `failed`, `canceled` (timeout), `none` |
| `download_trigger` | `navigation_response` or `script_or_subframe` |
| `navigation_aborted_for_download` | Playwright reported the navigation aborted because it became a download |
| `inspection_status`, `inspection_unresolved`, `file_stored` | |
| `label`, `policy_version`, `label_reasons`, `evidence_ids` | current label of the payload; empty when there is no file |
| `replay_status` | `url_replayable`, `requires_interaction`, `requires_session_context`, `not_url_replayable`, `renders_inline`, `not_replayable` |
| `failure_reason` | e.g. `http_status:410`, `download_failed:<browser reason>`, `byte_limit_exceeded`, `blocked_destination:<reason>`, `rendered_html_no_download`, `no_download_after_interaction` |
| `capped_reason`, `content_changed`, `previous_observation_id` | sampling and revalidation |
| `url_has_token`, `url_sensitive_reasons`, `feature_ref` | |

## `replay_manifest.jsonl`
One JSON object per interaction / session-dependent / generated observation:
`observation_id, classification, source_page, steps[{action: goto|click, url|selector,
...}], control{selector,text,tag,href,has_download_attr,scripted}, download_url,
download_url_is_context_bound, requires[interaction|cookies|post_data|method:*],
request_context{download_url,method,has_post_data,cookie_names,referer_sent,popup},
target_direct_replay_verified, sha256, browser_config_id, observed_at, replay_status`.
Cookie *names* only are recorded, never values.

## `crawl_errors.csv`
`error_id, run_id, stage (input|crawl|extract|sitemap|adapter|discovery|probe|render|verify),
seed_id, url, reason, details, created_at`.

## `labels.csv`
`sha256, label, policy_version, decided_at, reasons, evidence_ids` — full history.

## `dataset_metadata.csv`
`observation_id, sha256, initiating_url, group_domain, payload_component,
first_seen_payload, observed_at, payload_split (train|test),
unseen_domain_split (train|unseen_domain_test), temporal_split (train|temporal_test|empty),
in_sample, capped_reason`. See docs/dataset.md.

## `detector_features.csv`
`observation_id, initiating_url, final_url, referrer_page, redirect_count,
initiating_registrable_domain, final_registrable_domain, referrer_registrable_domain,
cross_domain_redirect, http_status, declared_mime, content_disposition,
suggested_filename, url_extension, suggested_filename_extension,
declared_content_length, download_trigger, url_has_token`.

## SQLite (`data_dir/collector.sqlite3`)
`runs`, `seeds`, `pages` (frontier; `queued` rows are resumed), `candidates`,
`browser_configs` (identity JSON keyed by `browser_config_id`), `files` (one row per
SHA-256: size, storage path, detected type, inspection), `observations`, `evidence`
(append-only, per SHA-256), `labels` (append-only, per SHA-256 + policy version),
`errors`, `api_quota`.
