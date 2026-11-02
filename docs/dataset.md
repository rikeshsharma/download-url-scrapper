# Dataset quality, splits and features

## Coverage reporting

`coverage_report.json` / `coverage_summary.md` count verified direct downloads by:
detected file family, declared MIME, URL extension, size bucket, initiating domain,
destination domain, publisher, hosting provider (known CDN/storage suffixes, else
`unknown`), discovery method and label — plus seeds, pages, candidate statuses,
observation classes, error reasons, budget exhaustion and duplicate-payload stats.
Coverage only describes what was reachable in scope; it is not a census.

## Sampling targets and caps

`sampling.targets` declares desired counts per dimension value; shortfalls are listed
under `sampling_targets_unmet`. The tool never manufactures, duplicates or
synthesises samples to meet a target — the fix is more or different seeds.

Caps (`per_domain`, `per_publisher`, `per_content_hash`) keep a few prolific sources
from dominating. URL diversity is preserved: the same payload served from many URLs
stays visible (each URL is an observation) while `sha256` ties them together.

## Splits (`dataset_metadata.csv`)

* **`payload_split`** — deterministic hash of the SHA-256 (`split_salt`), so
  identical payloads are always on the same side. Different URLs serving the same
  bytes cannot leak across train/test.
* **`unseen_domain_split`** — for evaluating generalisation to new sites. Samples are
  grouped by `group_domain` (adapter publisher if known, else the seed's registrable
  domain). Hashes and group domains form a bipartite graph; each connected component
  (`payload_component`) is assigned as a unit, so a payload shared by two publishers
  is never in both unseen-domain train and test.
* **`temporal_split`** — with `dataset.temporal_cutoff`, samples whose payload was
  first seen at/after the cutoff are `temporal_test`. `first_seen_payload` is per
  SHA-256 so identical payloads share a side; `observed_at` gives the per-URL time.

### Shared hosting and CDNs

Grouping by the *final download host* would be wrong in both directions: one storage
host (e.g. an object store or release-asset CDN) serves thousands of unrelated
publishers and would collapse them into one group, while one publisher using several
CDNs would be split. The tool therefore groups by the publisher / linking site and
reports the destination host and hosting provider separately. If your detector keys
on hosting infrastructure, also evaluate a split grouped by
`destination_registrable_domain` (available in `download_observations.csv`).

## Features vs. labels vs. collection artefacts

`detector_features.csv` contains only information available **when the browser
decides how to handle a download** (download start): initiating/final URL, referrer
page, redirect count and domains, HTTP status, declared MIME, Content-Disposition,
suggested filename and extensions, declared length, trigger type, token flag.

Not available at the decision point and therefore excluded: SHA-256, detected type,
actual size, archive contents, inspection status (all require the complete file),
labels, evidence, scanner/reputation results, revalidation results. Collection
artefacts (`observation_id`, timestamps, `browser_config_id`, discovery method,
crawl depth) describe how the sample was gathered; join on `observation_id` only for
analysis, not as model inputs — discovery method and depth reflect this crawler, not
real user traffic.

Labels live in `labels.csv` (by SHA-256) and `download_observations.csv`; join them
to features explicitly when building training data.
