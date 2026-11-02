# Labeling

Discovery and browser verification establish *how a URL behaves*, not *what a file
is*. Labeling is a separate stage (`duc label`) that records evidence per SHA-256
and applies a versioned policy (`config/labeling_policy.yaml`).

## States

Every sample starts as `unknown`. The policy is evaluated in this order; the first
matching state wins.

| State | Condition (default policy) |
| --- | --- |
| `malicious_evidence` | Any of: latest local AV result is a detection; hash report with ≥ 2 malicious engines; manual review `malicious`. |
| `suspicious` | Any of: publisher checksum mismatch; signature present but invalid; hash report with suspicious engines; manual review `suspicious`; executable content whose declared MIME/extension disagrees with its bytes. |
| `benign_validated` | **All** requirements — fresh clean local AV scan with a fresh signature DB (`av_scan_clean`) and complete inspection (`inspection_complete`) — **and ≥ 2 distinct positive facts**. |
| `benign_candidate` | ≥ 1 positive fact, no negative evidence (requirements may be missing; `reasons` lists them). |
| `unknown` | Otherwise. |

Positive facts (each counts once):

* `publisher_provenance` — source page, initiating URL and download host all match a
  publisher listed in `trusted_publishers`, all over HTTPS, and (by default) a
  publisher checksum matched. Popularity is never used.
* `trusted_signature` — valid code signature whose signer is listed for a trusted
  publisher (Authenticode via `osslsigncode`, where supported).
* `reputation_clean` — fresh hash report, 0 malicious / 0 suspicious, ≥ 50 engines.
* `manual_review_benign` — `duc review --verdict benign`.

### Why no single signal can validate

The policy loader rejects any policy where `benign_validated.min_independent_positive
< 2`, where `av_scan_clean` is not required, or where a requirement fact is listed as
positive evidence. Therefore:

* zero AV detections is necessary but never sufficient;
* an absent threat-feed entry (`not_found`) is recorded but is not positive evidence;
* a valid signature alone yields at most `benign_candidate`;
* a known or popular domain contributes nothing unless explicitly configured as a
  trusted publisher, and even then it is one fact.

Publisher checksums establish integrity *relative to the publisher* (the bytes are
what the publisher lists). They qualify provenance; on their own they are not
positive evidence. A mismatch is `suspicious`.

## Freshness and missing evidence

`max_evidence_age_days` sets how old each evidence type may be. Stale evidence is
ignored for promotion and named in `reasons` (`stale:av_scan:clamav`,
`stale:av_signature_db:clamav`, `unknown_signature_db_date:...`, `stale:reputation`).
A scanner that is unavailable or errors produces evidence with that verdict, which
blocks `benign_validated` (`missing_required:av_scan_clean`).

Inspection that is unresolved — encrypted, unsupported, truncated or oversized
archives, archive inspection disabled, size mismatch with declared length — blocks
`benign_validated` through `inspection_complete`.

## Evidence record

Each `evidence` row: `sha256, kind (av_scan|signature|reputation|publisher_checksum|
provenance|manual_review), source, verdict, tool_version, signature_db_version,
signature_db_date, details_json, observed_at`. Each `labels` row: `sha256, label,
policy_version, reasons, evidence_ids, decided_at`. Both tables are append-only.
Labels reference the exact evidence ids that justified them.

## Revalidation

`duc revalidate` re-verifies each direct-download URL in a fresh context. Every
attempt is a new observation linked to the previous one; if the bytes changed,
`content_changed=true` and the new hash starts unlabeled. Historical labels remain
attached to the old hash. URL lists use the latest observation per URL, so a URL whose
content changed is benign only if the *new* payload is validated.

## Adapters

* **Local scanner** — `ClamAVScanner` (`clamscan`/`clamdscan`; engine version, DB
  version and DB date parsed from `--version`). `MockScanner` for tests/dry runs.
* **Signatures** — `OsslsigncodeVerifier` for PE/MSI/CAB (trust depends on
  `signature.ca_file`); `MockSignatureVerifier`. macOS/Linux package signatures are
  not implemented and are recorded as unsupported.
* **Reputation** — optional VirusTotal v3 *hash lookup*. API key only from the
  environment (`VT_API_KEY`), per-minute pacing and a persistent daily quota. Files are
  never uploaded; nothing is uploaded automatically anywhere.

## Limitations

* AV engines and reputation services have false negatives; new or targeted
  malware frequently has zero detections. `benign_validated` means "met this policy
  with this evidence at this time", not "safe".
* Trusted publishers can be compromised (supply-chain attacks); provenance is
  evidence of origin, not of intent.
* Signature verification depends on the trust store and does not detect revoked
  but still-valid-looking certificates unless the tool checks revocation.
* Archive inspection lists members; it does not scan nested content separately.
