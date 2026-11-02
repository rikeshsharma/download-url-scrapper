"""Shared enumerations and small value types."""

from __future__ import annotations

import datetime as _dt
import uuid
from enum import StrEnum


class Classification(StrEnum):
    DIRECT_DOWNLOAD = "direct_download"
    INTERACTION_DOWNLOAD = "interaction_download"
    SESSION_DEPENDENT = "session_dependent"
    GENERATED_DOWNLOAD = "generated_download"
    INLINE_RESOURCE = "inline_resource"
    FAILED_OR_UNVERIFIED = "failed_or_unverified"


class VerificationMode(StrEnum):
    DIRECT = "direct_navigation"
    INTERACTION = "page_interaction"
    REVALIDATION = "revalidation"


class Label(StrEnum):
    UNKNOWN = "unknown"
    BENIGN_CANDIDATE = "benign_candidate"
    BENIGN_VALIDATED = "benign_validated"
    SUSPICIOUS = "suspicious"
    MALICIOUS_EVIDENCE = "malicious_evidence"


class CandidateStatus(StrEnum):
    DISCOVERED = "discovered"
    PROBED_DOWNLOAD = "probed_likely_download"
    PROBED_HTML = "probed_html"
    PROBE_FAILED = "probe_failed"
    EXCLUDED = "excluded"
    CAPPED = "capped"
    VERIFIED = "verified"


class PageStatus(StrEnum):
    QUEUED = "queued"
    FETCHED = "fetched"
    NOT_HTML = "not_html"
    FAILED = "failed"
    EXCLUDED = "excluded"


class DiscoveryMethod(StrEnum):
    SEED = "seed"
    ANCHOR = "html_anchor"
    ANCHOR_DOWNLOAD_ATTR = "html_anchor_download_attr"
    AREA = "html_area"
    EMBED = "html_embed"
    DATA_ATTRIBUTE = "html_data_attribute"
    META_REFRESH = "meta_refresh"
    REDIRECT = "redirect"
    SITEMAP = "sitemap"
    DIRECTORY_LISTING = "directory_listing"
    ENDPOINT = "page_fetch_non_html"
    RENDERED_DOM = "rendered_dom"
    BROWSER_INTERACTION = "browser_interaction_target"
    ADAPTER = "source_adapter"


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex}"


def utcnow() -> str:
    return _dt.datetime.now(_dt.UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def parse_ts(ts: str) -> _dt.datetime:
    return _dt.datetime.fromisoformat(ts.replace("Z", "+00:00"))
