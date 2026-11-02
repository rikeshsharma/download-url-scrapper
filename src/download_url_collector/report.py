"""Coverage reporting (shareable: contains no unredacted URLs)."""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from .config import Config
from .crawler import sensitivity
from .export import Exporter, hosting_provider
from .models import Classification, Label
from .storage import Store, loads
from .urls import hostname, path_extension, redact_url, registrable_domain

SIZE_BUCKETS = [(100 * 1024, "<100KiB"), (1024**2, "100KiB-1MiB"), (10 * 1024**2, "1-10MiB"),
                (100 * 1024**2, "10-100MiB")]


def size_bucket(size: int | None) -> str:
    if size is None:
        return "unknown"
    for limit, name in SIZE_BUCKETS:
        if size < limit:
            return name
    return ">=100MiB"


def build_report(cfg: Config, store: Store, run_id: str) -> dict[str, Any]:
    ex = Exporter(cfg, store, run_id)  # reuse lookup helpers; writes nothing
    sens = sensitivity(cfg)

    run = store.get_run(run_id)
    assert run is not None
    seeds = store.seeds(run_id)
    pages = store.query("SELECT status, COUNT(*) n FROM pages WHERE run_id=? GROUP BY status", [run_id])
    cands = store.query("SELECT status, COUNT(*) n FROM candidates WHERE run_id=? GROUP BY status", [run_id])
    obs = store.observations(run_id)
    errors = Counter(f"{e['stage']}:{e['reason'].split(':')[0]}" for e in store.errors(run_id))

    latest = ex.latest_direct_by_url()
    direct = [o for o in latest.values() if o["classification"] == Classification.DIRECT_DOWNLOAD]
    dims: dict[str, Counter[str]] = defaultdict(Counter)
    payload_urls: dict[str, set[str]] = defaultdict(set)
    token_urls = 0
    for o in direct:
        extra = loads(o["extra_json"]) or {}
        cand = ex._cands.get(o["candidate_id"]) if o["candidate_id"] else None
        final_http = o["final_url"] if o["final_url"] and o["final_url"].startswith("http") else None
        lbl = ex._label(o["sha256"])
        dims["family"][extra.get("detected_family") or "unknown"] += 1
        dims["declared_mime"][(extra.get("declared_mime") or "absent").split(";")[0].strip().lower()] += 1
        dims["extension"][path_extension(o["initiating_url"]) or "none"] += 1
        dims["size"][size_bucket(o["size"])] += 1
        dims["domain"][registrable_domain(hostname(o["initiating_url"]))] += 1
        dims["destination_domain"][registrable_domain(hostname(final_http)) if final_http else "unknown"] += 1
        dims["publisher"][(cand["publisher"] if cand and cand["publisher"] else "unknown")] += 1
        dims["hosting_provider"][hosting_provider(hostname(final_http or o["initiating_url"])) or "unknown"] += 1
        dims["discovery_method"][cand["discovery_method"] if cand else "unknown"] += 1
        dims["label"][lbl["label"] if lbl else Label.UNKNOWN.value] += 1
        if o["sha256"]:
            payload_urls[o["sha256"]].add(o["initiating_url"])
        if extra.get("initiating_url_sensitive"):
            token_urls += 1

    unmet = []
    for dim, targets in cfg.sampling.targets.items():
        for value, target in targets.items():
            actual = dims.get(dim, Counter()).get(value, 0)
            if actual < target:
                unmet.append({"dimension": dim, "value": value, "target": target, "actual": actual,
                              "shortfall": target - actual})

    dup_payloads = {sha: len(urls) for sha, urls in payload_urls.items() if len(urls) > 1}
    return {
        "run_id": run_id,
        "status": run["status"],
        "config_fingerprint": run["config_fingerprint"],
        "notice": ("Coverage reflects only what was discoverable within configured scope and limits; it is "
                   "not exhaustive. Verified downloads are not established to be benign."),
        "seeds": {"valid": sum(1 for s in seeds if s["url"]), "invalid": sum(1 for s in seeds if not s["url"]),
                  "by_status": dict(Counter(s["status"] for s in seeds))},
        "pages": {r["status"]: r["n"] for r in pages},
        "candidates": {r["status"]: r["n"] for r in cands},
        "observations_by_classification": dict(Counter(o["classification"] for o in obs)),
        "observations_by_mode": dict(Counter(o["verification_mode"] for o in obs)),
        "verified_direct_download_urls": len(direct),
        "unique_payloads": len(payload_urls),
        "payloads_with_multiple_urls": len(dup_payloads),
        "max_urls_per_payload": max(dup_payloads.values(), default=1 if payload_urls else 0),
        "token_bearing_direct_urls": token_urls,
        "coverage": {k: dict(v.most_common()) for k, v in sorted(dims.items())},
        "sampling_targets_unmet": unmet,
        "errors_by_reason": dict(errors.most_common()),
        "budget": {"counters": loads(run["counters_json"]), "exhausted": loads(run["budget_exhausted_json"])},
        "example_failures": [
            {"url": redact_url(o["initiating_url"], sens), "reason": o["failure_reason"]}
            for o in obs if o["classification"] == Classification.FAILED_OR_UNVERIFIED][:20],
    }


def write_report(cfg: Config, store: Store, run_id: str, out_dir: Path) -> dict[str, Any]:
    out_dir.mkdir(parents=True, exist_ok=True)
    rep = build_report(cfg, store, run_id)
    (out_dir / "coverage_report.json").write_text(json.dumps(rep, indent=2, sort_keys=True, default=str))
    (out_dir / "coverage_summary.md").write_text(render_summary(rep))
    return rep


def render_summary(rep: dict[str, Any]) -> str:
    lines = [f"# Collection summary — {rep['run_id']}", "", f"> {rep['notice']}", "",
             f"- Run status: **{rep['status']}** (config `{rep['config_fingerprint']}`)",
             f"- Seeds: {rep['seeds']['valid']} valid, {rep['seeds']['invalid']} invalid",
             f"- Pages: {_fmt(rep['pages'])}",
             f"- Candidates: {_fmt(rep['candidates'])}",
             f"- Observations: {_fmt(rep['observations_by_classification'])}",
             f"- Verified direct-download URLs: **{rep['verified_direct_download_urls']}** "
             f"({rep['unique_payloads']} unique payloads; {rep['payloads_with_multiple_urls']} payloads seen at >1 URL)",
             f"- Token-bearing direct URLs (flagged, not altered): {rep['token_bearing_direct_urls']}",
             f"- Budget exhausted: {', '.join(rep['budget']['exhausted'] or []) or 'none'}", ""]
    lines.append("## Coverage")
    for dim, counts in rep["coverage"].items():
        lines.append(f"- **{dim}**: {_fmt(counts, limit=12)}")
    lines += ["", "## Sampling targets not met"]
    if rep["sampling_targets_unmet"]:
        for u in rep["sampling_targets_unmet"]:
            lines.append(f"- {u['dimension']}={u['value']}: {u['actual']}/{u['target']} (short {u['shortfall']})")
    else:
        lines.append("- none configured or all met")
    lines += ["", "## Errors and exclusions (top)"]
    for reason, n in list(rep["errors_by_reason"].items())[:20]:
        lines.append(f"- {reason}: {n}")
    return "\n".join(lines) + "\n"


def _fmt(d: dict[str, Any], limit: int = 50) -> str:
    items = list(d.items())[:limit]
    return ", ".join(f"{k}={v}" for k, v in items) or "none"
