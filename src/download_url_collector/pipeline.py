"""Stage orchestration: start/resume runs, crawl, browser-verify, revalidate, label."""

from __future__ import annotations

import asyncio
import logging
import sqlite3
from collections import Counter
from contextlib import AsyncExitStack
from pathlib import Path
from typing import Any

from .browser.environment import BrowserUnavailable
from .browser.integration import load_feature_collector
from .browser.verifier import BrowserVerifier, Observation
from .budget import Budget, BudgetExceeded
from .config import Config
from .crawler import Crawler, SeedState, sensitivity
from .discovery.adapters import build_adapters
from .discovery.html import ExtractedLink
from .discovery.traps import TrapDetector
from .http_client import PolicyHttpClient
from .inputs import read_seeds
from .inspection.inspector import FileStore
from .labeling.labeler import Labeler
from .labeling.policy import load_policy
from .labeling.reputation import VirusTotalLookup
from .labeling.scanners import build_scanner
from .labeling.signatures import build_signature_verifier
from .models import CandidateStatus, Classification, DiscoveryMethod, VerificationMode
from .netpolicy import NetworkPolicy
from .robots import RobotsCache
from .scope import Scope
from .storage import Store, loads
from .urls import (
    configure_psl,
    dedup_key,
    filename_extension,
    hostname,
    path_extension,
    registrable_domain,
    sensitive_findings,
)

log = logging.getLogger(__name__)


def open_store(cfg: Config) -> Store:
    return Store(cfg.collection.data_dir / "collector.sqlite3")


def start_run(cfg: Config, store: Store, seeds_path: Path, run_id: str | None = None) -> str:
    configure_psl(cfg.scope.psl_file)
    rows = read_seeds(seeds_path)
    run_id = store.create_run(cfg.model_dump(mode="json"), cfg.fingerprint(), str(seeds_path), run_id)
    for r in rows:
        status = "pending" if r.url else "invalid"
        seed_id = store.add_seed(run_id, r.row_number, r.raw_url, r.url, status, r.error,
                                 registrable_domain(hostname(r.url)) if r.url else None)
        if r.error:
            store.add_error(run_id, "input", r.raw_url or None, r.error, f"row {r.row_number}", seed_id)
    log.info("run_created", extra={"run_id": run_id, "seeds": sum(1 for r in rows if r.url),
                                   "invalid_rows": sum(1 for r in rows if r.error)})
    return run_id


class Runtime:
    """Shared per-invocation resources (budget restored from the run)."""

    def __init__(self, cfg: Config, store: Store, run_id: str) -> None:
        configure_psl(cfg.scope.psl_file)
        self.cfg = cfg
        self.store = store
        self.run_id = run_id
        run = store.get_run(run_id)
        if run is None:
            raise KeyError(f"unknown run {run_id}")
        self.budget = Budget(cfg.limits)
        self.budget.restore(loads(run["counters_json"]) or {})
        self.policy = NetworkPolicy(cfg.network)
        self.client = PolicyHttpClient(cfg, self.policy, self.budget)
        self.robots = RobotsCache(self.client, cfg.collection.robots_user_agent_token,
                                  cfg.politeness.max_crawl_delay_seconds)
        self.client.robots_check = self.robots.allowed
        self._stack = AsyncExitStack()

    async def __aenter__(self) -> Runtime:
        await self._stack.enter_async_context(self.client)
        return self

    async def __aexit__(self, *exc: object) -> None:
        self.store.update_run(self.run_id, counters_json=self.budget.snapshot(),
                              budget_exhausted_json=sorted(self.budget.exhausted))
        await self._stack.aclose()

    def crawler(self) -> Crawler:
        return Crawler(self.cfg, self.store, self.run_id, self.client, self.robots, self.budget,
                       build_adapters(self.cfg))


async def crawl(cfg: Config, store: Store, run_id: str) -> None:
    async with Runtime(cfg, store, run_id) as rt:
        store.update_run(run_id, status="crawling")
        await rt.crawler().run()
        store.update_run(run_id, status="crawled")


# ---------------------------------------------------------------------------
# Browser verification
# ---------------------------------------------------------------------------

class VerificationStage:
    def __init__(self, rt: Runtime, verifier: BrowserVerifier) -> None:
        self.rt = rt
        self.cfg = rt.cfg
        self.store = rt.store
        self.run_id = rt.run_id
        self.v = verifier
        self.sens = sensitivity(rt.cfg)
        self.domain_counts: Counter[str] = Counter()
        self.publisher_counts: Counter[str] = Counter()
        for o in self.store.query(
                "SELECT o.initiating_url, c.publisher FROM observations o LEFT JOIN candidates c "
                "ON c.candidate_id=o.candidate_id WHERE o.run_id=? AND o.classification=?",
                [self.run_id, Classification.DIRECT_DOWNLOAD]):
            self.domain_counts[registrable_domain(hostname(o["initiating_url"]))] += 1
            if o["publisher"]:
                self.publisher_counts[o["publisher"]] += 1

    # -- recording -------------------------------------------------------------
    def record(self, obs: Observation, candidate: sqlite3.Row | None, seed_id: str | None,
               previous: sqlite3.Row | None = None) -> str:
        insp = obs.inspection
        capped: str | None = None
        if insp is not None:
            self.store.upsert_file(insp.sha256, insp.size, obs.storage_path, obs.stored,
                                   insp.detected_family, insp.detected_mime, insp.status, insp.to_dict())
            cap = self.cfg.sampling.caps.per_content_hash
            if cap is not None and self.store.count_observations_for_hash(self.run_id, insp.sha256) >= cap:
                capped = "per_content_hash"
        headers = obs.http.get("headers") or {}
        from .probe import parse_content_disposition

        cd = parse_content_disposition(headers.get("content-disposition"))
        final_for_ext = obs.final_url if obs.final_url and obs.final_url.startswith("http") else None
        extra = {
            **obs.extra,
            "declared_mime": headers.get("content-type"),
            "content_disposition": headers.get("content-disposition"),
            "content_disposition_filename": cd.filename,
            "url_extension": path_extension(obs.initiating_url),
            "final_url_extension": path_extension(final_for_ext) if final_for_ext else None,
            "suggested_filename_extension": filename_extension(obs.suggested_filename),
            "detected_family": insp.detected_family if insp else None,
            "detected_mime": insp.detected_mime if insp else None,
            "inspection_status": insp.status if insp else None,
            "inspection_unresolved": insp.unresolved_reasons if insp else None,
            "stored": obs.stored,
            "initiating_url_sensitive": sensitive_findings(obs.initiating_url, self.sens),
            "final_url_sensitive": sensitive_findings(obs.final_url, self.sens) if final_for_ext else [],
        }
        oid = self.store.add_observation({
            "run_id": self.run_id, "candidate_id": candidate["candidate_id"] if candidate else None,
            "seed_id": seed_id, "verification_mode": obs.mode, "classification": str(obs.classification),
            "initiating_url": obs.initiating_url, "final_url": obs.final_url,
            "source_page": obs.source_page, "redirect_chain_json": obs.redirect_chain,
            "http_json": obs.http, "browser_config_id": self.v.config_id,
            "started_at": obs.started_at, "completed_at": obs.completed_at,
            "download_state": obs.download_state, "suggested_filename": obs.suggested_filename,
            "sha256": insp.sha256 if insp else None, "size": insp.size if insp else None,
            "failure_reason": obs.failure_reason, "replay_json": obs.replay,
            "replay_status": obs.replay_status,
            "discrepancies_json": insp.discrepancies if insp else None,
            "feature_ref": obs.feature_ref,
            "previous_observation_id": previous["observation_id"] if previous else None,
            "content_changed": (None if previous is None or insp is None or previous["sha256"] is None
                                else int(previous["sha256"] != insp.sha256)),
            "capped_reason": capped, "extra_json": extra,
        })
        log.info("observation", extra={
            "observation_id": oid, "mode": obs.mode, "classification": str(obs.classification),
            "url": obs.initiating_url, "final_url": obs.final_url, "failure_reason": obs.failure_reason,
            "sha256": insp.sha256 if insp else None, "browser_config_id": self.v.config_id})
        if candidate is not None and obs.mode != VerificationMode.REVALIDATION:
            self.store.update_candidate(candidate["candidate_id"], status=CandidateStatus.VERIFIED,
                                        status_reason=str(obs.classification))
        if obs.classification == Classification.FAILED_OR_UNVERIFIED:
            self.store.add_error(self.run_id, "verify", obs.initiating_url, obs.failure_reason or "unverified",
                                 None, seed_id)
        return oid

    # -- render / interaction ----------------------------------------------------
    async def render_and_interact(self) -> None:
        bc = self.cfg.browser
        clauses = []
        if bc.render_seed_pages:
            clauses.append("depth = 0")
        if bc.render_pages_with_controls:
            clauses.append("has_download_controls = 1")
        if not clauses:
            return
        pages = self.store.query(
            f"SELECT * FROM pages WHERE run_id=? AND status='fetched' AND rendered=0 AND ({' OR '.join(clauses)}) "
            "ORDER BY depth, rowid", [self.run_id])
        for page in pages:
            self.rt.budget.check_time()
            seed = self.store.one("SELECT * FROM seeds WHERE seed_id=?", [page["seed_id"]])
            assert seed is not None
            if not await self.rt.robots.allowed(page["url"]):
                self.store.update_page(page["page_id"], rendered=1)
                continue
            res = await self.v.render(page["url"])
            self.store.update_page(page["page_id"], rendered=1)
            if res.error:
                self.store.add_error(self.run_id, "render", page["url"], "render_failed", res.error,
                                     page["seed_id"])
                continue
            st = SeedState(seed, Scope.for_seed(seed["url"], self.cfg.scope), TrapDetector(self.cfg.traps))
            crawler = self.rt.crawler()
            known_links = {dedup_key(c["url"]) for c in self.store.candidates(self.run_id)}
            for link in res.links:
                href = link.get("href") or ""
                if not href.startswith(("http://", "https://")):
                    continue
                try:
                    from .urls import normalize_observed

                    url = normalize_observed(href)[0]
                except ValueError:
                    continue
                if dedup_key(url) in known_links:
                    continue
                el = ExtractedLink(url=url, raw_href=href, method=DiscoveryMethod.RENDERED_DOM,
                                   text=link.get("text") or "", download_attr=link.get("download"))
                # Only candidates are added here; rendered pages are not crawled further.
                from .discovery.hints import link_hints, url_kind

                if url_kind(url) == "download" or el.download_attr is not None or link_hints(url, el.text):
                    crawler._add_candidate(st, url, href, page["url"], DiscoveryMethod.RENDERED_DOM,
                                           page["depth"] + 1, text=el.text, download_attr=el.download_attr)
            if bc.interaction.enabled:
                # Plain links are verified by direct navigation; only controls whose
                # behaviour depends on the page (scripts, download attribute) are clicked.
                clickable = [c for c in res.controls if c.get("visible") and (
                    c.get("scripted") or c.get("has_download_attr")
                    or not str(c.get("href") or "").startswith("http"))]
                for control in clickable[: bc.interaction.max_controls_per_page]:
                    await self._interact(page, seed, st, crawler, control)

    async def _interact(self, page: sqlite3.Row, seed: sqlite3.Row, st: SeedState, crawler: Crawler,
                        control: dict[str, Any]) -> None:
        obs = await self.v.verify_control(page["url"], control)
        target = obs.final_url if obs.download_state == "completed" else None
        if obs.classification == Classification.INTERACTION_DOWNLOAD and target and target.startswith("http"):
            ctx = (obs.replay or {}).get("request_context") or {}
            requires: list[str] = []
            if ctx.get("method") not in (None, "GET"):
                requires.append(f"method:{ctx.get('method')}")
            if ctx.get("has_post_data"):
                requires.append("post_data")
            direct_ok = False
            if not requires:
                cid = crawler._add_candidate(st, target, target, page["url"],
                                             DiscoveryMethod.BROWSER_INTERACTION, page["depth"] + 1)
                cand = self.store.get_candidate(cid) if cid else self.store.candidate_by_key(
                    self.run_id, dedup_key(target))
                if cand is not None and cand["status"] != CandidateStatus.EXCLUDED \
                        and await self.rt.robots.allowed(target):
                    existing = self.store.latest_direct_observation(target)
                    if existing is not None and existing["run_id"] == self.run_id:
                        direct_ok = existing["classification"] == Classification.DIRECT_DOWNLOAD
                    else:
                        dobs = await self.v.verify_direct(target, candidate_id=cand["candidate_id"],
                                                          source_page=page["url"])
                        self.record(dobs, cand, seed["seed_id"])
                        direct_ok = dobs.classification == Classification.DIRECT_DOWNLOAD
            if not direct_ok:
                if ctx.get("cookie_names"):
                    requires.append("cookies")
                if requires:
                    # Replay needs state beyond the click itself.
                    obs.classification = Classification.SESSION_DEPENDENT
                    obs.replay_status = "requires_session_context"
                else:
                    # Only the recorded interaction (e.g. an a[download] click) is needed.
                    requires.append("interaction")
            obs.replay = {**(obs.replay or {}), "requires": requires or ["interaction"],
                          "target_direct_replay_verified": direct_ok}
        self.record(obs, None, seed["seed_id"])

    # -- direct verification ------------------------------------------------------
    def _eligible(self) -> list[sqlite3.Row]:
        out = []
        statuses = set(self.cfg.browser.verify_probe_failure_statuses)
        for c in self.store.candidates(self.run_id, (CandidateStatus.PROBED_DOWNLOAD,
                                                     CandidateStatus.PROBE_FAILED)):
            if c["status"] == CandidateStatus.PROBE_FAILED:
                probe = loads(c["probe_json"]) or {}
                if probe.get("status") not in statuses and "transfer_interrupted" not in (c["status_reason"] or ""):
                    continue
            out.append(c)
        return out

    def _cap_reason(self, c: sqlite3.Row) -> str | None:
        caps = self.cfg.sampling.caps
        dom = registrable_domain(hostname(c["url"]))
        if caps.per_domain is not None and self.domain_counts[dom] >= caps.per_domain:
            return "per_domain_cap"
        if caps.per_publisher is not None and c["publisher"] and \
                self.publisher_counts[c["publisher"]] >= caps.per_publisher:
            return "per_publisher_cap"
        return None

    async def verify_candidates(self) -> None:
        sem = asyncio.Semaphore(self.cfg.browser.verify_concurrency)
        stopped: list[str] = []

        async def one(c: sqlite3.Row) -> None:
            async with sem:
                if stopped:
                    return  # budget exhausted: leave remaining candidates for 'resume'
                try:
                    self.rt.budget.check_time()
                    if self.v.bytes_used >= self.v.max_bytes_total:
                        raise BudgetExceeded("max_download_bytes_total")
                except BudgetExceeded as exc:
                    stopped.append(exc.reason)
                    return
                if reason := self._cap_reason(c):
                    self.store.update_candidate(c["candidate_id"], status=CandidateStatus.CAPPED,
                                                status_reason=reason)
                    return
                if not await self.rt.robots.allowed(c["url"]):
                    self.store.update_candidate(c["candidate_id"], status=CandidateStatus.EXCLUDED,
                                                status_reason="robots_disallowed")
                    self.store.add_error(self.run_id, "verify", c["url"], "robots_disallowed", None,
                                         c["seed_id"])
                    return
                obs = await self.v.verify_direct(c["url"], candidate_id=c["candidate_id"],
                                                 source_page=c["source_page"])
                self.record(obs, c, c["seed_id"])
                if obs.classification == Classification.DIRECT_DOWNLOAD:
                    self.domain_counts[registrable_domain(hostname(c["url"]))] += 1
                    if c["publisher"]:
                        self.publisher_counts[c["publisher"]] += 1

        await asyncio.gather(*(one(c) for c in self._eligible()))
        if stopped:
            raise BudgetExceeded(stopped[0])


async def verify(cfg: Config, store: Store, run_id: str) -> None:
    if not cfg.browser.enabled:
        raise BrowserUnavailable("browser.enabled is false; verification requires the browser")
    hook = load_feature_collector(cfg.browser.feature_collector, cfg)
    files = FileStore(cfg.collection.data_dir / "files", cfg.storage.keep_files, cfg.storage.max_storage_bytes)
    async with Runtime(cfg, store, run_id) as rt:
        verifier = BrowserVerifier(cfg, rt.policy, files, hook, stored_bytes=store.stored_bytes())
        verifier.run_id = run_id
        verifier.max_bytes_total = rt.budget.remaining_bytes()
        async with verifier:
            assert verifier.identity is not None
            store.upsert_browser_config(verifier.config_id, verifier.identity.to_dict())
            store.update_run(run_id, status="verifying")
            stage = VerificationStage(rt, verifier)
            try:
                await stage.render_and_interact()
                # Probe anything new found while rendering, then verify.
                crawler = rt.crawler()
                for seed in store.seeds(run_id):
                    if seed["url"] is None:
                        continue
                    st = SeedState(seed, Scope.for_seed(seed["url"], cfg.scope), TrapDetector(cfg.traps))
                    await crawler._probe_candidates(st)
                await stage.verify_candidates()
                store.update_run(run_id, status="verified")
            except BudgetExceeded as exc:
                rt.budget.exhausted.add(exc.reason)
                store.add_error(run_id, "verify", None, "budget_exhausted", exc.reason)
                store.update_run(run_id, status="verify_incomplete")
            finally:
                rt.budget.bytes += verifier.bytes_used


async def revalidate(cfg: Config, store: Store, run_id: str, url_limit: int | None = None) -> dict[str, int]:
    """Re-verify direct-download URLs in fresh contexts. Every attempt is a new
    observation; content changes are flagged and labels stay with their hash."""
    hook = load_feature_collector(cfg.browser.feature_collector, cfg)
    files = FileStore(cfg.collection.data_dir / "files", cfg.storage.keep_files, cfg.storage.max_storage_bytes)
    stats: Counter[str] = Counter()
    async with Runtime(cfg, store, run_id) as rt:
        verifier = BrowserVerifier(cfg, rt.policy, files, hook, stored_bytes=store.stored_bytes())
        verifier.run_id = run_id
        verifier.max_bytes_total = rt.budget.remaining_bytes()
        async with verifier:
            assert verifier.identity is not None
            store.upsert_browser_config(verifier.config_id, verifier.identity.to_dict())
            stage = VerificationStage(rt, verifier)
            urls = [r["initiating_url"] for r in store.query(
                "SELECT DISTINCT initiating_url FROM observations WHERE run_id=? AND classification=? "
                "AND verification_mode IN ('direct_navigation','revalidation')",
                [run_id, Classification.DIRECT_DOWNLOAD])]
            for url in urls[:url_limit]:
                prev = store.latest_direct_observation(url)
                if not await rt.robots.allowed(url):
                    stats["robots_disallowed"] += 1
                    continue
                cand = store.get_candidate(prev["candidate_id"]) if prev and prev["candidate_id"] else None
                obs = await verifier.verify_direct(url, candidate_id=cand["candidate_id"] if cand else None,
                                                   source_page=prev["source_page"] if prev else None,
                                                   mode=VerificationMode.REVALIDATION)
                stage.record(obs, cand, prev["seed_id"] if prev else None, previous=prev)
                stats[str(obs.classification)] += 1
                if obs.inspection and prev and prev["sha256"] and prev["sha256"] != obs.inspection.sha256:
                    stats["content_changed"] += 1
            rt.budget.bytes += verifier.bytes_used
    return dict(stats)


async def label(cfg: Config, store: Store, run_id: str, force: bool = False) -> dict[str, int]:
    policy = load_policy(cfg.labeling.policy_file)
    async with Runtime(cfg, store, run_id) as rt:
        reputation = VirusTotalLookup(cfg.labeling.reputation, store, rt.client) \
            if cfg.labeling.reputation.enabled else None
        labeler = Labeler(cfg, store, policy, build_scanner(cfg.labeling.scanner),
                          build_signature_verifier(cfg.labeling.signature), rt.client, reputation)
        return await labeler.label_run(run_id, force=force)


async def resume(cfg: Config, store: Store, run_id: str, *, with_browser: bool = True) -> None:
    """Continue an interrupted run: unfinished seeds/pages/probes, then
    verification of candidates that have no observation yet (verified
    candidates change status and are not re-verified)."""
    await crawl(cfg, store, run_id)
    if with_browser:
        await verify(cfg, store, run_id)
