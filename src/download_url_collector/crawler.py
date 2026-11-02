"""Discovery stage: crawl pages within scope, collect and probe candidates.

All progress is persisted (pages, candidates, seed status, budget counters) so
an interrupted run can resume where it stopped.
"""

from __future__ import annotations

import asyncio
import logging
import sqlite3
import time
from contextlib import suppress
from dataclasses import dataclass, field
from typing import Any

from .budget import Budget, BudgetExceeded
from .config import Config
from .discovery.adapters import SourceAdapter
from .discovery.hints import is_html_mime, link_hints, url_kind
from .discovery.html import ExtractedLink, extract_links, parse_refresh, sniff_html_charset
from .discovery.sitemap import parse_sitemap
from .discovery.traps import TrapDetector
from .http_client import FetchResult, PolicyHttpClient
from .inspection.filetype import detect_prefix
from .models import CandidateStatus, DiscoveryMethod, PageStatus, utcnow
from .probe import ProbeResult, parse_content_disposition, probe_url
from .progress import TerminalProgress, progress_bar
from .robots import RobotsCache
from .scope import Scope
from .storage import Store
from .urls import (
    SensitivityPolicy,
    URLError,
    dedup_key,
    filename_extension,
    hostname,
    normalize_observed,
    origin,
    sensitive_findings,
)

log = logging.getLogger(__name__)


def sensitivity(cfg: Config) -> SensitivityPolicy:
    return SensitivityPolicy(frozenset(p.lower() for p in cfg.privacy.sensitive_params),
                             cfg.privacy.token_value_min_length)


@dataclass
class SeedState:
    seed: sqlite3.Row
    scope: Scope
    traps: TrapDetector
    stats: dict[str, int] = field(default_factory=dict)
    # Loaded lazily from SQLite for both fresh and resumed seeds. Candidate
    # insertion is synchronous, so this count cannot race another seed task.
    candidate_count: int | None = None

    def bump(self, key: str) -> None:
        self.stats[key] = self.stats.get(key, 0) + 1


class Crawler:
    def __init__(self, cfg: Config, store: Store, run_id: str, client: PolicyHttpClient,
                 robots: RobotsCache, budget: Budget, adapters: list[SourceAdapter]) -> None:
        self.cfg = cfg
        self.store = store
        self.run_id = run_id
        self.client = client
        self.robots = robots
        self.budget = budget
        self.adapters = adapters
        self.sens = sensitivity(cfg)
        self._stop_reason: str | None = None

    # ------------------------------------------------------------------
    async def run(self) -> None:
        valid_seeds = [s for s in self.store.seeds(self.run_id) if s["url"] is not None]
        seeds = [s for s in valid_seeds if s["status"] in ("pending", "crawling")]
        sem = asyncio.Semaphore(self.cfg.limits.concurrency)
        started = time.monotonic()
        processed = sum(s["status"] == "crawled" for s in valid_seeds)
        limited = 0
        display = TerminalProgress()
        active: dict[str, sqlite3.Row] = {}
        last_seed: tuple[sqlite3.Row, str] | None = None

        def update_bars() -> None:
            if not display.enabled:
                return
            seconds = int(time.monotonic() - started)
            elapsed = f"{seconds // 3600:02d}:{seconds // 60 % 60:02d}:{seconds % 60:02d}"
            lines = [f"Seeds {progress_bar(processed, len(valid_seeds), complete=processed == len(valid_seeds))} "
                     f"{processed}/{len(valid_seeds)} | elapsed {elapsed} | budget-limited {limited}"]
            items = [(seed, "working") for seed in active.values()]
            if last_seed is not None:
                items.append(last_seed)
            for seed, state in items:
                page_counts = {r["status"]: r["n"] for r in self.store.query(
                    "SELECT status, COUNT(*) n FROM pages WHERE run_id=? AND seed_id=? GROUP BY status",
                    [self.run_id, seed["seed_id"]])}
                candidate_counts = {r["status"]: r["n"] for r in self.store.query(
                    "SELECT status, COUNT(*) n FROM candidates WHERE run_id=? AND seed_id=? GROUP BY status",
                    [self.run_id, seed["seed_id"]])}
                pages_done = sum(page_counts.get(s, 0) for s in ("fetched", "failed", "not_html"))
                pages_total = max(pages_done, min(self.cfg.limits.max_pages_per_seed,
                                                sum(n for s, n in page_counts.items() if s != "excluded")))
                probes_total = sum(n for s, n in candidate_counts.items() if s != "excluded")
                probes_done = probes_total - candidate_counts.get("discovered", 0)
                bar = progress_bar(pages_done + probes_done, pages_total + probes_total,
                                   complete=state == "done")
                lines.append(f"Seed {seed['row_number']} {bar} pages {pages_done}/{pages_total} | "
                             f"probes {probes_done}/{probes_total} | {state} | {hostname(seed['url'])}")
            display.update(lines)

        def report_progress() -> None:
            elapsed = time.monotonic() - started
            seconds = int(elapsed)
            elapsed_text = f"{seconds // 3600:02d}:{seconds // 60 % 60:02d}:{seconds % 60:02d}"
            log.info(
                "Crawl progress: elapsed %s | seeds processed %d/%d | budget-limited %d",
                elapsed_text, processed, len(valid_seeds), limited,
                extra={"run_id": self.run_id, "elapsed_seconds": round(elapsed, 1),
                       "seeds_processed": processed, "seeds_total": len(valid_seeds),
                       "seeds_budget_limited": limited},
            )

        async def heartbeat() -> None:
            ticks = 0
            while True:
                await asyncio.sleep(1 if display.enabled else 10)
                update_bars()
                ticks += 1
                if not display.enabled or ticks % 10 == 0:
                    report_progress()

        async def one(seed: sqlite3.Row) -> None:
            nonlocal processed, limited, last_seed
            async with sem:
                active[seed["seed_id"]] = seed
                update_bars()
                state = "interrupted"
                try:
                    await self._crawl_seed(seed)
                    current = self.store.one("SELECT status FROM seeds WHERE seed_id=?", [seed["seed_id"]])
                    if current is not None and current["status"] == "crawled":
                        processed += 1
                        state = "done"
                    else:
                        limited += 1
                        state = "budget-limited"
                    report_progress()
                finally:
                    active.pop(seed["seed_id"], None)
                    last_seed = (seed, state)
                    update_bars()

        report_progress()
        update_bars()
        ticker = asyncio.create_task(heartbeat())
        try:
            await asyncio.gather(*(one(s) for s in seeds))
        finally:
            ticker.cancel()
            with suppress(asyncio.CancelledError):
                await ticker
            report_progress()
            update_bars()
            display.close()
        self.store.update_run(self.run_id, counters_json=self.budget.snapshot(),
                              budget_exhausted_json=sorted(self.budget.exhausted))

    async def _crawl_seed(self, seed: sqlite3.Row) -> None:
        st = SeedState(seed, Scope.for_seed(seed["url"], self.cfg.scope), TrapDetector(self.cfg.traps))
        fresh = seed["status"] == "pending"
        self.store.set_seed_status(seed["seed_id"], "crawling")
        try:
            if fresh:
                await self._bootstrap_seed(st)
            for _round in range(self.cfg.limits.max_depth + 3):
                progressed = await self._drain_pages(st)
                progressed |= await self._probe_candidates(st)
                if not progressed:
                    break
            self.store.set_seed_status(seed["seed_id"], "crawled")
        except BudgetExceeded as exc:
            self.store.add_error(self.run_id, "crawl", seed["url"], "budget_exhausted", exc.reason,
                                 seed["seed_id"])
            # Leave as "crawling" so 'resume' can continue after limits are raised.
        finally:
            self.store.update_run(self.run_id, counters_json=self.budget.snapshot(),
                                  budget_exhausted_json=sorted(self.budget.exhausted))

    async def _bootstrap_seed(self, st: SeedState) -> None:
        url = st.seed["url"]
        self.store.add_page(self.run_id, st.seed["seed_id"], url, dedup_key(url), 0, None,
                            DiscoveryMethod.SEED)
        for adapter in self.adapters:
            if adapter.matches(url):
                res = await adapter.discover(url, self.client)
                for err_url, reason in res.errors:
                    self.store.add_error(self.run_id, "adapter", err_url, reason, adapter.name,
                                         st.seed["seed_id"])
                for c in res.candidates:
                    self._add_candidate(st, c.url, c.url, c.source_page, DiscoveryMethod.ADAPTER, 1,
                                        text=c.filename or "", publisher=c.publisher,
                                        checksums=c.publisher_checksums,
                                        metadata={"adapter": adapter.name, **c.metadata},
                                        force_external_ok=True)
        await self._discover_sitemaps(st)

    # -- sitemaps ----------------------------------------------------------
    async def _discover_sitemaps(self, st: SeedState) -> None:
        lim = self.cfg.limits
        if lim.max_sitemap_files == 0:
            return
        seed_origin = origin(st.seed["url"])
        entry = await self.robots.entry(st.seed["url"])
        queue = list(dict.fromkeys([*entry.sitemaps, f"{seed_origin}/sitemap.xml"]))
        seen: set[str] = set()
        urls_added = 0
        while queue and len(seen) < lim.max_sitemap_files:
            sm = queue.pop(0)
            try:
                sm = normalize_observed(sm)[0]
            except URLError:
                continue
            if sm in seen or not st.scope.in_crawl_scope(sm):
                continue
            seen.add(sm)
            res = await self.client.fetch(sm, max_bytes=lim.max_html_bytes,
                                          scope_check=st.scope.crawl_redirect_reason)
            if not res.ok:
                if res.status != 404:
                    self.store.add_error(self.run_id, "sitemap", sm,
                                         res.error_detail or res.error or f"http_{res.status}",
                                         None, st.seed["seed_id"])
                continue
            parsed = parse_sitemap(res.body, res.final_url or sm, lim.max_html_bytes,
                                   lim.max_sitemap_urls - urls_added)
            if parsed.error:
                self.store.add_error(self.run_id, "sitemap", sm, "sitemap_parse_error", parsed.error,
                                     st.seed["seed_id"])
            queue.extend(parsed.child_sitemaps)
            for u in parsed.urls:
                if urls_added >= lim.max_sitemap_urls:
                    break
                urls_added += 1
                link = ExtractedLink(url=u, raw_href=u, method=DiscoveryMethod.SITEMAP)
                self._handle_link(st, sm, link, depth=0)

    # -- pages -------------------------------------------------------------
    async def _drain_pages(self, st: SeedState) -> bool:
        progressed = False
        done = self.store.count_pages(self.run_id, st.seed["seed_id"],
                                      (PageStatus.FETCHED, PageStatus.NOT_HTML, PageStatus.FAILED))
        while True:
            queued = self.store.queued_pages(self.run_id, st.seed["seed_id"])
            if not queued:
                return progressed
            for page in queued:
                progressed = True
                if done >= self.cfg.limits.max_pages_per_seed:
                    self.store.update_page(page["page_id"], status=PageStatus.EXCLUDED,
                                           reason="max_pages_per_seed")
                    continue
                await self._process_page(st, page)
                done += 1

    def _page_body_limit(self, headers: dict[str, str]) -> int:
        ct = headers.get("content-type")
        cd = parse_content_disposition(headers.get("content-disposition"))
        if cd.disposition == "attachment" or (ct and not is_html_mime(ct)):
            return self.cfg.limits.probe_sniff_bytes
        return self.cfg.limits.max_html_bytes

    async def _process_page(self, st: SeedState, page: sqlite3.Row) -> None:
        url = page["url"]
        self.budget.take_page()
        res = await self.client.fetch(url, max_bytes=self.cfg.limits.max_html_bytes,
                                      scope_check=st.scope.crawl_redirect_reason,
                                      body_limit=self._page_body_limit)
        now_fields: dict[str, Any] = {"http_json": res.http_meta(), "fetched_at": _now()}
        if res.error == "redirect_blocked" and res.error_detail == "redirect_out_of_crawl_scope":
            # In-scope URL redirecting off-site (e.g. a CDN hand-off): the page URL
            # itself is a candidate; the probe/verifier may follow external redirects.
            self.store.update_page(page["page_id"], status=PageStatus.NOT_HTML,
                                   reason="redirects_out_of_scope", **now_fields)
            self._add_candidate(st, url, url, page["discovered_from"] or url,
                                DiscoveryMethod.REDIRECT, page["depth"])
            return
        if res.error == "budget_exhausted":
            # Leave the page queued so 'resume' (with raised limits) fetches it.
            raise BudgetExceeded(res.error_detail or "budget")
        if res.error or res.status is None:
            reason = f"{res.error}:{res.error_detail}"
            self.store.update_page(page["page_id"], status=PageStatus.FAILED, reason=reason, **now_fields)
            self.store.add_error(self.run_id, "crawl", url, res.error_detail or res.error or "error",
                                 reason, st.seed["seed_id"])
            return
        if not (200 <= res.status < 300):
            self.store.update_page(page["page_id"], status=PageStatus.FAILED,
                                   reason=f"http_status:{res.status}", **now_fields)
            self.store.add_error(self.run_id, "crawl", url, f"http_status:{res.status}", None,
                                 st.seed["seed_id"])
            # Download-hinted URLs that fail are still kept as candidates for the record.
            if page["discovery_method"] != DiscoveryMethod.SEED and link_hints(url):
                self._add_candidate(st, url, url, page["discovered_from"] or url,
                                    DiscoveryMethod(page["discovery_method"]), page["depth"])
            return
        ct = res.header("content-type")
        cd = parse_content_disposition(res.header("content-disposition"))
        sniff = detect_prefix(res.body[:4096])
        is_html = cd.disposition != "attachment" and (
            is_html_mime(ct) or (ct is None and sniff.family == "html"))
        if not is_html:
            self.store.update_page(page["page_id"], status=PageStatus.NOT_HTML, reason="non_html_response",
                                   **now_fields)
            method = (DiscoveryMethod.SEED if page["discovery_method"] == DiscoveryMethod.SEED
                      else DiscoveryMethod.ENDPOINT)
            cid = self._add_candidate(st, url, url, page["discovered_from"] or url, method, page["depth"])
            if cid:
                self._record_probe(cid, self._probe_from_page_fetch(res, ct, cd, sniff.family, sniff.mime))
            return
        ext = extract_links(res.body, res.final_url or url, sniff_html_charset(ct))
        log.info("page_fetched", extra={"url": url, "status": res.status, "links": len(ext.links),
                                        "controls": len(ext.controls), "depth": page["depth"]})
        controls = [{"tag": c.tag, "text": c.text, "attrs": c.attrs} for c in ext.controls]
        self.store.update_page(page["page_id"], status=PageStatus.FETCHED,
                               has_download_controls=int(bool(controls)),
                               controls_json=controls, **now_fields)
        for href, err in ext.invalid_hrefs[:50]:
            self.store.add_error(self.run_id, "extract", href, "invalid_href", err, st.seed["seed_id"])
        refresh = ext.meta_refresh
        header_refresh = res.header("refresh")
        if refresh is None and header_refresh:
            refresh = parse_refresh(header_refresh, ext.base_url)
        if refresh is not None:
            if page["meta_refresh_hops"] < self.cfg.limits.max_meta_refresh:
                link = ExtractedLink(url=refresh[1], raw_href=refresh[1], method=DiscoveryMethod.META_REFRESH)
                self._handle_link(st, url, link, page["depth"], refresh_hops=page["meta_refresh_hops"] + 1)
            else:
                self.store.add_error(self.run_id, "crawl", refresh[1], "meta_refresh_limit", None,
                                     st.seed["seed_id"])
        for link in ext.links:
            self._handle_link(st, url, link, page["depth"])

    def _probe_from_page_fetch(self, res: FetchResult, ct: str | None, cd: Any, family: str,
                               mime: str) -> ProbeResult:
        cl = res.header("content-length")
        return ProbeResult(
            verdict="likely_download", reason="page_fetch_non_html", get=res.http_meta(),
            declared_mime=ct, content_disposition=cd.raw, disposition_type=cd.disposition,
            filename=cd.filename, filename_extension=filename_extension(cd.filename),
            declared_length=int(cl) if cl and cl.isdigit() else None, sniffed_family=family,
            sniffed_mime=mime, final_url=res.final_url, status=res.status,
            hints=["attachment_disposition"] if cd.disposition == "attachment" else [],
        )

    # -- links ---------------------------------------------------------------
    def _handle_link(self, st: SeedState, source: str, link: ExtractedLink, depth: int,
                     refresh_hops: int = 0) -> None:
        url = link.url
        kind = url_kind(url)
        hints = link_hints(url, link.text, link.download_attr)
        in_scope = st.scope.in_crawl_scope(url)
        # Hinted ambiguous URLs (no extension, e.g. /get?id=1 labelled "Download")
        # are probed as candidates; a probe that finds HTML re-queues them as pages.
        explicit = kind == "download" or link.download_attr is not None or (
            kind == "ambiguous" and bool(hints))
        if explicit:
            self._add_candidate(st, url, link.raw_href, source, link.method, depth + 1,
                                text=link.text, download_attr=link.download_attr, hints=hints)
            return
        if kind == "asset":
            st.bump("skipped_assets")
            return
        if in_scope:
            if depth + 1 > self.cfg.limits.max_depth:
                if hints:  # hinted ambiguous endpoint at the depth limit: probe it directly
                    self._add_candidate(st, url, link.raw_href, source, link.method, depth + 1,
                                        text=link.text, hints=hints)
                return
            key = dedup_key(url)
            if self.store.page_exists(self.run_id, key):
                return
            if reason := st.traps.check_page(url):
                self.store.add_page(self.run_id, st.seed["seed_id"], url, key, depth + 1, source,
                                    link.method, status=PageStatus.EXCLUDED, reason=reason)
                self.store.add_error(self.run_id, "crawl", url, reason, None, st.seed["seed_id"])
                return
            self.store.add_page(self.run_id, st.seed["seed_id"], url, key, depth + 1, source,
                                link.method, meta_refresh_hops=refresh_hops)
            return
        if hints and self.cfg.scope.verify_external_downloads:
            self._add_candidate(st, url, link.raw_href, source, link.method, depth + 1,
                                text=link.text, hints=hints, external=True)
        else:
            st.bump("out_of_scope_links")

    def _add_candidate(self, st: SeedState, url: str, raw_href: str, source: str,
                       method: DiscoveryMethod | str, depth: int, *, text: str = "",
                       download_attr: str | None = None, hints: list[str] | None = None,
                       external: bool | None = None, publisher: str | None = None,
                       checksums: dict[str, str] | None = None,
                       metadata: dict[str, Any] | None = None,
                       force_external_ok: bool = False) -> str | None:
        key = dedup_key(url)
        if self.store.candidate_by_key(self.run_id, key):
            return None
        if st.candidate_count is None:
            st.candidate_count = self.store.count_candidates(self.run_id, st.seed["seed_id"])
        is_external = (not st.scope.in_crawl_scope(url)) if external is None else external
        row: dict[str, Any] = {
            "run_id": self.run_id, "seed_id": st.seed["seed_id"], "url": url, "dedup_key": key,
            "raw_href": raw_href, "source_page": source, "discovery_method": str(method),
            "depth": depth, "is_external": int(is_external), "link_text": text,
            "download_attr": download_attr, "hints_json": hints or link_hints(url, text, download_attr),
            "publisher": publisher, "publisher_checksums_json": checksums or {},
            "adapter_metadata_json": metadata, "url_sensitive_json": sensitive_findings(url, self.sens),
        }
        reason: str | None = None
        if is_external and not (self.cfg.scope.verify_external_downloads or force_external_ok):
            reason = "external_verification_disabled"
        elif r := st.traps.check_candidate(url):
            reason = r
        elif st.candidate_count >= self.cfg.limits.max_candidates_per_seed:
            reason = "max_candidates_per_seed"
        else:
            try:
                self.budget.take_candidate()
            except BudgetExceeded as exc:
                reason = exc.reason
        if reason:
            row["status"], row["status_reason"] = CandidateStatus.EXCLUDED, reason
            self.store.add_error(self.run_id, "discovery", url, reason, None, st.seed["seed_id"])
        candidate_id = self.store.add_candidate(row)
        if candidate_id is not None:
            st.candidate_count += 1
        return candidate_id

    # -- probing ---------------------------------------------------------------
    async def _probe_candidates(self, st: SeedState) -> bool:
        pending = self.store.candidates(self.run_id, (CandidateStatus.DISCOVERED,), st.seed["seed_id"])
        if not pending:
            return False

        exhausted: list[str] = []

        async def one(c: sqlite3.Row) -> None:
            res = await probe_url(self.client, c["url"], self.cfg, st.scope.verify_redirect_reason)
            if res.reason and res.reason.startswith("budget_exhausted"):
                exhausted.append(res.reason.split(":", 1)[-1])  # stays 'discovered' for resume
                return
            self._record_probe(c["candidate_id"], res)
            # A hinted link that turned out to be an in-scope HTML page is crawled.
            if res.verdict == "html" and st.scope.in_crawl_scope(c["url"]) \
                    and c["depth"] <= self.cfg.limits.max_depth:
                key = dedup_key(c["url"])
                if not self.store.page_exists(self.run_id, key) and not st.traps.check_page(c["url"]):
                    self.store.add_page(self.run_id, st.seed["seed_id"], c["url"], key, c["depth"],
                                        c["source_page"], c["discovery_method"])

        await asyncio.gather(*(one(c) for c in pending))
        if exhausted:
            raise BudgetExceeded(exhausted[0])
        return True

    def _record_probe(self, candidate_id: str, res: ProbeResult) -> None:
        if res.verdict == "likely_download":
            status, reason = CandidateStatus.PROBED_DOWNLOAD, None
        elif res.verdict == "html":
            status, reason = CandidateStatus.PROBED_HTML, "html_response"
        elif res.reason and res.reason.startswith(("blocked:", "redirect_blocked:")):
            status, reason = CandidateStatus.EXCLUDED, res.reason.split(":", 1)[1]
        else:
            status, reason = CandidateStatus.PROBE_FAILED, res.reason
        self.store.update_candidate(candidate_id, status=status, status_reason=reason,
                                    probe_json=res.to_dict())
        log.info("candidate_probed", extra={"candidate_id": candidate_id, "status": str(status),
                                            "reason": reason, "http_status": res.status,
                                            "sniffed_family": res.sniffed_family})
        if status in (CandidateStatus.EXCLUDED, CandidateStatus.PROBE_FAILED):
            c = self.store.get_candidate(candidate_id)
            self.store.add_error(self.run_id, "probe", c["url"] if c else None, reason or "probe_failed",
                                 None, c["seed_id"] if c else None)


def _now() -> str:
    return utcnow()
