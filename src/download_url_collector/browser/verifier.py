"""Chromium verification of download behaviour.

Every verification uses a brand-new browser context (isolated, no cookies or
storage, service workers blocked) routed through the egress proxy. Download
listeners are attached to the context *before* any navigation, and to every
page the context opens (popups, ``target=_blank``), so no download event is
missed. Response headers are never rewritten and no setting is changed to
coerce inline content into a download.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..config import Config
from ..inspection.inspector import FileStore, InspectionResult, inspect_file
from ..models import Classification, VerificationMode, utcnow
from ..netpolicy import NetworkPolicy
from ..probe import parse_content_disposition
from ..urls import filename_extension, path_extension
from .environment import BrowserIdentity, launch
from .integration import FeatureCollectorHook, NullFeatureCollector, VerificationInfo
from .proxy import EgressProxy

log = logging.getLogger(__name__)

_NAV_ABORT_MARKERS = ("Download is starting", "net::ERR_ABORTED", "ERR_ABORTED")
_RENDER_JS = r"""
() => {
  const cssPath = (el) => {
    if (el.id && document.querySelectorAll('#' + CSS.escape(el.id)).length === 1)
      return '#' + CSS.escape(el.id);
    const parts = [];
    while (el && el.nodeType === 1 && el !== document.documentElement) {
      let i = 1, sib = el;
      while ((sib = sib.previousElementSibling)) if (sib.tagName === el.tagName) i++;
      parts.unshift(el.tagName.toLowerCase() + ':nth-of-type(' + i + ')');
      el = el.parentElement;
    }
    return 'html > ' + parts.join(' > ');
  };
  const rx = /download/i;
  const controls = [];
  const q = 'a,button,input[type=button],input[type=submit],[role=button],[onclick]';
  for (const el of document.querySelectorAll(q)) {
    const text = (el.innerText || el.value || el.getAttribute('aria-label') || el.title || '')
      .trim().replace(/\s+/g, ' ').slice(0, 200);
    const dataDl = [...el.attributes].some(a => a.name.startsWith('data-download'));
    const onclick = el.getAttribute('onclick') || '';
    const hasAttr = el.hasAttribute('download');
    if (!(hasAttr || dataDl || rx.test(text) || rx.test(onclick))) continue;
    const href = el.tagName === 'A' ? (el.href || null) : null;
    const r = el.getBoundingClientRect();
    controls.push({selector: cssPath(el), text, tag: el.tagName.toLowerCase(), href,
                   has_download_attr: hasAttr, visible: r.width > 0 && r.height > 0,
                   scripted: !!onclick || !href || /^javascript:/i.test(el.getAttribute('href') || '')});
  }
  const links = [...document.querySelectorAll('a[href],area[href]')].map(a => ({
    href: a.href, text: (a.innerText || '').trim().replace(/\s+/g, ' ').slice(0, 200),
    download: a.getAttribute('download')}));
  return {controls, links, url: location.href};
}
"""


@dataclass
class NetEntry:
    url: str
    method: str
    is_navigation: bool
    resource_type: str
    redirected_from: str | None
    has_post_data: bool
    cookie_names: list[str] = field(default_factory=list)
    referer: str | None = None
    status: int | None = None
    headers: dict[str, str] = field(default_factory=dict)
    failure: str | None = None


_RECORDED = ("content-type", "content-disposition", "content-length", "location",
             "x-content-type-options", "x-collector-blocked")


class NetLog:
    """Captures navigation/document requests in a context (no cookie values)."""

    def __init__(self, context: Any) -> None:
        self.entries: list[NetEntry] = []
        self._by_req: dict[int, NetEntry] = {}
        context.on("request", self._on_request)
        context.on("response", self._on_response)
        context.on("requestfailed", self._on_failed)

    async def _on_request(self, req: Any) -> None:
        try:
            nav = req.is_navigation_request()
        except Exception:
            nav = False
        e = NetEntry(url=req.url, method=req.method, is_navigation=nav,
                     resource_type=req.resource_type,
                     redirected_from=req.redirected_from.url if req.redirected_from else None,
                     has_post_data=req.post_data_buffer is not None)
        self._by_req[id(req)] = e
        self.entries.append(e)
        with contextlib.suppress(Exception):
            hdrs = await req.all_headers()
            cookie = hdrs.get("cookie")
            if cookie:
                e.cookie_names = [c.split("=", 1)[0].strip() for c in cookie.split(";") if c.strip()]
            e.referer = hdrs.get("referer")

    async def _on_response(self, resp: Any) -> None:
        e = self._by_req.get(id(resp.request))
        if e is None:
            return
        e.status = resp.status
        # Synchronous headers are available even when Chromium then aborts the
        # navigation to hand the response to the download manager.
        e.headers = {k: v for k, v in resp.headers.items() if k in _RECORDED}
        with contextlib.suppress(Exception):
            hdrs = await resp.all_headers()
            e.headers.update({k: v for k, v in hdrs.items() if k in _RECORDED})

    def _on_failed(self, req: Any) -> None:
        e = self._by_req.get(id(req))
        if e is not None:
            e.failure = req.failure

    def chain_to(self, url: str) -> list[NetEntry]:
        """Redirect chain ending at the last request for *url*."""
        target = next((e for e in reversed(self.entries) if e.url == url), None)
        if target is None:
            return []
        chain = [target]
        while chain[0].redirected_from:
            prev = next((e for e in reversed(self.entries)
                         if e.url == chain[0].redirected_from and e not in chain), None)
            if prev is None:
                break
            chain.insert(0, prev)
        return chain

    def main_navigation(self, start_url: str) -> list[NetEntry]:
        navs = [e for e in self.entries if e.is_navigation]
        if not navs:
            return []
        # Follow the chain that began at start_url.
        chain: list[NetEntry] = []
        cur = next((e for e in navs if e.url == start_url), navs[0])
        chain.append(cur)
        while True:
            nxt = next((e for e in navs if e.redirected_from == cur.url and e not in chain), None)
            if nxt is None:
                return chain
            chain.append(nxt)
            cur = nxt


@dataclass
class Observation:
    mode: str
    classification: str
    initiating_url: str
    source_page: str | None
    started_at: str
    completed_at: str | None = None
    final_url: str | None = None
    redirect_chain: list[dict[str, Any]] = field(default_factory=list)
    http: dict[str, Any] = field(default_factory=dict)
    download_state: str = "none"
    suggested_filename: str | None = None
    inspection: InspectionResult | None = None
    storage_path: str | None = None
    stored: bool = False
    failure_reason: str | None = None
    replay: dict[str, Any] | None = None
    replay_status: str = "not_replayable"
    extra: dict[str, Any] = field(default_factory=dict)
    feature_ref: str | None = None


@dataclass
class RenderResult:
    final_url: str | None
    links: list[dict[str, Any]]
    controls: list[dict[str, Any]]
    error: str | None = None


class BrowserVerifier:
    def __init__(self, cfg: Config, policy: NetworkPolicy, files: FileStore,
                 hook: FeatureCollectorHook | None = None,
                 stored_bytes: int = 0) -> None:
        self.cfg = cfg
        self.bcfg = cfg.browser
        self.policy = policy
        self.files = files
        self.hook = hook or NullFeatureCollector()
        self.stored_bytes = stored_bytes
        self.bytes_used = 0
        self._pw: Any = None
        self._browser: Any = None
        self.identity: BrowserIdentity | None = None
        self.max_bytes_total: int = cfg.limits.max_download_bytes_total
        self.run_id = ""

    async def __aenter__(self) -> BrowserVerifier:
        from playwright.async_api import async_playwright

        self._pw = await async_playwright().start()
        try:
            self._browser, self.identity = await launch(self._pw, self.bcfg)
        except Exception:
            await self._pw.stop()
            raise
        return self

    async def __aexit__(self, *exc: object) -> None:
        with contextlib.suppress(Exception):
            await self.hook.close()
        if self._browser is not None:
            with contextlib.suppress(Exception):
                await self._browser.close()
        if self._pw is not None:
            await self._pw.stop()

    @property
    def config_id(self) -> str:
        assert self.identity is not None
        return self.identity.config_id()

    # -- context management ------------------------------------------------
    @contextlib.asynccontextmanager
    async def _fresh_context(self, info: VerificationInfo):  # type: ignore[no-untyped-def]
        proxy: EgressProxy | None = None
        kwargs: dict[str, Any] = {"accept_downloads": True, "service_workers": "block",
                                  "java_script_enabled": True}
        if self.bcfg.egress_proxy:
            slack = 256 * 1024  # TLS/HTTP framing overhead
            proxy = EgressProxy(self.policy, self.cfg.limits.max_file_bytes + slack,
                                max(0, self.max_bytes_total - self.bytes_used))
            await proxy.start()
            # "<-loopback>" removes Chromium's implicit proxy bypass for localhost.
            kwargs["proxy"] = {"server": proxy.server_url, "bypass": "<-loopback>"}
        context = await self._browser.new_context(**kwargs)
        context.set_default_navigation_timeout(self.bcfg.navigation_timeout_seconds * 1000)
        context.set_default_timeout(self.bcfg.navigation_timeout_seconds * 1000)
        try:
            await self.hook.on_context_created(context, info)
            yield context, proxy
        finally:
            with contextlib.suppress(Exception):
                await context.close()
            if proxy is not None:
                self.bytes_used += proxy.bytes_downstream
                await proxy.stop()

    @staticmethod
    def _watch_downloads(context: Any, sink: list[Any], event: asyncio.Event,
                         on_start: Any, pages: list[Any] | None = None) -> None:
        """Attach download listeners to every page the context opens (including
        popups) before anything navigates."""
        def attach(page: Any) -> None:
            if pages is not None:
                pages.append(page)

            def on_download(d: Any) -> None:
                sink.append(d)
                event.set()
                asyncio.ensure_future(on_start(d))
            page.on("download", on_download)

        context.on("page", attach)

    # -- direct navigation ---------------------------------------------------
    async def verify_direct(self, url: str, *, candidate_id: str | None, source_page: str | None,
                            mode: VerificationMode = VerificationMode.DIRECT) -> Observation:
        info = VerificationInfo(self.run_id, candidate_id, str(mode), url, source_page, self.config_id)
        obs = Observation(mode=str(mode), classification=Classification.FAILED_OR_UNVERIFIED,
                          initiating_url=url, source_page=source_page, started_at=utcnow())
        downloads: list[Any] = []
        got = asyncio.Event()
        async with self._fresh_context(info) as (context, proxy):
            self._watch_downloads(context, downloads, got,
                                  lambda d: self.hook.on_download_started(d, info))
            netlog = NetLog(context)
            page = await context.new_page()
            nav_error: str | None = None
            nav_aborted = False
            response = None
            try:
                response = await page.goto(url, wait_until="load")
            except Exception as exc:  # Playwright raises on download-initiating navigations
                msg = str(exc)
                if any(m in msg for m in _NAV_ABORT_MARKERS):
                    nav_aborted = True
                else:
                    nav_error = msg.splitlines()[0][:300] if msg else type(exc).__name__
            if not downloads:
                with contextlib.suppress(asyncio.TimeoutError):
                    await asyncio.wait_for(got.wait(), self.bcfg.download_event_grace_seconds)
            obs.extra["navigation_aborted_for_download"] = nav_aborted
            nav_chain = netlog.main_navigation(url)
            if downloads:
                await self._complete_download(downloads[0], obs, netlog, nav_chain, page)
                if obs.download_state == "completed":
                    if obs.final_url and obs.final_url.startswith(("blob:", "data:")):
                        obs.classification = Classification.GENERATED_DOWNLOAD
                        obs.replay_status = "not_url_replayable"
                    else:
                        obs.classification = Classification.DIRECT_DOWNLOAD
                        obs.replay_status = "url_replayable"
            else:
                self._classify_no_download(obs, nav_chain, response, nav_error)
            if proxy is not None:
                self._apply_proxy_events(obs, proxy)
        obs.completed_at = utcnow()
        obs.feature_ref = await self.hook.on_observation(self._hook_view(obs), info)
        return obs

    def _classify_no_download(self, obs: Observation, nav_chain: list[NetEntry], response: Any,
                              nav_error: str | None) -> None:
        last = nav_chain[-1] if nav_chain else None
        obs.redirect_chain = [self._hop(e) for e in nav_chain]
        obs.final_url = last.url if last else (response.url if response else None)
        status = last.status if last else (response.status if response else None)
        headers = last.headers if last else {}
        obs.http = {"status": status, "headers": headers}
        if nav_error:
            obs.failure_reason = f"navigation_error:{nav_error}"
        elif status is None:
            obs.failure_reason = "no_response"
        elif status >= 400:
            obs.failure_reason = f"http_status:{status}"
        else:
            ctype = (headers.get("content-type") or "").split(";", 1)[0].strip().lower()
            if ctype in ("text/html", "application/xhtml+xml") or not ctype:
                obs.failure_reason = "rendered_html_no_download"
            else:
                obs.classification = Classification.INLINE_RESOURCE
                obs.replay_status = "renders_inline"
                obs.extra["rendered_content_type"] = ctype

    @staticmethod
    def _hop(e: NetEntry) -> dict[str, Any]:
        hop = {"url": e.url, "status": e.status, "method": e.method,
               "location": e.headers.get("location")}
        if e.headers.get("x-collector-blocked"):
            hop["blocked"] = e.headers["x-collector-blocked"]
        return hop

    def _apply_proxy_events(self, obs: Observation, proxy: EgressProxy) -> None:
        events = proxy.drain_events()
        blocked = [ev.to_dict() for ev in events if ev.kind == "blocked"]
        limited = [ev.to_dict() for ev in events if ev.kind == "byte_limit"]
        if blocked:
            obs.extra["proxy_blocked"] = blocked
        if limited:
            obs.extra["proxy_byte_limit"] = limited
        if obs.download_state == "completed":
            return  # events are recorded; they did not prevent the download
        if limited:
            obs.classification = Classification.FAILED_OR_UNVERIFIED
            obs.failure_reason = "byte_limit_exceeded"
            obs.replay_status = "not_replayable"
            return
        # Only a blocked *navigation* explains a failure; blocked subresources on
        # an otherwise working page do not. The proxy marks its own refusals.
        nav_marker = next((h["blocked"] for h in obs.redirect_chain if h.get("blocked")), None)
        nav_failed = (obs.failure_reason or "").startswith(("navigation_error", "no_response"))
        if nav_marker or (blocked and nav_failed):
            obs.classification = Classification.FAILED_OR_UNVERIFIED
            obs.failure_reason = f"blocked_destination:{nav_marker or blocked[-1]['detail']}"
            obs.replay_status = "not_replayable"

    async def _complete_download(self, d: Any, obs: Observation, netlog: NetLog,
                                 nav_chain: list[NetEntry], page: Any) -> None:
        obs.final_url = d.url
        obs.suggested_filename = d.suggested_filename
        chain = netlog.chain_to(d.url) if not d.url.startswith(("blob:", "data:")) else []
        if not chain:
            chain = nav_chain
        obs.redirect_chain = [self._hop(e) for e in chain]
        last = chain[-1] if chain else None
        obs.http = {"status": last.status if last else None, "headers": last.headers if last else {},
                    "method": last.method if last else None}
        obs.extra["download_trigger"] = (
            "navigation_response" if any(e.url == d.url and e.is_navigation for e in netlog.entries)
            else "script_or_subframe")
        obs.extra["download_page_is_popup"] = d.page is not page
        try:
            failure = await asyncio.wait_for(d.failure(), self.bcfg.download_timeout_seconds)
        except TimeoutError:
            with contextlib.suppress(Exception):
                await d.cancel()
            obs.download_state = "canceled"
            obs.failure_reason = "download_timeout"
            return
        if failure:
            # We never cancel except on timeout (handled above); the browser's own
            # failure string (e.g. "canceled" for a truncated body) is kept verbatim.
            obs.download_state = "failed"
            obs.failure_reason = f"download_failed:{failure}"
            return
        tmp = self.files.temp_path(uuid.uuid4().hex)
        try:
            await d.save_as(tmp)
        except Exception as exc:
            obs.download_state = "failed"
            obs.failure_reason = f"download_save_failed:{type(exc).__name__}"
            return
        self._inspect_and_store(tmp, obs)

    def _inspect_and_store(self, tmp: Path, obs: Observation) -> None:
        size = tmp.stat().st_size
        if size > self.cfg.limits.max_file_bytes:
            tmp.unlink(missing_ok=True)
            obs.download_state = "failed"
            obs.failure_reason = "file_over_max_file_bytes"
            return
        headers = obs.http.get("headers") or {}
        cd = parse_content_disposition(headers.get("content-disposition"))
        declared_len = headers.get("content-length")
        url_for_ext = obs.final_url if obs.final_url and obs.final_url.startswith("http") else obs.initiating_url
        res = inspect_file(
            tmp, declared_mime=headers.get("content-type"), url_ext=path_extension(url_for_ext),
            filename_ext=filename_extension(obs.suggested_filename or cd.filename),
            archive_cfg=self.cfg.inspection.archives,
            expected_size=int(declared_len) if declared_len and declared_len.isdigit()
            and "content-encoding" not in headers else None,
        )
        rel, stored, why = self.files.commit(tmp, res.sha256, res.size, self.stored_bytes)
        if stored and rel:
            self.stored_bytes += res.size
        obs.inspection = res
        obs.storage_path = rel
        obs.stored = stored
        if why:
            obs.extra["storage_note"] = why
        obs.download_state = "completed"

    # -- rendering and interaction ------------------------------------------
    async def render(self, url: str) -> RenderResult:
        info = VerificationInfo(self.run_id, None, "render", url, url, self.config_id)
        async with self._fresh_context(info) as (context, _proxy):
            # Downloads triggered merely by loading are verified elsewhere; ignore here.
            page = await context.new_page()
            try:
                await page.goto(url, wait_until="load")
                with contextlib.suppress(Exception):
                    await page.wait_for_load_state("networkidle", timeout=3000)
                data = await page.evaluate(_RENDER_JS)
            except Exception as exc:
                return RenderResult(None, [], [], f"{type(exc).__name__}: {str(exc)[:200]}")
        return RenderResult(data.get("url"), data.get("links", []), data.get("controls", []))

    async def verify_control(self, page_url: str, control: dict[str, Any]) -> Observation:
        """Click one recorded control in a fresh context and observe downloads,
        including those started in popups."""
        steps = [{"action": "goto", "url": page_url, "wait_until": "load"},
                 {"action": "click", "selector": control["selector"],
                  "text": control.get("text"), "tag": control.get("tag")}]
        info = VerificationInfo(self.run_id, None, str(VerificationMode.INTERACTION),
                                page_url, page_url, self.config_id)
        obs = Observation(mode=str(VerificationMode.INTERACTION),
                          classification=Classification.FAILED_OR_UNVERIFIED,
                          initiating_url=page_url, source_page=page_url, started_at=utcnow(),
                          replay={"source_page": page_url, "steps": steps, "control": control})
        downloads: list[Any] = []
        opened: list[Any] = []
        got = asyncio.Event()
        async with self._fresh_context(info) as (context, proxy):
            self._watch_downloads(context, downloads, got,
                                  lambda d: self.hook.on_download_started(d, info), opened)
            netlog = NetLog(context)
            page = await context.new_page()
            try:
                await page.goto(page_url, wait_until="load")
                await page.click(control["selector"], timeout=5000)
            except Exception as exc:
                msg = str(exc)
                if not any(m in msg for m in _NAV_ABORT_MARKERS):
                    obs.failure_reason = f"interaction_error:{msg.splitlines()[0][:200] if msg else type(exc).__name__}"
            if not downloads:
                with contextlib.suppress(asyncio.TimeoutError):
                    await asyncio.wait_for(got.wait(), self.bcfg.interaction.post_click_wait_seconds)
            if downloads:
                d = downloads[0]
                await self._complete_download(d, obs, netlog, [], page)
                obs.initiating_url = page_url
                req = next((e for e in reversed(netlog.entries) if e.url == d.url), None)
                ctx: dict[str, Any] = {
                    "download_url": d.url,
                    "method": req.method if req else None,
                    "has_post_data": req.has_post_data if req else None,
                    "cookie_names": req.cookie_names if req else None,
                    "referer_sent": bool(req.referer) if req else None,
                    # Chromium closes a popup whose navigation became a download and
                    # Playwright may then attribute the download to the opener.
                    "popup": d.page is not page or any(p is not page for p in opened),
                }
                obs.replay = {**(obs.replay or {}), "request_context": ctx}
                if obs.download_state == "completed":
                    if d.url.startswith(("blob:", "data:")):
                        obs.classification = Classification.GENERATED_DOWNLOAD
                        obs.replay_status = "not_url_replayable"
                    else:
                        obs.classification = Classification.INTERACTION_DOWNLOAD
                        obs.replay_status = "requires_interaction"
            elif obs.failure_reason is None:
                obs.failure_reason = "no_download_after_interaction"
            if proxy is not None:
                self._apply_proxy_events(obs, proxy)
        obs.completed_at = utcnow()
        obs.feature_ref = await self.hook.on_observation(self._hook_view(obs), info)
        return obs

    @staticmethod
    def _hook_view(obs: Observation) -> dict[str, Any]:
        return {"mode": obs.mode, "classification": str(obs.classification),
                "initiating_url": obs.initiating_url, "final_url": obs.final_url,
                "source_page": obs.source_page, "sha256": obs.inspection.sha256 if obs.inspection else None,
                "http": obs.http, "redirect_chain": obs.redirect_chain}
