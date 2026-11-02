"""Browser launch and identity recording.

The identity (executable path + hash, reported version, Playwright version, OS,
launch settings) is hashed into a ``browser_config_id`` stored with every
observation, so results from different browser builds are never conflated.
"""

from __future__ import annotations

import hashlib
import json
import platform
import sys
from dataclasses import asdict, dataclass, field
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Any

from ..config import BrowserConfig

# Flags applied to every launch. None of them changes how Chromium decides
# between rendering and downloading a response.
BASE_ARGS = [
    "--disable-quic",  # keep all HTTP traffic on TCP through the egress proxy
    "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
    "--disable-background-networking",
    "--disable-component-update",
    "--disable-sync",
    "--no-first-run",
    "--disable-default-apps",
    "--disable-features=DnsOverHttps,NetworkPrediction",
    "--dns-prefetch-disable",
]


class BrowserUnavailable(RuntimeError):
    pass


@dataclass
class BrowserIdentity:
    executable_path: str
    executable_sha256: str | None
    browser_name: str
    browser_version: str
    playwright_version: str
    python_version: str
    os: str
    machine: str
    headless: bool
    channel: str | None
    launch_args: list[str]
    settings: dict[str, Any] = field(default_factory=dict)

    def config_id(self) -> str:
        blob = json.dumps(asdict(self), sort_keys=True)
        return "bcfg_" + hashlib.sha256(blob.encode()).hexdigest()[:16]

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["browser_config_id"] = self.config_id()
        return d


def _hash_file(path: Path) -> str | None:
    try:
        h = hashlib.sha256()
        with path.open("rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


def _pw_version() -> str:
    try:
        return version("playwright")
    except PackageNotFoundError:
        return "unknown"


def _resolve_executable(pw: Any, channel: str | None) -> Path:
    """Best-effort path of the binary Playwright launched.

    ``pw.chromium.executable_path`` is the full Chromium build (used for
    ``channel="chromium"``). Without a channel, headless launches use the
    sibling chrome-headless-shell install of the same build.
    """
    full = Path(pw.chromium.executable_path)
    if channel == "chromium":
        return full
    if channel:
        return Path(f"<channel:{channel}>")  # e.g. a system Chrome install; path not exposed
    build_dir = next((p for p in full.parents if p.name.startswith("chromium-")), None)
    if build_dir is not None:
        shell_root = build_dir.parent / build_dir.name.replace("chromium-", "chromium_headless_shell-", 1)
        for name in ("chrome-headless-shell", "chrome-headless-shell.exe"):
            for cand in sorted(shell_root.rglob(name)):
                if cand.is_file():
                    return cand
    return full


async def launch(pw: Any, cfg: BrowserConfig) -> tuple[Any, BrowserIdentity]:
    """Launch Chromium (optionally a custom executable) and record its identity.

    Raises BrowserUnavailable with an actionable message if the browser cannot
    be started or controlled over the DevTools protocol.
    """
    args = [*BASE_ARGS, *cfg.extra_args]
    kwargs: dict[str, Any] = {"headless": cfg.headless, "args": args,
                              "chromium_sandbox": cfg.chromium_sandbox}
    exe: Path | None = None
    if cfg.executable_path is not None:
        exe = Path(cfg.executable_path).expanduser()
        if not exe.exists():
            raise BrowserUnavailable(f"browser.executable_path does not exist: {exe}")
        kwargs["executable_path"] = str(exe)
    elif cfg.channel:
        kwargs["channel"] = cfg.channel
    kwargs = {k: v for k, v in kwargs.items() if v is not None}
    try:
        browser = await pw.chromium.launch(**kwargs)
    except Exception as exc:
        raise BrowserUnavailable(
            "could not launch/control Chromium"
            + (f" at {exe}" if exe else "")
            + f": {type(exc).__name__}: {str(exc).splitlines()[0] if str(exc) else ''}. "
            "The executable must accept Playwright's Chromium launch flags and expose the "
            "Chrome DevTools Protocol over --remote-debugging-pipe. For bundled browsers "
            "run 'playwright install chromium'."
        ) from exc
    try:
        ver = browser.version
        if not ver:
            raise BrowserUnavailable("browser reported no version over CDP")
    except BrowserUnavailable:
        await browser.close()
        raise
    if exe is None:
        exe = _resolve_executable(pw, cfg.channel if cfg.headless or cfg.channel else "chromium")
    if not cfg.headless:
        headless_mode = "headed"
    elif cfg.executable_path is None and not cfg.channel:
        headless_mode = "headless_shell"  # no PDF viewer: PDFs download instead of rendering
    else:
        headless_mode = "new_headless"
    ident = BrowserIdentity(
        executable_path=str(exe), executable_sha256=_hash_file(exe), browser_name="chromium",
        browser_version=ver, playwright_version=_pw_version(),
        python_version=sys.version.split()[0], os=platform.platform(), machine=platform.machine(),
        headless=cfg.headless, channel=cfg.channel, launch_args=args,
        settings={"headless_mode": headless_mode,
                  "egress_proxy": cfg.egress_proxy, "accept_downloads": True,
                  "chromium_sandbox": cfg.chromium_sandbox,
                  "service_workers": "block", "fresh_context_per_verification": True,
                  "navigation_timeout_seconds": cfg.navigation_timeout_seconds,
                  "download_timeout_seconds": cfg.download_timeout_seconds},
    )
    return browser, ident
