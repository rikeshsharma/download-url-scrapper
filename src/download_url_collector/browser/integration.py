"""Integration point for the custom browser feature collector.

The collector's private API is intentionally not modelled here. This module
defines the hook surface the verifier calls at well-defined moments, passing
public Playwright objects (``BrowserContext``, ``Page``, ``Download``) and the
observation record. An implementation can, for example, open a CDP session
(``await context.new_cdp_session(page)``) or talk to a feature-collection
endpoint exposed by the modified browser build.

Configure with ``browser.feature_collector: "your_module:factory"`` where
``factory(config) -> FeatureCollectorHook``.
"""

from __future__ import annotations

import importlib
from dataclasses import dataclass
from typing import Any, Protocol


@dataclass(frozen=True)
class VerificationInfo:
    run_id: str
    candidate_id: str | None
    mode: str
    initiating_url: str
    source_page: str | None
    browser_config_id: str


class FeatureCollectorHook(Protocol):
    async def on_context_created(self, context: Any, info: VerificationInfo) -> None:
        """Called after a fresh context is created and before any navigation."""

    async def on_download_started(self, download: Any, info: VerificationInfo) -> None:
        """Called from the download event handler (before completion)."""

    async def on_observation(self, observation: dict[str, Any], info: VerificationInfo) -> str | None:
        """Called with the finished observation. May return an opaque reference
        (e.g. a feature-record ID) stored in ``observations.feature_ref``."""

    async def close(self) -> None: ...


class NullFeatureCollector:
    async def on_context_created(self, context: Any, info: VerificationInfo) -> None:
        return None

    async def on_download_started(self, download: Any, info: VerificationInfo) -> None:
        return None

    async def on_observation(self, observation: dict[str, Any], info: VerificationInfo) -> str | None:
        return None

    async def close(self) -> None:
        return None


def load_feature_collector(spec: str | None, config: Any) -> FeatureCollectorHook:
    if not spec:
        return NullFeatureCollector()
    module_name, _, attr = spec.partition(":")
    if not attr:
        raise ValueError("browser.feature_collector must be 'module:attribute'")
    factory = getattr(importlib.import_module(module_name), attr)
    hook = factory(config)
    for name in ("on_context_created", "on_download_started", "on_observation", "close"):
        if not callable(getattr(hook, name, None)):
            raise TypeError(f"feature collector is missing {name}()")
    return hook  # type: ignore[no-any-return]
