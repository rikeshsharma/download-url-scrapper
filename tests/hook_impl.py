"""Test double for the custom browser feature collector integration point."""

from __future__ import annotations

from typing import Any

CALLS: list[tuple[str, Any]] = []


class RecordingHook:
    async def on_context_created(self, context: Any, info: Any) -> None:
        CALLS.append(("context", len(context.pages)))  # no page has navigated yet

    async def on_download_started(self, download: Any, info: Any) -> None:
        CALLS.append(("download", download.url))

    async def on_observation(self, observation: dict[str, Any], info: Any) -> str | None:
        CALLS.append(("observation", observation["classification"]))
        return f"feature-record:{len(CALLS)}"

    async def close(self) -> None:
        CALLS.append(("close", None))


def factory(config: Any) -> RecordingHook:
    return RecordingHook()
