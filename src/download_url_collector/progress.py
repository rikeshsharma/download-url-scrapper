"""Small live terminal display; redirected output keeps ordinary JSON logs."""

from __future__ import annotations

import shutil
import sys
from typing import TextIO


def progress_bar(done: int, total: int, *, complete: bool = False) -> str:
    # Discovery can add work. Only a finished seed may show 100 percent.
    fraction = 1.0 if complete else min(done / total, 0.99) if total else 0.0
    filled = int(fraction * 20)
    return f"[{'#' * filled}{'-' * (20 - filled)}] {fraction:4.0%}"


class TerminalProgress:
    active: TerminalProgress | None = None

    def __init__(self, stream: TextIO | None = None) -> None:
        self.stream = stream if stream is not None else sys.stderr
        self.enabled = self.stream.isatty()
        self.lines: list[str] = []
        self.drawn = 0
        if self.enabled:
            TerminalProgress.active = self

    def clear(self) -> None:
        if self.drawn:
            self.stream.write(f"\x1b[{self.drawn}A\r\x1b[J")
            self.drawn = 0

    def draw(self) -> None:
        if not self.enabled:
            return
        width, height = shutil.get_terminal_size((100, 24))
        visible = self.lines[:max(1, height - 3)]
        if len(visible) < len(self.lines):
            visible[-1] = f"... {len(self.lines) - len(visible) + 1} more active seeds"
        for line in visible:
            # Keep each row on one physical line; never interpret data as ANSI.
            safe = ''.join(c if c.isprintable() else ' ' for c in line)
            self.stream.write(safe[:max(1, width - 1)] + "\n")
        self.drawn = len(visible)
        self.stream.flush()

    def update(self, lines: list[str]) -> None:
        if self.enabled:
            self.clear()
            self.lines = lines
            self.draw()

    def close(self) -> None:
        if TerminalProgress.active is self:
            TerminalProgress.active = None
        self.drawn = 0  # Leave the final snapshot visible.
