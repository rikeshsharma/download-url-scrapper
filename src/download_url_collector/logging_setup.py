"""Structured JSON logging with URL/credential redaction."""

from __future__ import annotations

import json
import logging
import sys
from typing import Any

from .urls import SensitivityPolicy, redact_text
from .progress import TerminalProgress

_STD = set(vars(logging.LogRecord("", 0, "", 0, "", (), None)).keys()) | {"message", "asctime"}
_SECRET_KEYS = {"authorization", "cookie", "set-cookie", "x-apikey", "api_key", "token", "password"}


class JsonFormatter(logging.Formatter):
    def __init__(self, policy: SensitivityPolicy) -> None:
        super().__init__()
        self.policy = policy

    def _clean(self, v: Any) -> Any:
        if isinstance(v, str):
            return redact_text(v, self.policy)
        if isinstance(v, dict):
            return {k: ("REDACTED" if str(k).lower() in _SECRET_KEYS else self._clean(x)) for k, x in v.items()}
        if isinstance(v, (list, tuple)):
            return [self._clean(x) for x in v]
        return v

    def format(self, record: logging.LogRecord) -> str:
        out: dict[str, Any] = {
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname.lower(),
            "logger": record.name,
            "event": redact_text(record.getMessage(), self.policy),
        }
        for k, v in record.__dict__.items():
            if k not in _STD and not k.startswith("_"):
                out[k] = "REDACTED" if k.lower() in _SECRET_KEYS else self._clean(v)
        if record.exc_info:
            out["exc"] = redact_text(self.formatException(record.exc_info), self.policy)
        return json.dumps(out, default=str)


class ProgressStreamHandler(logging.StreamHandler):
    """Keep live bars below log records without changing JSON file logging."""

    def emit(self, record: logging.LogRecord) -> None:
        display = TerminalProgress.active
        if display is not None and display.stream is self.stream:
            display.clear()
            try:
                super().emit(record)
            finally:
                display.draw()
        else:
            super().emit(record)


def setup_logging(level: str, policy: SensitivityPolicy, log_file: str | None = None) -> None:
    root = logging.getLogger()
    root.handlers.clear()
    fmt = JsonFormatter(policy)
    handler: logging.Handler = ProgressStreamHandler(sys.stderr)
    handler.setFormatter(fmt)
    root.addHandler(handler)
    if log_file:
        fh = logging.FileHandler(log_file, encoding="utf-8")
        fh.setFormatter(fmt)
        root.addHandler(fh)
    root.setLevel(level.upper())
    for noisy in ("asyncio", "urllib3", "filelock"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
