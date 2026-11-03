"""Controlled structured logging: analysis id, stage, duration, outcome. Secrets are redacted."""
from __future__ import annotations

import logging
import time
from contextlib import contextmanager
from typing import Iterator

from .redaction import RedactingFilter

_CONFIGURED = False


def configure_logging(level: str = "INFO") -> None:
    global _CONFIGURED
    root = logging.getLogger("qrshield")
    root.setLevel(getattr(logging, level.upper(), logging.INFO))
    if not _CONFIGURED:
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s"))
        handler.addFilter(RedactingFilter())
        root.addHandler(handler)
        root.propagate = False
        _CONFIGURED = True


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(f"qrshield.{name}")


@contextmanager
def stage(logger: logging.Logger, analysis_id: str, name: str, timings: dict | None = None) -> Iterator[None]:
    """Log stage, duration and success/failure; never logs payload content."""
    t0 = time.perf_counter()
    status = "ok"
    try:
        yield
    except Exception as exc:  # error isolation: log the type, not the content
        status = f"error:{type(exc).__name__}"
        raise
    finally:
        dt = (time.perf_counter() - t0) * 1000
        if timings is not None:
            timings[name] = round(dt, 2)
        logger.info("analysis=%s stage=%s status=%s duration_ms=%.1f", analysis_id, name, status, dt)
