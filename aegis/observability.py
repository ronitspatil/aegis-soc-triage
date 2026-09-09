"""Structured logging + metrics.

The metrics chosen are the ones that answer operational questions:
  * is the agent still automating anything?      (auto_close_rate)
  * did a model or prompt change break it?       (sudden rate movement)
  * are the integrations healthy?                (tool_errors by tool)
  * what is this costing?                        (llm_cost_usd_total)
"""

from __future__ import annotations

import json
import logging
import threading
import time
from collections import defaultdict
from typing import Any


class JsonFormatter(logging.Formatter):
    """One JSON object per line so a log aggregator can index the fields."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(record.created)),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        # Anything passed via `extra=` (alert_id, thread_id, ...) rides along.
        for key, value in record.__dict__.items():
            if key not in logging.LogRecord("", 0, "", 0, "", None, None).__dict__ and key not in payload:
                payload[key] = value
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


def setup_logging(level: int = logging.INFO, json_output: bool = True) -> None:
    handler = logging.StreamHandler()
    if json_output:
        handler.setFormatter(JsonFormatter())
    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(level)
    # httpx logs every request at INFO; too noisy for production output.
    logging.getLogger("httpx").setLevel(logging.WARNING)


class Metrics:
    """Minimal thread-safe metric registry with Prometheus text exposition."""

    def __init__(self) -> None:
        self._counters: dict[tuple[str, tuple[tuple[str, str], ...]], float] = defaultdict(float)
        self._latencies: list[float] = []
        self._lock = threading.Lock()

    def inc(self, name: str, value: float = 1.0, **labels: str) -> None:
        key = (name, tuple(sorted(labels.items())))
        with self._lock:
            self._counters[key] += value

    def observe_latency(self, seconds: float) -> None:
        with self._lock:
            self._latencies.append(seconds)
            # Bounded: this is a demo registry, not a TSDB.
            if len(self._latencies) > 10_000:
                del self._latencies[:5_000]

    @staticmethod
    def _series_name(name: str, labels: tuple[tuple[str, str], ...]) -> str:
        """Render `name{label="value"}` in Prometheus exposition form."""
        if not labels:
            return name
        rendered = ",".join(f'{k}="{v}"' for k, v in labels)
        return f"{name}{{{rendered}}}"

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            counters = {
                self._series_name(name, labels): value
                for (name, labels), value in self._counters.items()
            }
            lat = sorted(self._latencies)
        p95 = lat[int(len(lat) * 0.95)] if lat else 0.0
        return {
            "counters": counters,
            "triage_latency_p95_seconds": round(p95, 3),
            "triage_latency_count": len(lat),
        }

    def prometheus(self) -> str:
        snap = self.snapshot()
        lines = [f"{k} {v}" for k, v in sorted(snap["counters"].items())]
        lines.append(f"triage_latency_p95_seconds {snap['triage_latency_p95_seconds']}")
        lines.append(f"triage_latency_count {snap['triage_latency_count']}")
        return "\n".join(lines) + "\n"


METRICS = Metrics()
