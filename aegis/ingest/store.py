"""In-process queue + alert registry.

Single-process by design. For a real deployment, swap the queue for SQS/Redis
and the registry for Postgres; both sit behind these interfaces, so the API and
worker are unaffected. The registry is what makes the webhook idempotent: SIEMs
retry, and a retry must not trigger a second triage or a duplicate ticket.
"""

from __future__ import annotations

import queue
import threading
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from functools import lru_cache
from typing import Any

from aegis.llm.config import get_settings
from aegis.schemas.alert import SIEMAlert


class AlertStatus(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    AUTO_CLOSED = "auto_closed"
    AWAITING_APPROVAL = "awaiting_approval"
    RESOLVED = "resolved"
    FAILED = "failed"
    DUPLICATE = "duplicate"   # same situation as an alert already triaged


@dataclass
class AlertRecord:
    alert_id: str
    status: AlertStatus = AlertStatus.QUEUED
    received_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    verdict: str | None = None
    confidence: float | None = None
    ticket: dict[str, Any] | None = None
    decision: str | None = None
    error: str | None = None
    slack_ts: str | None = None  # message to edit once resolved
    occurrences: int = 1         # incremented by deduplicated alerts
    slack_updated_at: float = 0.0  # throttles occurrence-count edits
    duplicate_of: str | None = None


class InMemoryRegistry:
    """Thread-safe alert index. Swap for a DB table in production."""

    def __init__(self) -> None:
        self._records: dict[str, AlertRecord] = {}
        self._lock = threading.Lock()

    def create_if_absent(self, alert_id: str) -> tuple[AlertRecord, bool]:
        """Returns (record, created). `created=False` means this is a retry."""
        with self._lock:
            existing = self._records.get(alert_id)
            if existing is not None:
                return existing, False
            rec = AlertRecord(alert_id=alert_id)
            self._records[alert_id] = rec
            return rec, True

    def update(self, alert_id: str, **fields: Any) -> None:
        with self._lock:
            rec = self._records.get(alert_id)
            if rec is None:
                return
            for k, v in fields.items():
                setattr(rec, k, v)

    def get(self, alert_id: str) -> AlertRecord | None:
        with self._lock:
            return self._records.get(alert_id)

    def awaiting_approval(self) -> list[AlertRecord]:
        with self._lock:
            return [
                r for r in self._records.values()
                if r.status is AlertStatus.AWAITING_APPROVAL
            ]


ALERT_QUEUE: queue.Queue[SIEMAlert] = queue.Queue(maxsize=1000)


@lru_cache(maxsize=1)
def active_registry() -> Any:
    """Postgres when configured, memory otherwise.

    In-memory state is per-process: a restart loses alert status and occurrence
    counts, and two workers would not see each other's claims.
    """
    if get_settings().postgres_url:
        from aegis.ingest.store_pg import PostgresRegistry

        return PostgresRegistry()
    return InMemoryRegistry()


class _RegistryProxy:
    """Forwards to whichever backend is configured.

    A proxy rather than a choice made at import, so configuration is read on
    first use.
    """

    def __getattr__(self, name: str) -> Any:
        return getattr(active_registry(), name)


REGISTRY = _RegistryProxy()


def reset_stores() -> None:
    """Drop cached backends. Needed when configuration changes."""
    from aegis.dedup import active_dedupe_index

    active_registry.cache_clear()
    active_dedupe_index.cache_clear()
