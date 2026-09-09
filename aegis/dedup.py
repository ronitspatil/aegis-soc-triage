"""Alert deduplication.

Different alerts frequently describe the same underlying event: a brute force
run fires once per detection window, so one incident arrives as dozens of
alerts with distinct ids but identical entities. Triaging each one repeats the
enrichment calls and the synthesis call for an answer already known.

This is separate from the webhook's idempotency check, which catches the *same*
alert delivered twice (matched on alert_id). Here the ids differ.

Suppression is a cost and display decision, never an evidence decision. A
duplicate increments the occurrence count on the original alert so an ongoing
attack still reads as ongoing; it is never dropped.
"""

from __future__ import annotations

import hashlib
import threading
import time
from dataclasses import dataclass
from functools import lru_cache
from typing import Any

from aegis.llm.config import get_settings
from aegis.schemas.alert import SIEMAlert


def fingerprint(alert: SIEMAlert) -> str:
    """Identify the situation an alert describes, ignoring its id and time.

    Entities plus the rule, because that is what makes two alerts "the same
    thing happening again" rather than two unrelated events.
    """
    parts = [
        alert.rule_name.strip().lower(),
        str(alert.source_ip or ""),
        str(alert.destination_ip or ""),
        (alert.username or "").strip().lower(),
        (alert.hostname or "").strip().lower(),
        (alert.file_hash or "").strip().lower(),
    ]
    return hashlib.sha256("|".join(parts).encode()).hexdigest()[:32]


@dataclass
class DedupeEntry:
    alert_id: str          # the alert that was actually triaged
    first_seen: float
    last_seen: float
    occurrences: int


class InMemoryDedupeIndex:
    """Fingerprint to first-alert mapping, with a bounded window.

    The window has to expire: the same rule firing tomorrow is a new situation
    and deserves a fresh investigation.
    """

    def __init__(self) -> None:
        self._entries: dict[str, DedupeEntry] = {}
        self._lock = threading.Lock()

    def _purge(self, now: float, window: float) -> None:
        stale = [k for k, e in self._entries.items() if now - e.first_seen > window]
        for key in stale:
            del self._entries[key]

    def check(self, alert: SIEMAlert) -> DedupeEntry | None:
        """Record this alert and return the original if it is a duplicate.

        Returns None when the alert is the first of its kind, in which case the
        caller should triage it normally.
        """
        settings = get_settings()
        if not settings.dedupe_enabled:
            return None

        window = float(settings.dedupe_window_seconds)
        key = fingerprint(alert)
        now = time.monotonic()

        with self._lock:
            self._purge(now, window)
            existing = self._entries.get(key)
            if existing is not None:
                existing.occurrences += 1
                existing.last_seen = now
                # Return a copy so callers cannot mutate index state.
                return DedupeEntry(existing.alert_id, existing.first_seen,
                                   existing.last_seen, existing.occurrences)

            self._entries[key] = DedupeEntry(alert.alert_id, now, now, 1)
            return None

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()


@lru_cache(maxsize=1)
def active_dedupe_index() -> Any:
    """Postgres when configured, memory otherwise.

    Per-process fingerprints mean two workers each triage an alert storm once.
    """
    if get_settings().postgres_url:
        from aegis.ingest.store_pg import PostgresDedupeIndex

        return PostgresDedupeIndex()
    return InMemoryDedupeIndex()


class _DedupeProxy:
    def __getattr__(self, name: str) -> Any:
        return getattr(active_dedupe_index(), name)


DEDUPE_INDEX = _DedupeProxy()
