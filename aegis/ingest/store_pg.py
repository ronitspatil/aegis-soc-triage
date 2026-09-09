"""Postgres-backed registry and dedupe index.

The in-memory versions lose alert status and occurrence counts on restart, and
two worker processes hold separate state: the same alert storm would be triaged
once per worker.

Both operations that decide "has this been seen" are single statements with
ON CONFLICT, so the claim and the increment happen atomically. A read followed
by a write would let two workers both conclude they were first.
"""

from __future__ import annotations

import json
import logging
import threading
from datetime import UTC, datetime
from typing import Any

from aegis.dedup import DedupeEntry, fingerprint
from aegis.ingest.store import AlertRecord, AlertStatus
from aegis.llm.config import get_settings
from aegis.schemas.alert import SIEMAlert

logger = logging.getLogger(__name__)

SCHEMA = """
CREATE TABLE IF NOT EXISTS aegis_alerts (
    alert_id          text PRIMARY KEY,
    status            text NOT NULL,
    received_at       timestamptz NOT NULL DEFAULT now(),
    verdict           text,
    confidence        double precision,
    ticket            jsonb,
    decision          text,
    error             text,
    slack_ts          text,
    occurrences       integer NOT NULL DEFAULT 1,
    duplicate_of      text,
    slack_updated_at  double precision NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS aegis_alerts_status_idx ON aegis_alerts (status);

CREATE TABLE IF NOT EXISTS aegis_dedupe (
    fingerprint  text PRIMARY KEY,
    alert_id     text NOT NULL,
    first_seen   timestamptz NOT NULL DEFAULT now(),
    last_seen    timestamptz NOT NULL DEFAULT now(),
    occurrences  integer NOT NULL DEFAULT 1
);
"""

_pool: Any = None
_pool_lock = threading.Lock()


def _get_pool() -> Any:
    global _pool
    with _pool_lock:
        if _pool is None:
            from psycopg.rows import dict_row
            from psycopg_pool import ConnectionPool

            settings = get_settings()
            _pool = ConnectionPool(
                conninfo=settings.postgres_url,
                max_size=10,
                open=True,  # explicit: the library default is changing
                timeout=settings.postgres_connect_timeout,
                # client_encoding is explicit because a SQL_ASCII database
                # makes psycopg return text columns as bytes, and an enum
                # lookup then fails on b'queued' rather than 'queued'.
                kwargs={"autocommit": True, "row_factory": dict_row,
                        "client_encoding": "UTF8",
                        "connect_timeout": int(settings.postgres_connect_timeout)},
            )
            with _pool.connection() as conn:
                conn.execute(SCHEMA)
            logger.info("alert registry and dedupe index using postgres")
    return _pool


_COLUMNS = (
    "alert_id", "status", "received_at", "verdict", "confidence", "ticket",
    "decision", "error", "slack_ts", "occurrences", "duplicate_of",
    "slack_updated_at",
)


def _to_record(row: dict[str, Any]) -> AlertRecord:
    return AlertRecord(
        alert_id=row["alert_id"],
        status=AlertStatus(row["status"]),
        received_at=row["received_at"],
        verdict=row["verdict"],
        confidence=row["confidence"],
        ticket=row["ticket"],
        decision=row["decision"],
        error=row["error"],
        slack_ts=row["slack_ts"],
        occurrences=row["occurrences"],
        duplicate_of=row["duplicate_of"],
        slack_updated_at=row["slack_updated_at"],
    )


class PostgresRegistry:
    """Alert index shared by every worker."""

    def create_if_absent(self, alert_id: str) -> tuple[AlertRecord, bool]:
        """Claim an alert. `created=False` means another worker or poll had it.

        One statement: two workers polling the same overlapping window cannot
        both be told they were first.
        """
        with _get_pool().connection() as conn:
            row = conn.execute(
                "INSERT INTO aegis_alerts (alert_id, status) VALUES (%s, %s) "
                "ON CONFLICT (alert_id) DO NOTHING "
                f"RETURNING {', '.join(_COLUMNS)}",
                (alert_id, AlertStatus.QUEUED.value),
            ).fetchone()
            if row is not None:
                return _to_record(row), True

            existing = conn.execute(
                f"SELECT {', '.join(_COLUMNS)} FROM aegis_alerts WHERE alert_id = %s",
                (alert_id,),
            ).fetchone()
            return _to_record(existing), False

    def update(self, alert_id: str, **fields: Any) -> None:
        if not fields:
            return
        values: list[Any] = []
        sets: list[str] = []
        for key, value in fields.items():
            if key not in _COLUMNS:
                continue
            if key == "status" and isinstance(value, AlertStatus):
                value = value.value
            if key == "ticket" and value is not None:
                value = json.dumps(value)
            sets.append(f"{key} = %s")
            values.append(value)
        if not sets:
            return
        values.append(alert_id)
        with _get_pool().connection() as conn:
            conn.execute(
                f"UPDATE aegis_alerts SET {', '.join(sets)} WHERE alert_id = %s",
                values,
            )

    def get(self, alert_id: str) -> AlertRecord | None:
        with _get_pool().connection() as conn:
            row = conn.execute(
                f"SELECT {', '.join(_COLUMNS)} FROM aegis_alerts WHERE alert_id = %s",
                (alert_id,),
            ).fetchone()
        return _to_record(row) if row else None

    def awaiting_approval(self) -> list[AlertRecord]:
        with _get_pool().connection() as conn:
            rows = conn.execute(
                f"SELECT {', '.join(_COLUMNS)} FROM aegis_alerts "
                "WHERE status = %s ORDER BY received_at DESC LIMIT 200",
                (AlertStatus.AWAITING_APPROVAL.value,),
            ).fetchall()
        return [_to_record(r) for r in rows]


class PostgresDedupeIndex:
    """Fingerprint index shared by every worker."""

    def check(self, alert: SIEMAlert) -> DedupeEntry | None:
        """Claim a fingerprint, or report the alert that already holds it.

        The window expiry is evaluated inside the same statement: an entry older
        than the window is reset rather than incremented, so a recurrence
        tomorrow is triaged fresh.
        """
        settings = get_settings()
        if not settings.dedupe_enabled:
            return None

        key = fingerprint(alert)
        window = int(settings.dedupe_window_seconds)

        with _get_pool().connection() as conn:
            row = conn.execute(
                """
                INSERT INTO aegis_dedupe (fingerprint, alert_id)
                VALUES (%s, %s)
                ON CONFLICT (fingerprint) DO UPDATE SET
                    occurrences = CASE
                        WHEN now() - aegis_dedupe.first_seen
                             > make_interval(secs => %s) THEN 1
                        ELSE aegis_dedupe.occurrences + 1 END,
                    first_seen = CASE
                        WHEN now() - aegis_dedupe.first_seen
                             > make_interval(secs => %s) THEN now()
                        ELSE aegis_dedupe.first_seen END,
                    alert_id = CASE
                        WHEN now() - aegis_dedupe.first_seen
                             > make_interval(secs => %s) THEN EXCLUDED.alert_id
                        ELSE aegis_dedupe.alert_id END,
                    last_seen = now()
                RETURNING alert_id, occurrences,
                          extract(epoch FROM first_seen) AS first_seen,
                          extract(epoch FROM last_seen) AS last_seen
                """,
                (key, alert.alert_id, window, window, window),
            ).fetchone()

        # occurrences == 1 means this alert claimed the fingerprint, either as
        # the first of its kind or because the previous window had expired.
        if row["occurrences"] == 1:
            return None
        return DedupeEntry(row["alert_id"], row["first_seen"],
                           row["last_seen"], row["occurrences"])

    def clear(self) -> None:
        with _get_pool().connection() as conn:
            conn.execute("TRUNCATE aegis_dedupe")


def utcnow() -> datetime:
    return datetime.now(UTC)


def ping() -> bool:
    """Whether the database is reachable right now.

    A database that dies after startup should surface on the health endpoint
    rather than as failures buried in the logs.

    Recovery is not instant: the pool backs off between reconnect attempts, so
    this can report unreachable for around a minute after the database returns.
    That is the pool healing, not a stuck process.
    """
    try:
        with _get_pool().connection() as conn:
            conn.execute("SELECT 1")
        return True
    except Exception as exc:  # noqa: BLE001
        logger.warning("database unreachable: %s", exc)
        return False
