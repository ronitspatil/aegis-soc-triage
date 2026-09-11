"""Polling ingestion. No Splunk instance required."""

from __future__ import annotations

from typing import Any

import pytest

from aegis.ingest.splunk_poller import poll_once
from aegis.ingest.splunk_source import IngestResult
from aegis.ingest.store import ALERT_QUEUE, REGISTRY
from aegis.schemas.alert import SIEMAlert


def _alert(alert_id: str) -> SIEMAlert:
    return SIEMAlert(alert_id=alert_id, rule_name="R", severity="low",
                     timestamp="2026-09-09T00:00:00Z", hostname="H")


class FakeSource:
    def __init__(self, result: IngestResult) -> None:
        self.result = result
        self.calls: list[str] = []

    def search_alerts(self, spl: str, **kw: Any) -> IngestResult:
        self.calls.append(kw.get("earliest", ""))
        return self.result


def _drain() -> int:
    n = 0
    while not ALERT_QUEUE.empty():
        ALERT_QUEUE.get()
        ALERT_QUEUE.task_done()
        n += 1
    return n


def test_new_alerts_are_enqueued():
    _drain()
    source = FakeSource(IngestResult(alerts=[_alert("P-1"), _alert("P-2")]))
    counts = poll_once(source, "search x", 180)
    assert counts == {"seen": 2, "enqueued": 2, "duplicates": 0, "rejected": 0}
    assert _drain() == 2


def test_an_alert_seen_before_is_not_enqueued_again():
    """Each poll overlaps the previous window, so the same alert is returned
    repeatedly and must only be triaged once."""
    _drain()
    source = FakeSource(IngestResult(alerts=[_alert("P-DUP")]))
    poll_once(source, "search x", 180)
    _drain()
    counts = poll_once(source, "search x", 180)
    assert counts["enqueued"] == 0
    assert counts["duplicates"] == 1
    assert _drain() == 0


def test_the_lookback_window_is_applied():
    source = FakeSource(IngestResult())
    poll_once(source, "search x", 180)
    assert source.calls == ["-180s"]


def test_rejected_rows_are_counted_not_hidden():
    """A row that fails validation is a mapping problem worth seeing."""
    _drain()
    source = FakeSource(IngestResult(alerts=[_alert("P-OK")],
                                     rejected=[{"row": {}, "error": "bad ip"}]))
    counts = poll_once(source, "search x", 180)
    assert counts["rejected"] == 1
    assert counts["enqueued"] == 1
    _drain()


def test_registry_records_every_alert_the_poller_saw():
    _drain()
    poll_once(FakeSource(IngestResult(alerts=[_alert("P-REC")])), "search x", 180)
    assert REGISTRY.get("P-REC") is not None
    _drain()


# --- stall detection ---------------------------------------------------------


def test_empty_polls_are_counted():
    """A search matching nothing succeeds, so silence has to be counted or it
    is indistinguishable from a quiet night."""
    from aegis.ingest.splunk_poller import POLL_HEALTH

    POLL_HEALTH.__init__()
    source = FakeSource(IngestResult())
    for _ in range(3):
        poll_once(source, "search x", 180)
    assert POLL_HEALTH.consecutive_empty == 3


def test_the_empty_streak_resets_when_rows_come_back():
    from aegis.ingest.splunk_poller import POLL_HEALTH

    POLL_HEALTH.__init__()
    poll_once(FakeSource(IngestResult()), "search x", 180)
    assert POLL_HEALTH.consecutive_empty == 1
    poll_once(FakeSource(IngestResult(alerts=[_alert("P-RESET")])), "search x", 180)
    assert POLL_HEALTH.consecutive_empty == 0
    _drain()


def test_a_stalled_search_warns_once_not_every_poll():
    from aegis.ingest.splunk_poller import POLL_HEALTH, _warn_if_persistently_empty

    POLL_HEALTH.__init__()
    source = FakeSource(IngestResult())
    warned = []
    for _ in range(12):
        poll_once(source, "search x", 180)
        before = POLL_HEALTH.warned
        _warn_if_persistently_empty("search x", threshold=10)
        if POLL_HEALTH.warned and not before:
            warned.append(POLL_HEALTH.consecutive_empty)
    assert warned == [10]


def test_health_reports_degraded_while_ingestion_is_stalled(monkeypatch):
    from aegis.ingest.splunk_poller import POLL_HEALTH

    monkeypatch.setenv("SPLUNK_POLLING_ENABLED", "true")
    monkeypatch.setenv("SPLUNK_EMPTY_POLL_WARNING", "3")
    POLL_HEALTH.__init__()
    source = FakeSource(IngestResult())
    for _ in range(4):
        poll_once(source, "search x", 180)

    from aegis.ingest import api

    body = api.healthz()
    assert body["status"] == "degraded"
    assert body["ingestion"]["consecutive_empty_polls"] == 4


def test_health_is_ok_when_ingestion_is_flowing(monkeypatch):
    from aegis.ingest import api
    from aegis.ingest.splunk_poller import POLL_HEALTH

    monkeypatch.setenv("SPLUNK_POLLING_ENABLED", "true")
    POLL_HEALTH.__init__()
    poll_once(FakeSource(IngestResult(alerts=[_alert("P-FLOW")])), "search x", 180)
    body = api.healthz()
    assert body["status"] == "ok"
    assert body["ingestion"]["total_ingested"] == 1
    _drain()


# --- dependency health -------------------------------------------------------


def test_health_reports_an_unreachable_database(monkeypatch):
    """A database that dies after startup must surface on the health endpoint,
    not only in the logs."""
    from aegis.ingest import api

    monkeypatch.setenv("POSTGRES_URL", "postgresql://nobody@127.0.0.1:1/none")
    monkeypatch.setattr("aegis.ingest.store_pg.ping", lambda: False)
    body = api.healthz()
    assert body["database"] == "unreachable"
    assert body["status"] == "degraded"


def test_health_reports_a_reachable_database(monkeypatch):
    from aegis.ingest import api

    monkeypatch.setenv("POSTGRES_URL", "postgresql://x@127.0.0.1:5432/x")
    monkeypatch.setattr("aegis.ingest.store_pg.ping", lambda: True)
    body = api.healthz()
    assert body["database"] == "ok"
    assert body["status"] == "ok"


def test_health_omits_the_database_when_none_is_configured():
    from aegis.ingest import api

    assert "database" not in api.healthz()


# --- transient fault handling ------------------------------------------------


def test_a_dropped_database_connection_is_treated_as_transient():
    """The pool discards the dead connection and the next attempt succeeds, so
    failing the alert loses it for no reason."""
    import psycopg

    from aegis.ingest.worker import is_transient

    assert is_transient(psycopg.OperationalError("terminating connection"))


def test_a_programming_error_is_not_transient():
    from aegis.ingest.worker import is_transient

    assert not is_transient(ValueError("bad field"))
    assert not is_transient(KeyError("alert"))


def test_a_transient_fault_requeues_rather_than_failing_the_alert():
    import psycopg

    from aegis.ingest.store import REGISTRY, AlertStatus
    from aegis.ingest.worker import _handle_triage_error

    _drain()
    alert = _alert("RETRY-1")
    REGISTRY.create_if_absent("RETRY-1")
    _handle_triage_error(alert, psycopg.OperationalError("connection closed"))

    rec = REGISTRY.get("RETRY-1")
    assert rec.status is AlertStatus.QUEUED
    assert rec.attempts == 1
    assert _drain() == 1          # back on the queue


def test_retries_are_bounded(monkeypatch):
    """A genuinely broken alert must not loop forever."""
    import psycopg

    from aegis.ingest.store import REGISTRY, AlertStatus
    from aegis.ingest.worker import _handle_triage_error

    monkeypatch.setenv("MAX_TRIAGE_ATTEMPTS", "2")
    _drain()
    REGISTRY.create_if_absent("RETRY-2")
    REGISTRY.update("RETRY-2", attempts=1)
    _handle_triage_error(_alert("RETRY-2"), psycopg.OperationalError("closed"))

    assert REGISTRY.get("RETRY-2").status is AlertStatus.FAILED
    assert _drain() == 0


def test_a_permanent_error_fails_immediately_without_retrying():
    from aegis.ingest.store import REGISTRY, AlertStatus
    from aegis.ingest.worker import _handle_triage_error

    _drain()
    REGISTRY.create_if_absent("PERM-1")
    _handle_triage_error(_alert("PERM-1"), ValueError("schema mismatch"))
    assert REGISTRY.get("PERM-1").status is AlertStatus.FAILED
    assert _drain() == 0


def test_the_worker_survives_an_error_its_own_handler_cannot_absorb(monkeypatch):
    """triage_once handles its own failures, so an exception reaching the loop
    means the handling failed. Letting it propagate kills the thread and every
    later alert queues forever."""
    import threading

    from aegis.ingest import worker as worker_mod
    from aegis.ingest.store import ALERT_QUEUE, REGISTRY, AlertStatus

    _drain()
    monkeypatch.setattr(worker_mod, "get_app", lambda: object())

    def boom(app, alert, notifier=None):
        raise RuntimeError("registry write failed")

    monkeypatch.setattr(worker_mod, "triage_once", boom)

    REGISTRY.create_if_absent("BOOM-1")
    ALERT_QUEUE.put(_alert("BOOM-1"))
    stop = threading.Event()
    thread = threading.Thread(target=worker_mod.worker_loop, args=(stop,), daemon=True)
    thread.start()
    ALERT_QUEUE.join()          # the worker processed it rather than dying

    REGISTRY.create_if_absent("BOOM-2")
    ALERT_QUEUE.put(_alert("BOOM-2"))
    ALERT_QUEUE.join()          # and it is still alive for the next one
    stop.set()
    thread.join(timeout=5)

    assert REGISTRY.get("BOOM-1").status is AlertStatus.FAILED
    assert REGISTRY.get("BOOM-2").status is AlertStatus.FAILED


def test_a_non_utf8_database_is_refused(monkeypatch):
    """A SQL_ASCII database works until the first em dash a model writes."""
    from aegis.ingest.store_pg import _require_utf8

    class Conn:
        def __init__(self, enc): self.enc = enc
        def execute(self, sql):
            return type("R", (), {"fetchone": lambda _self: {"server_encoding": self.enc}})()

    _require_utf8(Conn("UTF8"))          # accepted
    with pytest.raises(RuntimeError, match="SQL_ASCII"):
        _require_utf8(Conn("SQL_ASCII"))
