"""Postgres-backed registry and dedupe index.

Skipped unless AEGIS_TEST_POSTGRES_URL points at a database that may be
written to. The properties here cannot be checked in memory: what matters is
that two processes cannot both conclude they claimed the same alert.

    AEGIS_TEST_POSTGRES_URL=postgresql://aegis@127.0.0.1:5436/aegis pytest tests/test_store_pg.py
"""

from __future__ import annotations

import os
import uuid

import pytest

TEST_URL = os.environ.get("AEGIS_TEST_POSTGRES_URL")
pytestmark = pytest.mark.skipif(not TEST_URL, reason="no test database configured")


@pytest.fixture
def pg(monkeypatch):
    """Point the stores at the test database, bypassing the suite-wide blanking."""
    monkeypatch.setenv("POSTGRES_URL", TEST_URL or "")
    from aegis.ingest.store import reset_stores

    reset_stores()
    yield
    reset_stores()


def _alert(alert_id: str, **kw):
    from aegis.schemas.alert import SIEMAlert

    base = dict(rule_name="Brute Force Authentication", severity="medium",
                timestamp="2026-09-09T00:00:00Z", source_ip="45.155.205.233",
                username="j.doe@corp.com", hostname="WIN-FINANCE-07")
    base.update(kw)
    return SIEMAlert(alert_id=alert_id, **base)


def _uid() -> str:
    return f"T-{uuid.uuid4().hex[:12]}"


# --- registry ----------------------------------------------------------------


def test_only_one_caller_claims_an_alert(pg):
    """Two workers polling overlapping windows must not both triage it."""
    from aegis.ingest.store import REGISTRY

    alert_id = _uid()
    _, first = REGISTRY.create_if_absent(alert_id)
    _, second = REGISTRY.create_if_absent(alert_id)
    assert first is True
    assert second is False


def test_state_survives_between_callers(pg):
    from aegis.ingest.store import REGISTRY, AlertStatus

    alert_id = _uid()
    REGISTRY.create_if_absent(alert_id)
    REGISTRY.update(alert_id, status=AlertStatus.AWAITING_APPROVAL,
                    verdict="true_positive", confidence=0.93,
                    ticket={"title": "t"}, slack_ts="1.1", occurrences=4)

    rec = REGISTRY.get(alert_id)
    assert rec.status is AlertStatus.AWAITING_APPROVAL
    assert rec.verdict == "true_positive"
    assert rec.confidence == 0.93
    assert rec.ticket == {"title": "t"}
    assert rec.slack_ts == "1.1"
    assert rec.occurrences == 4


def test_unknown_alert_reads_as_none(pg):
    from aegis.ingest.store import REGISTRY

    assert REGISTRY.get(_uid()) is None


def test_the_approval_queue_only_contains_pending_alerts(pg):
    from aegis.ingest.store import REGISTRY, AlertStatus

    pending, resolved = _uid(), _uid()
    for aid, status in ((pending, AlertStatus.AWAITING_APPROVAL),
                        (resolved, AlertStatus.RESOLVED)):
        REGISTRY.create_if_absent(aid)
        REGISTRY.update(aid, status=status)

    queued = {r.alert_id for r in REGISTRY.awaiting_approval()}
    assert pending in queued
    assert resolved not in queued


def test_unknown_columns_are_ignored_rather_than_breaking_the_update(pg):
    from aegis.ingest.store import REGISTRY

    alert_id = _uid()
    REGISTRY.create_if_absent(alert_id)
    REGISTRY.update(alert_id, verdict="ambiguous", not_a_column="x")
    assert REGISTRY.get(alert_id).verdict == "ambiguous"


# --- dedupe ------------------------------------------------------------------


def test_the_first_alert_of_its_kind_claims_the_fingerprint(pg):
    from aegis.dedup import DEDUPE_INDEX

    assert DEDUPE_INDEX.check(_alert(_uid(), hostname=_uid())) is None


def test_a_later_alert_points_back_at_the_first(pg):
    from aegis.dedup import DEDUPE_INDEX

    host = _uid()
    first = _uid()
    assert DEDUPE_INDEX.check(_alert(first, hostname=host)) is None
    hit = DEDUPE_INDEX.check(_alert(_uid(), hostname=host))
    assert hit is not None
    assert hit.alert_id == first
    assert hit.occurrences == 2


def test_occurrences_accumulate_across_callers(pg):
    from aegis.dedup import DEDUPE_INDEX

    host = _uid()
    DEDUPE_INDEX.check(_alert(_uid(), hostname=host))
    last = None
    for _ in range(5):
        last = DEDUPE_INDEX.check(_alert(_uid(), hostname=host))
    assert last.occurrences == 6


def test_unrelated_alerts_do_not_suppress_each_other(pg):
    from aegis.dedup import DEDUPE_INDEX

    DEDUPE_INDEX.check(_alert(_uid(), hostname=_uid()))
    assert DEDUPE_INDEX.check(_alert(_uid(), hostname=_uid())) is None


def test_an_expired_window_is_triaged_fresh(pg):
    """The same rule firing tomorrow is a new situation, and the expiry is
    evaluated inside the same statement that claims the fingerprint."""
    import psycopg

    from aegis.dedup import DEDUPE_INDEX, fingerprint

    host = _uid()
    alert = _alert(_uid(), hostname=host)
    assert DEDUPE_INDEX.check(alert) is None

    with psycopg.connect(TEST_URL, autocommit=True) as conn:
        conn.execute(
            "UPDATE aegis_dedupe SET first_seen = now() - interval '10 years' "
            "WHERE fingerprint = %s", (fingerprint(alert),))

    later = _alert(_uid(), hostname=host)
    assert DEDUPE_INDEX.check(later) is None      # reclaimed, not incremented

    followup = DEDUPE_INDEX.check(_alert(_uid(), hostname=host))
    assert followup.alert_id == later.alert_id    # the new window's owner


def test_dedupe_can_be_disabled(pg, monkeypatch):
    from aegis.dedup import DEDUPE_INDEX

    monkeypatch.setenv("DEDUPE_ENABLED", "false")
    host = _uid()
    assert DEDUPE_INDEX.check(_alert(_uid(), hostname=host)) is None
    assert DEDUPE_INDEX.check(_alert(_uid(), hostname=host)) is None
