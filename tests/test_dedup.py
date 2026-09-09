"""Alert deduplication. No LLM or network involved."""

from __future__ import annotations

import pytest

from aegis.dedup import DEDUPE_INDEX, DedupeIndex, fingerprint
from aegis.schemas.alert import SIEMAlert


@pytest.fixture(autouse=True)
def _clean_index():
    DEDUPE_INDEX.clear()
    yield
    DEDUPE_INDEX.clear()


def alert(alert_id: str, **kw) -> SIEMAlert:
    base = dict(rule_name="Brute Force Authentication", severity="medium",
                timestamp="2026-09-08T02:14:00Z", source_ip="45.155.205.233",
                username="j.doe@corp.com", hostname="WIN-FINANCE-07")
    base.update(kw)
    return SIEMAlert(alert_id=alert_id, **base)


# --- fingerprinting ----------------------------------------------------------


def test_same_situation_different_ids_share_a_fingerprint():
    """A brute force run fires once per detection window, so ids differ while
    the situation does not."""
    assert fingerprint(alert("SPL-1")) == fingerprint(alert("SPL-2"))


@pytest.mark.parametrize("field,value", [
    ("username", "other@corp.com"),
    ("hostname", "OTHER-HOST"),
    ("source_ip", "8.8.8.8"),
    ("rule_name", "A Different Rule"),
])
def test_different_entities_are_different_situations(field, value):
    assert fingerprint(alert("A")) != fingerprint(alert("A", **{field: value}))


def test_timestamp_and_id_do_not_affect_the_fingerprint():
    a = alert("SPL-1", timestamp="2026-09-08T02:14:00Z")
    b = alert("SPL-99", timestamp="2026-09-08T05:44:00Z")
    assert fingerprint(a) == fingerprint(b)


def test_entity_casing_is_normalised():
    assert fingerprint(alert("A")) == fingerprint(
        alert("A", username="J.Doe@Corp.com", hostname="win-finance-07"))


# --- the index ---------------------------------------------------------------


def test_first_alert_is_not_a_duplicate():
    assert DedupeIndex().check(alert("SPL-1")) is None


def test_subsequent_alerts_point_back_to_the_first():
    idx = DedupeIndex()
    assert idx.check(alert("SPL-1")) is None
    hit = idx.check(alert("SPL-2"))
    assert hit is not None
    assert hit.alert_id == "SPL-1"      # the one actually triaged
    assert hit.occurrences == 2


def test_occurrences_accumulate_so_an_ongoing_attack_still_reads_as_ongoing():
    idx = DedupeIndex()
    idx.check(alert("SPL-0"))
    last = None
    for i in range(1, 37):
        last = idx.check(alert(f"SPL-{i}"))
    assert last.occurrences == 37


def test_unrelated_alerts_do_not_suppress_each_other():
    idx = DedupeIndex()
    idx.check(alert("SPL-1"))
    assert idx.check(alert("SPL-2", hostname="OTHER-HOST")) is None


def test_window_expiry_lets_a_recurrence_be_triaged_fresh(monkeypatch):
    """The same rule firing tomorrow is a new situation, not a repeat."""
    monkeypatch.setenv("DEDUPE_WINDOW_SECONDS", "60")
    idx = DedupeIndex()
    idx.check(alert("SPL-1"))

    clock = {"t": 0.0}
    monkeypatch.setattr("aegis.dedup.time.monotonic", lambda: clock["t"])
    idx = DedupeIndex()
    idx.check(alert("SPL-1"))
    clock["t"] = 61.0
    assert idx.check(alert("SPL-2")) is None


def test_dedupe_can_be_disabled(monkeypatch):
    monkeypatch.setenv("DEDUPE_ENABLED", "false")
    idx = DedupeIndex()
    idx.check(alert("SPL-1"))
    assert idx.check(alert("SPL-2")) is None


def test_returned_entry_cannot_mutate_index_state():
    idx = DedupeIndex()
    idx.check(alert("SPL-1"))
    hit = idx.check(alert("SPL-2"))
    hit.occurrences = 999
    assert idx.check(alert("SPL-3")).occurrences == 3


# --- notification throttling -------------------------------------------------


def test_storm_of_duplicates_does_not_spam_slack(monkeypatch):
    """One chat.update per duplicate would exhaust Slack's rate limit."""
    from aegis.dedup import DedupeEntry
    from aegis.ingest.store import REGISTRY, AlertStatus
    from aegis.ingest.worker import _record_duplicate

    class FakeNotifier:
        def __init__(self): self.updates = 0
        def update_occurrences(self, *a, **kw): self.updates += 1

    REGISTRY.create_if_absent("ORIG-1")
    REGISTRY.update("ORIG-1", status=AlertStatus.AWAITING_APPROVAL,
                    slack_ts="1.1", ticket={"title": "t"})

    notifier = FakeNotifier()
    for i in range(50):
        REGISTRY.create_if_absent(f"DUP-{i}")
        _record_duplicate(alert(f"DUP-{i}"),
                          DedupeEntry("ORIG-1", 0.0, 0.0, i + 2), notifier)

    assert notifier.updates == 1                      # throttled
    assert REGISTRY.get("ORIG-1").occurrences == 51    # count still accurate


def test_resolved_tickets_are_not_reopened_by_duplicates():
    from aegis.dedup import DedupeEntry
    from aegis.ingest.store import REGISTRY, AlertStatus
    from aegis.ingest.worker import _record_duplicate

    class FakeNotifier:
        def __init__(self): self.updates = 0
        def update_occurrences(self, *a, **kw): self.updates += 1

    REGISTRY.create_if_absent("DONE-1")
    REGISTRY.update("DONE-1", status=AlertStatus.RESOLVED, slack_ts="1.1", ticket={})
    notifier = FakeNotifier()
    REGISTRY.create_if_absent("DUP-X")
    _record_duplicate(alert("DUP-X"), DedupeEntry("DONE-1", 0.0, 0.0, 2), notifier)
    assert notifier.updates == 0
