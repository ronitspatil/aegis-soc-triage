"""Trust-boundary behaviour of the data contracts."""

from __future__ import annotations

from datetime import UTC

import pytest
from pydantic import ValidationError

from aegis.schemas.alert import SIEMAlert
from aegis.schemas.state import EnrichmentData


def _mk(**kw):
    base = dict(
        alert_id="A", rule_name="R", severity="high", timestamp="2026-09-08T12:00:00"
    )
    base.update(kw)
    return SIEMAlert(**base)


def test_naive_timestamp_is_coerced_to_utc():
    assert _mk().timestamp.tzinfo == UTC


def test_offset_timestamp_is_converted_not_relabelled():
    a = _mk(timestamp="2026-09-08T12:00:00+05:00")
    assert a.timestamp.hour == 7  # 12:00+05:00 == 07:00Z


def test_file_hash_is_lowercased():
    assert _mk(file_hash="  ABC123  ").file_hash == "abc123"


def test_vendor_extra_fields_survive_rather_than_reject():
    """Perimeter models are permissive: dropping a real detection is worse."""
    a = _mk(index="main", splunk_sid="12345")
    assert a.model_extra == {"index": "main", "splunk_sid": "12345"}


def test_invalid_ip_is_rejected_at_the_boundary():
    with pytest.raises(ValidationError):
        _mk(source_ip="not-an-ip")


def test_alert_is_immutable_so_parallel_workers_cannot_race():
    a = _mk()
    with pytest.raises(ValidationError):
        a.username = "attacker@evil.com"  # type: ignore[misc]


def test_internal_model_rejects_unknown_fields():
    """Internal models are strict: an unexpected key means WE made a mistake."""
    with pytest.raises(ValidationError):
        EnrichmentData(agent_name="x", summary="y", risk_score=0.9)  # type: ignore[call-arg]


@pytest.mark.parametrize("bad", [-0.1, 1.1])
def test_risk_signal_is_bounded(bad):
    with pytest.raises(ValidationError):
        EnrichmentData(agent_name="x", summary="y", risk_signal=bad)
