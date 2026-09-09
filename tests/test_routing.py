"""The auto-close gate. Each of the five conditions is tested INDEPENDENTLY so a
later 'simplification' fails by name instead of silently widening auto-close.
"""

from __future__ import annotations

from aegis.graph import route_on_verdict
from aegis.schemas.state import EnrichmentData, Verdict


def _state(alert, enrichments, **kw):
    base = {
        "alert": alert,
        "enrichments": enrichments,
        "verdict": Verdict.FALSE_POSITIVE,
        "confidence": 0.99,
    }
    base.update(kw)
    return base


def test_baseline_clean_alert_auto_closes(alert, clean_enrichments):
    assert route_on_verdict(_state(alert, clean_enrichments)) == "auto_close"


def test_gate1_non_false_positive_verdict_escalates(alert, clean_enrichments):
    for v in (Verdict.TRUE_POSITIVE, Verdict.AMBIGUOUS):
        assert route_on_verdict(_state(alert, clean_enrichments, verdict=v)) == "human_review"


def test_gate2_low_confidence_escalates(alert, clean_enrichments):
    assert route_on_verdict(_state(alert, clean_enrichments, confidence=0.94)) == "human_review"


def test_gate3_any_enrichment_error_revokes_auto_close(alert, clean_enrichments):
    broken = clean_enrichments + [
        EnrichmentData(agent_name="threat_intel", summary="failed", error="429")
    ]
    assert route_on_verdict(_state(alert, broken)) == "human_review"


def test_gate4_critical_severity_always_gets_human_eyes(alert, clean_enrichments):
    crit = alert.model_copy(update={"severity": "critical"})
    assert route_on_verdict(_state(crit, clean_enrichments)) == "human_review"


def test_gate5_privileged_identity_escalates(alert, clean_enrichments):
    priv = [
        e.model_copy(update={"findings": {"is_privileged": True}})
        if e.agent_name == "identity" else e
        for e in clean_enrichments
    ]
    assert route_on_verdict(_state(alert, priv)) == "human_review"


def test_missing_enrichments_never_auto_closes(alert):
    assert route_on_verdict(_state(alert, [])) == "human_review"


# --- global safety overrides ---------------------------------------------


def test_shadow_mode_never_auto_closes(alert, clean_enrichments, monkeypatch):
    """A fresh deployment must close nothing until explicitly enabled."""
    monkeypatch.setenv("SHADOW_MODE", "true")
    assert route_on_verdict(_state(alert, clean_enrichments)) == "human_review"


def test_kill_switch_overrides_everything(alert, clean_enrichments, monkeypatch):
    """One env var, no deploy: flipped mid-incident."""
    monkeypatch.setenv("KILL_SWITCH", "true")
    assert route_on_verdict(_state(alert, clean_enrichments)) == "human_review"


def test_severity_ceiling_blocks_auto_close_above_the_limit(alert, clean_enrichments, monkeypatch):
    """Staged rollout: auto-close low severity first, widen later."""
    monkeypatch.setenv("MAX_AUTO_CLOSE_SEVERITY", "low")
    high = alert.model_copy(update={"severity": "high"})
    assert route_on_verdict(_state(high, clean_enrichments)) == "human_review"
    low = alert.model_copy(update={"severity": "low"})
    assert route_on_verdict(_state(low, clean_enrichments)) == "auto_close"


# --- post-deserialization state (the Postgres path) --------------------------


def test_router_handles_verdict_as_plain_string(alert, clean_enrichments):
    """A checkpoint round-trip flattens bare str-Enums back to strings."""
    s = _state(alert, clean_enrichments, verdict="false_positive")
    assert route_on_verdict(s) == "auto_close"
    s = _state(alert, clean_enrichments, verdict="true_positive")
    assert route_on_verdict(s) == "human_review"


def test_ticket_draft_handles_verdict_as_plain_string(alert, clean_enrichments):
    from aegis.graph import _draft_ticket

    s = _state(alert, clean_enrichments, verdict="true_positive", reasoning="x")
    assert _draft_ticket(s)["verdict"] == "true_positive"
