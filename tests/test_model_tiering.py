"""Which synthesis model an alert gets, and why.

The cheap tier is chosen from deterministic properties of the evidence, never
from the model's own confidence. Measured on the labelled corpus, a small model
reaches the same verdicts but reports higher confidence when evidence is
incomplete, so it is only used where nothing is missing.
"""

from __future__ import annotations

import pytest

from aegis.llm.config import ModelRole
from aegis.nodes.synthesizer import select_reasoner_role
from aegis.schemas.alert import SIEMAlert
from aegis.schemas.state import EnrichmentData


def _alert(severity: str = "low") -> SIEMAlert:
    return SIEMAlert(alert_id="T", rule_name="R", severity=severity,
                     timestamp="2026-09-08T12:00:00Z")


def _clean() -> list[EnrichmentData]:
    return [EnrichmentData(agent_name=a, summary="clean", risk_signal=0.0)
            for a in ("threat_intel", "identity", "endpoint")]


def test_structurally_easy_alert_uses_the_cheap_tier():
    assert select_reasoner_role(_alert(), _clean()) is ModelRole.FAST_REASONER


def test_any_suspicion_escalates_to_the_better_model():
    enr = _clean()[:2] + [EnrichmentData(agent_name="endpoint", summary="s", risk_signal=0.4)]
    assert select_reasoner_role(_alert(), enr) is ModelRole.REASONER


def test_failed_enrichment_escalates():
    """Reasoning under uncertainty is where confidence calibration matters."""
    enr = _clean()[:2] + [EnrichmentData(agent_name="endpoint", summary="s", error="429")]
    assert select_reasoner_role(_alert(), enr) is ModelRole.REASONER


def test_privileged_identity_escalates():
    enr = _clean()[:2] + [EnrichmentData(agent_name="identity", summary="s",
                                         findings={"is_privileged": True})]
    assert select_reasoner_role(_alert(), enr) is ModelRole.REASONER


@pytest.mark.parametrize("severity", ["high", "critical"])
def test_high_severity_escalates(severity):
    assert select_reasoner_role(_alert(severity), _clean()) is ModelRole.REASONER


def test_missing_enrichments_escalate():
    assert select_reasoner_role(_alert(), []) is ModelRole.REASONER


def test_tiering_can_be_disabled(monkeypatch):
    monkeypatch.setenv("MODEL_TIERING", "false")
    assert select_reasoner_role(_alert(), _clean()) is ModelRole.REASONER


def test_output_cap_leaves_headroom_for_reasoning_tokens():
    """A cap of 800 truncated structured output mid-JSON on a model that emits
    internal reasoning tokens, which surfaces as a parse failure rather than a
    shorter answer."""
    from aegis.llm.config import get_settings

    assert get_settings().reasoner_max_tokens >= 1200
