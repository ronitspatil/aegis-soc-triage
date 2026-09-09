"""Where the investigation agent sits in the graph.

These assert on topology rather than behaviour. The safety property is that the
agent cannot influence the auto-close decision, and a behavioural test could
pass by luck while the structure allows it.
"""

from __future__ import annotations

from typing import Any

import pytest

from aegis.graph import build_graph, route_after_synthesis, route_on_verdict
from aegis.schemas.alert import SIEMAlert
from aegis.schemas.investigation import InvestigationReport
from aegis.schemas.state import EnrichmentData, Verdict


@pytest.fixture
def clean_state():
    alert = SIEMAlert(alert_id="W-1", rule_name="R", severity="low",
                      timestamp="2026-09-08T12:00:00Z", hostname="H")
    return {
        "alert": alert,
        "enrichments": [
            EnrichmentData(agent_name=a, summary="clean", risk_signal=0.0,
                           findings={"is_privileged": False})
            for a in ("threat_intel", "identity", "endpoint")
        ],
        "verdict": Verdict.FALSE_POSITIVE,
        "confidence": 0.99,
    }


def _edges(app: Any) -> set[tuple[str, str]]:
    return {(e.source, e.target) for e in app.get_graph().edges}


# --- the safety property -----------------------------------------------------


def test_auto_close_bypasses_the_agent_entirely(clean_state, monkeypatch):
    """An alert that qualifies for auto-close never reaches the investigator,
    even with the agent enabled."""
    monkeypatch.setenv("INVESTIGATOR_ENABLED", "true")
    assert route_on_verdict(clean_state) == "auto_close"
    assert route_after_synthesis(clean_state) == "auto_close"


def test_investigation_only_happens_on_the_escalation_branch(clean_state, monkeypatch):
    monkeypatch.setenv("INVESTIGATOR_ENABLED", "true")
    escalating = {**clean_state, "verdict": Verdict.TRUE_POSITIVE}
    assert route_after_synthesis(escalating) == "investigator"


def test_agent_is_off_by_default(clean_state):
    """Enabled deliberately, like shadow mode. Escalation goes straight to the
    planner, which is itself a no-op unless enabled."""
    escalating = {**clean_state, "verdict": Verdict.TRUE_POSITIVE}
    assert route_after_synthesis(escalating) == "planner"


def test_nothing_routes_from_the_agent_back_into_auto_close():
    """If the agent could reach auto_close, a finding could close an alert."""
    edges = _edges(build_graph())
    for source in ("investigator", "investigation_tools", "investigation_report"):
        assert (source, "auto_close") not in edges


def test_the_agent_is_only_entered_from_synthesis_or_its_own_tools():
    edges = _edges(build_graph())
    into_investigator = {s for s, t in edges if t == "investigator"}
    assert into_investigator <= {"synthesizer", "investigation_tools"}


def test_the_loop_closes_and_terminates_at_human_review():
    edges = _edges(build_graph())
    assert ("investigator", "investigation_tools") in edges
    assert ("investigation_tools", "investigator") in edges
    assert ("investigation_report", "planner") in edges
    assert ("planner", "human_review") in edges


# --- the report reaches the analyst -----------------------------------------


def test_ticket_carries_the_investigation_when_one_ran(clean_state):
    from aegis.graph import _draft_ticket

    report = InvestigationReport(
        summary="Indicator seen on two hosts the alert did not name.",
        corroborating=["persistence via scheduled task"],
        unanswered=["payload not decoded"],
        scope_concern=True,
    )
    ticket = _draft_ticket({**clean_state, "investigation_report": report})
    assert ticket["investigation"]["scope_concern"] is True
    assert ticket["investigation"]["unanswered"] == ["payload not decoded"]


def test_ticket_omits_the_section_when_no_investigation_ran(clean_state):
    from aegis.graph import _draft_ticket

    assert "investigation" not in _draft_ticket(clean_state)


def test_slack_message_surfaces_scope_concern_and_gaps():
    import json

    from aegis.notify.slack import build_ticket_blocks

    ticket = {
        "title": "[HIGH] R", "verdict": "true_positive", "confidence": 0.9,
        "entities": {"hostname": "WIN-FINANCE-07"}, "reasoning": "r",
        "enrichment_signals": {},
        "investigation": {
            "summary": "Indicator seen on WIN-HR-02 and WIN-SALES-11.",
            "unanswered": ["payload not decoded"],
            "scope_concern": True, "budget_exhausted": False,
        },
    }
    rendered = json.dumps(build_ticket_blocks("W-1", ticket, "high"))
    assert "WIN-HR-02" in rendered
    assert "more hosts or accounts" in rendered      # scope warning
    assert "Not determined" in rendered              # gaps are visible
