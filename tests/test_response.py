"""Containment: what may be proposed, and what may actually run."""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import ValidationError

from aegis.graph import build_graph, route_after_decision
from aegis.nodes.executor import (
    DryRunExecutor,
    allowed_targets,
    decision_approves_response,
    executor_node,
)
from aegis.schemas.alert import SIEMAlert
from aegis.schemas.response import ProposedAction, ResponsePlan


def _alert() -> SIEMAlert:
    return SIEMAlert(alert_id="R-1", rule_name="R", severity="high",
                     timestamp="2026-09-08T12:00:00Z", source_ip="185.220.101.5",
                     username="j.doe@corp.com", hostname="WIN-FINANCE-07")


def _action(target: str = "WIN-FINANCE-07", action: str = "isolate_host"):
    return ProposedAction(action=action, target=target,
                          rationale="C2 beaconing observed from this host")


def _state(**kw: Any) -> dict[str, Any]:
    base = {
        "alert": _alert(),
        "response_plan": ResponsePlan(actions=[_action()], summary="Contain the host."),
        "human_decision": "Confirmed as an incident (by U1 via slack)",
    }
    base.update(kw)
    return base


@pytest.fixture(autouse=True)
def _enable(monkeypatch):
    monkeypatch.setenv("RESPONSE_ACTIONS_ENABLED", "true")
    monkeypatch.setenv("ACTION_DRY_RUN", "true")


# --- the schema is a wall ----------------------------------------------------


def test_the_model_cannot_invent_an_action():
    with pytest.raises(ValidationError):
        ProposedAction(action="wipe_disk", target="H", rationale="because reasons")


def test_irreversible_actions_are_marked():
    assert _action(action="isolate_host").reversible is True
    assert _action(target="j.doe@corp.com", action="disable_account").reversible is False


def test_an_over_long_plan_is_trimmed_not_discarded(monkeypatch):
    """The cap is applied after parsing. As a schema constraint, a model that
    proposed one action too many produced a validation error and no plan at
    all, which is a worse outcome than a trimmed one."""
    from aegis.nodes.planner import MAX_ACTIONS, planner_node

    monkeypatch.setenv("RESPONSE_PLANNER_ENABLED", "true")
    long_plan = ResponsePlan(actions=[_action() for _ in range(9)])

    class FakeLLM:
        def with_structured_output(self, schema): return self
        def invoke(self, messages, config=None): return long_plan

    monkeypatch.setattr("aegis.nodes.planner.get_llm", lambda role: FakeLLM())
    update = planner_node({**_state(), "verdict": "true_positive", "confidence": 0.9})

    assert len(update["response_plan"].actions) == MAX_ACTIONS


# --- approval gating ---------------------------------------------------------


@pytest.mark.parametrize("decision,expected", [
    ("Confirmed as an incident", True),
    ("Escalated to incident response", True),
    ("Closed as a false positive", False),
    ("reject and confirm", False),      # rejection wins on ambiguity
    ("", False),
    (None, False),
])
def test_only_an_approving_decision_authorises_containment(decision, expected):
    assert decision_approves_response(decision) is expected


def test_nothing_runs_without_an_approving_decision():
    update = executor_node(_state(human_decision="Closed as a false positive"))
    assert update.get("executed_actions") is None
    assert "not executed" in update["audit_log"][0]


def test_nothing_runs_when_the_feature_is_disabled(monkeypatch):
    monkeypatch.setenv("RESPONSE_ACTIONS_ENABLED", "false")
    update = executor_node(_state())
    assert "disabled" in update["audit_log"][0]


# --- target restriction ------------------------------------------------------


def test_targets_are_limited_to_entities_named_by_the_alert():
    assert allowed_targets(_state()) == {
        "win-finance-07", "j.doe@corp.com", "185.220.101.5"}


def test_an_action_on_an_unnamed_host_is_refused():
    """The plan is written by a model reading attacker-influenced evidence. A
    crafted log line must not be able to steer containment onto another host."""
    state = _state(response_plan=ResponsePlan(actions=[_action(target="DC-01")]))
    update = executor_node(state)
    assert update["executed_actions"] == []
    assert "REFUSED" in update["audit_log"][0]
    assert "DC-01" in update["audit_log"][0]


def test_a_refusal_does_not_stop_the_rest_of_the_plan():
    state = _state(response_plan=ResponsePlan(actions=[
        _action(target="DC-01"), _action(target="WIN-FINANCE-07")]))
    update = executor_node(state)
    assert len(update["executed_actions"]) == 1
    assert any("REFUSED" in line for line in update["audit_log"])


# --- dry run -----------------------------------------------------------------


def test_dry_run_is_the_default_and_performs_nothing():
    update = executor_node(_state())
    assert update["executed_actions"] == ["DRY RUN: would isolate_host WIN-FINANCE-07"]


def test_dry_run_executor_returns_a_description_not_an_effect():
    assert "DRY RUN" in DryRunExecutor().perform(_action())


def test_a_failing_action_does_not_abort_the_others(monkeypatch):
    class Flaky:
        def __init__(self): self.n = 0
        def perform(self, action):
            self.n += 1
            if self.n == 1:
                raise RuntimeError("api down")
            return f"contained {action.target}"

    monkeypatch.setattr("aegis.nodes.executor.resolve_executor", lambda: Flaky())
    state = _state(response_plan=ResponsePlan(actions=[
        _action(), _action(target="j.doe@corp.com", action="revoke_sessions")]))
    update = executor_node(state)
    assert len(update["executed_actions"]) == 1
    assert any("FAILED" in line for line in update["audit_log"])


# --- topology ----------------------------------------------------------------


def test_the_executor_is_reachable_only_after_human_review():
    """Asserted on structure: no code path reaches containment without passing
    through the interrupt."""
    edges = {(e.source, e.target) for e in build_graph().get_graph().edges}
    assert {s for s, t in edges if t == "executor"} == {"human_review"}


def test_routing_refuses_containment_on_rejection():
    assert route_after_decision(
        _state(human_decision="Closed as a false positive")) == "__end__"


def test_routing_refuses_containment_when_disabled(monkeypatch):
    monkeypatch.setenv("RESPONSE_ACTIONS_ENABLED", "false")
    assert route_after_decision(_state()) == "__end__"


def test_routing_allows_containment_only_on_approval():
    assert route_after_decision(_state()) == "executor"


def test_the_approver_is_told_which_actions_were_refused(monkeypatch):
    """Someone who approves a plan and is not told two steps were refused will
    assume they happened."""
    from aegis.ingest.store import REGISTRY, AlertStatus
    from aegis.notify.slack import APPROVE, SlackNotifier
    from aegis.notify.slack_handler import handle_block_action

    class FakeSlack:
        def __init__(self):
            self.posted: list[Any] = []
            self.updated: list[Any] = []

        def chat_postMessage(self, **kw):
            self.posted.append(kw)
            return {"ts": "1.1"}

        def chat_update(self, **kw):
            self.updated.append(kw)
            return {"ok": True}

    monkeypatch.setattr(
        "aegis.notify.slack_handler.apply_decision",
        lambda *a, **kw: {
            "executed_actions": ["DRY RUN: would isolate_host WIN-FINANCE-07"],
            "audit_log": ["[executor] REFUSED collect_forensics on WIN-HR-02: "
                          "target is not an entity named by this alert"],
        })
    REGISTRY.create_if_absent("REF-1")
    REGISTRY.update("REF-1", status=AlertStatus.AWAITING_APPROVAL,
                    slack_ts="1.1", ticket={"title": "t"})

    fake = FakeSlack()
    handle_block_action(
        {"type": "block_actions", "user": {"id": "U1"},
         "actions": [{"action_id": APPROVE, "value": "REF-1"}]},
        SlackNotifier(client=fake))

    summary = str(fake.posted)
    assert "Actions taken" in summary
    assert "Not taken" in summary
    assert "WIN-HR-02" in summary
