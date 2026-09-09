"""The investigation loop: termination, budgets, and tool safety.

No model is invoked. A scripted fake stands in so the control flow, which is
the part that must never misbehave, is tested deterministically.
"""

from __future__ import annotations

from typing import Any

import pytest
from langchain_core.messages import AIMessage

from aegis.nodes.investigation_tools import INVESTIGATION_TOOLS
from aegis.nodes.investigator import (
    budget_remaining,
    investigation_report_node,
    investigator_node,
    should_continue,
)
from aegis.schemas.alert import SIEMAlert
from aegis.schemas.investigation import InvestigationReport
from aegis.schemas.state import EnrichmentData


def _alert() -> SIEMAlert:
    return SIEMAlert(alert_id="INV-1", rule_name="Encoded PowerShell from Office",
                     severity="high", timestamp="2026-09-08T02:14:00Z",
                     source_ip="185.220.101.5", username="j.doe@corp.com",
                     hostname="WIN-FINANCE-07")


def _state(**kw: Any) -> dict[str, Any]:
    base = {
        "alert": _alert(),
        "enrichments": [EnrichmentData(agent_name="threat_intel", summary="s",
                                       risk_signal=0.95)],
        "verdict": "true_positive",
        "confidence": 0.95,
    }
    base.update(kw)
    return base


def _tool_call(name: str, **args: Any) -> AIMessage:
    return AIMessage(content="", tool_calls=[
        {"name": name, "args": args, "id": f"call-{name}"}])


class FakeLLM:
    """Replays a scripted sequence of model responses."""

    def __init__(self, responses: list[Any]) -> None:
        self.responses = list(responses)
        self.calls = 0

    def bind_tools(self, tools: list[Any]) -> FakeLLM:
        self.bound_tools = tools
        return self

    def with_structured_output(self, schema: Any) -> FakeLLM:
        return self

    def bind(self, **kw: Any) -> FakeLLM:
        return self

    def invoke(self, messages: list[Any], config: Any = None) -> Any:
        self.calls += 1
        return self.responses.pop(0) if self.responses else AIMessage(content="done")


@pytest.fixture
def fake_llm(monkeypatch):
    def install(responses: list[Any]) -> FakeLLM:
        llm = FakeLLM(responses)
        monkeypatch.setattr("aegis.nodes.investigator.get_llm", lambda role: llm)
        # The report path goes through the shared reporter, which binds a larger
        # output ceiling; stub it too or the real one is called.
        monkeypatch.setattr("aegis.nodes.investigator.get_report_llm",
                            lambda schema: llm)
        return llm
    return install


# --- tool safety -------------------------------------------------------------


def test_no_write_capable_tool_is_reachable():
    """The agent runs before a human decides. Nothing it can call may act."""
    names = {t.name for t in INVESTIGATION_TOOLS}
    forbidden = {"isolate_host", "contain", "revoke_sessions", "block_ip",
                 "delete", "quarantine", "execute", "run_query", "search_splunk"}
    assert not (names & forbidden)
    assert names == {"get_host_timeline", "get_user_auth_history",
                     "find_indicator", "count_rule_firings", "get_asset_context",
                     "list_known_assets", "list_active_rules"}


def test_no_tool_accepts_a_raw_query():
    """Structured parameters only: a model writing queries can scan a year of
    data, and tool results carry attacker-influenced text."""
    for tool in INVESTIGATION_TOOLS:
        for arg in tool.args:
            assert arg not in {"query", "spl", "kql", "search", "filter"}


# --- loop control ------------------------------------------------------------


def test_loop_continues_while_the_model_calls_tools(fake_llm):
    fake_llm([_tool_call("count_rule_firings", rule_name="R", days=7)])
    update = investigator_node(_state())
    assert should_continue({**_state(), **update}) == "tools"


def test_loop_stops_when_the_model_stops_calling_tools(fake_llm):
    fake_llm([AIMessage(content="I have enough context.")])
    update = investigator_node(_state())
    assert should_continue({**_state(), **update}) == "report"


def test_budget_stops_a_model_that_keeps_calling_tools(monkeypatch):
    """A model cannot be asked to reliably stop, so the ceiling is in code."""
    monkeypatch.setenv("INVESTIGATION_MAX_TOOL_CALLS", "3")
    state = _state(tool_calls_used=3,
                   investigation=[_tool_call("find_indicator", indicator="x")])
    assert budget_remaining(state) is False
    assert should_continue(state) == "report"


def test_wall_clock_timeout_also_stops_the_loop(monkeypatch):
    monkeypatch.setenv("INVESTIGATION_TIMEOUT_SECONDS", "1")
    monkeypatch.setattr("aegis.nodes.investigator.time.monotonic", lambda: 1000.0)
    state = _state(tool_calls_used=0, investigation_started_at=0.0)
    assert budget_remaining(state) is False


def test_tool_calls_are_counted_across_turns(fake_llm):
    fake_llm([_tool_call("get_host_timeline", hostname="H")])
    update = investigator_node(_state(tool_calls_used=4))
    assert update["tool_calls_used"] == 5


# --- auditability ------------------------------------------------------------


def test_every_tool_call_is_recorded_in_the_audit_trail(fake_llm):
    fake_llm([_tool_call("find_indicator", indicator="185.220.101.5")])
    update = investigator_node(_state())
    assert any("find_indicator" in line for line in update["audit_log"])
    assert any("185.220.101.5" in line for line in update["audit_log"])


def test_first_turn_seeds_the_conversation_with_alert_context(fake_llm):
    fake_llm([AIMessage(content="ok")])
    update = investigator_node(_state())
    opening = update["investigation"][1].content
    assert "WIN-FINANCE-07" in opening
    assert "Encoded PowerShell from Office" in opening


# --- degradation -------------------------------------------------------------


def test_a_model_failure_produces_a_report_rather_than_crashing(monkeypatch):
    """An investigation is optional context. Losing it must not lose the alert."""
    class Broken:
        def bind_tools(self, tools): return self
        def invoke(self, messages, config=None): raise RuntimeError("model unavailable")

    monkeypatch.setattr("aegis.nodes.investigator.get_llm", lambda role: Broken())
    update = investigator_node(_state())
    report = update["investigation_report"]
    assert isinstance(report, InvestigationReport)
    assert report.unanswered


def test_report_marks_when_the_budget_cut_the_investigation_short(fake_llm, monkeypatch):
    monkeypatch.setenv("INVESTIGATION_MAX_TOOL_CALLS", "2")
    fake_llm([InvestigationReport(summary="Partial investigation of the host.",
                                  corroborating=["chain observed"])])
    update = investigation_report_node(
        _state(tool_calls_used=2, investigation=[AIMessage(content="x")]))
    assert update["investigation_report"].budget_exhausted is True


def test_report_without_an_investigation_says_so(fake_llm):
    fake_llm([])
    update = investigation_report_node(_state(investigation=[]))
    assert "No investigation" in update["investigation_report"].summary
