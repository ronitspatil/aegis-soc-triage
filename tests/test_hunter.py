"""Autonomous hunting: bounds, honesty, and where findings go."""

from __future__ import annotations

from typing import Any

import pytest
from langchain_core.messages import AIMessage

from aegis.hunter import STANDARD_HYPOTHESES, file_findings, finding_to_alert, hunt
from aegis.schemas.hunt import HuntFinding, HuntResult


class FakeLLM:
    def __init__(self, responses: list[Any]) -> None:
        self.responses = list(responses)
        self.calls = 0

    def bind_tools(self, tools: list[Any]) -> FakeLLM:
        self.tools = tools
        return self

    def with_structured_output(self, schema: Any) -> FakeLLM:
        return self

    def bind(self, **kw: Any) -> FakeLLM:
        return self

    def invoke(self, messages: list[Any], config: Any = None) -> Any:
        self.calls += 1
        return self.responses.pop(0) if self.responses else AIMessage(content="done")


@pytest.fixture
def fake(monkeypatch):
    def install(responses: list[Any]) -> FakeLLM:
        llm = FakeLLM(responses)
        monkeypatch.setattr("aegis.hunter.get_llm", lambda role: llm)
        monkeypatch.setattr("aegis.hunter.get_report_llm", lambda schema: llm)
        return llm
    return install


def _query(name: str, **args: Any) -> AIMessage:
    return AIMessage(content="", tool_calls=[
        {"name": name, "args": args, "id": f"c-{name}"}])


# --- bounds ------------------------------------------------------------------


def test_a_hunt_stops_when_the_model_stops_querying(fake):
    fake([AIMessage(content="done"),
          HuntResult(hypothesis="h", summary="nothing found")])
    result = hunt("test hypothesis")
    assert result.queries_run == 0
    assert result.budget_exhausted is False


def test_the_query_budget_is_enforced_in_code(fake):
    """A model cannot be asked to reliably stop."""
    # Three queries is the budget; the fourth response is the report the
    # reporter asks for once the loop stops.
    fake([_query("count_rule_firings", rule_name="R") for _ in range(3)]
         + [HuntResult(hypothesis="h")])
    result = hunt("test hypothesis", max_tool_calls=3)
    assert result.queries_run == 3
    assert result.budget_exhausted is True


def test_findings_are_capped(fake, monkeypatch):
    """A hunt that floods the queue is worse than one that finds nothing."""
    monkeypatch.setenv("HUNT_MAX_FINDINGS", "2")
    many = [HuntFinding(title=f"Finding number {i}",
                        rationale="observed in the query results above")
            for i in range(9)]
    fake([AIMessage(content="done"), HuntResult(hypothesis="h", findings=many)])
    assert len(hunt("h").findings) == 2


def test_a_model_failure_returns_an_empty_hunt_rather_than_raising(monkeypatch):
    class Broken:
        def bind_tools(self, tools): return self
        def invoke(self, messages, config=None): raise RuntimeError("model down")

    monkeypatch.setattr("aegis.hunter.get_llm", lambda role: Broken())
    result = hunt("h")
    assert result.findings == []
    assert "could not run" in result.summary


# --- findings enter the normal pipeline --------------------------------------


def test_a_finding_becomes_an_ordinary_alert():
    """Hunt output gets no special standing: same pipeline, same gates, same
    human approval."""
    finding = HuntFinding(title="C2 address seen on three hosts",
                          rationale="find_indicator returned three distinct hosts",
                          severity="high", hostname="WIN-FINANCE-07",
                          indicator="185.220.101.5")
    alert = finding_to_alert(finding, "lateral movement")
    assert alert.alert_id.startswith("HUNT-")
    assert alert.rule_name.startswith("Threat Hunt:")
    assert str(alert.source_ip) == "185.220.101.5"
    assert alert.hostname == "WIN-FINANCE-07"
    assert "lateral movement" in alert.raw_log


def test_a_hash_indicator_is_not_mistaken_for_an_address():
    finding = HuntFinding(title="Unsigned binary dropped repeatedly",
                          rationale="observed on several hosts in the timeline",
                          indicator="e3b0c44298fc1c149afbf4c8996fb92427ae41e4")
    alert = finding_to_alert(finding, "h")
    assert alert.source_ip is None
    assert alert.file_hash is not None


def test_filed_findings_are_queued_for_triage():
    from aegis.ingest.store import ALERT_QUEUE

    result = HuntResult(hypothesis="h", findings=[
        HuntFinding(title="Something worth a look",
                    rationale="supported by the query results above")])
    filed = file_findings(result)
    assert len(filed) == 1
    drained = []
    while not ALERT_QUEUE.empty():
        drained.append(ALERT_QUEUE.get())
        ALERT_QUEUE.task_done()
    assert filed[0].alert_id in {a.alert_id for a in drained}


def test_an_empty_hunt_files_nothing():
    assert file_findings(HuntResult(hypothesis="h")) == []


def test_standard_hypotheses_are_defined():
    assert {"credential-access", "lateral-movement", "noisy-rules"} <= set(
        STANDARD_HYPOTHESES)
