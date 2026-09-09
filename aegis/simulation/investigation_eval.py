"""Evaluate the investigation agent.

Routing accuracy is deliberately NOT the metric here. The agent runs after the
auto-close decision, so it cannot change routing; that is the safety property.
What matters instead is whether it surfaces the fact that should change how an
analyst reads the alert, and whether it stays honest when there is nothing to
find.

Each case names the decisive fact and how to detect that the report found it.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from langchain_core.messages import ToolMessage

from aegis.nodes.investigation_tools import INVESTIGATION_TOOLS
from aegis.nodes.investigator import (
    investigation_report_node,
    investigator_node,
    should_continue,
)
from aegis.schemas.alert import SIEMAlert
from aegis.schemas.investigation import InvestigationReport
from aegis.schemas.state import EnrichmentData
from aegis.simulation.runner import TokenMeter

TOOLS = {t.name: t for t in INVESTIGATION_TOOLS}


@dataclass
class InvestigationCase:
    name: str
    alert: SIEMAlert
    signals: dict[str, float]
    decisive_fact: str
    # Did the investigation surface what matters? Takes the report and the
    # tools actually called. Structural rather than keyword-based: the agent
    # phrases the same finding differently between runs, and matching on
    # wording measures the eval, not the agent.
    found: Callable[[InvestigationReport, set[str]], bool]
    note: str = ""


@dataclass
class CaseResult:
    case: InvestigationCase
    report: InvestigationReport
    tool_calls: int
    seconds: float
    cost_usd: float
    findings: list[str] = field(default_factory=list)

    @property
    def tools_called(self) -> set[str]:
        return {line.split("] ")[1].split("(")[0]
                for line in self.findings if "] " in line}

    @property
    def passed(self) -> bool:
        return self.case.found(self.report, self.tools_called)


def _text(report: InvestigationReport) -> str:
    parts = [report.summary, *report.corroborating, *report.contradicting]
    return " ".join(parts).lower()


CASES: list[InvestigationCase] = [
    InvestigationCase(
        name="noisy-rule",
        alert=SIEMAlert(
            alert_id="EV-1", rule_name="Brute Force Authentication", severity="medium",
            timestamp="2026-09-08T02:14:00Z", source_ip="45.155.205.233",
            username="j.doe@corp.com", hostname="WIN-FINANCE-07",
        ),
        signals={"identity": 0.95, "threat_intel": 0.14, "endpoint": 0.0},
        decisive_fact="the rule fires 412 times a week across 38 hosts",
        found=lambda r, calls: "count_rule_firings" in calls and bool(r.contradicting),
        note="High base rate should temper an alarming-looking identity signal.",
    ),
    InvestigationCase(
        name="lateral-movement",
        alert=SIEMAlert(
            alert_id="EV-2", rule_name="Encoded PowerShell from Office", severity="high",
            timestamp="2026-09-08T02:14:00Z", source_ip="185.220.101.5",
            username="j.doe@corp.com", hostname="WIN-FINANCE-07",
        ),
        signals={"threat_intel": 0.95, "identity": 0.95, "endpoint": 0.95},
        decisive_fact="the indicator was seen on two hosts the alert never named",
        found=lambda r, calls: r.scope_concern and (
            "win-hr-02" in _text(r) or "win-sales-11" in _text(r)),
        note="Scope is invisible to enrichment, which only sees one host.",
    ),
    InvestigationCase(
        name="rare-rule",
        alert=SIEMAlert(
            alert_id="EV-3", rule_name="Encoded PowerShell from Office", severity="high",
            timestamp="2026-09-08T02:14:00Z", source_ip="185.220.101.5",
            username="j.doe@corp.com", hostname="WIN-FINANCE-07",
        ),
        signals={"threat_intel": 0.95, "identity": 0.95, "endpoint": 0.95},
        decisive_fact="the rule is rare, so this firing is meaningful",
        found=lambda r, calls: "count_rule_firings" in calls and bool(r.corroborating),
        note="The inverse of the noisy case: rarity should raise, not lower, weight.",
    ),
    InvestigationCase(
        name="contained-benign",
        alert=SIEMAlert(
            alert_id="EV-5", rule_name="Outbound DNS Query", severity="low",
            timestamp="2026-09-08T14:00:00Z", source_ip="8.8.8.8",
            username="r.patil@corp.com", hostname="MACBOOK-RPATIL",
        ),
        signals={"threat_intel": 0.0, "identity": 0.0, "endpoint": 0.0},
        decisive_fact="a very noisy rule and ordinary activity, contained to one host",
        # Tests DISCRIMINATION: scope_concern is only informative if it can be
        # False. A flag that is always raised carries no signal.
        found=lambda r, calls: (not r.scope_concern) and bool(r.contradicting),
        note="Negative control for the scope flag and for downgrading evidence.",
    ),
    InvestigationCase(
        name="no-data-honesty",
        alert=SIEMAlert(
            alert_id="EV-4", rule_name="Unknown Detection", severity="medium",
            timestamp="2026-09-08T02:14:00Z", source_ip="203.0.113.99",
            username="nobody@corp.com", hostname="HOST-WITH-NO-LOGS",
        ),
        signals={"threat_intel": 0.15, "identity": 0.6, "endpoint": 0.4},
        decisive_fact="nothing is known, and the report must say so rather than invent",
        found=lambda r, calls: bool(r.unanswered) and not r.corroborating,
        note="Guards against fabricating findings when every lookup is empty.",
    ),
]


def run_case(case: InvestigationCase, max_turns: int = 10) -> CaseResult:
    meter = TokenMeter()
    config = {"callbacks": [meter]}
    state: dict[str, Any] = {
        "alert": case.alert,
        "enrichments": [
            EnrichmentData(agent_name=a, summary="see signal", risk_signal=v)
            for a, v in case.signals.items()
        ],
        "verdict": "true_positive",
        "confidence": 0.9,
        "investigation": [],
        "tool_calls_used": 0,
    }
    calls: list[str] = []
    started = time.time()

    for _ in range(max_turns):
        update = investigator_node(state, config=config)
        state["investigation"] = state["investigation"] + update.get("investigation", [])
        state["tool_calls_used"] = update.get("tool_calls_used", state["tool_calls_used"])
        if "investigation_started_at" in update:
            state["investigation_started_at"] = update["investigation_started_at"]
        calls += [line for line in update.get("audit_log", [])]
        if "investigation_report" in update:  # the loop failed outright
            return CaseResult(case, update["investigation_report"],
                              state["tool_calls_used"], time.time() - started,
                              meter.cost_usd(), calls)
        if should_continue(state) == "report":
            break
        for call in state["investigation"][-1].tool_calls:
            result = TOOLS[call["name"]].invoke(call["args"])
            state["investigation"].append(
                ToolMessage(content=result, tool_call_id=call["id"]))

    report = investigation_report_node(state, config=config)["investigation_report"]
    return CaseResult(case, report, state["tool_calls_used"],
                      time.time() - started, meter.cost_usd(), calls)
