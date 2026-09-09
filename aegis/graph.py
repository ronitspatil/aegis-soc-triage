"""Graph orchestration + human-in-the-loop.

Topology:
              START
          ┌─────┼─────┐          three edges from START == parallel fan-out
     threat_intel identity endpoint
          └─────┼─────┘          fan-in merged by the `operator.add` reducers
             synthesizer
                 │
          route_on_verdict       pure function, no LLM
          ┌──────┴──────┐
      auto_close    human_review (interrupt)
          └──────┬──────┘
                END
"""

from __future__ import annotations

from functools import lru_cache
from typing import Any, Literal

from langgraph.graph import END, START, StateGraph
from langgraph.types import interrupt

from aegis.llm.config import get_settings
from aegis.nodes.endpoint import endpoint_node
from aegis.nodes.identity import identity_node
from aegis.nodes.synthesizer import synthesizer_node
from aegis.nodes.threat_intel import threat_intel_node
from aegis.persistence import build_checkpointer
from aegis.schemas.alert import SEVERITY_ORDER, Severity
from aegis.schemas.state import SOCAgentState, Verdict, verdict_of

# Conservative starting point. Tune DOWN only with shadow-mode data, never up
# front, see the asymmetry between the two failure modes.
AUTO_CLOSE_CONFIDENCE = 0.95


def orchestrator_node(state: SOCAgentState) -> dict:
    """Entry point. Seeds the audit trail and opens the investigation."""
    alert = state["alert"]
    return {
        "audit_log": [
            f"[orchestrator] investigating {alert.alert_id} "
            f"({alert.rule_name}, severity={alert.severity.value})"
        ],
        "requires_human_approval": False,
    }


def route_on_verdict(state: SOCAgentState) -> Literal["auto_close", "human_review"]:
    """Graph-facing router. Thin wrapper so LangGraph gets a single-arg callable."""
    return gate_decision(state)


def gate_decision(
    state: SOCAgentState, threshold: float = AUTO_CLOSE_CONFIDENCE
) -> Literal["auto_close", "human_review"]:
    """Pure routing function: no LLM, no I/O, exhaustively testable.

    Auto-close requires a CONJUNCTION of five conditions. Any single failure
    sends the alert to a human. Hard to satisfy by design: the cost of a
    needless review is minutes, the cost of auto-closing a breach is a breach.
    """
    alert = state["alert"]
    enrichments = state.get("enrichments", [])
    settings = get_settings()

    # Kill switch: forces every alert to a human. Env var only, no deploy,
    # so it can be flipped during an incident.
    if settings.kill_switch:
        return "human_review"

    # Shadow mode: run the full pipeline but close nothing. The verdict is
    # still recorded, so the counterfactual can be measured on real traffic.
    if settings.shadow_mode:
        return "human_review"

    # 0. No evidence cannot justify a close. Without this check, gates 3 and 5
    #    pass vacuously on an empty list (any([]) is False).
    if not enrichments:
        return "human_review"

    # 1. The model must have concluded benign. Compare by value, not identity:
    #    Verdict is a str enum and a deserialized checkpoint holds plain
    #    strings, so `is` would fail open here.
    if verdict_of(state) is not Verdict.FALSE_POSITIVE:
        return "human_review"

    # 2. It must be confident enough.
    if state.get("confidence", 0.0) < threshold:
        return "human_review"

    # 3. Every enrichment must have succeeded, no silent gaps.
    if any(e.error for e in enrichments):
        return "human_review"

    # 4. Critical-severity alerts always get eyes on them, whatever the verdict.
    if alert.severity == Severity.CRITICAL:
        return "human_review"

    # 4b. Staged rollout: refuse to auto-close above the configured severity.
    if SEVERITY_ORDER[alert.severity] > SEVERITY_ORDER[settings.max_auto_close_severity]:
        return "human_review"

    # 5. Privileged identities have too much blast radius to close blind.
    if any(e.findings.get("is_privileged") for e in enrichments):
        return "human_review"

    return "auto_close"


def auto_close_node(state: SOCAgentState) -> dict:
    """Terminal state for high-confidence false positives."""
    alert = state["alert"]
    return {
        "requires_human_approval": False,
        "human_decision": None,
        "audit_log": [
            f"[auto_close] {alert.alert_id} closed automatically "
            f"(confidence={state.get('confidence')}), no human review"
        ],
    }


def _draft_ticket(state: SOCAgentState) -> dict[str, Any]:
    """Assemble the incident ticket an analyst will approve or reject."""
    alert = state["alert"]
    return {
        "title": f"[{alert.severity.value.upper()}] {alert.rule_name}, {alert.alert_id}",
        "verdict": verdict_of(state).value,
        "confidence": state.get("confidence", 0.0),
        "entities": {
            "source_ip": str(alert.source_ip) if alert.source_ip else None,
            "username": alert.username,
            "hostname": alert.hostname,
        },
        "reasoning": state.get("reasoning", ""),
        "recommended_actions": state.get("recommended_actions", []),
        "enrichment_signals": {
            e.agent_name: {"risk": e.risk_signal, "error": e.error}
            for e in state.get("enrichments", [])
        },
    }


def human_review_node(state: SOCAgentState) -> dict:
    """Suspend the graph and wait for an analyst.

    `interrupt()` persists the whole state to the checkpointer and returns
    control to the caller. The process may exit entirely; resuming later with
    `Command(resume=...)` continues from exactly this line.
    """
    ticket = _draft_ticket(state)

    decision = interrupt(
        {
            "action_required": "approve_or_reject_incident",
            "ticket": ticket,
        }
    )

    return {
        "requires_human_approval": True,
        "human_decision": str(decision),
        "audit_log": [f"[human_review] analyst decision recorded: {decision}"],
    }


def build_graph(checkpointer: Any | None = None):
    """Compile the SOC triage graph.

    A checkpointer is REQUIRED for interrupts, without persisted state there is
    nothing to resume into.
    """
    g = StateGraph(SOCAgentState)

    g.add_node("orchestrator", orchestrator_node)
    g.add_node("threat_intel", threat_intel_node)
    g.add_node("identity", identity_node)
    g.add_node("endpoint", endpoint_node)
    g.add_node("synthesizer", synthesizer_node)
    g.add_node("auto_close", auto_close_node)
    g.add_node("human_review", human_review_node)

    g.add_edge(START, "orchestrator")

    # Three edges out of one node == concurrent execution. This is where the
    # `Annotated[..., operator.add]` reducers stop being decoration.
    g.add_edge("orchestrator", "threat_intel")
    g.add_edge("orchestrator", "identity")
    g.add_edge("orchestrator", "endpoint")

    # Fan-in: synthesizer waits for ALL three before running.
    g.add_edge("threat_intel", "synthesizer")
    g.add_edge("identity", "synthesizer")
    g.add_edge("endpoint", "synthesizer")

    g.add_conditional_edges(
        "synthesizer",
        route_on_verdict,
        {"auto_close": "auto_close", "human_review": "human_review"},
    )

    g.add_edge("auto_close", END)
    g.add_edge("human_review", END)

    # Durable when POSTGRES_URL is set, in-memory otherwise. Either way the
    # serializer restricts deserialization to our own types (aegis/serde.py).
    return g.compile(checkpointer=checkpointer or build_checkpointer())


@lru_cache(maxsize=1)
def get_app():
    """Process-wide compiled graph.

    MUST be shared. With an in-memory checkpointer each `build_graph()` call
    owns a SEPARATE state store, so a graph suspended by one instance cannot be
    resumed by another, the resume silently starts a fresh run instead. (Under
    POSTGRES_URL the state is external and this hazard disappears, which is one
    more reason to run durable checkpointing in production.)
    """
    return build_graph()
