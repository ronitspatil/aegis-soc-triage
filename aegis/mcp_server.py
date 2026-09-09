"""Aegis as an MCP server: the analyst-facing interface.

    .venv/bin/python -m aegis.mcp_server        # stdio transport

This is where MCP genuinely fits: an analyst's assistant DYNAMICALLY choosing
among our capabilities in response to natural language. The worker tools stay
direct API clients, because there the caller is deterministic code and the
protocol would only add latency and an injection surface.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any

# mcp>=2 renamed FastMCP -> MCPServer
from mcp.server.mcpserver import MCPServer

from aegis.decisions import DecisionError, apply_decision
from aegis.graph import get_app
from aegis.ingest.store import REGISTRY, AlertStatus
from aegis.schemas.alert import SIEMAlert
from aegis.schemas.state import verdict_of

logger = logging.getLogger(__name__)

mcp = MCPServer(
    name="aegis-soc",
    instructions=(
        "SOC alert triage. Use triage_alert to investigate an alert, "
        "list_pending_approvals to see the analyst queue, and submit_decision "
        "to approve or reject a drafted incident ticket."
    ),
)


@mcp.tool()
def triage_alert(
    rule_name: str,
    severity: str = "medium",
    alert_id: str | None = None,
    source_ip: str | None = None,
    username: str | None = None,
    hostname: str | None = None,
    file_hash: str | None = None,
    raw_log: str = "",
) -> dict[str, Any]:
    """Run full triage on a security alert.

    Enriches via threat intel, identity, and endpoint agents in parallel, then
    synthesizes a verdict. Returns either an auto-close result or a drafted
    incident ticket awaiting approval.
    """
    alert = SIEMAlert(
        alert_id=alert_id or f"MCP-{datetime.now(UTC).strftime('%Y%m%d%H%M%S')}",
        rule_name=rule_name,
        severity=severity,
        timestamp=datetime.now(UTC),
        source_ip=source_ip,
        username=username,
        hostname=hostname,
        file_hash=file_hash,
        raw_log=raw_log,
    )

    REGISTRY.create_if_absent(alert.alert_id)
    graph = get_app()
    cfg = {"configurable": {"thread_id": f"alert-{alert.alert_id}"}}
    out = graph.invoke({"alert": alert}, cfg)

    if "__interrupt__" in out:
        ticket = out["__interrupt__"][0].value["ticket"]
        REGISTRY.update(
            alert.alert_id, status=AlertStatus.AWAITING_APPROVAL, ticket=ticket,
            verdict=ticket["verdict"], confidence=ticket["confidence"],
        )
        return {
            "alert_id": alert.alert_id,
            "outcome": "awaiting_human_approval",
            "ticket": ticket,
        }

    REGISTRY.update(
        alert.alert_id, status=AlertStatus.AUTO_CLOSED,
        verdict=verdict_of(out).value, confidence=out.get("confidence"),
    )
    return {
        "alert_id": alert.alert_id,
        "outcome": "auto_closed",
        "verdict": verdict_of(out).value,
        "confidence": out.get("confidence"),
        "reasoning": out.get("reasoning"),
    }


@mcp.tool()
def list_pending_approvals() -> list[dict[str, Any]]:
    """List alerts the agent refused to close on its own: the analyst queue."""
    return [
        {
            "alert_id": r.alert_id,
            "verdict": r.verdict,
            "confidence": r.confidence,
            "title": (r.ticket or {}).get("title"),
            "recommended_actions": (r.ticket or {}).get("recommended_actions", []),
            "received_at": r.received_at.isoformat(),
        }
        for r in REGISTRY.awaiting_approval()
    ]


@mcp.tool()
def get_alert_status(alert_id: str) -> dict[str, Any]:
    """Look up the current triage status and verdict for one alert."""
    rec = REGISTRY.get(alert_id)
    if rec is None:
        return {"error": f"unknown alert_id: {alert_id}"}
    return {
        "alert_id": rec.alert_id,
        "status": rec.status.value,
        "verdict": rec.verdict,
        "confidence": rec.confidence,
        "decision": rec.decision,
    }


@mcp.tool()
def get_audit_trail(alert_id: str) -> dict[str, Any]:
    """Retrieve the full append-only audit trail for an alert.

    This is the compliance artefact: every enrichment score, the verdict, and
    any deterministic override that fired.
    """
    cfg = {"configurable": {"thread_id": f"alert-{alert_id}"}}
    snapshot = get_app().get_state(cfg)
    if not snapshot.values:
        return {"error": f"no triage record for {alert_id}"}
    return {
        "alert_id": alert_id,
        "audit_log": snapshot.values.get("audit_log", []),
        "verdict": verdict_of(snapshot.values).value if snapshot.values.get("verdict") else None,
        "confidence": snapshot.values.get("confidence"),
        "reasoning": snapshot.values.get("reasoning"),
        "suspended_at": list(snapshot.next) or None,
    }


@mcp.tool()
def submit_decision(alert_id: str, decision: str, analyst: str = "unknown") -> dict[str, Any]:
    """Approve, reject, or escalate a pending incident ticket.

    Resumes the suspended graph. Only works on alerts that are actually waiting
    on a human, a resolved alert cannot be re-decided.
    """
    try:
        out = apply_decision(alert_id, decision, actor=analyst, source="mcp")
    except DecisionError as exc:
        return {"error": str(exc)}

    return {"alert_id": alert_id, "status": "resolved", "decision": out.get("human_decision")}


if __name__ == "__main__":
    mcp.run(transport="stdio")
