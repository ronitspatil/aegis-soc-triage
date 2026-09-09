"""Single implementation of "an analyst decided something".

The REST API, the MCP server, and the Slack handler all funnel through here.
Three copies of "resume the graph" would drift, and this is the code path that
closes incidents, the one place drift is least acceptable.
"""

from __future__ import annotations

import logging
from typing import Any

from langgraph.types import Command

from aegis.graph import get_app
from aegis.ingest.store import REGISTRY, AlertStatus
from aegis.observability import METRICS

logger = logging.getLogger(__name__)


class DecisionError(RuntimeError):
    """Raised when an alert cannot accept a decision right now."""


def thread_config(alert_id: str) -> dict[str, Any]:
    """The checkpointer key. Every surface must agree on this format."""
    return {"configurable": {"thread_id": f"alert-{alert_id}"}}


def apply_decision(
    alert_id: str, decision: str, actor: str | None = None, source: str = "api"
) -> dict[str, Any]:
    """Resume a suspended graph with a human decision.

    Attribution matters: "APPROVED" is not an audit record, but
    "APPROVED (by U024BE7LH via slack)" is.
    """
    graph = get_app()
    cfg = thread_config(alert_id)

    snapshot = graph.get_state(cfg)
    if not snapshot.values:
        raise DecisionError(f"unknown alert_id: {alert_id}")
    if not snapshot.next:
        # Already resolved. Re-deciding would re-run terminal nodes.
        raise DecisionError(f"{alert_id} is not awaiting a decision")

    attributed = decision if not actor else f"{decision} (by {actor} via {source})"
    out = graph.invoke(Command(resume=attributed), cfg)

    REGISTRY.update(alert_id, status=AlertStatus.RESOLVED, decision=out.get("human_decision"))
    METRICS.inc("decisions_total", source=source)
    logger.info("decision applied", extra={"alert_id": alert_id, "source": source})
    return out
