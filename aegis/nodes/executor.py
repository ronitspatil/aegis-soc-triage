"""Executes approved containment actions. The only place write calls exist.

Reachable only from `human_review`, after an analyst approved the ticket. Three
controls apply even then:

  * The action must be a member of `ActionType`. Unknown actions are refused.
  * The target must be an entity from the alert itself. The plan is written by
    a model reading attacker-influenced evidence, and without this a crafted
    log line could steer the SOC into isolating an unrelated critical host.
  * `ACTION_DRY_RUN` logs instead of acting, and defaults to on.
"""

from __future__ import annotations

import logging
from typing import Any, Protocol

from aegis.llm.config import get_settings
from aegis.schemas.response import ProposedAction, ResponsePlan
from aegis.schemas.state import SOCAgentState

logger = logging.getLogger(__name__)

AGENT_NAME = "executor"

# Decisions that authorise containment. Anything else runs nothing.
_APPROVING = ("confirm", "approve", "escalat")
_REJECTING = ("reject", "false positive", "no action")


def decision_approves_response(decision: str | None) -> bool:
    """Whether an analyst's decision authorises containment.

    Rejection wins on ambiguity: an unrecognised decision runs nothing.
    """
    if not decision:
        return False
    text = decision.lower()
    if any(word in text for word in _REJECTING):
        return False
    return any(word in text for word in _APPROVING)


def allowed_targets(state: SOCAgentState) -> set[str]:
    """Entities named by the alert. Nothing else may be acted on.

    Hosts discovered during investigation are deliberately excluded: acting on
    them requires an analyst to raise a new alert, so a model's reading of a log
    line can never widen the blast radius on its own.
    """
    alert = state["alert"]
    candidates = [
        alert.hostname,
        alert.username,
        str(alert.source_ip) if alert.source_ip else None,
        str(alert.destination_ip) if alert.destination_ip else None,
        alert.file_hash,
    ]
    return {c.lower() for c in candidates if c}


class ActionExecutor(Protocol):
    """Backend that can actually perform a containment action."""

    def perform(self, action: ProposedAction) -> str: ...


class DryRunExecutor:
    """Records what would have happened. The default."""

    def perform(self, action: ProposedAction) -> str:
        return f"DRY RUN: would {action.action.value} {action.target}"


def resolve_executor() -> ActionExecutor:
    settings = get_settings()
    if settings.action_dry_run:
        return DryRunExecutor()
    from aegis.tools.containment import FalconContainment

    return FalconContainment()


def executor_node(state: SOCAgentState) -> dict[str, Any]:
    """Perform the approved plan, or explain why nothing ran."""
    settings = get_settings()
    raw_plan = state.get("response_plan")
    plan: ResponsePlan | None = (
        None if raw_plan is None
        else raw_plan if isinstance(raw_plan, ResponsePlan)
        else ResponsePlan.model_validate(raw_plan)
    )
    decision = state.get("human_decision")

    if not settings.response_actions_enabled:
        return {"audit_log": [f"[{AGENT_NAME}] skipped: response actions disabled"]}
    if plan is None or not plan.actions:
        return {"audit_log": [f"[{AGENT_NAME}] no actions proposed"]}
    if not decision_approves_response(decision):
        return {"audit_log": [
            f"[{AGENT_NAME}] not executed: decision '{decision}' does not approve containment"
        ]}

    permitted = allowed_targets(state)
    executor = resolve_executor()
    performed: list[str] = []
    audit: list[str] = []

    for action in plan.actions:
        if action.target.lower() not in permitted:
            # Refused, not silently skipped: an analyst must be able to see that
            # a proposed step did not run and why.
            audit.append(
                f"[{AGENT_NAME}] REFUSED {action.action.value} on {action.target}: "
                "target is not an entity named by this alert"
            )
            continue
        try:
            outcome = executor.perform(action)
        except Exception as exc:  # noqa: BLE001 - one failure must not skip the rest
            audit.append(f"[{AGENT_NAME}] FAILED {action.action.value} "
                         f"on {action.target}: {exc}")
            continue
        performed.append(outcome)
        audit.append(f"[{AGENT_NAME}] {outcome}")

    return {"executed_actions": performed, "audit_log": audit}
