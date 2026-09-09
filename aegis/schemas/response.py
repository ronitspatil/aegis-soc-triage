"""Containment actions: what may be proposed, and what may be run.

A `ProposedAction` is inert data. Producing one has no effect; only the
executor acts, and only on actions a human approved. The split exists so the
model's output can never be the thing that reaches an API.
"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, ConfigDict, Field


class ActionType(str, Enum):
    """The closed set of actions that may be proposed.

    A closed enum rather than free text: an action the executor does not
    recognise is refused, so the model cannot invent a capability.
    """

    ISOLATE_HOST = "isolate_host"
    REVOKE_SESSIONS = "revoke_sessions"
    DISABLE_ACCOUNT = "disable_account"
    BLOCK_INDICATOR = "block_indicator"
    COLLECT_FORENSICS = "collect_forensics"


# Actions that cannot be undone with a single call. Surfaced to the analyst so
# approval is informed, and used to require the higher-friction path later.
IRREVERSIBLE: frozenset[ActionType] = frozenset({
    ActionType.DISABLE_ACCOUNT,
})


class ProposedAction(BaseModel):
    """One containment step, awaiting human approval."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    action: ActionType
    target: str = Field(
        ..., min_length=1,
        description="Exactly what to act on: a hostname, username or indicator.",
    )
    rationale: str = Field(
        ..., min_length=10,
        description="One sentence on why this step follows from the evidence.",
    )
    urgency: str = Field(
        default="normal",
        description="'immediate' only when delay materially increases damage.",
    )

    @property
    def reversible(self) -> bool:
        return self.action not in IRREVERSIBLE


class ResponsePlan(BaseModel):
    """What the planner proposes. Approval is all-or-nothing at the ticket."""

    model_config = ConfigDict(extra="forbid")

    # No max_length here on purpose. A structured-output constraint the model
    # can violate turns a slightly over-long plan into a validation error and
    # no plan at all. The limit is applied in code after parsing.
    actions: list[ProposedAction] = Field(
        default_factory=list,
        description=(
            "Containment steps, most urgent first. Propose nothing for a false "
            "positive. Only propose a step the evidence supports; an analyst "
            "reviewing a padded plan will stop reading it."
        ),
    )
    summary: str = Field(
        default="",
        description="One sentence describing the response as a whole.",
    )
