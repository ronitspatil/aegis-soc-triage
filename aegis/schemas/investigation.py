"""Output contract for the investigation agent."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class InvestigationReport(BaseModel):
    """What the agent learned. Read by an analyst, never by the auto-close gate."""

    model_config = ConfigDict(extra="forbid")

    summary: str = Field(
        ...,
        min_length=20,
        description=(
            "2-3 sentences on what the historical evidence shows. Lead with the "
            "finding that most changes how an analyst should read this alert."
        ),
    )
    corroborating: list[str] = Field(
        default_factory=list,
        description="Findings that support the alert being a genuine incident.",
    )
    contradicting: list[str] = Field(
        default_factory=list,
        description=(
            "Findings that argue the alert is benign, such as a rule with a high "
            "base rate or activity matching an established pattern."
        ),
    )
    unanswered: list[str] = Field(
        default_factory=list,
        description=(
            "Questions the available tools could not answer, and lookups that "
            "returned nothing. Absence of data is not evidence of safety."
        ),
    )
    scope_concern: bool = Field(
        default=False,
        description=(
            "True if evidence suggests more hosts or accounts are involved than "
            "the alert names."
        ),
    )
    budget_exhausted: bool = Field(
        default=False,
        description="True if the investigation stopped on its step budget.",
    )
