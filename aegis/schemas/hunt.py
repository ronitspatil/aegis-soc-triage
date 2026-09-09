"""Output contract for the threat hunter."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from aegis.schemas.alert import Severity


class HuntFinding(BaseModel):
    """Something worth triaging, discovered without an alert prompting it."""

    model_config = ConfigDict(extra="forbid")

    title: str = Field(..., min_length=8, description="What was found, in a few words.")
    rationale: str = Field(
        ..., min_length=20,
        description=(
            "What in the query results supports this. Cite the specific "
            "observation. Do not report a finding you did not observe."
        ),
    )
    severity: Severity = Field(default=Severity.MEDIUM)
    hostname: str | None = Field(default=None, description="Host involved, if any.")
    username: str | None = Field(default=None, description="Principal involved, if any.")
    indicator: str | None = Field(default=None, description="IP or hash involved, if any.")


class HuntResult(BaseModel):
    """What one hunt produced."""

    model_config = ConfigDict(extra="forbid")

    hypothesis: str
    findings: list[HuntFinding] = Field(
        default_factory=list,
        description=(
            "Only what the data supports. An empty list is a valid and common "
            "result: most hunts find nothing, and inventing findings to appear "
            "productive wastes an analyst's day."
        ),
    )
    summary: str = Field(default="", description="One sentence on what was checked.")
    queries_run: int = 0
    budget_exhausted: bool = False
