"""Internal models + the LangGraph shared state channel definitions."""

from __future__ import annotations

import operator
from enum import Enum
from typing import Annotated, Any, TypedDict

from pydantic import BaseModel, ConfigDict, Field

from aegis.schemas.alert import SIEMAlert


def union_strings(current: list[str], update: list[str]) -> list[str]:
    """Reducer that MERGES rather than concatenates.

    A reducer is just `(current, update) -> merged`; `operator.add` is only the
    most common one, not a special case. Concatenation would yield duplicates
    when two agents independently observe the same ATT&CK technique, inflating
    any "how many techniques did we see" heuristic.
    """
    return sorted(set(current) | set(update))


class Verdict(str, Enum):
    """Terminal classification produced by the synthesis node."""

    FALSE_POSITIVE = "false_positive"
    TRUE_POSITIVE = "true_positive"
    AMBIGUOUS = "ambiguous"


class EnrichmentData(BaseModel):
    """One specialist worker's contribution to the investigation.

    Internal model -> `extra="forbid"`. Unlike inbound SIEM data, a stray key
    here means *we* made a mistake and should fail loudly.
    """

    model_config = ConfigDict(extra="forbid")

    agent_name: str = Field(..., description="Which worker produced this (e.g. 'threat_intel')")
    summary: str = Field(..., description="Short natural-language finding for the synthesizer")
    findings: dict[str, Any] = Field(default_factory=dict, description="Structured raw evidence")
    risk_signal: float = Field(
        default=0.0, ge=0.0, le=1.0, description="This worker's isolated suspicion score"
    )
    # Workers report failure as data, not exceptions: a dead API must not abort
    # triage, but the synthesizer MUST know it reasoned on partial evidence.
    error: str | None = Field(None, description="Populated if this enrichment failed")


class SOCAgentState(TypedDict, total=False):
    """Shared graph state. Each key is a LangGraph channel.

    `total=False` because nodes return *partial* updates, not the whole state.
    """

    alert: SIEMAlert

    # Fan-in channel: Identity / ThreatIntel / Endpoint agents write CONCURRENTLY.
    # `operator.add` is the reducer that concatenates their lists; without it
    # parallel writes to one channel raise InvalidUpdateError.
    enrichments: Annotated[list[EnrichmentData], operator.add]

    # Multiple agents may independently observe the SAME technique, so this
    # channel merges as a SET, not a concatenation.
    mitre_techniques: Annotated[list[str], union_strings]

    # --- Written by the synthesis / evaluator node (single writer, no reducer) ---
    verdict: Verdict
    confidence: float
    reasoning: str
    recommended_actions: list[str]

    # Slack message id for this alert's ticket. Checkpointed (not held in
    # process memory) so ANY process handling the button click knows which
    # message to edit, the listener and the triage worker are separate.
    slack_ts: str

    # --- HITL control plane ---
    requires_human_approval: bool
    human_decision: str | None

    # Append-only audit trail. Non-negotiable in a SOC: every automated close
    # must be reconstructable after the fact.
    audit_log: Annotated[list[str], operator.add]


def verdict_of(state: SOCAgentState | dict) -> Verdict:
    """Read `verdict` from state, tolerating a post-deserialization plain string.

    A bare str-Enum flattens to its string value when a checkpoint round-trips
    through Postgres (Pydantic models survive; bare enums do not). Code that
    reads state must therefore normalize rather than assume the declared type.
    Under MemorySaver nothing is serialized, so this bug is invisible in dev.
    """
    raw = state.get("verdict")
    if raw is None:
        return Verdict.AMBIGUOUS
    return Verdict(raw)
