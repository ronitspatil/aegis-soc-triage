"""The synthesis node's OUTPUT contract.

This model is passed to `llm.with_structured_output()`, so every `description`
below is injected into the prompt and read by the model. They are written as
instructions to the LLM, not as notes to a developer.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from aegis.schemas.state import Verdict


class SynthesisResult(BaseModel):
    """Structured triage decision produced by the high-reasoning model."""

    model_config = ConfigDict(extra="forbid")

    verdict: Verdict = Field(
        ...,
        description=(
            "false_positive = benign activity explained by legitimate context. "
            "true_positive = evidence of genuine malicious activity. "
            "ambiguous = evidence is conflicting, insufficient, or an enrichment "
            "source failed. When in doubt, choose ambiguous, never false_positive."
        ),
    )
    confidence: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description=(
            "Your certainty in the verdict. Confidence at or above 0.95 on a "
            "false_positive permits this alert to be CLOSED AUTOMATICALLY with no "
            "human review. Only go that high when every enrichment succeeded and "
            "the benign explanation accounts for all observations."
        ),
    )
    reasoning: str = Field(
        ...,
        min_length=40,
        description=(
            "2-4 sentences explaining how the evidence supports the verdict. "
            "Reference specific findings. State explicitly whether the specialist "
            "agents corroborate one another or conflict."
        ),
    )
    key_evidence: list[str] = Field(
        default_factory=list,
        description="The specific observations that drove the verdict, most important first.",
    )
    intel_gaps: list[str] = Field(
        default_factory=list,
        description=(
            "What you could NOT verify: failed lookups, absent telemetry, unknown "
            "indicators. Be explicit, an empty list asserts that nothing was missing."
        ),
    )
    recommended_actions: list[str] = Field(
        default_factory=list,
        description=(
            "Concrete next steps for the analyst (e.g. 'Isolate WIN-FINANCE-07', "
            "'Revoke active sessions for j.doe'). Empty if the verdict is false_positive."
        ),
    )
