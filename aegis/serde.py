"""Checkpoint serialization allowlist.

LangGraph persists graph state via msgpack. By default it will deserialize ANY
type with only a warning, and an attacker able to write to the checkpoint
store could use that for code execution. We enumerate exactly the types our
state contains, so anything else is refused.
"""

from __future__ import annotations

from langgraph.checkpoint.serde.jsonplus import JsonPlusSerializer

# (module, qualname) pairs for every custom type that can appear in SOCAgentState.
ALLOWED_TYPES: list[tuple[str, str]] = [
    ("aegis.schemas.alert", "SIEMAlert"),
    ("aegis.schemas.alert", "Severity"),
    ("aegis.schemas.state", "EnrichmentData"),
    ("aegis.schemas.state", "Verdict"),
    ("aegis.schemas.investigation", "InvestigationReport"),
    ("aegis.schemas.response", "ResponsePlan"),
    ("aegis.schemas.response", "ProposedAction"),
    ("aegis.schemas.response", "ActionType"),
]


def build_serializer() -> JsonPlusSerializer:
    """Serializer restricted to our own types plus LangGraph's safe built-ins."""
    return JsonPlusSerializer(allowed_msgpack_modules=ALLOWED_TYPES)
