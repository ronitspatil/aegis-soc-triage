"""Mock VirusTotal-style threat intelligence.

Swap-in point: replace `_FIXTURES` lookups with a real `vt` / requests client.
The Pydantic return type is the contract, callers never change.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, computed_field


class ThreatIntelUnavailable(RuntimeError):
    """Raised when the upstream TI provider is unreachable / rate limited."""


class IPReputation(BaseModel):
    """Normalized reputation verdict for a single indicator.

    A third-party API response is untrusted input like any other, so it is
    parsed into a typed model at the seam rather than passed around as a dict.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    indicator: str
    malicious_votes: int = Field(default=0, ge=0)
    harmless_votes: int = Field(default=0, ge=0)
    categories: list[str] = Field(default_factory=list)
    asn_owner: str | None = None
    is_known_tor_exit: bool = False
    seen_in_intel: bool = Field(default=True, description="False = no record at all")

    @computed_field  # type: ignore[prop-decorator]
    @property
    def malice_ratio(self) -> float:
        """0.0-1.0 share of engines flagging this indicator."""
        total = self.malicious_votes + self.harmless_votes
        return round(self.malicious_votes / total, 3) if total else 0.0


# Deterministic corpus. Keys chosen to exercise every branch the agent must
# handle: known-bad, known-good, unknown, and hard failure.
RAISE_ON_LOOKUP = "203.0.113.66"  # any lookup of this IOC simulates an outage

_FIXTURES: dict[str, IPReputation] = {
    "185.220.101.5": IPReputation(
        indicator="185.220.101.5",
        malicious_votes=41,
        harmless_votes=2,
        categories=["tor-exit-node", "anonymizer", "malicious"],
        asn_owner="Zwiebelfreunde e.V.",
        is_known_tor_exit=True,
    ),
    "8.8.8.8": IPReputation(
        indicator="8.8.8.8",
        malicious_votes=0,
        harmless_votes=88,
        categories=["public-dns", "benign"],
        asn_owner="Google LLC",
    ),
    "52.94.236.248": IPReputation(
        indicator="52.94.236.248",
        malicious_votes=0,
        harmless_votes=63,
        categories=["cloud-provider", "benign"],
        asn_owner="Amazon.com, Inc.",
    ),
}


def lookup_ip_reputation(indicator: str) -> IPReputation:
    """Return reputation for an IP. Raises `ThreatIntelUnavailable` on outage.

    Unknown indicators return `seen_in_intel=False`. Absence of evidence has to
    stay distinguishable from evidence of absence, or the synthesizer reads
    silence as safety.
    """
    if indicator == RAISE_ON_LOOKUP:
        raise ThreatIntelUnavailable(f"429 rate limited on lookup of {indicator}")

    hit = _FIXTURES.get(indicator)
    if hit is not None:
        return hit

    return IPReputation(indicator=indicator, seen_in_intel=False)


def resolve_ip_reputation(indicator: str) -> IPReputation:
    """Provider-aware entry point used by the node.

    Swapping mock -> live is an env var, not a code change, because both
    implementations satisfy the same `IPReputation` contract.
    """
    from aegis.llm.config import ToolProvider, get_settings

    provider = get_settings().threat_intel_provider
    if provider is ToolProvider.LIVE:
        from aegis.tools.vt_client import lookup_ip_reputation_live

        return lookup_ip_reputation_live(indicator)
    if provider is ToolProvider.PUBLIC:
        from aegis.tools.isc_client import lookup_ip_reputation_public

        return lookup_ip_reputation_public(indicator)
    return lookup_ip_reputation(indicator)
