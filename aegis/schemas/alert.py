"""Inbound SIEM alert contract: the system's trust boundary.

Anything crossing this module is untrusted, externally-supplied data.
Once parsed into `SIEMAlert`, downstream nodes may assume validity.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import Enum

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    IPvAnyAddress,
    field_validator,
)


class Severity(str, Enum):
    """Normalized severity ladder. Vendor-specific scales map onto this."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class SIEMAlert(BaseModel):
    """A single detection emitted by the SIEM / alert queue."""

    # `extra="allow"` keeps vendor-specific fields instead of rejecting the
    # alert. Dropping a real detection over an unknown key is a worse failure
    # than carrying a few unused fields.
    model_config = ConfigDict(extra="allow", frozen=True)

    alert_id: str = Field(..., min_length=1, description="Vendor-unique alert ID")
    rule_name: str = Field(..., min_length=1, description="Detection rule that fired")
    severity: Severity = Field(..., description="Normalized severity")
    timestamp: datetime = Field(..., description="Detection time (coerced to UTC)")

    # --- Entities under investigation. Optional: not every rule has all three.
    source_ip: IPvAnyAddress | None = Field(None, description="Observed source IP")
    destination_ip: IPvAnyAddress | None = Field(None, description="Observed dest IP")
    username: str | None = Field(None, description="Principal / UPN, if identity-related")
    hostname: str | None = Field(None, description="Endpoint the alert fired on")
    file_hash: str | None = Field(None, description="SHA256/MD5 of implicated file")

    raw_log: str = Field(default="", description="Original log line for LLM context")

    @field_validator("timestamp")
    @classmethod
    def _force_utc(cls, v: datetime) -> datetime:
        """Naive timestamps silently corrupt time-window correlation. Reject ambiguity."""
        if v.tzinfo is None:
            return v.replace(tzinfo=UTC)
        return v.astimezone(UTC)

    @field_validator("file_hash")
    @classmethod
    def _normalize_hash(cls, v: str | None) -> str | None:
        """Threat-intel APIs are case-sensitive on hash lookups often enough to matter."""
        return v.lower().strip() if v else None


# Ordered severity ladder for threshold comparisons (str enums do not order).
SEVERITY_ORDER: dict[str, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}
