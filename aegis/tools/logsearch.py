"""Historical log search, abstracted away from any one SIEM.

The investigation agent queries through this protocol rather than a vendor
client, for three reasons:

  * Portability. Each backend translates the same structured parameters into
    SPL, KQL or ES DSL.
  * Safety. A model that writes raw queries can produce one that scans a year
    of data. Fixed parameters are bounded by construction.
  * Injection resistance. Tool results contain attacker-controlled log text. If
    that text could shape a raw query string on the next iteration, an attacker
    would gain partial control of what gets asked. With fixed parameters the
    worst case is a lookup of a value they chose.

The cost is expressiveness: the agent cannot invent a correlation the protocol
does not expose.
"""

from __future__ import annotations

from datetime import datetime
from typing import Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field, computed_field


class LogEvent(BaseModel):
    """One observed event. Deliberately flat: backends differ, callers should not."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    timestamp: datetime
    hostname: str
    event_type: str = Field(description="process, network, file, auth, other")
    message: str = ""
    process_name: str | None = None
    parent_name: str | None = None
    command_line: str | None = None
    remote_ip: str | None = None
    username: str | None = None


class AuthEvent(BaseModel):
    """An authentication attempt."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    timestamp: datetime
    username: str
    hostname: str | None = None
    source_ip: str | None = None
    succeeded: bool = False
    country: str | None = None


class RuleStats(BaseModel):
    """How often a detection rule fires. Base rate is often the whole answer."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    rule_name: str
    days: int = Field(gt=0)
    total_firings: int = Field(ge=0)
    distinct_hosts: int = Field(default=0, ge=0)
    distinct_users: int = Field(default=0, ge=0)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def firings_per_day(self) -> float:
        return round(self.total_firings / self.days, 2)


@runtime_checkable
class LogSearchBackend(Protocol):
    """What the investigator is allowed to ask. Read-only by construction."""

    def host_timeline(self, hostname: str, hours: int = 24) -> list[LogEvent]:
        """Recent activity on one host."""
        ...

    def user_auth_history(self, username: str, hours: int = 24) -> list[AuthEvent]:
        """Authentication attempts for one principal."""
        ...

    def find_indicator(self, indicator: str, hours: int = 168) -> list[LogEvent]:
        """Everywhere an IP, hash or domain was observed. Lateral movement."""
        ...

    def count_rule_firings(self, rule_name: str, days: int = 7) -> RuleStats:
        """How noisy a detection rule is."""
        ...

    def list_active_rules(self, days: int = 7) -> list[RuleStats]:
        """Which rules fired recently, so a caller need not guess rule names."""
        ...


def resolve_log_backend() -> LogSearchBackend:
    """Pick the backend from configuration. Adding a SIEM is a new module here."""
    from aegis.llm.config import LogBackend, get_settings

    backend = get_settings().log_backend
    if backend is LogBackend.SPLUNK:
        from aegis.tools.logsearch_splunk import SplunkLogSearch

        return SplunkLogSearch()

    from aegis.tools.logsearch_mock import MockLogSearch

    return MockLogSearch()
