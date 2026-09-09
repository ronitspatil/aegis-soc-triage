"""Mock EDR / endpoint telemetry (CrowdStrike / Defender shaped).

Swap-in point: replace `_HOSTS` with a real EDR client. `HostTelemetry` is the
contract the Endpoint worker node depends on.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class EDRUnavailable(RuntimeError):
    """Raised when the EDR platform is unreachable."""


class ProcessEvent(BaseModel):
    """A single process execution observed on the host."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str
    # Most attacker-controlled string in the system. Prose input only, never
    # an input to scoring.
    command_line: str = ""
    parent_name: str | None = None
    is_signed: bool = True
    sha256: str | None = None


class HostTelemetry(BaseModel):
    """Endpoint posture + recent activity."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    hostname: str
    os: str
    # A dead sensor is a BLIND SPOT, not a clean bill of health.
    edr_agent_healthy: bool = True
    is_isolated: bool = False
    recent_processes: list[ProcessEvent] = Field(default_factory=list)
    outbound_connections: list[str] = Field(default_factory=list)


# Hashes our (mock) intel considers known-bad.
KNOWN_MALICIOUS_HASHES: set[str] = {
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
}

RAISE_ON_LOOKUP = "EDR-OUTAGE-HOST"

_HOSTS: dict[str, HostTelemetry] = {
    # Classic maldoc chain: Word spawns encoded PowerShell, beacons to Tor.
    "WIN-FINANCE-07": HostTelemetry(
        hostname="WIN-FINANCE-07",
        os="Windows 11 22H2",
        recent_processes=[
            ProcessEvent(
                name="powershell.exe",
                command_line="powershell.exe -nop -w hidden -enc SQBFAFgAKABOAGUAdwAt",
                parent_name="winword.exe",
                is_signed=True,  # signed LOLBin, signing proves nothing here
                sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            ),
        ],
        outbound_connections=["185.220.101.5:443"],
    ),
    # Ordinary developer activity, the false-positive baseline.
    "MACBOOK-RPATIL": HostTelemetry(
        hostname="MACBOOK-RPATIL",
        os="macOS 15.2",
        recent_processes=[
            ProcessEvent(
                name="python3.12",
                command_line="python3.12 manage.py runserver",
                parent_name="zsh",
            ),
        ],
        outbound_connections=["8.8.8.8:53"],
    ),
    # Legitimate backup job on a server whose sensor has stopped reporting.
    "SRV-BACKUP-01": HostTelemetry(
        hostname="SRV-BACKUP-01",
        os="Windows Server 2022",
        edr_agent_healthy=False,
        recent_processes=[
            ProcessEvent(
                name="veeam.backup.exe",
                command_line="veeam.backup.exe --job nightly",
                parent_name="services.exe",
            ),
        ],
        outbound_connections=["52.94.236.248:443"],
    ),
}


def get_host_telemetry(hostname: str) -> HostTelemetry | None:
    """Return telemetry, or None if the host is unknown to the EDR fleet."""
    if hostname == RAISE_ON_LOOKUP:
        raise EDRUnavailable(f"504 gateway timeout querying EDR for {hostname}")
    return _HOSTS.get(hostname)


def resolve_host_telemetry(hostname: str) -> HostTelemetry | None:
    """Provider-aware entry point. Switching mock to live is an env var."""
    from aegis.llm.config import ToolProvider, get_settings

    if get_settings().endpoint_provider is ToolProvider.LIVE:
        from aegis.tools.edr_client import get_host_telemetry_live

        return get_host_telemetry_live(hostname)
    return get_host_telemetry(hostname)
