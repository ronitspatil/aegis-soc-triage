"""CrowdStrike Falcon endpoint telemetry.

Returns the same `HostTelemetry` contract as the mock, so `endpoint_node` is
unchanged.

Endpoint choices were verified against a live us-2 tenant:
  * `/alerts/queries|entities/alerts/v2` is the current API. The legacy
    `/detects/` endpoints return 404 on tenants provisioned recently.
  * The alerts entity endpoint takes `composite_ids`, not `ids`.
  * FQL values must be quoted: `hostname:'HOST-1'`. An unquoted value or an
    unknown field returns 400, so a 200 with no resources genuinely means
    "nothing matched" rather than a malformed query.

Alert *field* names below follow CrowdStrike's documented schema and have not
been observed against real detections, since the trial tenant had none. Parsing
is defensive for that reason.
"""

from __future__ import annotations

import logging
import threading
import time
from typing import Any

from aegis.llm.config import get_settings
from aegis.tools._http import ToolHTTPError, request_json
from aegis.tools.endpoint import EDRUnavailable, HostTelemetry, ProcessEvent


class EDRParseError(EDRUnavailable):
    """Alerts came back but none could be parsed.

    Field names in the alerts payload are not verified against real detections.
    If Falcon reports alerts for a host and we extract nothing from them, the
    likely cause is a schema mismatch, not a quiet host. Failing loudly here
    keeps a parsing bug from being reported as clean telemetry, which would let
    a compromised host look benign.
    """

logger = logging.getLogger(__name__)

# Tokens last 30 minutes. Cache and refresh early rather than authenticating
# on every alert.
_token: dict[str, Any] = {"value": None, "expires_at": 0.0}
_token_lock = threading.Lock()

MAX_ALERTS_PER_HOST = 20


def _auth_headers() -> dict[str, str]:
    settings = get_settings()
    if not (settings.crowdstrike_client_id and settings.crowdstrike_client_secret):
        raise EDRUnavailable("CROWDSTRIKE_CLIENT_ID / _SECRET are not configured")

    with _token_lock:
        if _token["value"] and time.monotonic() < _token["expires_at"]:
            return {"Authorization": f"Bearer {_token['value']}"}

        try:
            payload = request_json(
                "POST",
                f"{settings.crowdstrike_base_url}/oauth2/token",
                data={
                    "client_id": settings.crowdstrike_client_id,
                    "client_secret": settings.crowdstrike_client_secret,
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                timeout=settings.tool_timeout_seconds,
                retries=settings.tool_max_retries,
            ) or {}
        except ToolHTTPError as exc:
            # A 403 here is usually the wrong cloud region rather than a bad key.
            raise EDRUnavailable(
                f"CrowdStrike auth failed against {settings.crowdstrike_base_url}: {exc}"
            ) from exc

        token = payload.get("access_token")
        if not token:
            raise EDRUnavailable("CrowdStrike returned no access_token")

        _token["value"] = token
        # Refresh a minute early so a token cannot expire mid-investigation.
        _token["expires_at"] = time.monotonic() + int(payload.get("expires_in", 1800)) - 60
        return {"Authorization": f"Bearer {token}"}


def _resources(payload: dict[str, Any] | None) -> list[Any]:
    return list((payload or {}).get("resources") or [])


def _parse_behavior(behavior: dict[str, Any]) -> ProcessEvent:
    """Map one alert behaviour onto a process event."""
    parent = behavior.get("parent_details") or {}
    return ProcessEvent(
        name=behavior.get("filename") or "unknown",
        command_line=behavior.get("cmdline") or "",
        parent_name=parent.get("filename") or parent.get("parent_process_filename"),
        # Falcon does not always report signing status. Absent is not signed:
        # assuming otherwise would suppress risk we cannot actually rule out.
        is_signed=bool(behavior.get("signed", False)),
        sha256=behavior.get("sha256"),
    )


def _parse_alert(alert: dict[str, Any]) -> tuple[list[ProcessEvent], list[str]]:
    """Extract processes and network indicators from one alert.

    Alerts v2 flattens some fields to the top level and nests others under
    `behaviors`, and which you get varies by detection type, so both are read.
    """
    processes: list[ProcessEvent] = []
    connections: list[str] = []

    behaviors = alert.get("behaviors") or []
    if not behaviors and alert.get("filename"):
        behaviors = [alert]  # flattened single-behaviour alert

    for behavior in behaviors:
        if isinstance(behavior, dict):
            processes.append(_parse_behavior(behavior))

    for access in alert.get("network_accesses") or []:
        if isinstance(access, dict) and access.get("remote_address"):
            connections.append(str(access["remote_address"]))

    return processes, connections


def get_host_telemetry_live(hostname: str) -> HostTelemetry | None:
    """Resolve a hostname to a device and pull its recent alert activity.

    Returns None when the host is unknown to the Falcon fleet, which the scorer
    treats as a visibility gap rather than a clean host.
    """
    settings = get_settings()
    base = settings.crowdstrike_base_url
    kw = dict(
        headers=_auth_headers(),
        timeout=settings.tool_timeout_seconds,
        retries=settings.tool_max_retries,
    )

    try:
        # 1. hostname -> device id. FQL values must be quoted.
        found = request_json(
            "GET", f"{base}/devices/queries/devices/v1",
            params={"filter": f"hostname:'{hostname}'", "limit": 1}, **kw,
        )
        device_ids = _resources(found)
        if not device_ids:
            return None

        device_id = device_ids[0]

        # 2. device detail
        detail = request_json(
            "GET", f"{base}/devices/entities/devices/v2",
            params={"ids": device_id}, **kw,
        )
        devices = _resources(detail)
        device: dict[str, Any] = devices[0] if devices else {}

        # 3. alerts for that device (current API; /detects/ is gone)
        alert_query = request_json(
            "GET", f"{base}/alerts/queries/alerts/v2",
            params={
                "filter": f"device.device_id:'{device_id}'",
                "limit": MAX_ALERTS_PER_HOST,
                "sort": "created_timestamp|desc",
            },
            **kw,
        )
        alert_ids = _resources(alert_query)

        alerts: list[dict[str, Any]] = []
        if alert_ids:
            # The entity endpoint takes `composite_ids`, not `ids`.
            alerts = _resources(request_json(
                "POST", f"{base}/alerts/entities/alerts/v2",
                json_body={"composite_ids": alert_ids}, **kw,
            ))

    except ToolHTTPError as exc:
        raise EDRUnavailable(f"CrowdStrike query failed for {hostname}: {exc}") from exc
    except EDRUnavailable:
        raise
    except Exception as exc:  # noqa: BLE001 - unexpected payload shape
        raise EDRUnavailable(f"CrowdStrike response unusable for {hostname}: {exc}") from exc

    processes: list[ProcessEvent] = []
    connections: list[str] = []
    for alert in alerts:
        if not isinstance(alert, dict):
            continue
        procs, conns = _parse_alert(alert)
        processes.extend(procs)
        connections.extend(conns)

    # Alerts existed but produced nothing: treat as a parsing failure, not a
    # clean host. Log the observed keys so the mismatch is diagnosable.
    if alerts and not processes:
        observed = sorted({k for a in alerts if isinstance(a, dict) for k in a})
        logger.error(
            "parsed 0 processes from %d Falcon alert(s) on %s; observed keys: %s",
            len(alerts), hostname, observed,
        )
        raise EDRParseError(
            f"{len(alerts)} Falcon alert(s) for {hostname} could not be parsed "
            f"(observed keys: {observed[:12]})"
        )

    status = str(device.get("status", "")).lower()
    return HostTelemetry(
        hostname=device.get("hostname") or hostname,
        os=device.get("os_version") or device.get("platform_name") or "unknown",
        # A sensor in reduced functionality mode is a blind spot, and the
        # scorer treats that as added risk rather than a clean result.
        edr_agent_healthy=not device.get("reduced_functionality_mode")
        and status not in {"", "unknown"},
        is_isolated=status == "contained",
        recent_processes=processes,
        outbound_connections=sorted(set(connections)),
    )
