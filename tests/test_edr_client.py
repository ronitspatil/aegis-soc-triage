"""CrowdStrike client. No credentials or network required.

The endpoint and parameter choices asserted here were confirmed against a live
us-2 tenant; see the module docstring in aegis/tools/edr_client.py.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

import httpx
import pytest

import aegis.tools.edr_client as edr
from aegis.tools.endpoint import EDRUnavailable


@pytest.fixture(autouse=True)
def _creds_and_fresh_token(monkeypatch):
    monkeypatch.setenv("CROWDSTRIKE_CLIENT_ID", "id")
    monkeypatch.setenv("CROWDSTRIKE_CLIENT_SECRET", "secret")
    monkeypatch.setenv("CROWDSTRIKE_BASE_URL", "https://api.us-2.crowdstrike.com")
    monkeypatch.setattr("aegis.tools._http.time.sleep", lambda *_: None)
    edr._token.update({"value": None, "expires_at": 0.0})
    yield
    edr._token.update({"value": None, "expires_at": 0.0})


def install(monkeypatch, handler: Callable[..., tuple[int, Any]]) -> list[dict]:
    calls: list[dict] = []

    def fake(method: str, url: str, **kw: Any) -> httpx.Response:
        calls.append({"method": method, "url": str(url),
                      "params": kw.get("params"), "json": kw.get("json")})
        status, body = handler(method, str(url), kw)
        return httpx.Response(status_code=status,
                              content=json.dumps(body).encode(),
                              request=httpx.Request(method, url))

    monkeypatch.setattr(httpx, "request", fake)
    return calls


TOKEN = {"access_token": "tok-123", "expires_in": 1799}

ALERT = {
    "behaviors": [{
        "filename": "powershell.exe",
        "cmdline": "powershell.exe -nop -w hidden -enc SQBFAFgA",
        "parent_details": {"filename": "winword.exe"},
        "sha256": "abc123",
        "signed": True,
    }],
    "network_accesses": [{"remote_address": "185.220.101.5"}],
}


def _handler(devices=("dev1",), alert_ids=("cid:ind:aid:1",), alerts=(ALERT,), device=None):
    device = device or {"hostname": "WIN-FINANCE-07", "os_version": "Windows 11",
                        "status": "normal"}

    def handler(method, url, kw):
        if "oauth2/token" in url:
            return 201, TOKEN
        if "devices/queries/devices" in url:
            return 200, {"resources": list(devices)}
        if "devices/entities/devices" in url:
            return 200, {"resources": [device]}
        if "alerts/queries/alerts" in url:
            return 200, {"resources": list(alert_ids)}
        if "alerts/entities/alerts" in url:
            return 200, {"resources": list(alerts)}
        return 200, {"resources": []}
    return handler


def test_uses_the_alerts_api_not_the_removed_detects_endpoints(monkeypatch):
    """/detects/ returns 404 on tenants provisioned recently."""
    calls = install(monkeypatch, _handler())
    edr.get_host_telemetry_live("WIN-FINANCE-07")
    urls = " ".join(c["url"] for c in calls)
    assert "/alerts/queries/alerts/v2" in urls
    assert "/alerts/entities/alerts/v2" in urls
    assert "/detects/" not in urls


def test_alert_entities_are_requested_with_composite_ids(monkeypatch):
    """`ids` is rejected by this endpoint; `composite_ids` is the accepted key."""
    calls = install(monkeypatch, _handler())
    edr.get_host_telemetry_live("WIN-FINANCE-07")
    entity_call = next(c for c in calls if "alerts/entities" in c["url"])
    assert "composite_ids" in entity_call["json"]
    assert "ids" not in entity_call["json"]


def test_fql_values_are_quoted(monkeypatch):
    """An unquoted FQL value returns 400 Invalid filter expression."""
    calls = install(monkeypatch, _handler())
    edr.get_host_telemetry_live("WIN-FINANCE-07")
    device_query = next(c for c in calls if "devices/queries" in c["url"])
    assert device_query["params"]["filter"] == "hostname:'WIN-FINANCE-07'"


def test_unknown_host_returns_none_rather_than_raising(monkeypatch):
    """Verified live: a host absent from the fleet is a visibility gap, and the
    scorer must be able to tell that apart from a clean host."""
    install(monkeypatch, _handler(devices=()))
    assert edr.get_host_telemetry_live("NOT-ENROLLED") is None


def test_behaviours_map_to_process_events(monkeypatch):
    install(monkeypatch, _handler())
    tel = edr.get_host_telemetry_live("WIN-FINANCE-07")
    assert len(tel.recent_processes) == 1
    proc = tel.recent_processes[0]
    assert proc.name == "powershell.exe"
    assert proc.parent_name == "winword.exe"
    assert proc.sha256 == "abc123"
    assert tel.outbound_connections == ["185.220.101.5"]


def test_flattened_alert_without_behaviours_is_still_parsed(monkeypatch):
    """Alerts v2 flattens some detection types to the top level."""
    flat = {"filename": "mshta.exe", "cmdline": "mshta.exe http://x",
            "parent_details": {"filename": "explorer.exe"}}
    install(monkeypatch, _handler(alerts=(flat,)))
    tel = edr.get_host_telemetry_live("WIN-FINANCE-07")
    assert tel.recent_processes[0].name == "mshta.exe"


def test_reduced_functionality_mode_counts_as_an_unhealthy_sensor(monkeypatch):
    install(monkeypatch, _handler(device={
        "hostname": "SRV-1", "os_version": "Windows Server 2022",
        "status": "normal", "reduced_functionality_mode": "yes"}))
    tel = edr.get_host_telemetry_live("SRV-1")
    assert tel.edr_agent_healthy is False


def test_a_sensor_reporting_no_rfm_is_healthy(monkeypatch):
    """Falcon sends the string "no", which is truthy: a live tenant caught this."""
    install(monkeypatch, _handler(device={
        "hostname": "numbat", "os_version": "Ubuntu 26.04",
        "status": "normal", "reduced_functionality_mode": "no"}))
    assert edr.get_host_telemetry_live("numbat").edr_agent_healthy is True


def test_contained_host_is_reported_as_isolated(monkeypatch):
    install(monkeypatch, _handler(device={
        "hostname": "H", "os_version": "Windows 11", "status": "contained"}))
    assert edr.get_host_telemetry_live("H").is_isolated is True


def test_unsigned_is_assumed_when_falcon_omits_signing(monkeypatch):
    """Absent is not signed: assuming otherwise suppresses risk we cannot rule out."""
    alert = {"behaviors": [{"filename": "x.exe", "cmdline": "x.exe"}]}
    install(monkeypatch, _handler(alerts=(alert,)))
    tel = edr.get_host_telemetry_live("WIN-FINANCE-07")
    assert tel.recent_processes[0].is_signed is False


def test_token_is_cached_across_calls(monkeypatch):
    calls = install(monkeypatch, _handler())
    edr.get_host_telemetry_live("WIN-FINANCE-07")
    edr.get_host_telemetry_live("WIN-FINANCE-07")
    assert sum(1 for c in calls if "oauth2/token" in c["url"]) == 1


def test_auth_failure_mentions_the_region(monkeypatch):
    """A 403 on token exchange is usually the wrong cloud, not a bad key."""
    def handler(method, url, kw):
        return (403, {"errors": [{"message": "access denied"}]}) if "oauth2" in url else (200, {})

    install(monkeypatch, handler)
    with pytest.raises(EDRUnavailable) as exc:
        edr.get_host_telemetry_live("H")
    assert "api.us-2.crowdstrike.com" in str(exc.value)


def test_missing_credentials_raise_rather_than_silently_passing(monkeypatch):
    monkeypatch.setenv("CROWDSTRIKE_CLIENT_ID", "")
    monkeypatch.setenv("CROWDSTRIKE_CLIENT_SECRET", "")
    with pytest.raises(EDRUnavailable):
        edr.get_host_telemetry_live("H")


def test_unparseable_alerts_fail_loudly_instead_of_looking_clean(monkeypatch):
    """Alert field names are not yet verified against real detections. If Falcon
    reports alerts and we extract nothing, that is a schema mismatch. Reporting
    an empty process list would score the host 0.0 and let a compromised
    machine look benign."""
    unknown_shape = {"some_new_field": "value", "another": {"nested": 1}}
    install(monkeypatch, _handler(alerts=(unknown_shape,)))
    with pytest.raises(EDRUnavailable) as exc:
        edr.get_host_telemetry_live("WIN-FINANCE-07")
    assert "could not be parsed" in str(exc.value)


def test_a_host_with_no_alerts_is_still_reported_as_clean(monkeypatch):
    """The guard must not fire when Falcon genuinely has nothing to report."""
    install(monkeypatch, _handler(alert_ids=(), alerts=()))
    tel = edr.get_host_telemetry_live("WIN-FINANCE-07")
    assert tel is not None
    assert tel.recent_processes == []
