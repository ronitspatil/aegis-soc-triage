"""Report what a CrowdStrike tenant actually exposes.

Run this before writing any mapping code. Every integration so far has returned
something the documentation did not predict, so the client should be written
against observed responses rather than assumed ones.

    .venv/bin/python scripts/probe_crowdstrike.py
"""

from __future__ import annotations

import json
import sys
from typing import Any, Optional

import httpx

from aegis.llm.config import get_settings

settings = get_settings()
BASE = settings.crowdstrike_base_url


def fail(msg: str) -> None:
    print(f"\n{msg}")
    sys.exit(1)


def get_token() -> str:
    if not (settings.crowdstrike_client_id and settings.crowdstrike_client_secret):
        fail("CROWDSTRIKE_CLIENT_ID / CROWDSTRIKE_CLIENT_SECRET are not set in .env")

    r = httpx.post(
        f"{BASE}/oauth2/token",
        data={
            "client_id": settings.crowdstrike_client_id,
            "client_secret": settings.crowdstrike_client_secret,
        },
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        timeout=30,
    )
    if r.status_code == 403:
        fail(f"403 from {BASE}. Usually the wrong cloud region: check the console URL.")
    if r.status_code != 201:
        fail(f"auth failed ({r.status_code}): {r.text[:300]}")

    body = r.json()
    print(f"auth ok   base={BASE}  expires_in={body.get('expires_in')}s")
    return str(body["access_token"])


def probe(client: httpx.Client, label: str, method: str, path: str,
          **kw: Any) -> Optional[dict[str, Any]]:
    """Call one endpoint and report availability, not just success."""
    try:
        r = client.request(method, path, **kw)
    except Exception as exc:  # noqa: BLE001
        print(f"  {label:34} ERROR {exc}")
        return None

    if r.status_code == 403:
        print(f"  {label:34} 403 forbidden (missing scope)")
        return None
    if r.status_code == 404:
        print(f"  {label:34} 404 not available on this tenant")
        return None
    if r.status_code >= 400:
        print(f"  {label:34} {r.status_code} {r.text[:120]}")
        return None

    body = r.json()
    n = len(body.get("resources") or [])
    print(f"  {label:34} {r.status_code} ok, {n} resource(s)")
    return body


def main() -> None:
    token = get_token()
    client = httpx.Client(
        base_url=BASE,
        headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        timeout=45,
    )

    print("\nendpoints:")
    devices = probe(client, "hosts: device ids", "GET",
                    "/devices/queries/devices/v1", params={"limit": 5})
    probe(client, "alerts: ids (v2, current)", "GET",
          "/alerts/queries/alerts/v2", params={"limit": 5})
    probe(client, "detects: ids (legacy)", "GET",
          "/detects/queries/detects/v1", params={"limit": 5})
    probe(client, "incidents: ids", "GET",
          "/incidents/queries/incidents/v1", params={"limit": 5})

    ids = (devices or {}).get("resources") or []
    if ids:
        print("\nsample device shape:")
        detail = probe(client, "hosts: device detail", "GET",
                       "/devices/entities/devices/v2", params={"ids": ids[0]})
        res = (detail or {}).get("resources") or []
        if res:
            keys = sorted(res[0].keys())
            print(f"  {len(keys)} fields available")
            print("  relevant:", [k for k in keys if any(
                t in k for t in ("host", "os", "status", "platform", "policies",
                                 "reduced", "last_seen", "agent"))])
            print("\n  first device (truncated):")
            print("  " + json.dumps({k: res[0].get(k) for k in (
                "hostname", "os_version", "platform_name", "status",
                "reduced_functionality_mode", "last_seen", "agent_version")},
                indent=2).replace("\n", "\n  "))
    else:
        print("\nNo devices enrolled yet. Auth and scopes are still verifiable;")
        print("install a Falcon sensor to get real telemetry to map.")


if __name__ == "__main__":
    main()
