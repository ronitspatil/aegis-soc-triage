"""Splunk as an alert SOURCE.

Two ingestion styles, both producing validated `SIEMAlert` objects:

  * `search_alerts()` , run SPL and map result rows. This is the practical
    path: poll a detection search on a schedule, checkpointing on time.
  * `fired_alerts()`  , read Splunk's own triggered saved-search alerts.

Splunk results are UNTRUSTED external input. A single malformed row must not
abort the batch, so rows are validated individually and failures are collected
rather than raised.
"""

from __future__ import annotations

import contextlib
import json
import logging
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

import httpx
from pydantic import ValidationError

from aegis.llm.config import get_settings
from aegis.schemas.alert import SIEMAlert

logger = logging.getLogger(__name__)

# Splunk field names vary by deployment (CIM, custom detections, raw sourcetypes).
# Each tuple lists candidate source fields in priority order.
FIELD_MAP: dict[str, tuple[str, ...]] = {
    "alert_id": ("alert_id", "event_id", "signature_id", "_cd"),
    "rule_name": ("rule", "rule_name", "search_name", "signature", "savedsearch_name"),
    "severity": ("severity", "urgency", "priority"),
    "timestamp": ("_time", "timestamp", "event_time"),
    "source_ip": ("src_ip", "src", "source_ip", "clientip"),
    "destination_ip": ("dest_ip", "dest", "destination_ip"),
    "username": ("user", "username", "user_name", "src_user"),
    # NOTE: detection-specific names come FIRST. Splunk's reserved `host`
    # metadata is the forwarder that shipped the event, which is almost never
    # the endpoint the detection is about.
    "hostname": ("hostname", "dest_host", "computer", "dest_nt_host", "host"),
    "file_hash": ("file_hash", "sha256", "hash"),
    "raw_log": ("msg", "message", "_raw", "description"),
}

# Vendor severity vocabularies -> our normalized ladder.
SEVERITY_MAP = {
    "1": "info", "2": "low", "3": "medium", "4": "high", "5": "critical",
    "informational": "info", "warning": "medium", "unknown": "medium",
}


@dataclass
class IngestResult:
    alerts: list[SIEMAlert] = field(default_factory=list)
    rejected: list[dict[str, Any]] = field(default_factory=list)


def _pick(row: dict[str, Any], candidates: Iterable[str]) -> Any | None:
    for key in candidates:
        value = row.get(key)
        if value not in (None, "", "-"):
            return value
    return None


def map_row(row: dict[str, Any]) -> SIEMAlert:
    """Map one Splunk result row onto our schema. Raises ValidationError."""
    # Detection payloads are often a JSON blob in `_raw`. The PAYLOAD WINS on
    # collision: Splunk's reserved metadata (`host`, `source`, `sourcetype`)
    # describes ingestion, not the detection. Letting Splunk's `host` override
    # the event's own host makes the agent investigate the log forwarder
    # instead of the compromised endpoint, a silent, plausible wrong answer.
    raw = row.get("_raw")
    if isinstance(raw, str) and raw.strip().startswith("{"):
        with contextlib.suppress(json.JSONDecodeError):
            row = {**row, **json.loads(raw)}

    severity = str(_pick(row, FIELD_MAP["severity"]) or "medium").lower()
    return SIEMAlert(
        alert_id=str(_pick(row, FIELD_MAP["alert_id"]) or row.get("_cd") or "SPLUNK-UNKNOWN"),
        rule_name=str(_pick(row, FIELD_MAP["rule_name"]) or "Unnamed Splunk Detection"),
        severity=SEVERITY_MAP.get(severity, severity),
        timestamp=_pick(row, FIELD_MAP["timestamp"]),
        source_ip=_pick(row, FIELD_MAP["source_ip"]),
        destination_ip=_pick(row, FIELD_MAP["destination_ip"]),
        username=_pick(row, FIELD_MAP["username"]),
        hostname=_pick(row, FIELD_MAP["hostname"]),
        file_hash=_pick(row, FIELD_MAP["file_hash"]),
        raw_log=str(_pick(row, FIELD_MAP["raw_log"]) or ""),
    )


class SplunkSource:
    """Thin REST client for pulling detections out of Splunk."""

    def __init__(self) -> None:
        settings = get_settings()
        if not settings.splunk_token:
            raise RuntimeError("SPLUNK_TOKEN is not configured")
        self._client = httpx.Client(
            base_url=settings.splunk_url,
            verify=settings.splunk_verify_ssl,
            headers={"Authorization": f"Bearer {settings.splunk_token}"},
            timeout=60.0,
        )

    def whoami(self) -> dict[str, Any]:
        r = self._client.get(
            "/services/authentication/current-context", params={"output_mode": "json"}
        )
        r.raise_for_status()
        return r.json()["entry"][0]["content"]

    def run_search(
        self, spl: str, earliest: str = "-24h", latest: str = "now"
    ) -> list[dict[str, Any]]:
        """Execute a blocking one-shot search and return result rows."""
        if not spl.lstrip().startswith(("search ", "|")):
            spl = f"search {spl}"
        r = self._client.post(
            "/services/search/jobs",
            data={
                "search": spl,
                "exec_mode": "oneshot",
                "earliest_time": earliest,
                "latest_time": latest,
                "output_mode": "json",
                "count": 0,
            },
        )
        r.raise_for_status()
        return r.json().get("results", [])

    def search_alerts(self, spl: str, **kw: Any) -> IngestResult:
        """Run SPL and convert every row into a validated `SIEMAlert`."""
        out = IngestResult()
        for row in self.run_search(spl, **kw):
            try:
                out.alerts.append(map_row(row))
            except ValidationError as exc:
                # One bad row must not drop the whole batch of detections.
                logger.warning("rejected Splunk row: %s", exc)
                out.rejected.append({"row": row, "error": str(exc)})
        return out

    def fired_alerts(self) -> list[dict[str, Any]]:
        """Splunk's own triggered saved-search alerts."""
        r = self._client.get(
            "/services/alerts/fired_alerts", params={"output_mode": "json", "count": 0}
        )
        r.raise_for_status()
        return [
            {"name": e["name"], **e.get("content", {})}
            for e in r.json().get("entry", [])
            if e["name"] != "-"
        ]
