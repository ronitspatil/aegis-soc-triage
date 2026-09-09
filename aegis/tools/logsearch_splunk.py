"""Splunk implementation of `LogSearchBackend`.

Structured parameters are translated into SPL here, so the agent never sees a
query language. The SPL templates assume broadly CIM-ish field names and will
need adjusting per deployment; the protocol above them does not change.
"""

from __future__ import annotations

import logging
import re
from datetime import UTC, datetime
from typing import Any

from aegis.ingest.splunk_source import SplunkSource
from aegis.tools.logsearch import AuthEvent, LogEvent, RuleStats

logger = logging.getLogger(__name__)

MAX_ROWS = 200

# `spath` parses JSON payloads sitting in _raw, which Splunk does not
# field-extract for arbitrary custom sourcetypes. The free-text term alongside
# each field match keeps the query working either way: in deployments with CIM
# extractions the field match hits, elsewhere the term does.
#
# Each JSON field is extracted under a distinct `json_` name. A bare `| spath`
# merges the payload's `host` into Splunk's metadata `host`, producing a
# multivalue field holding both the forwarder and the real endpoint.
_SPATH = " ".join(
    f"| spath output=json_{name} path={name}"
    for name in ("host", "hostname", "user", "src_ip", "rule", "msg", "severity")
)

# Values reaching these queries originate in alerts, which carry
# attacker-influenced content. Anything outside this set is stripped rather
# than escaped, so a crafted hostname cannot terminate a quoted string and
# append its own SPL.
_SAFE_VALUE = re.compile(r"[^A-Za-z0-9._:@\-/\\ *,]")


def _clean(value: str, limit: int = 200) -> str:
    return _SAFE_VALUE.sub("", str(value))[:limit]


def _parse_time(raw: Any) -> datetime:
    if isinstance(raw, str):
        try:
            return datetime.fromisoformat(raw.replace("Z", "+00:00"))
        except ValueError:
            pass
    return datetime.now(UTC)


def _pick(row: dict[str, Any], *names: str) -> str | None:
    """First usable value among `names`.

    Splunk returns a list when a field is multivalue, so flatten rather than
    stringifying the list itself.
    """
    for name in names:
        value = row.get(name)
        if isinstance(value, list):
            value = next((v for v in value if v not in (None, "", "-")), None)
        if value not in (None, "", "-"):
            return str(value)
    return None


class SplunkLogSearch:
    """Historical search over Splunk. Read-only: every query is a search."""

    def __init__(self, source: SplunkSource | None = None,
                 index: str | None = None) -> None:
        from aegis.llm.config import get_settings

        self._source = source or SplunkSource()
        self._index = _clean(index or get_settings().splunk_search_index or "*",
                             limit=120) or "*"

    @property
    def _scope(self) -> str:
        return f"index={self._index}"

    def _rows(self, spl: str, earliest: str) -> list[dict[str, Any]]:
        try:
            return self._source.run_search(spl, earliest=earliest)
        except Exception as exc:  # noqa: BLE001 - a failed lookup is a gap, not a crash
            logger.warning("log search failed (%s): %s", spl[:80], exc)
            return []

    def _to_event(self, row: dict[str, Any], fallback_host: str = "") -> LogEvent:
        return LogEvent(
            timestamp=_parse_time(row.get("_time")),
            hostname=_pick(row, "json_hostname", "json_host", "hostname",
                            "dest_host", "computer", "host") or fallback_host,
            event_type=_pick(row, "event_type", "sourcetype") or "other",
            message=(_pick(row, "json_msg", "message", "msg", "_raw") or "")[:500],
            process_name=_pick(row, "process_name", "process", "filename"),
            parent_name=_pick(row, "parent_process_name", "parent_process"),
            command_line=_pick(row, "process", "cmdline", "command_line"),
            remote_ip=_pick(row, "dest_ip", "dest", "remote_address", "json_src_ip"),
            username=_pick(row, "json_user", "user", "username", "src_user"),
        )

    def host_timeline(self, hostname: str, hours: int = 24) -> list[LogEvent]:
        host = _clean(hostname)
        spl = (
            f'search {self._scope} ("{host}" OR host="{host}" OR hostname="{host}" '
            f'OR dest_host="{host}") {_SPATH} | head {MAX_ROWS}'
        )
        return [self._to_event(r, host) for r in self._rows(spl, f"-{int(hours)}h")]

    def user_auth_history(self, username: str, hours: int = 24) -> list[AuthEvent]:
        user = _clean(username)
        spl = (
            f'search {self._scope} ("{user}" OR user="{user}" OR src_user="{user}") '
            f"{_SPATH} | head {MAX_ROWS}"
        )
        events: list[AuthEvent] = []
        for row in self._rows(spl, f"-{int(hours)}h"):
            outcome = (_pick(row, "action", "outcome", "result") or "").lower()
            events.append(AuthEvent(
                timestamp=_parse_time(row.get("_time")),
                username=user,
                hostname=_pick(row, "json_hostname", "json_host", "hostname", "dest_host", "host"),
                source_ip=_pick(row, "json_src_ip", "src_ip", "src", "source_ip"),
                succeeded=outcome in {"success", "succeeded", "allowed"},
                country=_pick(row, "src_country", "country"),
            ))
        return events

    def find_indicator(self, indicator: str, hours: int = 168) -> list[LogEvent]:
        ioc = _clean(indicator, limit=120)
        spl = f'search {self._scope} "{ioc}" {_SPATH} | head {MAX_ROWS}'
        return [self._to_event(r) for r in self._rows(spl, f"-{int(hours)}h")]

    def count_rule_firings(self, rule_name: str, days: int = 7) -> RuleStats:
        rule = _clean(rule_name)
        spl = (
            f'search {self._scope} ("{rule}" OR rule="{rule}" OR search_name="{rule}" '
            f'OR rule_name="{rule}") {_SPATH} '
            # Splunk's `host` is the forwarder, so prefer an extracted hostname
            # before falling back to it.
            "| eval _h=coalesce(json_hostname, json_host, hostname, dest_host, host) "
            "| stats count as total, dc(_h) as hosts, dc(user) as users"
        )
        rows = self._rows(spl, f"-{int(days)}d")
        row = rows[0] if rows else {}

        def as_int(value: Any) -> int:
            try:
                return int(value)
            except (TypeError, ValueError):
                return 0

        return RuleStats(
            rule_name=rule_name,
            days=days,
            total_firings=as_int(row.get("total")),
            distinct_hosts=as_int(row.get("hosts")),
            distinct_users=as_int(row.get("users")),
        )
