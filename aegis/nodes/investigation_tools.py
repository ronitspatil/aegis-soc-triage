"""Read-only tools available to the investigation agent.

Every tool is a bounded lookup through `LogSearchBackend`. No tool writes
anything, and none accepts a query string: the agent chooses which question to
ask, never how to ask it.

Results are summarised rather than dumped. The whole conversation is resent on
each loop iteration, so an unbounded tool result is paid for repeatedly.
"""

from __future__ import annotations

import logging
from typing import Any

from langchain_core.tools import tool

from aegis.tools.logsearch import resolve_log_backend

logger = logging.getLogger(__name__)

MAX_ROWS_IN_RESULT = 15


@tool
def get_host_timeline(hostname: str, hours: int = 24) -> str:
    """Recent process, network and file activity on one host.

    Use to reconstruct what happened around an alert: what spawned what, and
    where it connected.
    """
    events = resolve_log_backend().host_timeline(hostname, hours)
    if not events:
        # Absence is reported plainly so the model does not read it as "clean".
        return f"No events recorded for {hostname} in the last {hours}h."

    lines = [f"{len(events)} events on {hostname} in the last {hours}h:"]
    for e in events[:MAX_ROWS_IN_RESULT]:
        parent = f"{e.parent_name} -> " if e.parent_name else ""
        detail = e.command_line or e.message
        target = f" [{e.remote_ip}]" if e.remote_ip else ""
        lines.append(
            f"- {e.timestamp:%Y-%m-%d %H:%M} {e.event_type}: "
            f"{parent}{e.process_name or ''}{target} {detail[:120]}"
        )
    if len(events) > MAX_ROWS_IN_RESULT:
        lines.append(f"({len(events) - MAX_ROWS_IN_RESULT} more not shown)")
    return "\n".join(lines)


@tool
def get_user_auth_history(username: str, hours: int = 24) -> str:
    """Authentication attempts for one principal.

    Use to check whether failures are a burst or a trickle, and whether logins
    come from unusual sources.
    """
    events = resolve_log_backend().user_auth_history(username, hours)
    if not events:
        return f"No authentication events for {username} in the last {hours}h."

    failures = [e for e in events if not e.succeeded]
    sources = sorted({e.source_ip for e in events if e.source_ip})
    countries = sorted({e.country for e in events if e.country})
    return (
        f"{len(events)} authentication events for {username} in the last {hours}h: "
        f"{len(failures)} failed, {len(events) - len(failures)} succeeded. "
        f"Source IPs: {', '.join(sources) or 'unknown'}. "
        f"Countries: {', '.join(countries) or 'unknown'}."
    )


@tool
def find_indicator(indicator: str, hours: int = 168) -> str:
    """Everywhere an IP, hash or domain was observed across the estate.

    Use to check whether an indicator touched hosts the alert did not name,
    which is how lateral movement becomes visible.
    """
    events = resolve_log_backend().find_indicator(indicator, hours)
    if not events:
        return (
            f"{indicator} was not observed anywhere in the last {hours}h. "
            "This may mean it is genuinely absent or that coverage is incomplete."
        )

    hosts = sorted({e.hostname for e in events if e.hostname})
    processes = sorted({e.process_name for e in events if e.process_name})
    return (
        f"{indicator} observed {len(events)} times on {len(hosts)} host(s) "
        f"in the last {hours}h: {', '.join(hosts)}. "
        f"Processes involved: {', '.join(processes) or 'unknown'}."
    )


@tool
def count_rule_firings(rule_name: str, days: int = 7) -> str:
    """How often a detection rule fires across the estate.

    Use to establish a base rate. A rule firing hundreds of times a week is
    usually noisy rather than evidence of a widespread compromise.
    """
    stats = resolve_log_backend().count_rule_firings(rule_name, days)
    if stats.total_firings == 0:
        return (
            f"No recorded firings of '{rule_name}' in the last {days} days. "
            "Either the rule is new or historical data is unavailable."
        )
    return (
        f"'{rule_name}' fired {stats.total_firings} times in {days} days "
        f"({stats.firings_per_day}/day) across {stats.distinct_hosts} host(s) "
        f"and {stats.distinct_users} user(s)."
    )


@tool
def get_asset_context(hostname: str) -> str:
    """What a host is: its criticality, type, environment and owner.

    Use to judge blast radius. The same activity on a lab VM and a domain
    controller warrant different urgency.
    """
    from aegis.tools.assets import lookup_asset

    asset = lookup_asset(hostname)
    if not asset.in_inventory:
        return (
            f"{hostname} is not in the asset inventory. Its criticality and owner "
            "are unknown, which is a gap in inventory rather than evidence the "
            "host is unimportant."
        )
    tags = f" Tags: {', '.join(asset.tags)}." if asset.tags else ""
    return (
        f"{hostname} is a {asset.criticality.value} {asset.asset_type} in "
        f"{asset.environment}, owned by {asset.owner or 'unknown'} "
        f"({asset.business_unit or 'unknown business unit'}).{tags}"
    )


@tool
def list_known_assets(minimum_criticality: str = "") -> str:
    """The hosts in the asset inventory, most critical first.

    Use when you need to know what exists rather than guessing hostnames.
    Pass a level such as "high" to narrow the list.
    """
    from aegis.tools.assets import Criticality, list_assets

    level = None
    if minimum_criticality:
        try:
            level = Criticality(minimum_criticality.strip().lower())
        except ValueError:
            return (f"'{minimum_criticality}' is not a criticality level. "
                    f"Use one of: {', '.join(c.value for c in Criticality)}.")

    assets = list_assets(level)
    if not assets:
        return "No assets in inventory match that criticality."
    lines = [f"{len(assets)} asset(s) in inventory:"]
    lines += [f"- {a.hostname}: {a.criticality.value} {a.asset_type} "
              f"({a.environment})" for a in assets]
    return "\n".join(lines)


@tool
def list_active_rules(days: int = 7) -> str:
    """Detection rules that fired recently, noisiest first.

    Use to find which rules exist rather than guessing their names.
    """
    from aegis.tools.logsearch import resolve_log_backend

    stats = resolve_log_backend().list_active_rules(days)
    if not stats:
        return f"No detection rules recorded any firings in the last {days} days."
    lines = [f"{len(stats)} rule(s) fired in the last {days} days:"]
    lines += [f"- {r.rule_name}: {r.total_firings} firings "
              f"({r.firings_per_day}/day) across {r.distinct_hosts} host(s)"
              for r in stats]
    return "\n".join(lines)


INVESTIGATION_TOOLS = [
    get_host_timeline,
    get_user_auth_history,
    find_indicator,
    count_rule_firings,
    get_asset_context,
    list_known_assets,
    list_active_rules,
]


def all_investigation_tools() -> list[Any]:
    """Built-in tools plus any read-only tools loaded over MCP.

    The built-ins come first so they are preferred, and MCP failures degrade to
    the built-in set rather than to no investigation.
    """
    from aegis.tools.mcp_tools import load_mcp_tools

    return [*INVESTIGATION_TOOLS, *load_mcp_tools()]
