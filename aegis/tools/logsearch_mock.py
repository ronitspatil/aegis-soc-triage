"""Deterministic log search fixtures.

Extends the corpus in `aegis/tools/` with historical context, so the
investigation agent can be exercised with no SIEM. Two fixtures exist
specifically to encode cases where history changes the verdict:

  * "Brute Force Authentication" fires ~400 times a week across 38 hosts. An
    alert that looks alarming in isolation is a known-noisy rule.
  * 185.220.101.5 was contacted by three hosts, not one. An alert that looks
    contained is lateral movement.

Neither fact is visible to the enrichment pipeline, which only sees the alert.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from aegis.tools.logsearch import AuthEvent, LogEvent, RuleStats

_NOW = datetime(2026, 9, 8, 12, 0, tzinfo=UTC)


def _t(minutes_ago: int) -> datetime:
    return _NOW - timedelta(minutes=minutes_ago)


_TIMELINES: dict[str, list[LogEvent]] = {
    "WIN-FINANCE-07": [
        LogEvent(timestamp=_t(600), hostname="WIN-FINANCE-07", event_type="process",
                 process_name="winword.exe", parent_name="explorer.exe",
                 command_line="winword.exe /n Invoice_Q3.docm",
                 message="Office document opened from email attachment"),
        LogEvent(timestamp=_t(599), hostname="WIN-FINANCE-07", event_type="process",
                 process_name="powershell.exe", parent_name="winword.exe",
                 command_line="powershell.exe -nop -w hidden -enc SQBFAFgAKABOAGUAdwAt",
                 message="Encoded PowerShell spawned by Office application"),
        LogEvent(timestamp=_t(598), hostname="WIN-FINANCE-07", event_type="network",
                 process_name="powershell.exe", remote_ip="185.220.101.5",
                 message="Outbound TLS connection to 185.220.101.5:443"),
        LogEvent(timestamp=_t(597), hostname="WIN-FINANCE-07", event_type="file",
                 process_name="powershell.exe",
                 message="Wrote C:\\Users\\Public\\svchost.exe"),
        LogEvent(timestamp=_t(596), hostname="WIN-FINANCE-07", event_type="process",
                 process_name="schtasks.exe", parent_name="powershell.exe",
                 command_line="schtasks /create /tn Updater /tr C:\\Users\\Public\\svchost.exe",
                 message="Scheduled task created for persistence"),
    ],
    "MACBOOK-RPATIL": [
        LogEvent(timestamp=_t(30), hostname="MACBOOK-RPATIL", event_type="process",
                 process_name="python3.12", parent_name="zsh",
                 command_line="python3.12 manage.py runserver",
                 message="Development server started"),
        LogEvent(timestamp=_t(29), hostname="MACBOOK-RPATIL", event_type="network",
                 process_name="python3.12", remote_ip="8.8.8.8",
                 message="DNS query to 8.8.8.8:53"),
    ],
    "SRV-BACKUP-01": [
        LogEvent(timestamp=_t(180), hostname="SRV-BACKUP-01", event_type="process",
                 process_name="veeam.backup.exe", parent_name="services.exe",
                 command_line="veeam.backup.exe --job nightly",
                 message="Scheduled backup job started"),
        LogEvent(timestamp=_t(175), hostname="SRV-BACKUP-01", event_type="network",
                 process_name="veeam.backup.exe", remote_ip="52.94.236.248",
                 message="Upload to S3 endpoint"),
    ],
}

_AUTH: dict[str, list[AuthEvent]] = {
    "j.doe@corp.com": (
        [AuthEvent(timestamp=_t(300 + i), username="j.doe@corp.com",
                   hostname="WIN-FINANCE-07", source_ip="45.155.205.233",
                   succeeded=False, country="RU")
         for i in range(37)]
    ),
    "r.patil@corp.com": [
        AuthEvent(timestamp=_t(120), username="r.patil@corp.com",
                  hostname="MACBOOK-RPATIL", source_ip="10.20.1.44",
                  succeeded=True, country="US"),
    ],
    "svc-backup@corp.com": [
        AuthEvent(timestamp=_t(180), username="svc-backup@corp.com",
                  hostname="SRV-BACKUP-01", source_ip="10.20.9.5",
                  succeeded=True, country="US"),
    ],
}

# Indicator sightings. The extra hosts on the Tor address are the point: the
# alert names one machine, the logs show three.
_INDICATORS: dict[str, list[LogEvent]] = {
    "185.220.101.5": [
        LogEvent(timestamp=_t(598), hostname="WIN-FINANCE-07", event_type="network",
                 remote_ip="185.220.101.5", process_name="powershell.exe",
                 message="Outbound TLS to 185.220.101.5:443"),
        LogEvent(timestamp=_t(540), hostname="WIN-HR-02", event_type="network",
                 remote_ip="185.220.101.5", process_name="rundll32.exe",
                 message="Outbound TLS to 185.220.101.5:443"),
        LogEvent(timestamp=_t(495), hostname="WIN-SALES-11", event_type="network",
                 remote_ip="185.220.101.5", process_name="powershell.exe",
                 message="Outbound TLS to 185.220.101.5:443"),
    ],
    "8.8.8.8": [
        LogEvent(timestamp=_t(29), hostname=h, event_type="network",
                 remote_ip="8.8.8.8", message="DNS query")
        for h in ("MACBOOK-RPATIL", "WIN-HR-02", "WIN-SALES-11", "SRV-BACKUP-01")
    ],
}

_RULE_STATS: dict[str, RuleStats] = {
    "brute force authentication": RuleStats(
        rule_name="Brute Force Authentication", days=7,
        total_firings=412, distinct_hosts=38, distinct_users=51,
    ),
    "encoded powershell from office": RuleStats(
        rule_name="Encoded PowerShell from Office", days=7,
        total_firings=3, distinct_hosts=1, distinct_users=1,
    ),
    "off-hours service account logon": RuleStats(
        rule_name="Off-hours Service Account Logon", days=7,
        total_firings=140, distinct_hosts=6, distinct_users=4,
    ),
    "outbound dns query": RuleStats(
        rule_name="Outbound DNS Query", days=7,
        total_firings=9800, distinct_hosts=210, distinct_users=180,
    ),
}


class MockLogSearch:
    """In-memory `LogSearchBackend`. No network, fully deterministic."""

    def host_timeline(self, hostname: str, hours: int = 24) -> list[LogEvent]:
        cutoff = _NOW - timedelta(hours=hours)
        return [e for e in _TIMELINES.get(hostname, []) if e.timestamp >= cutoff]

    def user_auth_history(self, username: str, hours: int = 24) -> list[AuthEvent]:
        cutoff = _NOW - timedelta(hours=hours)
        return [e for e in _AUTH.get(username, []) if e.timestamp >= cutoff]

    def find_indicator(self, indicator: str, hours: int = 168) -> list[LogEvent]:
        cutoff = _NOW - timedelta(hours=hours)
        return [e for e in _INDICATORS.get(indicator, []) if e.timestamp >= cutoff]

    def count_rule_firings(self, rule_name: str, days: int = 7) -> RuleStats:
        hit = _RULE_STATS.get(rule_name.strip().lower())
        if hit is None:
            # Unknown rule: report zero rather than inventing a base rate.
            return RuleStats(rule_name=rule_name, days=days, total_firings=0)
        return hit
