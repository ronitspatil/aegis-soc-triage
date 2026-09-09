"""Labelled alert corpus for end-to-end evaluation.

Each scenario carries GROUND TRUTH, what a senior analyst says should happen.
Without it you can only observe what the agent did, never whether it was right.
The label is the ROUTE, not the verdict: "correctly auto-closed vs correctly
escalated" is the question that actually matters operationally.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from aegis.schemas.alert import SIEMAlert

Route = Literal["auto_close", "human_review"]


@dataclass(frozen=True)
class Scenario:
    alert: SIEMAlert
    expected_route: Route
    rationale: str
    # Auto-closing a genuine attack is categorically worse than over-escalating.
    is_real_attack: bool = False


SCENARIOS: list[Scenario] = [
    Scenario(
        alert=SIEMAlert(
            alert_id="SIM-001", rule_name="Encoded PowerShell from Office",
            severity="high", timestamp="2026-09-08T02:14:00",
            source_ip="185.220.101.5", username="j.doe@corp.com",
            hostname="WIN-FINANCE-07",
            raw_log="winword.exe spawned powershell.exe -nop -w hidden -enc SQBFAFgA",
        ),
        expected_route="human_review", is_real_attack=True,
        rationale="Maldoc chain + disabled privileged account + Tor C2. Textbook intrusion.",
    ),
    Scenario(
        alert=SIEMAlert(
            alert_id="SIM-002", rule_name="Outbound DNS Query", severity="low",
            timestamp="2026-09-08T14:00:00", source_ip="8.8.8.8",
            username="r.patil@corp.com", hostname="MACBOOK-RPATIL",
            raw_log="python3.12 manage.py runserver ; DNS lookup 8.8.8.8:53",
        ),
        expected_route="auto_close",
        rationale="Every source clean, ordinary dev activity. The alert this system exists to kill.",
    ),
    Scenario(
        alert=SIEMAlert(
            alert_id="SIM-003", rule_name="Off-hours Service Account Logon",
            severity="medium", timestamp="2026-09-08T03:00:00",
            source_ip="52.94.236.248", username="svc-backup@corp.com",
            hostname="SRV-BACKUP-01",
            raw_log="veeam.backup.exe --job nightly started by services.exe",
        ),
        expected_route="human_review",
        rationale="GATE 5: benign evidence, but a privileged service account is too much blast radius.",
    ),
    Scenario(
        alert=SIEMAlert(
            alert_id="SIM-004", rule_name="Anomalous Outbound Connection",
            severity="low", timestamp="2026-09-08T09:00:00",
            source_ip="203.0.113.66", username="r.patil@corp.com",
            hostname="MACBOOK-RPATIL", raw_log="python3.12 manage.py runserver",
        ),
        expected_route="human_review",
        rationale="GATE 3: threat intel outage. Unverified indicator must not auto-close.",
    ),
    Scenario(
        alert=SIEMAlert(
            alert_id="SIM-005", rule_name="Logon From Unrecognised Principal",
            severity="medium", timestamp="2026-09-08T04:30:00",
            source_ip="8.8.8.8", username="ghost@corp.com", hostname="UNKNOWN-LAPTOP",
            raw_log="successful interactive logon for ghost@corp.com",
        ),
        expected_route="human_review", is_real_attack=True,
        rationale="Principal absent from directory on an unmanaged host, possible attacker-created identity.",
    ),
    Scenario(
        alert=SIEMAlert(
            alert_id="SIM-006", rule_name="Crown Jewel Access", severity="critical",
            timestamp="2026-09-08T11:00:00", source_ip="8.8.8.8",
            username="r.patil@corp.com", hostname="MACBOOK-RPATIL",
            raw_log="python3.12 manage.py runserver",
        ),
        expected_route="human_review",
        rationale="GATE 4: evidence is clean, but CRITICAL severity always gets human eyes.",
    ),
    Scenario(
        alert=SIEMAlert(
            alert_id="SIM-007", rule_name="Identity Provider Query", severity="medium",
            timestamp="2026-09-08T10:00:00", source_ip="8.8.8.8",
            username="idp-outage@corp.com", hostname="MACBOOK-RPATIL",
            raw_log="okta lookup issued",
        ),
        expected_route="human_review",
        rationale="GATE 3: identity provider outage. Incomplete evidence revokes auto-close.",
    ),
    Scenario(
        alert=SIEMAlert(
            alert_id="SIM-008", rule_name="Connection to Known Bad IP", severity="high",
            timestamp="2026-09-08T13:00:00", source_ip="185.220.101.5",
            username="r.patil@corp.com", hostname="MACBOOK-RPATIL",
            raw_log="python3.12 requests.get('https://185.220.101.5')",
        ),
        expected_route="human_review",
        rationale="CONFLICT: malicious IP, healthy user and host. Honest answer is ambiguity.",
    ),
]
