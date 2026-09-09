"""Interactive single-alert triage CLI.

    python -m aegis.triage --ip 185.220.101.5 --user j.doe@corp.com --host WIN-FINANCE-07
    python -m aegis.triage --json alert.json
    python -m aegis.triage --json -            # read a SIEM payload from stdin

Stops at the human-in-the-loop interrupt and asks YOU to approve or reject.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys
from datetime import UTC, datetime
from typing import Any

from langgraph.types import Command
from pydantic import ValidationError

from aegis.graph import build_graph
from aegis.schemas.alert import SIEMAlert


def _build_alert(args: argparse.Namespace) -> SIEMAlert:
    """Construct the alert from --json or from individual flags."""
    if args.json:
        raw = sys.stdin.read() if args.json == "-" else pathlib.Path(args.json).read_text()
        return SIEMAlert(**json.loads(raw))

    return SIEMAlert(
        alert_id=args.alert_id,
        rule_name=args.rule,
        severity=args.severity,
        timestamp=args.timestamp or datetime.now(UTC).isoformat(),
        source_ip=args.ip,
        username=args.user,
        hostname=args.host,
        file_hash=args.hash,
        raw_log=args.raw_log or "",
    )


def _print_ticket(ticket: dict[str, Any]) -> None:
    print("\n" + "=" * 70)
    print("  DRAFT INCIDENT TICKET, analyst approval required")
    print("=" * 70)
    print(f"  {ticket['title']}")
    print(f"  verdict    : {ticket['verdict']}  (confidence {ticket['confidence']})")
    print(f"  entities   : {ticket['entities']}")
    print("\n  signals:")
    for agent, s in ticket["enrichment_signals"].items():
        status = f"  FAILED: {s['error']}" if s["error"] else ""
        print(f"    {agent:14} {s['risk']}{status}")
    print(f"\n  reasoning  : {ticket['reasoning']}")
    if ticket["recommended_actions"]:
        print("\n  recommended actions:")
        for a in ticket["recommended_actions"]:
            print(f"    - {a}")
    print("=" * 70)


def main() -> None:
    p = argparse.ArgumentParser(description="Triage a single SIEM alert.")
    p.add_argument("--json", help="Path to a JSON alert payload, or '-' for stdin")
    p.add_argument("--alert-id", default="MANUAL-001")
    p.add_argument("--rule", default="Manual Test Alert")
    p.add_argument(
        "--severity", default="medium",
        choices=["info", "low", "medium", "high", "critical"],
    )
    p.add_argument("--timestamp", help="ISO-8601; defaults to now (UTC)")
    p.add_argument("--ip", help="source IP")
    p.add_argument("--user", help="username / UPN")
    p.add_argument("--host", help="hostname")
    p.add_argument("--hash", help="file hash")
    p.add_argument("--raw-log", help="original log line")
    p.add_argument("--auto-approve", action="store_true", help="skip the prompt (for scripting)")
    args = p.parse_args()

    try:
        alert = _build_alert(args)
    except (ValidationError, json.JSONDecodeError) as exc:
        # The trust boundary doing its job, reject malformed input loudly.
        print(f"Invalid alert payload:\n{exc}", file=sys.stderr)
        raise SystemExit(2) from exc

    app = build_graph()
    cfg = {"configurable": {"thread_id": f"cli-{alert.alert_id}"}}

    print(f"\nTriaging {alert.alert_id} ({alert.rule_name}, {alert.severity.value})...")
    out = app.invoke({"alert": alert}, cfg)

    if "__interrupt__" not in out:
        print("\nRESULT: AUTO-CLOSED (no human review required)")
        print(f"  verdict   : {out['verdict'].value} @ {out['confidence']}")
        print(f"  reasoning : {out['reasoning']}")
    else:
        _print_ticket(out["__interrupt__"][0].value["ticket"])
        if args.auto_approve:
            decision = "APPROVED (non-interactive)"
        else:
            # The graph is SUSPENDED here. State is checkpointed; this process
            # could exit and resume hours later against the same thread_id.
            choice = input("\n  [a]pprove / [r]eject / [e]scalate? ").strip().lower()
            decision = {"a": "APPROVED", "r": "REJECTED, false positive",
                        "e": "ESCALATED to IR"}.get(choice, "APPROVED")
        out = app.invoke(Command(resume=decision), cfg)
        print(f"\nRESULT: {out['human_decision']}")

    print("\n--- AUDIT TRAIL ---")
    for entry in out["audit_log"]:
        print(f"  {entry}")


if __name__ == "__main__":
    main()
