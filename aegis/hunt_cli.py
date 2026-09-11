"""CLI for the threat hunter: `python -m aegis.hunt_cli`"""

from __future__ import annotations

import argparse

from aegis.cli_support import with_friendly_config_errors
from aegis.hunter import STANDARD_HYPOTHESES, file_findings, hunt
from aegis.observability import setup_logging


@with_friendly_config_errors
def main() -> None:
    p = argparse.ArgumentParser(description="Run a threat hunt.")
    p.add_argument("--hypothesis", help="Free-text hypothesis to test")
    p.add_argument("--name", choices=sorted(STANDARD_HYPOTHESES),
                   help="Run one of the standard hypotheses")
    p.add_argument("--all", action="store_true", help="Run every standard hypothesis")
    p.add_argument("--list", action="store_true", help="Show the standard hypotheses")
    p.add_argument("--file", action="store_true",
                   help="File findings as alerts for triage")
    args = p.parse_args()

    if args.list:
        for name, text in sorted(STANDARD_HYPOTHESES.items()):
            print(f"{name}\n  {text}\n")
        return

    setup_logging(json_output=False)

    if args.all:
        hypotheses = list(STANDARD_HYPOTHESES.values())
    elif args.name:
        hypotheses = [STANDARD_HYPOTHESES[args.name]]
    elif args.hypothesis:
        hypotheses = [args.hypothesis]
    else:
        p.error("one of --hypothesis, --name, --all or --list is required")

    for hypothesis in hypotheses:
        print(f"\n{'=' * 72}\n{hypothesis[:70]}\n{'=' * 72}")
        result = hunt(hypothesis)
        print(f"  queries: {result.queries_run}"
              f"{'  (budget exhausted)' if result.budget_exhausted else ''}")
        print(f"  summary: {result.summary}")
        if not result.findings:
            print("  findings: none. Most hunts find nothing.")
            continue
        for f in result.findings:
            entity = f.hostname or f.username or f.indicator or "-"
            print(f"  - [{f.severity.value}] {f.title}  ({entity})")
            print(f"      {f.rationale[:140]}")
        if args.file:
            filed = file_findings(result)
            print(f"  filed {len(filed)} alert(s) for triage: "
                  f"{[a.alert_id for a in filed]}")


if __name__ == "__main__":
    main()
