"""CLI report: `python -m aegis.simulation`"""

from __future__ import annotations

from aegis.cli_support import with_friendly_config_errors
from aegis.graph import AUTO_CLOSE_CONFIDENCE
from aegis.simulation.runner import Result, run_all, shadow_analysis

THRESHOLDS = [0.80, 0.85, 0.90, 0.95, 0.99]


def _print_table(results: list[Result]) -> None:
    print(f"\n{'ALERT':9} {'EXPECTED':13} {'ACTUAL':13} {'VERDICT':15} {'CONF':>5} {'MODEL':>7}  OK")
    print("-" * 78)
    for r in results:
        mark = "PASS" if r.correct else "FAIL"
        if r.is_critical_miss:
            mark = "MISS!"
        model = "haiku" if any("haiku" in m for m in r.models) else "sonnet"
        print(
            f"{r.scenario.alert.alert_id:9} {r.scenario.expected_route:13} "
            f"{r.actual_route:13} {r.verdict.value:15} {r.confidence:>5.2f} "
            f"{model:>7}  {mark}"
        )


@with_friendly_config_errors
def main() -> None:
    results = run_all()
    _print_table(results)

    correct = sum(r.correct for r in results)
    misses = [r for r in results if r.is_critical_miss]
    total_cost = sum(r.cost_usd for r in results)

    print(f"\nRouting accuracy : {correct}/{len(results)} at threshold {AUTO_CLOSE_CONFIDENCE}")
    print(f"Critical misses  : {len(misses)}  (real attacks auto-closed)")
    print(f"Cost             : ${total_cost:.4f} total, ${total_cost/len(results):.4f}/alert")
    print(f"Projected        : ${total_cost/len(results)*500:.2f}/day at 500 alerts/day")

    print("\nSHADOW MODE, what each threshold would have done (no LLM re-run):")
    print(f"\n{'THRESH':>7} {'AUTO-CLOSED':>12} {'RATE':>7} {'ATTACKS MISSED':>15}")
    print("-" * 46)
    for t, row in shadow_analysis(results, THRESHOLDS).items():
        flag = "  <-- UNSAFE" if row["attacks_missed"] else ""
        print(
            f"{t:>7.2f} {row['auto_closed']:>12} {row['auto_close_rate']:>6.0%} "
            f"{row['attacks_missed']:>15}{flag}"
        )

    for r in results:
        if not r.correct:
            print(f"\nMISCLASSIFIED {r.scenario.alert.alert_id}")
            print(f"  expected: {r.scenario.expected_route}, {r.scenario.rationale}")
            print(f"  model said: {r.reasoning[:300]}")


if __name__ == "__main__":
    main()
