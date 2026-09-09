"""CLI: `python -m aegis.simulation.eval_investigation`"""

from __future__ import annotations

from aegis.simulation.investigation_eval import CASES, run_case


def main() -> None:
    results = [run_case(c) for c in CASES]

    print(f"\n{'CASE':18} {'CALLS':>5} {'SECS':>6} {'COST':>8}  FOUND DECISIVE FACT")
    print("-" * 78)
    for r in results:
        print(f"{r.case.name:18} {r.tool_calls:>5} {r.seconds:>6.1f} "
              f"${r.cost_usd:>7.4f}  {'yes' if r.passed else 'NO'}")

    passed = sum(r.passed for r in results)
    total_cost = sum(r.cost_usd for r in results)
    avg_calls = sum(r.tool_calls for r in results) / len(results)
    avg_secs = sum(r.seconds for r in results) / len(results)

    print(f"\nDecisive facts found : {passed}/{len(results)}")
    print(f"Cost per investigation: ${total_cost / len(results):.4f}")
    print(f"Tool calls (avg)      : {avg_calls:.1f}")
    print(f"Added latency (avg)   : {avg_secs:.1f}s")

    print("\nPer case:")
    for r in results:
        print(f"\n  {r.case.name}  ({'PASS' if r.passed else 'MISS'})")
        print(f"    should find : {r.case.decisive_fact}")
        print(f"    why it matters: {r.case.note}")
        print(f"    summary     : {r.report.summary[:190]}")
        print(f"    scope={r.report.scope_concern} "
              f"corroborating={len(r.report.corroborating)} "
              f"contradicting={len(r.report.contradicting)} "
              f"unanswered={len(r.report.unanswered)}")


if __name__ == "__main__":
    main()
