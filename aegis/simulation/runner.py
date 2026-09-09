"""End-to-end simulation harness.

Runs the labelled corpus through the real graph, meters cost, and replays the
finished states through the gate at alternative thresholds (shadow mode).
Shadow mode is only possible because `gate_decision` is a PURE function of
state, no re-running of the LLM required.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from langchain_core.callbacks import BaseCallbackHandler
from langgraph.types import Command

from aegis.graph import build_graph, gate_decision
from aegis.llm.config import get_settings
from aegis.schemas.state import Verdict, verdict_of
from aegis.simulation.scenarios import SCENARIOS, Scenario

# OpenRouter list price for anthropic/claude-sonnet-5, USD per token.
REASONER_INPUT_COST = 2.0 / 1_000_000
REASONER_OUTPUT_COST = 10.0 / 1_000_000


class TokenMeter(BaseCallbackHandler):
    """Captures per-model token usage across every LLM call in a graph run."""

    def __init__(self) -> None:
        self.usage: dict[str, dict[str, int]] = {}

    def on_llm_end(self, response: Any, **kwargs: Any) -> None:
        try:
            gen = response.generations[0][0]
            msg = getattr(gen, "message", None)
            meta = getattr(msg, "usage_metadata", None) or {}
            model = (
                (response.llm_output or {}).get("model_name")
                or getattr(msg, "response_metadata", {}).get("model_name")
                or "unknown"
            )
        except Exception:  # noqa: BLE001 - metering must never break a run
            return
        bucket = self.usage.setdefault(model, {"input": 0, "output": 0})
        bucket["input"] += int(meta.get("input_tokens", 0) or 0)
        bucket["output"] += int(meta.get("output_tokens", 0) or 0)

    def cost_usd(self, reasoner_model: str) -> float:
        """Only the remote reasoner is billed; local workers are free."""
        total = 0.0
        for model, u in self.usage.items():
            if reasoner_model.split("/")[-1] in model:
                total += u["input"] * REASONER_INPUT_COST
                total += u["output"] * REASONER_OUTPUT_COST
        return total


@dataclass
class Result:
    scenario: Scenario
    actual_route: str
    verdict: Verdict
    confidence: float
    reasoning: str
    cost_usd: float
    final_state: dict[str, Any] = field(repr=False, default_factory=dict)

    @property
    def correct(self) -> bool:
        return self.actual_route == self.scenario.expected_route

    @property
    def is_critical_miss(self) -> bool:
        """Auto-closed a real attack. The failure mode that matters most."""
        return self.scenario.is_real_attack and self.actual_route == "auto_close"


def run_scenario(app: Any, scenario: Scenario) -> Result:
    """Execute one alert end to end, auto-approving any human interrupt."""
    meter = TokenMeter()
    cfg = {
        "configurable": {"thread_id": f"sim-{scenario.alert.alert_id}"},
        "callbacks": [meter],
    }

    out = app.invoke({"alert": scenario.alert}, cfg)

    if "__interrupt__" in out:
        route = "human_review"
        out = app.invoke(Command(resume="SIMULATED ANALYST: approved"), cfg)
    else:
        route = "auto_close"

    return Result(
        scenario=scenario,
        actual_route=route,
        verdict=verdict_of(out),
        confidence=out.get("confidence", 0.0),
        reasoning=out.get("reasoning", ""),
        cost_usd=meter.cost_usd(get_settings().reasoner_model),
        final_state=dict(out),
    )


def shadow_analysis(results: list[Result], thresholds: list[float]) -> dict[float, dict]:
    """Replay finished states through the gate at other thresholds.

    This is how you pick a threshold from DATA rather than intuition, and it
    costs nothing, because no model is re-invoked.
    """
    report: dict[float, dict] = {}
    for t in thresholds:
        closed, missed = 0, 0
        for r in results:
            if gate_decision(r.final_state, threshold=t) == "auto_close":
                closed += 1
                if r.scenario.is_real_attack:
                    missed += 1
        report[t] = {
            "auto_closed": closed,
            "auto_close_rate": closed / len(results) if results else 0.0,
            "attacks_missed": missed,
        }
    return report


def run_all() -> list[Result]:
    app = build_graph()
    return [run_scenario(app, s) for s in SCENARIOS]
