"""Shared fixtures. NOTE: no test in this suite makes a network or LLM call."""

from __future__ import annotations

import pytest

from aegis.schemas.alert import SIEMAlert
from aegis.schemas.state import EnrichmentData


@pytest.fixture(autouse=True)
def _production_safeties_off(monkeypatch):
    """Tests exercise the GATES, so the global overrides are disabled here.

    They default to safe-on in production: shadow_mode=True means a fresh
    deployment closes nothing until someone deliberately turns it off.
    """
    monkeypatch.setenv("SHADOW_MODE", "false")
    monkeypatch.setenv("KILL_SWITCH", "false")
    monkeypatch.setenv("MAX_AUTO_CLOSE_SEVERITY", "critical")
    # Blank any real credentials from .env: the suite must never depend on (or
    # accidentally use) the developer's live tokens. Empty string beats delenv,
    # which cannot unset a value that pydantic-settings reads from the file.
    # POSTGRES_URL included: the suite must never touch a real database.
    for var in ("SLACK_BOT_TOKEN", "SLACK_APP_TOKEN", "VIRUSTOTAL_API_KEY",
                "SPLUNK_TOKEN", "POSTGRES_URL",
                "CROWDSTRIKE_CLIENT_ID", "CROWDSTRIKE_CLIENT_SECRET"):
        monkeypatch.setenv(var, "")
    monkeypatch.setenv("THREAT_INTEL_PROVIDER", "mock")
    monkeypatch.setenv("ENDPOINT_PROVIDER", "mock")
    monkeypatch.setenv("LOG_BACKEND", "mock")
    monkeypatch.setenv("MCP_ENABLED", "false")
    monkeypatch.setenv("INVESTIGATOR_ENABLED", "false")
    monkeypatch.setenv("RESPONSE_PLANNER_ENABLED", "false")
    monkeypatch.setenv("RESPONSE_ACTIONS_ENABLED", "false")

    # LLMSettings requires a key for whichever reasoner provider is selected, so
    # a placeholder is needed for settings to construct at all. No test invokes
    # a model, so the value is never used. Without this the suite only passes on
    # a machine that happens to have a real .env, which defeats the point.
    monkeypatch.setenv("WORKER_PROVIDER", "ollama")
    monkeypatch.setenv("REASONER_PROVIDER", "openrouter")
    monkeypatch.setenv("OPENROUTER_API_KEY", "test-key-never-used")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "")

    # The registry and dedupe backends are cached, and that cache can be
    # populated during collection while .env is still in effect. Clearing it
    # around every test keeps the suite from reaching a real database.
    from aegis.ingest.store import reset_stores

    reset_stores()
    yield
    reset_stores()


@pytest.fixture
def alert() -> SIEMAlert:
    return SIEMAlert(
        alert_id="TEST-1",
        rule_name="Test Rule",
        severity="medium",
        timestamp="2026-09-08T12:00:00Z",
        source_ip="8.8.8.8",
        username="r.patil@corp.com",
        hostname="MACBOOK-RPATIL",
    )


@pytest.fixture
def clean_enrichments() -> list[EnrichmentData]:
    return [
        EnrichmentData(agent_name="threat_intel", summary="clean", risk_signal=0.0),
        EnrichmentData(
            agent_name="identity", summary="clean", risk_signal=0.0,
            findings={"is_privileged": False},
        ),
        EnrichmentData(agent_name="endpoint", summary="clean", risk_signal=0.0),
    ]
