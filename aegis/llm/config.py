"""Validated runtime configuration.

Loaded and validated ONCE at import time so a missing credential fails at
startup with a clear message, never mid-investigation.
"""

from __future__ import annotations

from enum import Enum

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class ModelRole(str, Enum):
    """Which tier of intelligence a node is asking for.

    Nodes request a ROLE, never a model name. That indirection is what lets us
    re-tune cost/quality globally without touching a single node.
    """

    WORKER = "worker"      # high-volume, low-reasoning: 3x per alert
    REASONER = "reasoner"  # single high-stakes synthesis call per alert


class ToolProvider(str, Enum):
    """Which implementation backs a security tool. Lets prod and dev differ
    by env var alone, and keeps tests hermetic."""

    MOCK = "mock"
    LIVE = "live"
    # Free, keyless public feeds (SANS ISC + Shodan InternetDB). Real data,
    # no account, useful for genuine end-to-end testing before you buy a
    # commercial feed.
    PUBLIC = "public"


class Provider(str, Enum):
    OLLAMA = "ollama"
    OPENROUTER = "openrouter"
    ANTHROPIC = "anthropic"


class LLMSettings(BaseSettings):
    """Environment-driven model + credential configuration."""

    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8", extra="ignore"
    )

    # --- Worker tier: cheap, local by default, runs 3x per alert ---
    worker_provider: Provider = Provider.OLLAMA
    worker_model: str = Field(default="llama3.1:8b")
    ollama_base_url: str = Field(default="http://localhost:11434")

    # --- Reasoner tier: expensive, runs exactly once per alert ---
    reasoner_provider: Provider = Provider.ANTHROPIC
    reasoner_model: str = Field(default="claude-sonnet-5")

    # --- Credentials (only required if the matching provider is selected) ---
    anthropic_api_key: str | None = None
    openrouter_api_key: str | None = None
    openrouter_base_url: str = "https://openrouter.ai/api/v1"

    # Determinism matters in a SOC: the same alert should triage the same way.
    temperature: float = Field(default=0.0, ge=0.0, le=2.0)
    request_timeout: int = Field(default=60, gt=0)

    # --- Data governance: controls what leaves the machine ---
    # Worker tier is local, so raw logs never leave. The REASONER is remote,
    # so this is the single switch a compliance team cares about.
    send_raw_log_to_reasoner: bool = Field(
        default=True, description="Include (redacted, truncated) raw_log in the synthesis prompt"
    )
    max_raw_log_chars: int = Field(default=2000, gt=0)

    # --- Security tool backends ---
    threat_intel_provider: ToolProvider = ToolProvider.MOCK
    endpoint_provider: ToolProvider = ToolProvider.MOCK
    virustotal_api_key: str | None = None

    # CrowdStrike Falcon. The base URL is region specific; the wrong region
    # fails authentication in a way that looks like bad credentials.
    crowdstrike_base_url: str = "https://api.crowdstrike.com"
    crowdstrike_client_id: str | None = None
    crowdstrike_client_secret: str | None = None
    # IOC reputation is near-static hour to hour and the same indicators recur
    # constantly, so caching is the single biggest cost/latency win available.
    ioc_cache_ttl_seconds: int = Field(default=3600, ge=0)
    tool_max_retries: int = Field(default=2, ge=0)
    tool_timeout_seconds: float = Field(default=10.0, gt=0)

    # --- Safety controls (Phase 6 rollout) ---
    # Single env var that forces EVERY alert to a human. Flip this during an
    # incident or a suspected model regression; it needs no deploy.
    kill_switch: bool = Field(
        default=False, description="Force all alerts to human_review"
    )
    # Shadow mode: the graph runs and LOGS what it would have closed, but closes
    # nothing. This is how you earn the right to auto-close on real traffic.
    shadow_mode: bool = Field(
        default=True, description="Never auto-close; log the counterfactual instead"
    )
    # Auto-close permitted only at or below this severity while ramping up.
    max_auto_close_severity: str = Field(default="critical")

    # --- Persistence ---
    postgres_url: str | None = Field(
        default=None, description="If set, interrupts survive process restarts"
    )

    # --- Ingestion ---
    webhook_hmac_secret: str | None = None

    # --- Slack (analyst approval surface) ---
    slack_bot_token: str | None = None       # xoxb-...
    slack_app_token: str | None = None       # xapp-... (Socket Mode)
    slack_signing_secret: str | None = None  # HTTP interactivity only
    slack_channel: str = "#soc-alerts"
    # Auto-closed alerts are posted too: silent automation cannot be validated,
    # and analyst reactions are the labelled data you need to tune the gate.
    slack_notify_auto_close: bool = True

    # --- Splunk (SIEM source) ---
    splunk_url: str = "https://localhost:8089"
    splunk_token: str | None = None
    # Local Splunk ships a self-signed cert. Keep verification ON in production.
    splunk_verify_ssl: bool = False

    @model_validator(mode="after")
    def _require_key_for_selected_provider(self) -> LLMSettings:
        """Fail fast: only demand the credentials we will actually use."""
        selected = {self.worker_provider, self.reasoner_provider}
        if Provider.ANTHROPIC in selected and not self.anthropic_api_key:
            raise ValueError("ANTHROPIC_API_KEY required when provider=anthropic")
        if Provider.OPENROUTER in selected and not self.openrouter_api_key:
            raise ValueError("OPENROUTER_API_KEY required when provider=openrouter")
        return self


def get_settings() -> LLMSettings:
    """Single entry point so tests can monkeypatch one function."""
    return LLMSettings()
