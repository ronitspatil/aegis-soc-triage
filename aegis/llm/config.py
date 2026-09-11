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
    REASONER = "reasoner"  # high-stakes synthesis on hard alerts
    FAST_REASONER = "fast_reasoner"  # structurally easy alerts, cheaper model


class ToolProvider(str, Enum):
    """Which implementation backs a security tool. Lets prod and dev differ
    by env var alone, and keeps tests hermetic."""

    MOCK = "mock"
    LIVE = "live"
    # Free, keyless public feeds (SANS ISC + Shodan InternetDB). Real data,
    # no account, useful for genuine end-to-end testing before you buy a
    # commercial feed.
    PUBLIC = "public"


class AssetInventoryBackend(str, Enum):
    """Where asset criticality comes from."""

    MOCK = "mock"
    FILE = "file"


class LogBackend(str, Enum):
    """Which SIEM the investigation agent searches. The core pipeline does not
    depend on any of these; only the agent's tools do."""

    MOCK = "mock"
    SPLUNK = "splunk"


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
    # Structurally easy alerts (no conflict, no gaps, nothing suspicious) go to
    # a cheaper model. Tiering is keyed on deterministic signals rather than the
    # model's own confidence, which is less well calibrated on small models.
    fast_reasoner_model: str = Field(default="claude-haiku-4-5-20251001")
    model_tiering: bool = Field(default=True)
    # Output is 5x the price of input per token and was the bulk of the cost.
    # Do not tighten this much further: with structured output a truncated
    # response is a parse failure, not a shorter answer, and models that emit
    # internal reasoning tokens spend part of this budget before the JSON.
    reasoner_max_tokens: int = Field(default=1500, gt=0)

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
    identity_provider: ToolProvider = ToolProvider.MOCK
    virustotal_api_key: str | None = None

    # Keycloak. Admin credentials suit a local realm; a deployment should use a
    # service account client with the realm-management view roles.
    keycloak_url: str | None = None
    keycloak_realm: str = "aegis"
    keycloak_admin_user: str | None = None
    keycloak_admin_password: str | None = None

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
    # Bounded so an unreachable database is reported rather than retried
    # indefinitely at startup.
    postgres_connect_timeout: float = Field(default=5.0, gt=0)
    postgres_url: str | None = Field(
        default=None, description="If set, interrupts survive process restarts"
    )

    # --- Ingestion ---
    webhook_hmac_secret: str | None = None

    # Deduplication. The window must be bounded: the same rule firing tomorrow
    # is a new situation, not a repeat of today's.
    # A transient database or network fault must not lose an alert. Bounded so
    # a genuinely broken alert cannot loop forever.
    max_triage_attempts: int = Field(default=3, gt=0)
    dedupe_enabled: bool = True
    dedupe_window_seconds: int = Field(default=900, gt=0)
    # An alert storm would otherwise edit the Slack message once per duplicate
    # and hit the chat.update rate limit.
    slack_occurrence_update_seconds: int = Field(default=30, ge=0)

    # --- Slack (analyst approval surface) ---
    slack_bot_token: str | None = None       # xoxb-...
    slack_app_token: str | None = None       # xapp-... (Socket Mode)
    slack_signing_secret: str | None = None  # HTTP interactivity only
    slack_channel: str = "#soc-alerts"
    # Auto-closed alerts are posted too: silent automation cannot be validated,
    # and analyst reactions are the labelled data you need to tune the gate.
    slack_notify_auto_close: bool = True

    # --- Investigation agent ---
    # Off by default. Turned on deliberately, like shadow mode.
    investigator_enabled: bool = False
    # Budgets are enforced in the node, never asked of the model.
    investigation_max_tool_calls: int = Field(default=10, gt=0)
    investigation_timeout_seconds: float = Field(default=120.0, gt=0)
    # The report summarises a long tool conversation, so the model spends far
    # more on internal reasoning than synthesis does. Measured truncation at
    # 1500 with 1263 reasoning tokens, which surfaces as a parse failure rather
    # than a shorter report.
    investigation_report_max_tokens: int = Field(default=4000, gt=0)

    # --- External tools over MCP (investigation only) ---
    # A server's tool descriptions enter the prompt, so adding one is a
    # supply-chain decision. Off by default.
    mcp_enabled: bool = False
    mcp_config_path: str | None = None
    mcp_aws_enabled: bool = True
    # Pinned: an unpinned server ships new tool descriptions into your prompt.
    mcp_aws_version: str = "latest"
    aws_region: str = "us-east-1"
    aws_profile: str | None = None

    # --- Response actions ---
    response_planner_enabled: bool = False
    # Executing anything is a separate, later opt-in from proposing it.
    response_actions_enabled: bool = False
    # Even with execution enabled, actions are logged rather than performed
    # until this is turned off. Shadow mode for containment.
    action_dry_run: bool = True

    # --- Threat hunting ---
    hunter_enabled: bool = False
    hunt_max_tool_calls: int = Field(default=12, gt=0)
    # A hunt that floods the queue is worse than one that finds nothing.
    hunt_max_findings: int = Field(default=5, gt=0)

    # --- Asset inventory ---
    asset_inventory: AssetInventoryBackend = AssetInventoryBackend.MOCK
    asset_inventory_path: str = "assets.yaml"

    # --- Historical log search (investigation agent) ---
    log_backend: LogBackend = LogBackend.MOCK
    # Splunk only searches a role's default indexes unless told otherwise, so a
    # custom index returns nothing without this. Narrow it in production: an
    # unscoped search across every index is slow and expensive.
    splunk_search_index: str = "*"

    # --- Splunk polling ---
    # Splunk's native webhook alert action cannot set custom headers, so it
    # cannot sign requests for /webhook/alert. Polling a detection search is
    # the practical ingestion route for a Splunk source.
    # Run the poller inside the API process. Separate processes would hold
    # separate in-memory queues and registries, so /metrics and /approvals
    # would report on a process that never triaged anything.
    splunk_polling_enabled: bool = False
    splunk_poll_search: str = "index=aegis_demo sourcetype=aegis:detection"
    splunk_poll_interval_seconds: int = Field(default=60, gt=0)
    # Each poll looks back further than the interval, so an alert indexed late
    # is not missed. Duplicates are absorbed by the registry's idempotency.
    splunk_poll_overlap_seconds: int = Field(default=120, ge=0)
    # A search that matches nothing looks identical to a quiet night. After
    # this many consecutive empty polls the poller says so, because the usual
    # cause is a filter on a field the deployment does not extract.
    splunk_empty_poll_warning: int = Field(default=10, gt=0)

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
