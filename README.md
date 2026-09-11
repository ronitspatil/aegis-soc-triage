# Aegis

A SOC alert triage agent built with LangGraph. It enriches a SIEM alert from
several sources in parallel, reasons over the evidence with an LLM, and either
closes the alert or drafts an incident ticket for a human to approve. Escalated
alerts can be investigated further by a tool-calling agent that searches
historical logs.

```
SIEM webhook / Splunk poller
        |
     dedupe                       repeats reuse the first verdict
        |
  orchestrator
        |
   +----+----+----------+
   |         |          |
threat    identity   endpoint     parallel, local model
 intel        |          |
   +----+----+----------+
        |
   synthesizer                    one paid call, tiered by difficulty
        |
  route_on_verdict                pure function, no LLM
     /        \
auto-close   investigator <-> tools    bounded loop, read-only
                  |
               planner                 proposes containment
                  |
            human review               interrupt -> Slack approval
                  |
               executor                the only write calls
```

Worker calls run on a local Ollama model. Synthesis costs roughly $0.011 per
alert; an investigation adds about $0.04 and runs only on escalated alerts.

## Setup

```bash
python3 -m venv .venv
.venv/bin/pip install -e ".[server,dev]"
cp .env.example .env
ollama pull llama3.1:8b
```

Add a reasoner key to `.env`: either `OPENROUTER_API_KEY` with
`REASONER_PROVIDER=openrouter`, or `ANTHROPIC_API_KEY` with
`REASONER_PROVIDER=anthropic`.

## Usage

```bash
aegis-triage --ip 185.220.101.5 --user j.doe@corp.com --host WIN-FINANCE-07 --severity high
aegis-simulate                                  # labelled scenarios, accuracy, cost
python -m aegis.simulation.eval_investigation   # investigation agent evaluation
aegis-hunt --list                               # scheduled threat hunting
aegis-slack                                     # Slack approval listener
uvicorn aegis.ingest.api:app --port 8000        # ingestion API and Splunk poller
```

### API

| Method | Path | |
|---|---|---|
| POST | `/webhook/alert` | SIEM push, HMAC signed, idempotent |
| GET | `/alerts/{id}` | triage status |
| GET | `/approvals` | alerts waiting on a human |
| POST | `/alerts/{id}/decision` | approve or reject, resumes the graph |
| GET | `/metrics` | Prometheus exposition |
| GET | `/healthz` | queue depth, switch state, ingestion and database health |

## Integrations

Each backend returns the same Pydantic type as its mock, so nodes are unchanged
when you switch.

| Source | Setting |
|---|---|
| Mock fixtures | default, no credentials |
| SANS ISC + Shodan | `THREAT_INTEL_PROVIDER=public`, no API key |
| VirusTotal | `THREAT_INTEL_PROVIDER=live` + `VIRUSTOTAL_API_KEY` |
| CrowdStrike Falcon | `ENDPOINT_PROVIDER=live` + API client (Hosts, Alerts read) |
| Splunk | `SPLUNK_URL` + `SPLUNK_TOKEN` |
| Slack | `SLACK_BOT_TOKEN` + `SLACK_APP_TOKEN` |
| AWS, over MCP | `MCP_ENABLED=true` + `AWS_PROFILE`, read-only tools only |
| Postgres | `POSTGRES_URL`, durable checkpoints, alert registry and dedupe index |
| Asset inventory | `ASSET_INVENTORY=file` + a YAML or CSV you maintain |

Splunk cannot sign webhook requests, so alerts are ingested by polling a
detection search: set `SPLUNK_POLLING_ENABLED=true` and `SPLUNK_POLL_SEARCH`.
`/healthz` reports degraded when that search stops matching anything. The
webhook route remains for sources that can sign.

For Slack, create the app from `slack_app_manifest.yml`, add an app-level token
with `connections:write`, invite the bot to your channel, and run
`aegis-slack --check`.

## Configuration

| Variable | Default | |
|---|---|---|
| `SHADOW_MODE` | `true` | Run the pipeline but never close anything |
| `KILL_SWITCH` | `false` | Force every alert to a human |
| `MAX_AUTO_CLOSE_SEVERITY` | `critical` | Ceiling for automatic closure |
| `AUTO_CLOSE_CONFIDENCE` | `0.95` | Threshold, set in `aegis/graph.py` |
| `MODEL_TIERING` | `true` | Send structurally easy alerts to a cheaper model |
| `DEDUPE_ENABLED` | `true` | Skip triage for a situation already triaged |
| `DEDUPE_WINDOW_SECONDS` | `900` | How long a fingerprint suppresses repeats |
| `INVESTIGATOR_ENABLED` | `false` | Tool-calling investigation on escalated alerts |
| `INVESTIGATION_MAX_TOOL_CALLS` | `10` | Step budget, enforced in code |
| `LOG_BACKEND` | `mock` | `mock` or `splunk`, for the agent's tools |
| `HUNTER_ENABLED` | `false` | Scheduled hunting, independent of alerts |
| `ASSET_INVENTORY` | `mock` | `mock` or `file`; see `assets.example.yaml` |
| `MAX_TRIAGE_ATTEMPTS` | `3` | Requeue on transient faults before failing |
| `RESPONSE_PLANNER_ENABLED` | `false` | Draft containment actions for approval |
| `RESPONSE_ACTIONS_ENABLED` | `false` | Let the executor run approved actions |
| `ACTION_DRY_RUN` | `true` | Log containment instead of performing it |
| `MCP_ENABLED` | `false` | Load external investigation tools over MCP |
| `SPLUNK_POLLING_ENABLED` | `false` | Poll Splunk for new alerts |

Auto-close requires all of: a false positive verdict, confidence above the
threshold, no failed enrichments, severity at or below the ceiling, no
privileged identity, no crown-jewel asset, and shadow mode off. Containment
additionally requires an approving human decision, and only targets entities
named by the alert.

## Mock fixtures

Useful inputs for the CLI: `185.220.101.5` (Tor exit), `8.8.8.8` (clean),
`j.doe@corp.com` (disabled privileged account), `svc-backup@corp.com` (service
account), `WIN-FINANCE-07` (encoded PowerShell from Office), `MACBOOK-RPATIL`
(clean). The identifiers ending in `-OUTAGE` or `203.0.113.66` force an
integration failure. Full set in `aegis/tools/`.

## Development

```bash
pytest                      # 247 tests, no network, no credentials
ruff check aegis tests

# Postgres integration tests, skipped without a database
AEGIS_TEST_POSTGRES_URL=postgresql://localhost/aegis_test pytest tests/test_store_pg.py
```

The suite blanks any credentials in `.env`, so it cannot reach live services or
a real database.

## License

MIT
