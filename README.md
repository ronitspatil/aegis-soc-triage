# Aegis

A SOC alert triage agent built with LangGraph. It enriches a SIEM alert from
several sources in parallel, reasons over the evidence with an LLM, and either
closes the alert or drafts an incident ticket for a human to approve.

```
SIEM webhook / Splunk
        |
  orchestrator
        |
   +----+----+----------+
   |         |          |
threat    identity   endpoint     parallel, local model
 intel        |          |
   +----+----+----------+
        |
   synthesizer                    Claude Sonnet, one call per alert
        |
  route_on_verdict                pure function, no LLM
     /        \
auto-close   human review         LangGraph interrupt -> Slack approval
```

Worker calls run on a local Ollama model. Only synthesis uses a paid model, at
roughly $0.013 per alert.

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
aegis-slack                                     # Slack approval listener
uvicorn aegis.ingest.api:app --port 8000        # ingestion API
```

### API

| Method | Path | |
|---|---|---|
| POST | `/webhook/alert` | SIEM push, HMAC signed, idempotent |
| GET | `/alerts/{id}` | triage status |
| GET | `/approvals` | alerts waiting on a human |
| POST | `/alerts/{id}/decision` | approve or reject, resumes the graph |
| GET | `/metrics` | Prometheus exposition |
| GET | `/healthz` | queue depth, switch state |

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
| Postgres | `POSTGRES_URL`, durable checkpoints, alert registry and dedupe index |

`SplunkSource().search_alerts(spl)` returns validated alerts plus any rows that
failed validation. For Slack, create the app from `slack_app_manifest.yml`, add
an app-level token with `connections:write`, invite the bot to your channel, and
run `aegis-slack --check`.

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

Auto-close requires all of: a false positive verdict, confidence above the
threshold, no failed enrichments, severity at or below the ceiling, no
privileged identity, and shadow mode off.

## Mock fixtures

Useful inputs for the CLI: `185.220.101.5` (Tor exit), `8.8.8.8` (clean),
`j.doe@corp.com` (disabled privileged account), `svc-backup@corp.com` (service
account), `WIN-FINANCE-07` (encoded PowerShell from Office), `MACBOOK-RPATIL`
(clean). The identifiers ending in `-OUTAGE` or `203.0.113.66` force an
integration failure. Full set in `aegis/tools/`.

## Development

```bash
pytest                      # 83 tests, no network, no credentials
ruff check aegis tests
```

The suite blanks any credentials in `.env`, so it cannot reach live services.

## License

MIT
