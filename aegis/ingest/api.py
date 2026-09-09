"""FastAPI ingestion + approval surface.

    uvicorn aegis.ingest.api:app --port 8000

Endpoints:
    POST /webhook/alert          SIEM pushes here (HMAC-signed)
    GET  /alerts/{alert_id}      triage status
    GET  /approvals              alerts waiting on a human
    POST /alerts/{id}/decision   analyst approves/rejects -> resumes the graph
    GET  /healthz
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import threading
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, Header, HTTPException, Request, Response, status
from pydantic import BaseModel, ValidationError

from aegis.decisions import DecisionError, apply_decision
from aegis.graph import get_app
from aegis.ingest.store import ALERT_QUEUE, REGISTRY, AlertStatus
from aegis.ingest.worker import worker_loop
from aegis.llm.config import get_settings
from aegis.observability import METRICS, setup_logging
from aegis.schemas.alert import SIEMAlert

logger = logging.getLogger(__name__)

_stop = threading.Event()
_graph: Any = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Start the background triage worker alongside the API."""
    setup_logging()
    global _graph
    _graph = get_app()  # shared with the worker thread; see get_app() docstring
    t = threading.Thread(target=worker_loop, args=(_stop,), daemon=True)
    t.start()
    yield
    _stop.set()
    t.join(timeout=5)


app = FastAPI(title="Aegis SOC Triage", lifespan=lifespan)


def verify_signature(
    request_body: bytes, signature: str | None
) -> None:
    """Reject unsigned or mis-signed webhooks.

    Without this, anyone who can reach the endpoint can inject alerts, and
    injected alerts are attacker-controlled input to an automated system that
    can close incidents. `compare_digest` avoids a timing side channel.
    """
    secret = get_settings().webhook_hmac_secret
    if not secret:
        # Fail loudly rather than silently accepting unauthenticated alerts.
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="WEBHOOK_HMAC_SECRET is not configured; refusing unauthenticated alerts",
        )
    if not signature:
        raise HTTPException(status_code=401, detail="missing X-Signature header")

    expected = hmac.new(secret.encode(), request_body, hashlib.sha256).hexdigest()
    provided = signature.removeprefix("sha256=")
    if not hmac.compare_digest(expected, provided):
        raise HTTPException(status_code=401, detail="invalid signature")


class DecisionRequest(BaseModel):
    decision: str
    analyst: str | None = None


@app.get("/healthz")
def healthz() -> dict[str, Any]:
    s = get_settings()
    return {
        "status": "ok",
        "queue_depth": ALERT_QUEUE.qsize(),
        "shadow_mode": s.shadow_mode,
        "kill_switch": s.kill_switch,
    }


@app.get("/metrics")
def metrics() -> Response:
    """Prometheus exposition. Alert on auto_close_rate moving suddenly, that is
    the canary for a prompt or model regression."""
    return Response(content=METRICS.prometheus(), media_type="text/plain")


@app.post("/webhook/alert", status_code=status.HTTP_202_ACCEPTED)
async def receive_alert(
    request: Request, x_signature: str | None = Header(default=None)
) -> dict[str, Any]:
    """Validate, enqueue, return immediately.

    Triage takes ~15s; a SIEM will time out long before that. We do the cheap
    work synchronously (auth + schema validation) and hand the rest to a worker.
    """
    body = await request.body()
    verify_signature(body, x_signature)

    try:
        alert = SIEMAlert(**json.loads(body))
    except (ValidationError, json.JSONDecodeError) as exc:
        # The trust boundary: malformed payloads are rejected here, not deeper in.
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    record, created = REGISTRY.create_if_absent(alert.alert_id)
    if not created:
        # SIEMs retry. Re-triaging costs an LLM call and files a second ticket.
        return {"alert_id": alert.alert_id, "status": record.status.value, "duplicate": True}

    ALERT_QUEUE.put(alert)
    return {"alert_id": alert.alert_id, "status": AlertStatus.QUEUED.value, "duplicate": False}


@app.get("/alerts/{alert_id}")
def get_alert(alert_id: str) -> dict[str, Any]:
    rec = REGISTRY.get(alert_id)
    if rec is None:
        raise HTTPException(status_code=404, detail="unknown alert_id")
    return {
        "alert_id": rec.alert_id,
        "status": rec.status.value,
        "verdict": rec.verdict,
        "confidence": rec.confidence,
        "decision": rec.decision,
        "error": rec.error,
        "received_at": rec.received_at.isoformat(),
    }


@app.get("/approvals")
def list_approvals() -> list[dict[str, Any]]:
    """The analyst work queue: everything the agent refused to close alone."""
    return [
        {
            "alert_id": r.alert_id,
            "verdict": r.verdict,
            "confidence": r.confidence,
            "title": (r.ticket or {}).get("title"),
            "recommended_actions": (r.ticket or {}).get("recommended_actions", []),
        }
        for r in REGISTRY.awaiting_approval()
    ]


@app.post("/alerts/{alert_id}/decision")
def submit_decision(alert_id: str, body: DecisionRequest) -> dict[str, Any]:
    """Resume a suspended graph with the analyst's decision.

    The graph has been parked in the checkpointer, possibly for hours, across
    process restarts if POSTGRES_URL is set. `thread_id` is what reconnects us.
    """
    rec = REGISTRY.get(alert_id)
    if rec is None:
        raise HTTPException(status_code=404, detail="unknown alert_id")
    if rec.status is not AlertStatus.AWAITING_APPROVAL:
        raise HTTPException(
            status_code=409, detail=f"alert is {rec.status.value}, not awaiting approval"
        )

    try:
        apply_decision(alert_id, body.decision, actor=body.analyst, source="api")
    except DecisionError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc

    rec = REGISTRY.get(alert_id)
    return {"alert_id": alert_id, "status": AlertStatus.RESOLVED.value,
            "decision": rec.decision if rec else None}
