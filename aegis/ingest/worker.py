"""Background triage worker.

Pulls alerts off the queue and runs the graph. Kept OUT of the request path so
the webhook can answer in milliseconds while triage takes ~15 seconds.
"""

from __future__ import annotations

import logging
import threading
import time
from typing import Any

from aegis.dedup import DEDUPE_INDEX
from aegis.graph import get_app
from aegis.ingest.store import ALERT_QUEUE, REGISTRY, AlertStatus
from aegis.llm.config import get_settings
from aegis.notify.slack import SlackNotifier
from aegis.observability import METRICS
from aegis.schemas.alert import SIEMAlert
from aegis.schemas.state import verdict_of

logger = logging.getLogger(__name__)


def is_transient(exc: BaseException) -> bool:
    """Whether an error is worth another attempt.

    A dropped database connection fails the current call and succeeds on the
    next one, because the pool discards the dead connection. Treating that as a
    permanent failure loses the alert.
    """
    try:
        import psycopg
    except ImportError:
        return False
    if isinstance(exc, psycopg.OperationalError):
        return True
    try:
        from psycopg_pool import PoolTimeout

        return isinstance(exc, PoolTimeout)
    except ImportError:
        return False


def _handle_triage_error(alert: SIEMAlert, exc: BaseException) -> None:
    """Requeue on a transient fault, fail loudly otherwise."""
    record = REGISTRY.get(alert.alert_id)
    attempts = (record.attempts if record else 0) + 1
    limit = get_settings().max_triage_attempts

    if is_transient(exc) and attempts < limit:
        METRICS.inc("triage_retries_total")
        logger.warning("triage hit a transient fault, requeuing (attempt %d of %d): %s",
                       attempts, limit, exc,
                       extra={"alert_id": alert.alert_id})
        REGISTRY.update(alert.alert_id, status=AlertStatus.QUEUED,
                        attempts=attempts, error=str(exc))
        ALERT_QUEUE.put(alert)
        return

    # A crashed triage must be visible, never silently dropped.
    logger.exception("triage failed", extra={"alert_id": alert.alert_id})
    METRICS.inc("triage_failures_total")
    REGISTRY.update(alert.alert_id, status=AlertStatus.FAILED,
                    attempts=attempts, error=str(exc))


def _record_duplicate(alert: SIEMAlert, duplicate: Any, notifier: Any) -> None:
    """Attach a suppressed alert to the one already triaged.

    The duplicate is never dropped: the original's occurrence count rises so an
    ongoing attack still reads as ongoing rather than as a single event.
    """
    original_id = duplicate.alert_id
    METRICS.inc("alerts_deduplicated_total", rule=alert.rule_name)
    REGISTRY.update(alert.alert_id, status=AlertStatus.DUPLICATE,
                    duplicate_of=original_id)
    REGISTRY.update(original_id, occurrences=duplicate.occurrences)
    logger.info("suppressed duplicate", extra={"alert_id": alert.alert_id,
                                               "duplicate_of": original_id})

    original = REGISTRY.get(original_id)
    # Only a ticket still awaiting a decision is worth updating; a resolved one
    # has already been actioned.
    if not (original and original.status is AlertStatus.AWAITING_APPROVAL
            and original.slack_ts and original.ticket):
        return

    # Throttle: a storm of duplicates would otherwise edit the message once per
    # alert and exhaust Slack's chat.update rate limit.
    interval = get_settings().slack_occurrence_update_seconds
    now = time.monotonic()
    if interval and now - original.slack_updated_at < interval:
        return

    REGISTRY.update(original_id, slack_updated_at=now)
    notifier.update_occurrences(original.slack_ts, original_id, original.ticket,
                                duplicate.occurrences, alert.severity.value)


def triage_once(app: Any, alert: SIEMAlert, notifier: Any = None) -> None:
    """Run one alert to a terminal state or to a pending approval."""
    notifier = notifier or SlackNotifier()

    # Cheapest possible path: an alert describing a situation already triaged
    # costs nothing. Checked before any enrichment or model call.
    duplicate = DEDUPE_INDEX.check(alert)
    if duplicate is not None:
        _record_duplicate(alert, duplicate, notifier)
        return

    REGISTRY.update(alert.alert_id, status=AlertStatus.RUNNING)
    METRICS.inc("alerts_triaged_total", severity=alert.severity.value)
    cfg = {"configurable": {"thread_id": f"alert-{alert.alert_id}"}}
    started = time.monotonic()

    try:
        out = app.invoke({"alert": alert}, cfg)
    except Exception as exc:  # noqa: BLE001
        _handle_triage_error(alert, exc)
        return
    finally:
        METRICS.observe_latency(time.monotonic() - started)

    for e in out.get("enrichments", []):
        if e.error:
            METRICS.inc("tool_errors_total", tool=e.agent_name)

    if "__interrupt__" in out:
        METRICS.inc("alerts_escalated_total")
        ticket = out["__interrupt__"][0].value["ticket"]
        # Post BEFORE recording status so the analyst surface is never behind
        # the registry, an approval-needed alert with no message is invisible.
        ts = notifier.post_ticket(alert.alert_id, ticket, alert.severity.value)
        if ts:
            # Write into the checkpoint so a different process can find it.
            app.update_state(cfg, {"slack_ts": ts})
        REGISTRY.update(
            alert.alert_id,
            status=AlertStatus.AWAITING_APPROVAL,
            ticket=ticket,
            verdict=ticket["verdict"],
            confidence=ticket["confidence"],
            slack_ts=ts,
        )
    else:
        METRICS.inc("alerts_auto_closed_total")
        settings = get_settings()
        if settings.slack_notify_auto_close:
            notifier.post_auto_close(
                alert.alert_id, verdict_of(out).value, out.get("confidence", 0.0),
                out.get("reasoning", ""), shadow=settings.shadow_mode,
            )
        REGISTRY.update(
            alert.alert_id,
            status=AlertStatus.AUTO_CLOSED,
            verdict=verdict_of(out).value,
            confidence=out.get("confidence"),
        )


def worker_loop(stop: threading.Event) -> None:
    app = get_app()
    logger.info("triage worker started")
    while not stop.is_set():
        try:
            alert = ALERT_QUEUE.get(timeout=0.5)
        except Exception:
            continue
        try:
            triage_once(app, alert)
        except Exception as exc:  # noqa: BLE001
            # triage_once handles its own failures, so reaching here means the
            # handling itself failed. Letting it propagate kills the worker
            # thread and every later alert queues forever, which is a far worse
            # outcome than losing one alert.
            logger.exception("worker caught an unhandled error",
                             extra={"alert_id": alert.alert_id})
            METRICS.inc("worker_unhandled_errors_total")
            try:
                REGISTRY.update(alert.alert_id, status=AlertStatus.FAILED,
                                error=f"unhandled: {exc}")
            except Exception:  # noqa: BLE001 - the registry may be the thing failing
                logger.error("could not record the failure for %s", alert.alert_id)
        finally:
            ALERT_QUEUE.task_done()
    logger.info("triage worker stopped")
