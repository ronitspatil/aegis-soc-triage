"""Pull detections from Splunk on an interval.

Splunk's built-in webhook alert action sends a fixed payload with no custom
headers, so it cannot produce the HMAC signature `/webhook/alert` requires.
Polling a detection search needs no Splunk-side configuration beyond a token.

Each poll looks back further than the interval so a late-indexed event is not
missed, and the resulting duplicates are absorbed by the registry: an alert_id
already seen is never enqueued twice.

    python -m aegis.ingest.splunk_poller
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass

from aegis.ingest.splunk_source import SplunkSource
from aegis.ingest.store import ALERT_QUEUE, REGISTRY
from aegis.llm.config import get_settings
from aegis.observability import METRICS

logger = logging.getLogger(__name__)


@dataclass
class PollHealth:
    """Whether ingestion is actually ingesting.

    A misconfigured search returns zero rows and reports success, so silence is
    indistinguishable from a quiet night unless it is counted.
    """

    polls: int = 0
    consecutive_empty: int = 0
    total_ingested: int = 0
    last_ingest_at: float | None = None
    warned: bool = False

    def record(self, seen: int, enqueued: int) -> None:
        self.polls += 1
        self.total_ingested += enqueued
        if seen == 0:
            self.consecutive_empty += 1
            return
        self.consecutive_empty = 0
        self.warned = False
        if enqueued:
            self.last_ingest_at = time.time()

    def as_dict(self) -> dict[str, object]:
        return {
            "polls": self.polls,
            "consecutive_empty_polls": self.consecutive_empty,
            "total_ingested": self.total_ingested,
            "seconds_since_last_ingest": (
                None if self.last_ingest_at is None
                else round(time.time() - self.last_ingest_at, 1)
            ),
        }


POLL_HEALTH = PollHealth()


def poll_once(source: SplunkSource, spl: str, lookback_seconds: int) -> dict[str, int]:
    """One poll. Returns counts for logging and metrics."""
    result = source.search_alerts(spl, earliest=f"-{int(lookback_seconds)}s")
    METRICS.inc("splunk_polls_total")

    enqueued = duplicates = 0
    for alert in result.alerts:
        _, created = REGISTRY.create_if_absent(alert.alert_id)
        if not created:
            duplicates += 1
            continue
        ALERT_QUEUE.put(alert)
        enqueued += 1

    if result.rejected:
        # A row that fails validation is a mapping problem worth seeing, not
        # something to silently drop.
        METRICS.inc("splunk_rows_rejected_total", value=len(result.rejected))
        logger.warning("%d Splunk row(s) failed validation", len(result.rejected))

    METRICS.inc("alerts_ingested_total", value=enqueued)
    if not result.alerts:
        METRICS.inc("splunk_empty_polls_total")
    POLL_HEALTH.record(len(result.alerts), enqueued)

    return {"seen": len(result.alerts), "enqueued": enqueued,
            "duplicates": duplicates, "rejected": len(result.rejected)}


def _warn_if_persistently_empty(spl: str, threshold: int) -> None:
    """Say something once when a search has stopped matching anything.

    The common cause is a filter on a field the deployment does not extract:
    the query succeeds, matches nothing, and ingestion silently stops.
    """
    if POLL_HEALTH.consecutive_empty < threshold or POLL_HEALTH.warned:
        return
    POLL_HEALTH.warned = True
    METRICS.inc("splunk_poll_stalled_total")
    logger.warning(
        "%d consecutive polls returned no rows for: %s. Check that the search "
        "matches, that filtered fields are extracted, and that the lookback "
        "window covers how often alerts arrive.",
        POLL_HEALTH.consecutive_empty, spl,
    )


def poll_loop(stop: threading.Event) -> None:
    settings = get_settings()
    source = SplunkSource()
    spl = settings.splunk_poll_search
    lookback = settings.splunk_poll_interval_seconds + settings.splunk_poll_overlap_seconds

    logger.info("polling Splunk every %ss: %s", settings.splunk_poll_interval_seconds, spl)
    while not stop.is_set():
        try:
            counts = poll_once(source, spl, lookback)
            if counts["enqueued"]:
                logger.info("ingested %d new alert(s) (%d duplicate, %d rejected)",
                            counts["enqueued"], counts["duplicates"], counts["rejected"])
            _warn_if_persistently_empty(spl, settings.splunk_empty_poll_warning)
        except Exception as exc:  # noqa: BLE001 - a failed poll must not end the loop
            METRICS.inc("splunk_poll_failures_total")
            logger.warning("poll failed: %s", exc)
        stop.wait(settings.splunk_poll_interval_seconds)
    logger.info("poller stopped")


def main() -> None:
    from aegis.ingest.worker import worker_loop
    from aegis.observability import setup_logging

    setup_logging(json_output=False)
    stop = threading.Event()
    worker = threading.Thread(target=worker_loop, args=(stop,), daemon=True)
    worker.start()
    try:
        poll_loop(stop)
    except KeyboardInterrupt:
        stop.set()
        worker.join(timeout=10)


if __name__ == "__main__":
    main()
