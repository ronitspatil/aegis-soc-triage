"""Checkpointer selection.

`MemorySaver` loses every pending interrupt when the process restarts, an
analyst approving tomorrow morning would find nothing to resume into. Setting
POSTGRES_URL swaps in durable storage with no other code change.
"""

from __future__ import annotations

import logging
from typing import Any

from langgraph.checkpoint.memory import MemorySaver

from aegis.llm.config import get_settings
from aegis.serde import build_serializer

logger = logging.getLogger(__name__)

_pool: Any = None  # module-level so the pool is created once per process


def build_checkpointer() -> Any:
    """Return a Postgres-backed saver when configured, else in-memory."""
    global _pool
    settings = get_settings()

    if not settings.postgres_url:
        logger.info("no POSTGRES_URL: using MemorySaver (interrupts do not survive restart)")
        return MemorySaver(serde=build_serializer())

    from langgraph.checkpoint.postgres import PostgresSaver
    from psycopg.rows import dict_row
    from psycopg_pool import ConnectionPool

    if _pool is None:
        # PostgresSaver requires autocommit and dict rows.
        _pool = ConnectionPool(
            conninfo=settings.postgres_url,
            max_size=20,
            open=True,  # explicit: the library default is changing
            # Bounded: without these an unreachable database makes startup
            # retry forever instead of reporting anything.
            timeout=settings.postgres_connect_timeout,
            kwargs={"autocommit": True, "prepare_threshold": 0,
                    "row_factory": dict_row,
                    "connect_timeout": int(settings.postgres_connect_timeout)},
        )

    saver = PostgresSaver(_pool, serde=build_serializer())
    try:
        saver.setup()  # idempotent: creates the checkpoint tables if absent
    except Exception as exc:  # noqa: BLE001
        # Fail loudly rather than falling back to memory. Starting without
        # durable checkpoints would silently discard suspended approvals, and
        # a process that exits with a clear reason is easier to operate than
        # one that appears healthy and is not.
        _pool = None
        raise RuntimeError(
            f"POSTGRES_URL is set but unreachable ({settings.postgres_url}): {exc}. "
            "Start the database, or unset POSTGRES_URL to run without durable state."
        ) from exc
    logger.info("using PostgresSaver, interrupts survive restarts")
    return saver
