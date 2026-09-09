"""Shared HTTP behaviour for live security-tool clients.

Retries are BOUNDED and only cover transient status codes: a 429 that clears on
retry should never degrade an alert to human review, but a 401 is terminal and
retrying it just wastes the alert's latency budget.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Mapping
from typing import Any

import httpx

logger = logging.getLogger(__name__)

TRANSIENT_STATUS = {429, 500, 502, 503, 504}


class ToolHTTPError(RuntimeError):
    """Raised after retries are exhausted, or on a terminal status."""


def request_json(
    method: str,
    url: str,
    *,
    headers: Mapping[str, str] | None = None,
    params: Mapping[str, Any] | None = None,
    json_body: Any | None = None,
    data: Mapping[str, Any] | None = None,
    timeout: float = 10.0,
    retries: int = 2,
    allow_404: bool = False,
) -> dict[str, Any] | None:
    """Perform a request with bounded exponential backoff.

    Returns None on 404 when `allow_404`, callers use that to express
    "no record found", which is neither an error nor a clean result.
    """
    last: Exception | None = None

    for attempt in range(retries + 1):
        try:
            resp = httpx.request(
                method, url, headers=headers, params=params,
                json=json_body, data=data, timeout=timeout,
            )
            if resp.status_code == 404 and allow_404:
                return None
            if resp.status_code in TRANSIENT_STATUS:
                raise httpx.HTTPStatusError(
                    f"transient {resp.status_code}", request=resp.request, response=resp
                )
            resp.raise_for_status()
            return resp.json()

        except (httpx.HTTPStatusError, httpx.RequestError) as exc:
            status = getattr(getattr(exc, "response", None), "status_code", None)
            # Terminal client errors: retrying a bad token never helps.
            if status is not None and status not in TRANSIENT_STATUS and 400 <= status < 500:
                raise ToolHTTPError(f"{method} {url} failed permanently: {exc}") from exc
            last = exc
            if attempt < retries:
                backoff = 2**attempt
                logger.warning("%s %s failed (%s); retry in %ss", method, url, exc, backoff)
                time.sleep(backoff)

    raise ToolHTTPError(f"{method} {url} failed after {retries + 1} attempts: {last}")
