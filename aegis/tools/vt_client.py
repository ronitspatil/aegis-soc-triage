"""Live VirusTotal client.

Returns the SAME `IPReputation` contract as the mock, so `threat_intel_node`
is unchanged. That interchangeability is the payoff of typing the seam in
Module 3 instead of passing raw dicts around.
"""

from __future__ import annotations

import logging
import threading
import time
from typing import Any

from aegis.llm.config import get_settings
from aegis.tools._http import ToolHTTPError, request_json
from aegis.tools.threat_intel import IPReputation, ThreatIntelUnavailable

logger = logging.getLogger(__name__)

_VT_URL = "https://www.virustotal.com/api/v3/ip_addresses/{ip}"

# Process-local TTL cache. Single-process only, use Redis when you scale out,
# so a fleet of workers shares one cache and one rate-limit budget.
_cache: dict[str, tuple[float, IPReputation]] = {}
_cache_lock = threading.Lock()


def _cache_get(key: str, ttl: int) -> IPReputation | None:
    if ttl <= 0:
        return None
    with _cache_lock:
        hit = _cache.get(key)
    if not hit:
        return None
    ts, value = hit
    if time.monotonic() - ts > ttl:
        return None
    return value


def _cache_put(key: str, value: IPReputation) -> None:
    with _cache_lock:
        _cache[key] = (time.monotonic(), value)


def _parse(indicator: str, payload: dict[str, Any]) -> IPReputation:
    """Map VT's response onto our normalized contract.

    Third-party JSON is untrusted input: every field is fetched defensively and
    the result is Pydantic-validated before it can reach the graph.
    """
    attrs = payload.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    malicious = int(stats.get("malicious", 0)) + int(stats.get("suspicious", 0))
    harmless = int(stats.get("harmless", 0)) + int(stats.get("undetected", 0))

    # VT returns `categories` as a {vendor: category} dict for domains but as a
    # LIST (often empty) for IP addresses. Assuming one shape crashes on the
    # other, found by querying the real API, not the docs.
    raw_categories = attrs.get("categories")
    if isinstance(raw_categories, dict):
        categories = sorted({str(v) for v in raw_categories.values() if v})
    elif isinstance(raw_categories, list):
        categories = sorted({str(v) for v in raw_categories if v})
    else:
        categories = []
    tags = [str(t).lower() for t in (attrs.get("tags") or [])]

    return IPReputation(
        indicator=indicator,
        malicious_votes=malicious,
        harmless_votes=harmless,
        categories=categories or tags,
        asn_owner=attrs.get("as_owner"),
        is_known_tor_exit=any("tor" in t for t in tags + categories),
        seen_in_intel=True,
    )


def lookup_ip_reputation_live(indicator: str) -> IPReputation:
    """Query VirusTotal with caching and bounded retries.

    Retry/terminal semantics come from `_http.request_json`, so a 401 fails
    immediately while a 429 is retried, the same rules every live client uses.
    """
    settings = get_settings()
    if not settings.virustotal_api_key:
        raise ThreatIntelUnavailable("VIRUSTOTAL_API_KEY is not configured")

    cached = _cache_get(indicator, settings.ioc_cache_ttl_seconds)
    if cached is not None:
        logger.debug("cache hit for %s", indicator)
        return cached

    try:
        payload = request_json(
            "GET",
            _VT_URL.format(ip=indicator),
            headers={"x-apikey": settings.virustotal_api_key},
            timeout=settings.tool_timeout_seconds,
            retries=settings.tool_max_retries,
            allow_404=True,
        )
    except ToolHTTPError as exc:
        raise ThreatIntelUnavailable(f"VT lookup failed for {indicator}: {exc}") from exc

    # 404 == VT has no record. NOT benign, preserve the distinction.
    if payload is None:
        result = IPReputation(indicator=indicator, seen_in_intel=False)
    else:
        try:
            result = _parse(indicator, payload)
        except Exception as exc:  # noqa: BLE001 - unexpected payload shape
            raise ThreatIntelUnavailable(f"VT response unusable for {indicator}: {exc}") from exc

    _cache_put(indicator, result)
    return result
