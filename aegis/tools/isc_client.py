"""Keyless public threat intelligence: SANS Internet Storm Center + Shodan InternetDB.

Both are REAL security data sources requiring no account, so this provider lets
you verify the whole pipeline against live intel before committing to a paid
feed. Returns the same `IPReputation` contract as the mock and the VT client.
"""

from __future__ import annotations

import logging
from typing import Any

from aegis.llm.config import get_settings
from aegis.tools._http import ToolHTTPError, request_json
from aegis.tools.threat_intel import IPReputation, ThreatIntelUnavailable

logger = logging.getLogger(__name__)

_ISC_URL = "https://isc.sans.edu/api/ip/{ip}?json"
_SHODAN_URL = "https://internetdb.shodan.io/{ip}"

# Shodan tags that indicate anonymizing or otherwise notable infrastructure.
_SUSPICIOUS_TAGS = {"tor", "proxy", "vpn", "compromised", "malware", "c2"}

# ISC feed taxonomy. NOT every listing is a threat signal, this distinction is
# the difference between a working scorer and one that flags Google DNS.
#
# Informational feeds describe a FACT about the host, not a threat: 8.8.8.8 is
# an open resolver and 1.1.1.1 is on `mastodon` because they are widely-used
# public infrastructure. Counting those as malicious votes scores the internet's
# most benign IPs at 1.0.
_INFORMATIONAL_FEEDS = {
    "myip", "openresolver", "mastodon", "rosti", "miner", "sshpwauth",
}
# Curated, high-confidence blocklists maintained by security vendors.
_HIGH_CONFIDENCE_FEEDS = {
    "ciarmy", "emergincompromised", "talos", "blocklistde", "dshield",
    "sslblacklist", "spamhaus", "feodotracker",
}
# Weak signal: abuse-adjacent but frequently noisy or stale.
_LOW_CONFIDENCE_FEEDS = {"forumspam", "webiron", "bruteforceblocker"}

# Stand-in for "engines that did not flag this". Keeps a single weak listing
# from reading as a 100% malice ratio.
_HARMLESS_BASELINE = 6


def _as_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def lookup_ip_reputation_public(indicator: str) -> IPReputation:
    """Query ISC and Shodan, merging both into one normalized verdict."""
    settings = get_settings()
    kw = dict(timeout=settings.tool_timeout_seconds, retries=settings.tool_max_retries)

    try:
        isc = request_json("GET", _ISC_URL.format(ip=indicator), allow_404=True, **kw) or {}
    except ToolHTTPError as exc:
        raise ThreatIntelUnavailable(f"ISC lookup failed for {indicator}: {exc}") from exc

    # Shodan is supplementary: its absence must not fail the whole enrichment.
    shodan: dict[str, Any] = {}
    try:
        shodan = request_json("GET", _SHODAN_URL.format(ip=indicator), allow_404=True, **kw) or {}
    except ToolHTTPError as exc:
        logger.warning("Shodan unavailable for %s (continuing): %s", indicator, exc)

    ip_block: dict[str, Any] = isc.get("ip") or {}
    # ISC returns the queried IP echoed back even when it knows nothing about it.
    known_to_isc = bool(ip_block.get("number"))

    feeds = ip_block.get("threatfeeds") or {}
    feed_names = sorted(feeds.keys())
    attacks = _as_int(ip_block.get("attacks"))

    tags = [str(t).lower() for t in (shodan.get("tags") or [])]
    hostnames = [str(h).lower() for h in (shodan.get("hostnames") or [])]

    is_tor = (
        "alltor" in feeds
        or "tor" in tags
        or any("tor-exit" in h or "torservers" in h for h in hostnames)
    )

    # Weight listings by feed quality rather than counting them equally.
    malicious = 0
    for feed in feed_names:
        if feed in _INFORMATIONAL_FEEDS:
            continue                      # a fact about the host, not a threat
        if feed in _HIGH_CONFIDENCE_FEEDS:
            malicious += 2
        elif feed in _LOW_CONFIDENCE_FEEDS:
            malicious += 1
        else:
            malicious += 1                # unknown feed: treat as weak signal
    if attacks:
        malicious += 2
    malicious += sum(1 for t in tags if t in _SUSPICIOUS_TAGS and t != "tor")

    threat_feeds = [f for f in feed_names if f not in _INFORMATIONAL_FEEDS]
    categories = threat_feeds + [t for t in tags if t not in threat_feeds]

    return IPReputation(
        indicator=indicator,
        malicious_votes=malicious,
        harmless_votes=_HARMLESS_BASELINE,
        categories=categories,
        asn_owner=ip_block.get("asname") or ip_block.get("as") and str(ip_block.get("as")),
        is_known_tor_exit=is_tor,
        # Absence from every feed is NOT proof of benignity, but ISC does have a
        # record of the network, so we did successfully observe something.
        seen_in_intel=known_to_isc or bool(shodan),
    )
