"""Live-client verification WITHOUT credentials or network.

`httpx.request` is intercepted and fed payloads shaped like the real APIs, so
the two things most likely to be wrong in an integration, response-field
mapping and retry semantics, are actually exercised. This does NOT prove the
vendors return exactly these shapes; it proves our parsing and error handling
are correct for the documented shapes.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

import httpx
import pytest

from aegis.tools import vt_client
from aegis.tools._http import ToolHTTPError, request_json


@pytest.fixture(autouse=True)
def _no_sleep(monkeypatch):
    """Retry backoff must not slow the suite."""
    monkeypatch.setattr("aegis.tools._http.time.sleep", lambda *_: None)


@pytest.fixture(autouse=True)
def _clear_vt_cache():
    vt_client._cache.clear()
    yield
    vt_client._cache.clear()


def install(monkeypatch, handler: Callable[[str, str], tuple[int, Any]]) -> list[str]:
    """Route every httpx.request through `handler(method, url) -> (status, body)`."""
    calls: list[str] = []

    def fake(method: str, url: str, **kw: Any) -> httpx.Response:
        calls.append(f"{method} {url}")
        status, body = handler(method, str(url))
        return httpx.Response(
            status_code=status,
            content=json.dumps(body).encode() if body is not None else b"",
            request=httpx.Request(method, url),
        )

    monkeypatch.setattr(httpx, "request", fake)
    return calls


# --- shared HTTP semantics --------------------------------------------------


def test_transient_status_is_retried_then_succeeds(monkeypatch):
    state = {"n": 0}

    def handler(method, url):
        state["n"] += 1
        return (429, {}) if state["n"] == 1 else (200, {"ok": True})

    install(monkeypatch, handler)
    assert request_json("GET", "https://x/y", retries=2) == {"ok": True}
    assert state["n"] == 2  # retried exactly once


def test_client_error_is_terminal_and_not_retried(monkeypatch):
    calls = install(monkeypatch, lambda m, u: (401, {"error": "bad token"}))
    with pytest.raises(ToolHTTPError):
        request_json("GET", "https://x/y", retries=3)
    assert len(calls) == 1  # a bad token never becomes valid on retry


def test_retries_are_bounded(monkeypatch):
    calls = install(monkeypatch, lambda m, u: (503, {}))
    with pytest.raises(ToolHTTPError):
        request_json("GET", "https://x/y", retries=2)
    assert len(calls) == 3  # initial + 2 retries


# --- VirusTotal -------------------------------------------------------------

VT_TOR = {
    "data": {
        "attributes": {
            "last_analysis_stats": {"malicious": 38, "suspicious": 3, "harmless": 2, "undetected": 0},
            "as_owner": "Zwiebelfreunde e.V.",
            "tags": ["tor", "anonymizer"],
            "categories": {"Forcepoint": "malicious"},
        }
    }
}


def test_vt_maps_a_malicious_response(monkeypatch):
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "vt-test")
    install(monkeypatch, lambda m, u: (200, VT_TOR))
    rep = vt_client.lookup_ip_reputation_live("185.220.101.5")
    assert rep.malicious_votes == 41       # malicious + suspicious
    assert rep.harmless_votes == 2         # harmless + undetected
    assert rep.is_known_tor_exit is True
    assert rep.asn_owner == "Zwiebelfreunde e.V."
    assert rep.malice_ratio > 0.9


def test_vt_404_means_unknown_not_benign(monkeypatch):
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "vt-test")
    install(monkeypatch, lambda m, u: (404, {"error": "NotFound"}))
    rep = vt_client.lookup_ip_reputation_live("10.1.2.3")
    assert rep.seen_in_intel is False
    assert rep.malicious_votes == 0


def test_vt_caches_so_repeat_indicators_cost_nothing(monkeypatch):
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "vt-test")
    calls = install(monkeypatch, lambda m, u: (200, VT_TOR))
    vt_client.lookup_ip_reputation_live("185.220.101.5")
    vt_client.lookup_ip_reputation_live("185.220.101.5")
    assert len(calls) == 1


def test_vt_outage_raises_the_tool_specific_error(monkeypatch):
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "vt-test")
    install(monkeypatch, lambda m, u: (503, {}))
    with pytest.raises(Exception) as exc:
        vt_client.lookup_ip_reputation_live("1.2.3.4")
    assert "VT lookup failed" in str(exc.value)


def test_vt_categories_may_be_a_list_not_a_dict(monkeypatch):
    """Regression: VT returns `categories` as a dict for domains but a LIST for
    IPs. Assuming the dict shape raises AttributeError mid-triage. Found by
    querying the real API, the empty-list case passed only by accident."""
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "vt-test")
    body = {"data": {"attributes": {
        "last_analysis_stats": {"malicious": 12, "suspicious": 3, "harmless": 46, "undetected": 28},
        "as_owner": "Stiftung Erneuerbare Freiheit",
        "tags": ["suspicious-udp", "tor", "self-signed"],
        "categories": ["anonymizer", "proxy"],
    }}}
    install(monkeypatch, lambda m, u: (200, body))
    rep = vt_client.lookup_ip_reputation_live("185.220.101.5")
    assert rep.categories == ["anonymizer", "proxy"]
    assert rep.is_known_tor_exit is True
    assert rep.malicious_votes == 15


def test_vt_categories_dict_form_still_works(monkeypatch):
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "vt-test")
    body = {"data": {"attributes": {
        "last_analysis_stats": {"malicious": 1, "harmless": 10},
        "categories": {"Forcepoint": "malicious", "Sophos": "spam"},
    }}}
    install(monkeypatch, lambda m, u: (200, body))
    rep = vt_client.lookup_ip_reputation_live("1.2.3.4")
    assert rep.categories == ["malicious", "spam"]


# --- ISC / Shodan public feeds ----------------------------------------------
# Payloads below are REAL responses recorded from the live APIs.

ISC_GOOGLE = {"ip": {"number": "8.8.8.8", "asname": "GOOGLE", "attacks": None,
                     "threatfeeds": {"miner": {}, "myip": {}, "openresolver": {}}}}
ISC_TOR = {"ip": {"number": "185.220.101.5", "asname": "ZWIEBELFREUN", "attacks": None,
                  "threatfeeds": {"alltor": {}, "ciarmy": {}, "emergincompromised": {},
                                  "forumspam": {}, "myip": {}, "rosti": {},
                                  "talos": {}, "torexit": {}, "webiron": {}}}}
ISC_WEAK = {"ip": {"number": "45.155.205.233", "asname": "PROTON66", "attacks": None,
                   "threatfeeds": {"forumspam": {}}}}


def _isc_handler(isc_body, shodan_body=None):
    def handler(method, url):
        if "isc.sans.edu" in url:
            return 200, isc_body
        if "internetdb.shodan.io" in url:
            return (200, shodan_body) if shodan_body else (404, None)
        return 200, {}
    return handler


def test_informational_feeds_do_not_make_google_dns_malicious(monkeypatch):
    """Regression: 8.8.8.8 IS an open resolver. That is a fact, not a threat.

    Counting every ISC listing equally scored the internet's most benign IP at
    1.0, found by querying the real API, not by reasoning about it.
    """
    from aegis.nodes.threat_intel import _score_reputation
    from aegis.tools.isc_client import lookup_ip_reputation_public

    install(monkeypatch, _isc_handler(ISC_GOOGLE))
    rep = lookup_ip_reputation_public("8.8.8.8")
    assert rep.malicious_votes == 0
    assert _score_reputation(rep) == 0.0


def test_high_confidence_feeds_and_tor_are_weighted(monkeypatch):
    from aegis.nodes.threat_intel import _score_reputation
    from aegis.tools.isc_client import lookup_ip_reputation_public

    install(monkeypatch, _isc_handler(
        ISC_TOR, {"tags": ["tor"], "hostnames": ["berlin01.tor-exit.artikel10.org"]}))
    rep = lookup_ip_reputation_public("185.220.101.5")
    assert rep.is_known_tor_exit is True
    assert "myip" not in rep.categories
    assert _score_reputation(rep) >= 0.7


def test_single_weak_feed_is_not_a_full_malice_ratio(monkeypatch):
    from aegis.tools.isc_client import lookup_ip_reputation_public

    install(monkeypatch, _isc_handler(ISC_WEAK))
    rep = lookup_ip_reputation_public("45.155.205.233")
    assert 0.0 < rep.malice_ratio < 0.25


def test_shodan_outage_does_not_fail_the_enrichment(monkeypatch):
    from aegis.tools.isc_client import lookup_ip_reputation_public

    def handler(method, url):
        return (200, ISC_TOR) if "isc.sans.edu" in url else (503, {})

    install(monkeypatch, handler)
    rep = lookup_ip_reputation_public("185.220.101.5")
    assert rep.is_known_tor_exit is True
