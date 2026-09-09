"""Splunk row -> SIEMAlert mapping. No Splunk instance required."""

from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from aegis.ingest.splunk_source import map_row


def test_detection_payload_beats_splunk_host_metadata():
    """Regression: Splunk's reserved `host` is the FORWARDER, not the endpoint.

    Letting it win made every alert name 127.0.0.1, so the agent would have
    investigated the log shipper instead of the compromised machine.
    """
    row = {
        "host": "127.0.0.1",          # Splunk ingestion metadata
        "sourcetype": "aegis:detection",
        "_time": "2026-09-08T02:14:00.000+00:00",
        "_raw": json.dumps({
            "alert_id": "SPL-1000", "rule": "Encoded PowerShell from Office",
            "severity": "high", "src_ip": "185.220.101.5",
            "user": "j.doe@corp.com", "host": "WIN-FINANCE-07",
            "msg": "winword.exe spawned powershell.exe -enc SQBFAFgA",
        }),
    }
    a = map_row(row)
    assert a.hostname == "WIN-FINANCE-07"
    assert a.alert_id == "SPL-1000"
    assert str(a.source_ip) == "185.220.101.5"
    assert a.severity.value == "high"


def test_numeric_urgency_is_normalised():
    a = map_row({"_time": "2026-09-08T00:00:00Z", "search_name": "R", "urgency": "5"})
    assert a.severity.value == "critical"


def test_cim_field_names_are_supported():
    a = map_row({
        "_time": "2026-09-08T00:00:00Z", "search_name": "Access - Brute Force",
        "src": "45.155.205.233", "src_user": "j.doe@corp.com", "dest_host": "WIN-01",
    })
    assert str(a.source_ip) == "45.155.205.233"
    assert a.username == "j.doe@corp.com"
    assert a.hostname == "WIN-01"


def test_missing_rule_name_falls_back_rather_than_dropping_the_alert():
    a = map_row({"_time": "2026-09-08T00:00:00Z", "_cd": "1:42"})
    assert a.rule_name == "Unnamed Splunk Detection"
    assert a.alert_id == "1:42"


def test_malformed_row_raises_so_the_batch_can_reject_just_that_row():
    with pytest.raises(ValidationError):
        map_row({"_time": "2026-09-08T00:00:00Z", "rule": "R", "src_ip": "not-an-ip"})
