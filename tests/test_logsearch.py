"""Historical log search: protocol, fixtures, and SPL translation."""

from __future__ import annotations

from typing import Any

import pytest

from aegis.tools.logsearch import LogSearchBackend, resolve_log_backend
from aegis.tools.logsearch_mock import MockLogSearch
from aegis.tools.logsearch_splunk import SplunkLogSearch, _clean

# --- backend selection -------------------------------------------------------


def test_default_backend_is_the_mock():
    assert isinstance(resolve_log_backend(), MockLogSearch)


def test_mock_satisfies_the_protocol():
    assert isinstance(MockLogSearch(), LogSearchBackend)


def test_splunk_backend_satisfies_the_protocol():
    assert isinstance(SplunkLogSearch.__new__(SplunkLogSearch), LogSearchBackend)


# --- fixtures the investigation agent depends on -----------------------------


def test_host_timeline_returns_the_execution_chain():
    events = MockLogSearch().host_timeline("WIN-FINANCE-07", hours=24)
    chain = [(e.parent_name, e.process_name) for e in events if e.event_type == "process"]
    assert ("winword.exe", "powershell.exe") in chain
    assert any(e.remote_ip == "185.220.101.5" for e in events)


def test_timeline_respects_the_time_window():
    backend = MockLogSearch()
    assert len(backend.host_timeline("WIN-FINANCE-07", hours=24)) == 5
    assert backend.host_timeline("WIN-FINANCE-07", hours=1) == []


def test_unknown_host_returns_no_events():
    assert MockLogSearch().host_timeline("NOT-A-HOST") == []


def test_auth_history_exposes_the_failed_attempts():
    events = MockLogSearch().user_auth_history("j.doe@corp.com", hours=24)
    assert len(events) == 37
    assert all(not e.succeeded for e in events)
    assert {e.source_ip for e in events} == {"45.155.205.233"}


def test_indicator_search_reveals_hosts_the_alert_never_named():
    """The alert names one machine; the logs show three. This is the finding an
    enrichment pipeline structurally cannot produce."""
    events = MockLogSearch().find_indicator("185.220.101.5")
    assert {e.hostname for e in events} == {
        "WIN-FINANCE-07", "WIN-HR-02", "WIN-SALES-11"}


def test_base_rates_separate_a_noisy_rule_from_a_rare_one():
    backend = MockLogSearch()
    noisy = backend.count_rule_firings("Brute Force Authentication")
    rare = backend.count_rule_firings("Encoded PowerShell from Office")
    assert noisy.total_firings > 400 and noisy.firings_per_day > 50
    assert rare.total_firings < 5
    assert rare.firings_per_day < 1


def test_rule_name_lookup_is_case_insensitive():
    assert MockLogSearch().count_rule_firings("BRUTE force AUTHENTICATION").total_firings == 412


def test_unknown_rule_reports_zero_rather_than_inventing_a_base_rate():
    stats = MockLogSearch().count_rule_firings("Some New Rule")
    assert stats.total_firings == 0


# --- SPL translation and injection resistance --------------------------------


class FakeSource:
    def __init__(self, rows: list[dict[str, Any]] | None = None) -> None:
        self.rows = rows or []
        self.queries: list[str] = []

    def run_search(self, spl: str, **kw: Any) -> list[dict[str, Any]]:
        self.queries.append(spl)
        return self.rows


@pytest.mark.parametrize("hostile", [
    'HOST" | delete | search "x',
    'a" OR 1=1 "',
    'h";|tstats count from datamodel=x|"',
])
def test_hostile_values_cannot_break_out_of_the_query(hostile):
    """Hostnames and indicators come from alerts, which carry attacker-influenced
    content, and are interpolated into a query language."""
    cleaned = _clean(hostile)
    assert '"' not in cleaned
    assert "|" not in cleaned


def test_legitimate_values_survive_sanitisation():
    assert _clean("WIN-FINANCE-07") == "WIN-FINANCE-07"
    assert _clean("j.doe@corp.com") == "j.doe@corp.com"
    assert _clean("185.220.101.5") == "185.220.101.5"


def test_host_timeline_builds_a_bounded_query():
    source = FakeSource()
    SplunkLogSearch(source=source).host_timeline("WIN-FINANCE-07", hours=6)
    spl = source.queries[0]
    assert 'host="WIN-FINANCE-07"' in spl
    assert "head" in spl          # unbounded searches can take a cluster down


def test_rows_map_onto_typed_events():
    source = FakeSource([{
        "_time": "2026-09-08T02:14:00+00:00", "host": "WIN-FINANCE-07",
        "process_name": "powershell.exe", "parent_process_name": "winword.exe",
        "dest_ip": "185.220.101.5", "message": "encoded powershell",
    }])
    event = SplunkLogSearch(source=source).host_timeline("WIN-FINANCE-07")[0]
    assert event.process_name == "powershell.exe"
    assert event.parent_name == "winword.exe"
    assert event.remote_ip == "185.220.101.5"


def test_a_failed_search_is_a_gap_not_a_crash():
    """One dead query must not abort an investigation mid-loop."""
    class Broken:
        def run_search(self, *a: Any, **kw: Any) -> list[dict[str, Any]]:
            raise RuntimeError("splunk unreachable")

    assert SplunkLogSearch(source=Broken()).host_timeline("H") == []


def test_rule_stats_handle_a_missing_row():
    stats = SplunkLogSearch(source=FakeSource([])).count_rule_firings("R", days=7)
    assert stats.total_firings == 0
    assert stats.days == 7


def test_json_payload_host_beats_splunk_metadata_host():
    """Verified against live Splunk: `| spath` merges a JSON `host` field into
    Splunk's metadata `host`, and the metadata value is the forwarder."""
    source = FakeSource([{
        "_time": "2026-09-08T02:14:00+00:00",
        "host": "127.0.0.1",                 # forwarder
        "json_host": "WIN-FINANCE-07",       # the endpoint the detection is about
        "json_msg": "winword.exe spawned powershell.exe",
    }])
    event = SplunkLogSearch(source=source).host_timeline("WIN-FINANCE-07")[0]
    assert event.hostname == "WIN-FINANCE-07"


def test_multivalue_fields_are_flattened_not_stringified():
    """Splunk returns a list for multivalue fields; str() on it yields
    "['127.0.0.1', 'WIN-FINANCE-07']" as a hostname."""
    source = FakeSource([{
        "_time": "2026-09-08T02:14:00+00:00",
        "hostname": ["WIN-FINANCE-07", "127.0.0.1"],
    }])
    event = SplunkLogSearch(source=source).host_timeline("X")[0]
    assert event.hostname == "WIN-FINANCE-07"
    assert "[" not in event.hostname


def test_queries_are_scoped_to_an_index():
    """Splunk searches only a role's default indexes without an index clause,
    so a custom index silently returns nothing."""
    source = FakeSource()
    SplunkLogSearch(source=source, index="aegis_demo").host_timeline("H")
    assert "index=aegis_demo" in source.queries[0]


def test_json_fields_are_extracted_under_distinct_names():
    source = FakeSource()
    SplunkLogSearch(source=source).host_timeline("H")
    spl = source.queries[0]
    assert "output=json_host path=host" in spl
    assert "| spath |" not in spl        # a bare spath causes the collision
