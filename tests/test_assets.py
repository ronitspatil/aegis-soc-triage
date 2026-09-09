"""Asset criticality and the blast-radius gate."""

from __future__ import annotations

import pytest

from aegis.graph import route_on_verdict
from aegis.schemas.alert import SIEMAlert
from aegis.schemas.state import EnrichmentData, Verdict
from aegis.tools.assets import Criticality, lookup_asset


def _clean_state(hostname: str):
    alert = SIEMAlert(alert_id="A-1", rule_name="R", severity="low",
                      timestamp="2026-09-09T12:00:00Z", hostname=hostname)
    return {
        "alert": alert,
        "enrichments": [
            EnrichmentData(agent_name=a, summary="clean", risk_signal=0.0,
                           findings={"is_privileged": False})
            for a in ("threat_intel", "identity", "endpoint")
        ],
        "verdict": Verdict.FALSE_POSITIVE,
        "confidence": 0.99,
    }


# --- inventory ---------------------------------------------------------------


@pytest.mark.parametrize("hostname,expected", [
    ("DC-01", Criticality.CROWN_JEWEL),
    ("SRV-BACKUP-01", Criticality.HIGH),
    ("WIN-FINANCE-07", Criticality.STANDARD),
    ("LAB-VM-14", Criticality.LOW),
])
def test_known_hosts_carry_their_criticality(hostname, expected):
    assert lookup_asset(hostname).criticality is expected


def test_an_absent_host_is_unknown_rather_than_unimportant():
    """A host missing from inventory is a gap in the inventory."""
    asset = lookup_asset("NOT-IN-CMDB")
    assert asset.criticality is Criticality.UNKNOWN
    assert asset.in_inventory is False


def test_unknown_outranks_standard():
    """Not knowing what a host is should not be safer than knowing it is
    ordinary."""
    assert lookup_asset("NOT-IN-CMDB").at_least(Criticality.STANDARD)
    assert not lookup_asset("LAB-VM-14").at_least(Criticality.STANDARD)


def test_criticality_comparisons_are_ordered():
    assert lookup_asset("DC-01").at_least(Criticality.HIGH)
    assert not lookup_asset("WIN-FINANCE-07").at_least(Criticality.HIGH)


# --- the gate ----------------------------------------------------------------


def test_an_ordinary_workstation_can_auto_close():
    assert route_on_verdict(_clean_state("WIN-FINANCE-07")) == "auto_close"


def test_a_crown_jewel_never_auto_closes():
    """Being wrong about a domain controller costs more than every needless
    review combined."""
    assert route_on_verdict(_clean_state("DC-01")) == "human_review"


def test_a_high_criticality_server_may_still_auto_close():
    """The gate is deliberately set at crown jewel. Blocking every production
    server would suppress most of the automation's value."""
    assert route_on_verdict(_clean_state("SRV-BACKUP-01")) == "auto_close"


def test_an_uninventoried_host_does_not_block_auto_close():
    """Unknown assets raise investigation priority, but gating auto-close on
    them would stop automation everywhere inventory is incomplete."""
    assert route_on_verdict(_clean_state("NOT-IN-CMDB")) == "auto_close"


def test_an_alert_without_a_hostname_is_unaffected():
    state = _clean_state("H")
    state["alert"] = state["alert"].model_copy(update={"hostname": None})
    assert route_on_verdict(state) == "auto_close"


# --- the tool ----------------------------------------------------------------


def test_the_tool_reports_criticality_and_owner():
    from aegis.nodes.investigation_tools import get_asset_context

    text = get_asset_context.invoke({"hostname": "DC-01"})
    assert "crown_jewel" in text
    assert "domain_controller" in text
    assert "platform@corp.com" in text


def test_the_tool_says_unknown_rather_than_inventing():
    from aegis.nodes.investigation_tools import get_asset_context

    text = get_asset_context.invoke({"hostname": "NOT-IN-CMDB"})
    assert "not in the asset inventory" in text
    assert "gap in inventory" in text
