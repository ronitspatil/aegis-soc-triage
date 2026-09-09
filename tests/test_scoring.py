"""Deterministic scoring. No LLM, no network: this is the point of the split."""

from __future__ import annotations

import pytest

from aegis.nodes.endpoint import _score_telemetry
from aegis.nodes.identity import _score_identity
from aegis.nodes.threat_intel import _score_reputation
from aegis.tools.endpoint import get_host_telemetry
from aegis.tools.identity import lookup_user
from aegis.tools.threat_intel import lookup_ip_reputation


@pytest.mark.parametrize(
    "ip,expected", [("185.220.101.5", 0.953), ("8.8.8.8", 0.0), ("52.94.236.248", 0.0)]
)
def test_reputation_scores_are_stable(ip, expected):
    """Same evidence must always produce the same number: auditability."""
    assert _score_reputation(lookup_ip_reputation(ip)) == expected


def test_unknown_indicator_is_not_treated_as_benign():
    """Absence of evidence != evidence of absence."""
    assert _score_reputation(lookup_ip_reputation("10.1.2.3")) == 0.15


def test_tor_exit_gets_a_floor_regardless_of_votes():
    rep = lookup_ip_reputation("185.220.101.5")
    assert rep.is_known_tor_exit and _score_reputation(rep) >= 0.70


def test_disabled_account_short_circuits_everything():
    assert _score_identity(lookup_user("j.doe@corp.com")) == 0.95


def test_service_account_is_not_penalised_for_missing_mfa():
    """Non-interactive accounts CANNOT enrol; penalising them floods the queue."""
    p = lookup_user("svc-backup@corp.com")
    assert p.mfa_enrolled is False
    assert _score_identity(p) < 0.5


def test_healthy_ordinary_user_scores_zero():
    assert _score_identity(lookup_user("r.patil@corp.com")) == 0.0


def test_office_spawning_shell_is_high_risk():
    assert _score_telemetry(get_host_telemetry("WIN-FINANCE-07")) >= 0.9


def test_routine_developer_activity_scores_zero():
    assert _score_telemetry(get_host_telemetry("MACBOOK-RPATIL")) == 0.0


def test_dead_edr_sensor_adds_risk_rather_than_clearing_the_host():
    tel = get_host_telemetry("SRV-BACKUP-01")
    assert tel.edr_agent_healthy is False
    assert _score_telemetry(tel) > 0.0
