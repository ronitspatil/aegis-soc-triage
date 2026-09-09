"""Slack approval surface. No Slack workspace or token required."""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from typing import Any

from aegis.notify.slack import (
    APPROVE,
    ESCALATE,
    REJECT,
    SlackNotifier,
    build_auto_close_blocks,
    build_ticket_blocks,
    verify_slack_signature,
)
from aegis.notify.slack_handler import handle_block_action

TICKET = {
    "title": "[HIGH] Encoded PowerShell from Office. SPL-1000",
    "verdict": "true_positive",
    "confidence": 0.93,
    "entities": {"source_ip": "185.220.101.5", "username": "j.doe@corp.com",
                 "hostname": "WIN-FINANCE-07"},
    "reasoning": "Three specialists corroborate a maldoc chain beaconing to a Tor exit node.",
    "recommended_actions": ["Isolate WIN-FINANCE-07", "Revoke sessions", "Block 185.220.101.5"],
    "enrichment_signals": {"threat_intel": {"risk": 0.7, "error": None},
                           "identity": {"risk": 0.95, "error": None},
                           "endpoint": {"risk": 0.95, "error": None}},
}


class FakeSlack:
    """Records API calls instead of making them."""

    def __init__(self) -> None:
        self.posted: list[dict[str, Any]] = []
        self.updated: list[dict[str, Any]] = []

    def chat_postMessage(self, **kw: Any) -> dict[str, str]:
        self.posted.append(kw)
        return {"ts": "1725800000.000100"}

    def chat_update(self, **kw: Any) -> dict[str, str]:
        self.updated.append(kw)
        return {"ok": "true"}


# --- rendering ---------------------------------------------------------------


def test_buttons_carry_the_alert_id_for_correlation():
    blocks = build_ticket_blocks("SPL-1000", TICKET, "high")
    buttons = blocks[-1]["elements"]
    assert [b["action_id"] for b in buttons] == [APPROVE, REJECT, ESCALATE]
    assert {b["value"] for b in buttons} == {"SPL-1000"}


def test_message_uses_a_colour_bar_rather_than_emoji_decoration():
    """Severity is carried once, by the attachment colour: not repeated as an
    emoji on every field."""
    from aegis.notify.slack import SEVERITY_COLOR

    fake = FakeSlack()
    SlackNotifier(client=fake).post_ticket("SPL-1000", TICKET, "high")
    assert fake.posted[0]["attachments"][0]["color"] == SEVERITY_COLOR["high"]
    assert ":rotating_light:" not in json.dumps(fake.posted[0])


def test_verdict_is_rendered_in_plain_english():
    rendered = json.dumps(build_ticket_blocks("SPL-1000", TICKET, "high"))
    assert "True positive" in rendered
    assert "true_positive" not in rendered


def test_ticket_message_never_contains_raw_log():
    """Channel membership is the access control on these messages; raw logs are
    the most sensitive material we hold. Same reasoning as the reasoner prompt."""
    ticket = {**TICKET, "raw_log": "winword.exe -enc SQBFAFgA password=Hunter2"}
    rendered = json.dumps(build_ticket_blocks("SPL-1000", ticket, "high"))
    assert "Hunter2" not in rendered
    assert "raw_log" not in rendered


def test_long_reasoning_is_truncated_below_slacks_limit():
    ticket = {**TICKET, "reasoning": "x" * 9000}
    for block in build_ticket_blocks("SPL-1000", ticket):
        text = (block.get("text") or {}).get("text", "")
        assert len(text) <= 3000


def test_shadow_mode_auto_close_is_labelled_as_counterfactual():
    blocks = build_auto_close_blocks("SPL-1", "false_positive", 0.97, "clean", shadow=True)
    assert "SHADOW" in json.dumps(blocks)
    assert "would have auto-closed" in json.dumps(blocks)


# --- request authenticity ----------------------------------------------------


def _sign(secret: str, ts: str, body: bytes) -> str:
    base = f"v0:{ts}:{body.decode()}".encode()
    return "v0=" + hmac.new(secret.encode(), base, hashlib.sha256).hexdigest()


def test_valid_signature_accepted():
    ts, body = str(int(time.time())), b"payload=x"
    assert verify_slack_signature("s3cret", ts, body, _sign("s3cret", ts, body))


def test_replayed_signature_rejected():
    """A captured, validly-signed request must not work five minutes later."""
    old = str(int(time.time()) - 600)
    body = b"payload=x"
    assert not verify_slack_signature("s3cret", old, body, _sign("s3cret", old, body))


def test_forged_signature_rejected():
    ts, body = str(int(time.time())), b"payload=x"
    assert not verify_slack_signature("s3cret", ts, body, "v0=deadbeef")


def test_tampered_body_rejected():
    ts = str(int(time.time()))
    sig = _sign("s3cret", ts, b"payload=original")
    assert not verify_slack_signature("s3cret", ts, b"payload=tampered", sig)


# --- interaction handling ----------------------------------------------------


def _payload(action_id: str, alert_id: str = "SPL-1000", user: str = "U024BE7LH"):
    return {"type": "block_actions", "user": {"id": user},
            "actions": [{"action_id": action_id, "value": alert_id}]}


def test_approval_resumes_the_graph_and_attributes_the_analyst(monkeypatch):
    seen: dict[str, Any] = {}

    def fake_apply(alert_id, decision, actor=None, source="api"):
        seen.update(alert_id=alert_id, decision=decision, actor=actor, source=source)
        return {}

    monkeypatch.setattr("aegis.notify.slack_handler.apply_decision", fake_apply)
    fake = FakeSlack()
    result = handle_block_action(_payload(APPROVE), SlackNotifier(client=fake))

    assert result["ok"] is True
    assert seen["alert_id"] == "SPL-1000"
    assert seen["actor"] == "U024BE7LH"      # Slack user id -> audit trail
    assert seen["source"] == "slack"
    assert seen["decision"] == "Confirmed as an incident"


def test_second_click_is_rejected_without_re_resolving(monkeypatch):
    """Two analysts clicking the same message is normal, not an error."""
    from aegis.decisions import DecisionError

    def fake_apply(*a, **kw):
        raise DecisionError("SPL-1000 is not awaiting a decision")

    monkeypatch.setattr("aegis.notify.slack_handler.apply_decision", fake_apply)
    result = handle_block_action(_payload(REJECT), SlackNotifier(client=FakeSlack()))
    assert result["ok"] is False
    assert "not awaiting" in result["error"]


def test_unknown_action_is_ignored():
    result = handle_block_action(_payload("some_other_button"), SlackNotifier(client=FakeSlack()))
    assert result["ok"] is False


def test_resolved_message_replaces_the_buttons(monkeypatch):
    from aegis.ingest.store import REGISTRY

    monkeypatch.setattr("aegis.notify.slack_handler.apply_decision", lambda *a, **kw: {})
    rec, _ = REGISTRY.create_if_absent("SPL-BTN")
    REGISTRY.update("SPL-BTN", slack_ts="1725800000.000100", ticket=TICKET)

    fake = FakeSlack()
    handle_block_action(_payload(APPROVE, "SPL-BTN"), SlackNotifier(client=fake))

    assert len(fake.updated) == 1
    rendered = json.dumps(fake.updated[0]["attachments"])
    assert "actions" not in rendered          # buttons gone
    assert "U024BE7LH" in rendered            # attributed


def test_notifier_is_a_noop_without_a_token(monkeypatch):
    """Slack being unconfigured must never break triage."""
    monkeypatch.setenv("SLACK_BOT_TOKEN", "")
    n = SlackNotifier()
    assert n.post_ticket("X", TICKET) is None
