"""Slack as the analyst approval surface.

Renders a suspended alert's ticket as an interactive Block Kit message. The
button click resumes the LangGraph interrupt via `apply_decision`.

`raw_log` is omitted on purpose. Channel membership is the only access control
on these messages, and raw logs carry the most sensitive data in the system.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import re
import time
from typing import Any

from aegis.llm.config import get_settings

logger = logging.getLogger(__name__)

# Slack rejects section text over 3000 chars.
_MAX_TEXT = 2800

# A single coloured bar carries severity, the way alerting tools do it -
# instead of an emoji on every field.
SEVERITY_COLOR = {
    "info": "#8A94A6", "low": "#8A94A6", "medium": "#D9A441",
    "high": "#D64545", "critical": "#A32020",
}
RESOLVED_COLOR = "#8A94A6"
AUTO_CLOSE_COLOR = "#4C9A6A"

# Human-readable verdicts. `true_positive` is a database value, not English.
VERDICT_LABEL = {
    "true_positive": "True positive",
    "false_positive": "False positive",
    "ambiguous": "Inconclusive",
}

APPROVE = "aegis_approve"
REJECT = "aegis_reject"
ESCALATE = "aegis_escalate"

ACTION_DECISIONS = {
    APPROVE: "Confirmed as an incident",
    REJECT: "Closed as a false positive",
    ESCALATE: "Escalated to incident response",
}


def _truncate(text: str, limit: int = _MAX_TEXT) -> str:
    return text if len(text) <= limit else text[: limit - 1] + "\u2026"


ENTITY_LABEL = {
    "source_ip": "Source IP", "destination_ip": "Destination IP",
    "username": "User", "hostname": "Host", "file_hash": "File hash",
}


def _agent_label(name: str) -> str:
    return {"threat_intel": "Threat intel", "identity": "Identity",
            "endpoint": "Endpoint"}.get(name, name.replace("_", " ").capitalize())


def build_ticket_blocks(alert_id: str, ticket: dict[str, Any], severity: str = "medium",
                        occurrences: int = 1) -> list[dict]:
    """Render a drafted incident ticket for analyst review.

    `occurrences` above 1 means duplicates were suppressed for cost, and the
    analyst still needs to see that the situation is recurring.
    """
    verdict = str(ticket.get("verdict", "ambiguous"))
    confidence = ticket.get("confidence")
    entities = {k: v for k, v in (ticket.get("entities") or {}).items() if v}
    signals = ticket.get("enrichment_signals") or {}

    title = str(ticket.get("title", alert_id))
    # Strip the "[HIGH] " prefix, severity is already on the subtitle line.
    title = re.sub(r"^\[[A-Z]+\]\s*", "", title).split(" \u2014 ")[0]

    subtitle = " \u00b7 ".join(
        p for p in (
            severity.capitalize(), f"`{alert_id}`", entities.get("hostname"),
            f"{occurrences} occurrences" if occurrences > 1 else None,
        ) if p
    )

    summary = f"*{title}*\n{subtitle}"
    if confidence is not None:
        summary += f"\n\n{VERDICT_LABEL.get(verdict, verdict)} \u00b7 {round(float(confidence) * 100)}% confidence"

    blocks: list[dict] = [
        {"type": "section", "text": {"type": "mrkdwn", "text": _truncate(summary)}},
        {"type": "section", "text": {"type": "mrkdwn",
         "text": _truncate(str(ticket.get("reasoning", "")))}},
    ]

    if entities:
        blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": _truncate(
            "*Indicators*\n" + "\n".join(
                f"{ENTITY_LABEL.get(k, k.replace('_', ' ').capitalize())} \u00b7 `{v}`"
                for k, v in entities.items()))}})

    actions = ticket.get("recommended_actions") or []
    if actions:
        listed = "\n".join(f"{i}. {a}" for i, a in enumerate(actions[:4], 1))
        if len(actions) > 4:
            listed += f"\n_{len(actions) - 4} further steps in the full ticket_"
        blocks.append({"type": "section", "text": {"type": "mrkdwn",
                       "text": _truncate(f"*Suggested response*\n{listed}")}})

    inv = ticket.get("investigation")
    if inv:
        parts = [f"*Investigation*\n{inv.get('summary', '')}"]
        if inv.get("scope_concern"):
            parts.append("_Evidence suggests more hosts or accounts are involved "
                         "than this alert names._")
        gaps = inv.get("unanswered") or []
        if gaps:
            listed = "\n".join(f"\u2022 {g}" for g in gaps[:3])
            parts.append(f"*Not determined*\n{listed}")
        if inv.get("budget_exhausted"):
            parts.append("_Investigation stopped on its step budget._")
        blocks.append({"type": "section", "text": {"type": "mrkdwn",
                       "text": _truncate("\n\n".join(parts))}})

    if signals:
        line = "  \u00b7  ".join(
            f"{_agent_label(a)} {v.get('risk')}" + (" (failed)" if v.get("error") else "")
            for a, v in signals.items()
        )
        blocks.append({"type": "context", "elements": [{"type": "mrkdwn", "text": _truncate(line, 300)}]})

    blocks.append({"type": "actions", "block_id": f"aegis_decision::{alert_id}", "elements": [
        {"type": "button", "action_id": APPROVE, "style": "danger",
         "text": {"type": "plain_text", "text": "Confirm incident"}, "value": alert_id},
        {"type": "button", "action_id": REJECT,
         "text": {"type": "plain_text", "text": "False positive"}, "value": alert_id},
        {"type": "button", "action_id": ESCALATE,
         "text": {"type": "plain_text", "text": "Escalate"}, "value": alert_id},
    ]})
    return blocks


def build_resolved_blocks(alert_id: str, ticket: dict[str, Any], decision: str, actor: str) -> list[dict]:
    """Replace the buttons once decided, so an alert cannot be double-actioned."""
    title = re.sub(r"^\[[A-Z]+\]\s*", "", str(ticket.get("title", alert_id))).split(" \u2014 ")[0]
    return [
        {"type": "section", "text": {"type": "mrkdwn",
         "text": _truncate(f"*{title}*\n{decision} by <@{actor}>")}},
        {"type": "context", "elements": [
            {"type": "mrkdwn", "text": f"`{alert_id}` \u00b7 recorded in the audit trail"}]},
    ]


def build_auto_close_blocks(alert_id: str, verdict: str, confidence: float, reasoning: str,
                            shadow: bool = False) -> list[dict]:
    """Post auto-closes too: silent automation cannot be reviewed."""
    lead = "SHADOW \u00b7 would have auto-closed" if shadow else "Closed automatically"
    return [
        {"type": "section", "text": {"type": "mrkdwn", "text": _truncate(
            f"*{lead}* \u00b7 `{alert_id}`\n"
            f"{VERDICT_LABEL.get(verdict, verdict)} \u00b7 {round(float(confidence) * 100)}% confidence\n\n"
            f"{reasoning}")}},
        {"type": "context", "elements": [
            {"type": "mrkdwn", "text": "No action required \u00b7 reply in thread if this looks wrong"}]},
    ]


def verify_slack_signature(signing_secret: str, timestamp: str, body: bytes, signature: str) -> bool:
    """Validate an inbound Slack request (HTTP interactivity mode).

    Without this, anyone who finds the endpoint can close incidents. The
    timestamp check blocks replay of a captured, validly-signed request.
    """
    try:
        if abs(time.time() - int(timestamp)) > 60 * 5:
            return False
    except (TypeError, ValueError):
        return False
    base = f"v0:{timestamp}:{body.decode('utf-8', 'replace')}".encode()
    expected = "v0=" + hmac.new(signing_secret.encode(), base, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature or "")


class SlackNotifier:
    """Thin wrapper over the Slack Web API. No-ops when unconfigured."""

    def __init__(self, client: Any = None) -> None:
        settings = get_settings()
        self.channel = settings.slack_channel
        self.enabled = bool(settings.slack_bot_token) or client is not None
        if client is not None:
            self._client = client
        elif settings.slack_bot_token:
            from slack_sdk import WebClient

            self._client = WebClient(token=settings.slack_bot_token)
        else:
            self._client = None
            logger.info("SLACK_BOT_TOKEN unset; Slack notifications disabled")

    def _post(self, blocks: list[dict], text: str, color: str) -> str | None:
        if not self._client:
            return None
        try:
            # A left colour bar reads as an alerting tool, not a chat bot.
            resp = self._client.chat_postMessage(
                channel=self.channel, text=text,
                attachments=[{"color": color, "blocks": blocks}],
            )
            return resp.get("ts")
        except Exception as exc:  # noqa: BLE001 - notification must never break triage
            logger.warning("slack post failed: %s", exc)
            return None

    def post_ticket(self, alert_id: str, ticket: dict[str, Any], severity: str = "medium") -> str | None:
        return self._post(build_ticket_blocks(alert_id, ticket, severity),
                          text=f"Review needed: {ticket.get('title', alert_id)}",
                          color=SEVERITY_COLOR.get(severity, SEVERITY_COLOR["medium"]))

    def post_auto_close(self, alert_id: str, verdict: str, confidence: float,
                        reasoning: str, shadow: bool = False) -> str | None:
        return self._post(build_auto_close_blocks(alert_id, verdict, confidence, reasoning, shadow),
                          text=f"Auto-closed {alert_id}",
                          color=RESOLVED_COLOR if shadow else AUTO_CLOSE_COLOR)

    def update_occurrences(self, ts: str, alert_id: str, ticket: dict[str, Any],
                           occurrences: int, severity: str = "medium") -> None:
        """Refresh a pending ticket with a new occurrence count."""
        if not (self._client and ts):
            return
        try:
            self._client.chat_update(
                channel=self.channel, ts=ts,
                text=f"Review needed: {ticket.get('title', alert_id)}",
                blocks=[],
                attachments=[{
                    "color": SEVERITY_COLOR.get(severity, SEVERITY_COLOR["medium"]),
                    "blocks": build_ticket_blocks(alert_id, ticket, severity, occurrences),
                }])
        except Exception as exc:  # noqa: BLE001 - notification must not break triage
            logger.warning("slack occurrence update failed: %s", exc)

    def mark_resolved(self, ts: str, alert_id: str, ticket: dict[str, Any],
                      decision: str, actor: str) -> None:
        if not (self._client and ts):
            return
        try:
            self._client.chat_update(
                channel=self.channel, ts=ts, text=f"{alert_id} resolved",
                blocks=[],
                attachments=[{"color": RESOLVED_COLOR,
                              "blocks": build_resolved_blocks(alert_id, ticket, decision, actor)}])
        except Exception as exc:  # noqa: BLE001
            logger.warning("slack update failed: %s", exc)
