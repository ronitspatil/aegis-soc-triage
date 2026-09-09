"""Slack interactivity: turn a button click into a resumed LangGraph interrupt.

Run with Socket Mode (no public HTTPS endpoint needed):

    .venv/bin/python -m aegis.notify.slack_handler
"""

from __future__ import annotations

import logging
from typing import Any

from aegis.decisions import DecisionError, apply_decision, thread_config
from aegis.graph import _draft_ticket, get_app
from aegis.ingest.store import REGISTRY
from aegis.llm.config import get_settings
from aegis.notify.slack import ACTION_DECISIONS, SlackNotifier

logger = logging.getLogger(__name__)


def handle_block_action(payload: dict[str, Any], notifier: SlackNotifier | None = None) -> dict[str, Any]:
    """Process one Slack `block_actions` payload.

    Pure enough to unit test: everything external is the notifier or the graph.
    """
    actions = payload.get("actions") or []
    if not actions:
        return {"ok": False, "error": "no actions in payload"}

    action = actions[0]
    action_id = action.get("action_id", "")
    alert_id = action.get("value")
    user = (payload.get("user") or {}).get("id", "unknown")

    decision = ACTION_DECISIONS.get(action_id)
    if decision is None:
        return {"ok": False, "error": f"unknown action_id: {action_id}"}
    if not alert_id:
        return {"ok": False, "error": "no alert_id on the action"}

    try:
        # Slack's user id becomes the audit attribution, a real improvement
        # over free-text decisions.
        apply_decision(alert_id, decision, actor=user, source="slack")
    except DecisionError as exc:
        # Two analysts clicking the same message is normal, not an error.
        logger.info("slack decision rejected: %s", exc)
        return {"ok": False, "error": str(exc), "alert_id": alert_id}

    notifier = notifier or SlackNotifier()

    # Prefer the checkpointed value: this process may never have seen the alert.
    ts, ticket = None, {}
    try:
        values = get_app().get_state(thread_config(alert_id)).values or {}
        ts = values.get("slack_ts")
        if values.get("alert") is not None:
            ticket = _draft_ticket(values)
    except Exception as exc:  # noqa: BLE001 - fall back to local state
        logger.debug("could not read checkpoint for %s: %s", alert_id, exc)

    record = REGISTRY.get(alert_id)
    if record:
        ts = ts or record.slack_ts
        ticket = ticket or (record.ticket or {})

    if ts:
        # Swap the buttons for a resolution line so it cannot be double-actioned.
        notifier.mark_resolved(ts, alert_id, ticket, decision, user)

    return {"ok": True, "alert_id": alert_id, "decision": decision, "actor": user}


def run_socket_mode() -> None:
    """Open an outbound WebSocket to Slack. No public endpoint required."""
    settings = get_settings()
    if not (settings.slack_app_token and settings.slack_bot_token):
        raise RuntimeError("SLACK_APP_TOKEN and SLACK_BOT_TOKEN are required for Socket Mode")

    from slack_sdk import WebClient
    from slack_sdk.socket_mode import SocketModeClient
    from slack_sdk.socket_mode.request import SocketModeRequest
    from slack_sdk.socket_mode.response import SocketModeResponse

    client = SocketModeClient(
        app_token=settings.slack_app_token,
        web_client=WebClient(token=settings.slack_bot_token),
    )
    notifier = SlackNotifier()

    def on_request(c: SocketModeClient, req: SocketModeRequest) -> None:
        # Slack requires an ack within 3 seconds; acknowledge first, work after.
        c.send_socket_mode_response(SocketModeResponse(envelope_id=req.envelope_id))
        if req.type == "interactive" and req.payload.get("type") == "block_actions":
            result = handle_block_action(req.payload, notifier)
            logger.info("slack action handled: %s", result)

    client.socket_mode_request_listeners.append(on_request)
    logger.info("connecting to Slack in Socket Mode...")
    client.connect()
    import threading

    threading.Event().wait()


def check_connection() -> int:
    """Verify both tokens and post a test message. `--check` entry point."""
    from slack_sdk import WebClient

    settings = get_settings()
    if not settings.slack_bot_token:
        print("SLACK_BOT_TOKEN is not set in .env")
        return 1

    client = WebClient(token=settings.slack_bot_token)
    try:
        auth = client.auth_test()
    except Exception as exc:  # noqa: BLE001
        print(f"bot token rejected: {exc}")
        return 1
    print(f"bot token OK  -> team={auth['team']} bot={auth['user']}")

    try:
        client.chat_postMessage(
            channel=settings.slack_channel,
            text="Aegis connected. Incident tickets will appear in this channel.",
        )
        print(f"posted test message to {settings.slack_channel}")
    except Exception as exc:  # noqa: BLE001
        print(f"could not post to {settings.slack_channel}: {exc}")
        print("  -> create the channel, or invite the bot:  /invite @Aegis")
        return 1

    if not settings.slack_app_token:
        print("SLACK_APP_TOKEN is not set. Socket Mode (buttons) will not work")
        return 1
    print("app token present -> Socket Mode ready")
    return 0


def main() -> None:
    """Console entry point. `--check` verifies tokens without connecting."""
    import sys

    from aegis.observability import setup_logging

    setup_logging(json_output=False)
    if "--check" in sys.argv:
        raise SystemExit(check_connection())
    run_socket_mode()


if __name__ == "__main__":
    main()
