"""Live containment via CrowdStrike Falcon.

Reached only from the executor, which runs after human approval and with
`ACTION_DRY_RUN` off. Requires an API client with host write scope; the
read-only client used for enrichment cannot perform these calls.
"""

from __future__ import annotations

import logging

from aegis.llm.config import get_settings
from aegis.schemas.response import ActionType, ProposedAction
from aegis.tools._http import ToolHTTPError, request_json
from aegis.tools.edr_client import _auth_headers

logger = logging.getLogger(__name__)


class ContainmentUnavailable(RuntimeError):
    """Raised when an action cannot be performed."""


class FalconContainment:
    """Only host isolation is implemented; other actions need their own systems."""

    def perform(self, action: ProposedAction) -> str:
        if action.action is not ActionType.ISOLATE_HOST:
            raise ContainmentUnavailable(
                f"{action.action.value} has no configured backend"
            )

        settings = get_settings()
        base = settings.crowdstrike_base_url
        kw = dict(headers=_auth_headers(), timeout=settings.tool_timeout_seconds,
                  retries=0)  # a containment call is not safe to blind-retry

        try:
            found = request_json(
                "GET", f"{base}/devices/queries/devices/v1",
                params={"filter": f"hostname:'{action.target}'", "limit": 1}, **kw,
            ) or {}
            ids = found.get("resources") or []
            if not ids:
                raise ContainmentUnavailable(f"{action.target} is not in the fleet")

            request_json(
                "POST", f"{base}/devices/entities/devices-actions/v2",
                params={"action_name": "contain"},
                json_body={"ids": [ids[0]], "action_parameters": []}, **kw,
            )
        except ToolHTTPError as exc:
            raise ContainmentUnavailable(f"containment failed: {exc}") from exc

        return f"isolated {action.target} via CrowdStrike"
