"""Identity enrichment from Keycloak.

Returns the same `UserProfile` contract as the mock directory, so
`identity_node` is unchanged.

Field choices were verified against a live Keycloak 26 realm:
  * The user record carries a `totp` boolean, which is simpler and more
    reliable than inspecting the credentials list for an OTP entry.
  * `enabled` is the authoritative account state; a deactivated user still
    generates LOGIN_ERROR events, which is exactly the signal that matters.
  * Custom attributes such as `department` are dropped unless the realm enables
    unmanaged attributes, so their absence is normal rather than an error.
  * Failed logins come from the events API filtered by user id. Events must be
    enabled on the realm or that count is always zero.
"""

from __future__ import annotations

import logging
import threading
import time
from datetime import UTC, datetime, timedelta
from typing import Any

from aegis.llm.config import get_settings
from aegis.tools._http import ToolHTTPError, request_json
from aegis.tools.identity import IdentityProviderUnavailable, UserProfile

logger = logging.getLogger(__name__)

# Group names that confer elevated rights. Tune to your realm.
PRIVILEGED_GROUP_MARKERS = ("admin", "privileged", "superuser", "operator")

_token: dict[str, Any] = {"value": None, "expires_at": 0.0}
_token_lock = threading.Lock()


def _admin_token() -> str:
    """Fetch and cache an admin token.

    Username and password suit a local realm. A deployment should use a service
    account client granted the realm-management view roles instead.
    """
    settings = get_settings()
    if not (settings.keycloak_url and settings.keycloak_admin_user
            and settings.keycloak_admin_password):
        raise IdentityProviderUnavailable(
            "KEYCLOAK_URL / KEYCLOAK_ADMIN_USER / KEYCLOAK_ADMIN_PASSWORD are not set"
        )

    with _token_lock:
        if _token["value"] and time.monotonic() < _token["expires_at"]:
            return str(_token["value"])

        try:
            payload = request_json(
                "POST",
                f"{settings.keycloak_url}/realms/master/protocol/openid-connect/token",
                data={"grant_type": "password", "client_id": "admin-cli",
                      "username": settings.keycloak_admin_user,
                      "password": settings.keycloak_admin_password},
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                timeout=settings.tool_timeout_seconds,
                retries=settings.tool_max_retries,
            ) or {}
        except ToolHTTPError as exc:
            raise IdentityProviderUnavailable(
                f"Keycloak auth failed against {settings.keycloak_url}: {exc}"
            ) from exc

        token = payload.get("access_token")
        if not token:
            raise IdentityProviderUnavailable("Keycloak returned no access_token")
        # Tokens are short lived; refresh early rather than mid-investigation.
        _token["value"] = token
        _token["expires_at"] = time.monotonic() + int(payload.get("expires_in", 60)) - 10
        return str(token)


def _first_attribute(user: dict[str, Any], name: str) -> str | None:
    values = (user.get("attributes") or {}).get(name) or []
    return str(values[0]) if values else None


def lookup_user_live(username: str) -> UserProfile | None:
    """Fetch a principal from Keycloak. Returns None if it does not exist."""
    settings = get_settings()
    base = f"{settings.keycloak_url}/admin/realms/{settings.keycloak_realm}"
    kw = dict(
        headers={"Authorization": f"Bearer {_admin_token()}"},
        timeout=settings.tool_timeout_seconds,
        retries=settings.tool_max_retries,
    )

    try:
        matches = request_json(
            "GET", f"{base}/users",
            params={"username": username, "exact": "true"}, **kw,
        ) or []
        if not matches:
            return None  # genuinely absent: a finding, not an error
        user: dict[str, Any] = matches[0]
        uid = user["id"]

        groups = request_json("GET", f"{base}/users/{uid}/groups", **kw) or []
        credentials = request_json("GET", f"{base}/users/{uid}/credentials", **kw) or []

        since = (datetime.now(UTC) - timedelta(hours=24)).date().isoformat()
        failures = request_json(
            "GET", f"{base.rsplit('/users', 1)[0]}/events",
            params={"type": "LOGIN_ERROR", "user": uid, "dateFrom": since, "max": 500},
            **kw,
        ) or []

    except ToolHTTPError as exc:
        raise IdentityProviderUnavailable(
            f"Keycloak lookup failed for {username}: {exc}") from exc
    except IdentityProviderUnavailable:
        raise
    except Exception as exc:  # noqa: BLE001 - unexpected payload shape
        raise IdentityProviderUnavailable(
            f"Keycloak response unusable for {username}: {exc}") from exc

    names = [str(g.get("name", "")).lower() for g in groups]
    privileged = any(marker in name for name in names
                     for marker in PRIVILEGED_GROUP_MARKERS)

    password_created = next(
        (c.get("createdDate") for c in credentials if c.get("type") == "password"), None
    )
    last_change = (
        datetime.fromtimestamp(password_created / 1000, tz=UTC)
        if password_created else None
    )

    display = " ".join(
        p for p in (user.get("firstName"), user.get("lastName")) if p
    ) or username

    return UserProfile(
        username=username,
        display_name=display,
        department=_first_attribute(user, "department") or "unknown",
        is_privileged=privileged,
        # `enabled` is the account state; a disabled account still generating
        # authentication events is the signal worth escalating.
        is_disabled=not user.get("enabled", True),
        mfa_enrolled=bool(user.get("totp")),
        usual_login_countries=[],  # needs a behavioural baseline store
        failed_logins_24h=len(failures),
        last_password_change=last_change,
    )
