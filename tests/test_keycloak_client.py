"""Keycloak identity client. No server or credentials required.

Behaviours asserted here were observed against a live Keycloak 26 realm.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

import httpx
import pytest

import aegis.tools.keycloak_client as kc
from aegis.tools.identity import IdentityProviderUnavailable


@pytest.fixture(autouse=True)
def _config(monkeypatch):
    monkeypatch.setenv("KEYCLOAK_URL", "http://localhost:8081")
    monkeypatch.setenv("KEYCLOAK_REALM", "aegis")
    monkeypatch.setenv("KEYCLOAK_ADMIN_USER", "admin")
    monkeypatch.setenv("KEYCLOAK_ADMIN_PASSWORD", "admin")
    monkeypatch.setattr("aegis.tools._http.time.sleep", lambda *_: None)
    kc._token.update({"value": None, "expires_at": 0.0})
    yield
    kc._token.update({"value": None, "expires_at": 0.0})


def install(monkeypatch, handler: Callable[[str, str], tuple[int, Any]]) -> list[str]:
    calls: list[str] = []

    def fake(method: str, url: str, **kw: Any) -> httpx.Response:
        calls.append(f"{method} {url}")
        status, body = handler(method, str(url))
        return httpx.Response(status, content=json.dumps(body).encode(),
                              request=httpx.Request(method, url))

    monkeypatch.setattr(httpx, "request", fake)
    return calls


USER = {
    "id": "u1", "username": "j.doe@example.com", "enabled": False, "totp": False,
    "firstName": "J", "lastName": "Doe",
    "attributes": {"department": ["Finance"]},
}


def _handler(user=None, groups=(), creds=(), failures=0, found=True):
    def handler(method, url):
        if "openid-connect/token" in url:
            return 200, {"access_token": "tok", "expires_in": 60}
        if "/groups" in url:
            return 200, list(groups)
        if "/credentials" in url:
            return 200, list(creds)
        if "/events" in url:
            return 200, [{"type": "LOGIN_ERROR"}] * failures
        if "/users" in url:
            return 200, ([user or USER] if found else [])
        return 200, {}
    return handler


# --- mapping -----------------------------------------------------------------


def test_a_disabled_account_maps_to_is_disabled(monkeypatch):
    """A deactivated account still generates login events, which is the signal
    worth escalating."""
    install(monkeypatch, _handler(failures=6))
    profile = kc.lookup_user_live("j.doe@example.com")
    assert profile.is_disabled is True
    assert profile.failed_logins_24h == 6


def test_group_membership_determines_privilege(monkeypatch):
    install(monkeypatch, _handler(groups=[{"name": "Administrators"}]))
    assert kc.lookup_user_live("svc@example.com").is_privileged is True


def test_an_unrelated_group_does_not_confer_privilege(monkeypatch):
    install(monkeypatch, _handler(groups=[{"name": "Engineering"}]))
    assert kc.lookup_user_live("r@example.com").is_privileged is False


def test_mfa_comes_from_the_totp_flag(monkeypatch):
    """The user record carries `totp`, which is simpler and more reliable than
    inspecting the credentials list."""
    install(monkeypatch, _handler(user={**USER, "totp": True}))
    assert kc.lookup_user_live("r@example.com").mfa_enrolled is True


def test_password_age_comes_from_the_credential(monkeypatch):
    install(monkeypatch, _handler(creds=[{"type": "password",
                                          "createdDate": 1700000000000}]))
    changed = kc.lookup_user_live("r@example.com").last_password_change
    assert changed is not None
    assert changed.year == 2023


def test_a_missing_department_is_not_an_error(monkeypatch):
    """Keycloak drops unmanaged attributes unless the realm enables them, so
    their absence is normal configuration rather than a fault."""
    install(monkeypatch, _handler(user={**USER, "attributes": None}))
    assert kc.lookup_user_live("r@example.com").department == "unknown"


def test_display_name_falls_back_to_the_username(monkeypatch):
    install(monkeypatch, _handler(user={k: v for k, v in USER.items()
                                        if k not in ("firstName", "lastName")}))
    assert kc.lookup_user_live("r@example.com").display_name == "r@example.com"


# --- absence and failure -----------------------------------------------------


def test_an_absent_user_returns_none_rather_than_raising(monkeypatch):
    """A principal not in the directory is a finding, not an error."""
    install(monkeypatch, _handler(found=False))
    assert kc.lookup_user_live("ghost@example.com") is None


def test_missing_configuration_raises(monkeypatch):
    monkeypatch.setenv("KEYCLOAK_URL", "")
    with pytest.raises(IdentityProviderUnavailable):
        kc.lookup_user_live("r@example.com")


def test_an_auth_failure_names_the_server(monkeypatch):
    def handler(method, url):
        return (401, {"error": "invalid_grant"}) if "token" in url else (200, {})

    install(monkeypatch, handler)
    with pytest.raises(IdentityProviderUnavailable) as exc:
        kc.lookup_user_live("r@example.com")
    assert "localhost:8081" in str(exc.value)


def test_the_admin_token_is_cached(monkeypatch):
    calls = install(monkeypatch, _handler())
    kc.lookup_user_live("a@example.com")
    kc.lookup_user_live("b@example.com")
    assert sum(1 for c in calls if "openid-connect/token" in c) == 1


def test_the_failed_login_query_is_scoped_to_a_day(monkeypatch):
    calls = install(monkeypatch, _handler())
    kc.lookup_user_live("r@example.com")
    events = next(c for c in calls if "/events" in c)
    assert "/events" in events
