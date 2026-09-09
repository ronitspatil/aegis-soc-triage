"""Mock Okta / Entra ID identity provider lookups.

Swap-in point: replace `_DIRECTORY` with an Okta Users API client. The
`UserProfile` contract is what the Identity worker node depends on.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from pydantic import BaseModel, ConfigDict, Field


class IdentityProviderUnavailable(RuntimeError):
    """Raised when the IdP is unreachable."""


class UserProfile(BaseModel):
    """Directory facts about a principal, normalized across Okta/Entra."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    username: str
    display_name: str
    department: str
    is_privileged: bool = Field(
        default=False, description="Holds admin/elevated roles, raises blast radius"
    )
    is_disabled: bool = False
    mfa_enrolled: bool = True
    # Behavioral baseline: the countries this user NORMALLY authenticates from.
    # Deviation is signal; absence of deviation is exculpatory.
    usual_login_countries: list[str] = Field(default_factory=list)
    failed_logins_24h: int = Field(default=0, ge=0)
    last_password_change: datetime | None = None


_NOW = datetime.now(UTC)

_DIRECTORY: dict[str, UserProfile] = {
    "r.patil@corp.com": UserProfile(
        username="r.patil@corp.com",
        display_name="R. Patil",
        department="Engineering",
        is_privileged=False,
        mfa_enrolled=True,
        usual_login_countries=["US", "CA"],
        failed_logins_24h=0,
        last_password_change=_NOW - timedelta(days=45),
    ),
    "svc-backup@corp.com": UserProfile(
        username="svc-backup@corp.com",
        display_name="Backup Service Account",
        department="Infrastructure",
        is_privileged=True,   # service account with domain rights: high blast radius
        mfa_enrolled=False,   # non-interactive account, cannot MFA
        usual_login_countries=["US"],
        failed_logins_24h=0,
        last_password_change=_NOW - timedelta(days=890),  # ancient credential
    ),
    "j.doe@corp.com": UserProfile(
        username="j.doe@corp.com",
        display_name="J. Doe",
        department="Finance",
        is_privileged=True,
        is_disabled=True,     # OFFBOARDED, any auth attempt is deeply suspicious
        mfa_enrolled=True,
        usual_login_countries=["US"],
        failed_logins_24h=37,
        last_password_change=_NOW - timedelta(days=210),
    ),
}

RAISE_ON_LOOKUP = "idp-outage@corp.com"


def lookup_user(username: str) -> UserProfile | None:
    """Return the directory profile, or None if the principal does not exist.

    `None` is meaningful: an alert naming a user who is not in the directory is
    itself a finding (typo, local account, or attacker-created identity).
    """
    if username == RAISE_ON_LOOKUP:
        raise IdentityProviderUnavailable(f"503 from IdP on lookup of {username}")
    return _DIRECTORY.get(username)
