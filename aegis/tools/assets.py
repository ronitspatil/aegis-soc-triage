"""Asset criticality: what a host is worth, and what breaking it costs.

Every autonomy decision depends on blast radius. An alert on a laptop and the
same alert on a domain controller warrant different handling, and nothing else
in the system can tell them apart.

Unknown assets are deliberately not treated as unimportant. A host missing from
inventory is a gap in the inventory, not evidence that it does not matter.
"""

from __future__ import annotations

from enum import Enum
from functools import lru_cache
from typing import Protocol

from pydantic import BaseModel, ConfigDict, Field


class Criticality(str, Enum):
    """How much damage follows from this asset being compromised or disrupted."""

    CROWN_JEWEL = "crown_jewel"   # domain controllers, key stores, payment systems
    HIGH = "high"                 # production servers, systems holding regulated data
    STANDARD = "standard"         # ordinary workstations and internal services
    LOW = "low"                   # lab and test machines
    UNKNOWN = "unknown"           # not in inventory: a gap, not a low score


# Ordered so thresholds can be compared. str enums do not order on their own.
CRITICALITY_ORDER: dict[str, int] = {
    Criticality.LOW: 0,
    Criticality.STANDARD: 1,
    # Unknown sits above standard: not knowing is worse than knowing it is ordinary.
    Criticality.UNKNOWN: 2,
    Criticality.HIGH: 3,
    Criticality.CROWN_JEWEL: 4,
}


class AssetProfile(BaseModel):
    """What inventory knows about a host."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    hostname: str
    criticality: Criticality = Criticality.UNKNOWN
    asset_type: str = "unknown"
    environment: str = "unknown"
    owner: str | None = None
    business_unit: str | None = None
    tags: list[str] = Field(default_factory=list)

    @property
    def in_inventory(self) -> bool:
        return self.criticality is not Criticality.UNKNOWN

    def at_least(self, level: Criticality) -> bool:
        return CRITICALITY_ORDER[self.criticality] >= CRITICALITY_ORDER[level]


class AssetInventory(Protocol):
    def lookup(self, hostname: str) -> AssetProfile: ...

    def list_assets(self, minimum: Criticality | None = None) -> list[AssetProfile]:
        """Known assets, so a caller does not have to guess hostnames."""
        ...


_INVENTORY: dict[str, AssetProfile] = {
    "DC-01": AssetProfile(
        hostname="DC-01", criticality=Criticality.CROWN_JEWEL,
        asset_type="domain_controller", environment="production",
        owner="platform@corp.com", business_unit="Infrastructure",
        tags=["active-directory", "tier-0"],
    ),
    "SRV-BACKUP-01": AssetProfile(
        hostname="SRV-BACKUP-01", criticality=Criticality.HIGH,
        asset_type="server", environment="production",
        owner="infra@corp.com", business_unit="Infrastructure",
        tags=["backup", "holds-restorable-data"],
    ),
    "WIN-FINANCE-07": AssetProfile(
        hostname="WIN-FINANCE-07", criticality=Criticality.STANDARD,
        asset_type="workstation", environment="production",
        owner="j.doe@corp.com", business_unit="Finance",
    ),
    "MACBOOK-RPATIL": AssetProfile(
        hostname="MACBOOK-RPATIL", criticality=Criticality.STANDARD,
        asset_type="workstation", environment="production",
        owner="r.patil@corp.com", business_unit="Engineering",
    ),
    "LAB-VM-14": AssetProfile(
        hostname="LAB-VM-14", criticality=Criticality.LOW,
        asset_type="virtual_machine", environment="lab",
        owner="research@corp.com", business_unit="Security Research",
        tags=["ephemeral", "malware-analysis"],
    ),
}


class MockAssetInventory:
    """In-memory CMDB. Swap for a real inventory behind the same protocol."""

    def list_assets(self, minimum: Criticality | None = None) -> list[AssetProfile]:
        assets = sorted(_INVENTORY.values(),
                        key=lambda a: -CRITICALITY_ORDER[a.criticality])
        if minimum is None:
            return assets
        return [a for a in assets if a.at_least(minimum)]

    def lookup(self, hostname: str) -> AssetProfile:
        hit = _INVENTORY.get(hostname)
        if hit is not None:
            return hit
        # Absent from inventory is reported as unknown, never as unimportant.
        return AssetProfile(hostname=hostname, criticality=Criticality.UNKNOWN)


@lru_cache(maxsize=1)
def resolve_asset_inventory() -> AssetInventory:
    """Pick the configured inventory. File-backed is the real one.

    A file that cannot be read raises rather than falling back to the mock:
    fabricated criticality feeding the auto-close gate is worse than an error.
    """
    from aegis.llm.config import AssetInventoryBackend, get_settings

    settings = get_settings()
    if settings.asset_inventory is AssetInventoryBackend.FILE:
        from aegis.tools.assets_file import FileAssetInventory

        return FileAssetInventory(settings.asset_inventory_path)
    return MockAssetInventory()


def reset_asset_inventory() -> None:
    """Drop the cached inventory. Needed when configuration changes."""
    resolve_asset_inventory.cache_clear()


def lookup_asset(hostname: str) -> AssetProfile:
    return resolve_asset_inventory().lookup(hostname)


def list_assets(minimum: Criticality | None = None) -> list[AssetProfile]:
    return resolve_asset_inventory().list_assets(minimum)
