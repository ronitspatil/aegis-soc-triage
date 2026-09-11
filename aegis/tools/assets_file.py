"""Asset inventory backed by a file you maintain.

Not a mock: a CSV or YAML of hosts, criticality and owners, kept in version
control and edited when machines change, is how plenty of teams actually track
this. It has a real update path and real review history, which an API does not
automatically give you.

Swappable later for NetBox, Intune or cloud tags behind the same protocol.

YAML:
    - hostname: DC-01
      criticality: crown_jewel
      asset_type: domain_controller
      environment: production
      owner: platform@corp.com
      tags: [tier-0]

CSV: the same field names as a header row, tags separated by semicolons.
"""

from __future__ import annotations

import csv
import logging
import threading
from pathlib import Path
from typing import Any

from aegis.tools.assets import CRITICALITY_ORDER, AssetProfile, Criticality

logger = logging.getLogger(__name__)


class AssetInventoryError(RuntimeError):
    """The inventory file could not be read or is not valid."""


def _coerce(row: dict[str, Any]) -> AssetProfile:
    """Build one profile, reporting what is wrong rather than skipping quietly."""
    hostname = str(row.get("hostname") or "").strip()
    if not hostname:
        raise ValueError("entry has no hostname")

    raw = str(row.get("criticality") or Criticality.UNKNOWN.value).strip().lower()
    try:
        criticality = Criticality(raw)
    except ValueError as exc:
        valid = ", ".join(c.value for c in Criticality)
        raise ValueError(
            f"{hostname}: '{raw}' is not a criticality. Use one of: {valid}"
        ) from exc

    tags = row.get("tags") or []
    if isinstance(tags, str):
        tags = [t.strip() for t in tags.replace(";", ",").split(",") if t.strip()]

    return AssetProfile(
        hostname=hostname,
        criticality=criticality,
        asset_type=str(row.get("asset_type") or "unknown"),
        environment=str(row.get("environment") or "unknown"),
        owner=(str(row["owner"]).strip() or None) if row.get("owner") else None,
        business_unit=(str(row["business_unit"]).strip() or None)
        if row.get("business_unit") else None,
        tags=list(tags),
    )


def load_inventory(path: Path) -> dict[str, AssetProfile]:
    """Parse an inventory file. Raises rather than returning a partial view.

    A half-loaded inventory is worse than none: it would report known hosts as
    unknown, and unknown ranks high enough to change decisions.
    """
    if not path.exists():
        raise AssetInventoryError(f"asset inventory not found: {path}")

    try:
        if path.suffix.lower() in {".yaml", ".yml"}:
            import yaml

            raw = yaml.safe_load(path.read_text()) or []
        elif path.suffix.lower() == ".csv":
            with path.open(newline="") as fh:
                raw = list(csv.DictReader(fh))
        else:
            raise AssetInventoryError(
                f"unsupported inventory format '{path.suffix}'; use .yaml or .csv"
            )
    except AssetInventoryError:
        raise
    except Exception as exc:  # noqa: BLE001 - malformed file
        raise AssetInventoryError(f"could not read {path}: {exc}") from exc

    if isinstance(raw, dict):  # a mapping of hostname -> fields is also accepted
        raw = [{"hostname": k, **(v or {})} for k, v in raw.items()]
    if not isinstance(raw, list):
        raise AssetInventoryError(f"{path} should contain a list of assets")

    assets: dict[str, AssetProfile] = {}
    problems: list[str] = []
    for entry in raw:
        if not isinstance(entry, dict):
            problems.append(f"not an object: {entry!r}")
            continue
        try:
            profile = _coerce(entry)
        except ValueError as exc:
            problems.append(str(exc))
            continue
        assets[profile.hostname] = profile

    if problems:
        raise AssetInventoryError(
            f"{path} has {len(problems)} invalid entr(ies): " + "; ".join(problems[:5])
        )
    return assets


class FileAssetInventory:
    """Reads an inventory file, reloading when it changes on disk.

    Reloading matters operationally: adding a host should not require a
    restart, and an inventory that is annoying to update stops being accurate.
    """

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)
        self._assets: dict[str, AssetProfile] = {}
        self._mtime: float | None = None
        self._lock = threading.Lock()

    def _refresh(self) -> dict[str, AssetProfile]:
        with self._lock:
            try:
                mtime = self._path.stat().st_mtime
            except OSError as exc:
                raise AssetInventoryError(
                    f"asset inventory unreadable: {self._path} ({exc})"
                ) from exc
            if mtime != self._mtime:
                self._assets = load_inventory(self._path)
                self._mtime = mtime
                logger.info("loaded %d asset(s) from %s",
                            len(self._assets), self._path)
            return self._assets

    def lookup(self, hostname: str) -> AssetProfile:
        hit = self._refresh().get(hostname)
        if hit is not None:
            return hit
        return AssetProfile(hostname=hostname, criticality=Criticality.UNKNOWN)

    def list_assets(self, minimum: Criticality | None = None) -> list[AssetProfile]:
        assets = sorted(self._refresh().values(),
                        key=lambda a: -CRITICALITY_ORDER[a.criticality])
        if minimum is None:
            return assets
        return [a for a in assets if a.at_least(minimum)]
