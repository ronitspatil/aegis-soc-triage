"""File-backed asset inventory."""

from __future__ import annotations

from pathlib import Path

import pytest

from aegis.tools.assets import Criticality
from aegis.tools.assets_file import (
    AssetInventoryError,
    FileAssetInventory,
    load_inventory,
)

YAML = """
- hostname: DC-01
  criticality: crown_jewel
  asset_type: domain_controller
  environment: production
  owner: platform@corp.com
  tags: [tier-0, active-directory]
- hostname: LAPTOP-9
  criticality: standard
"""

CSV = """hostname,criticality,asset_type,owner,tags
DC-01,crown_jewel,domain_controller,platform@corp.com,tier-0;active-directory
LAPTOP-9,standard,workstation,,
"""


def _write(tmp_path: Path, name: str, body: str) -> Path:
    path = tmp_path / name
    path.write_text(body)
    return path


# --- parsing -----------------------------------------------------------------


def test_yaml_is_parsed(tmp_path):
    assets = load_inventory(_write(tmp_path, "a.yaml", YAML))
    assert assets["DC-01"].criticality is Criticality.CROWN_JEWEL
    assert assets["DC-01"].tags == ["tier-0", "active-directory"]
    assert assets["LAPTOP-9"].criticality is Criticality.STANDARD


def test_csv_is_parsed(tmp_path):
    assets = load_inventory(_write(tmp_path, "a.csv", CSV))
    assert assets["DC-01"].asset_type == "domain_controller"
    assert assets["DC-01"].tags == ["tier-0", "active-directory"]
    assert assets["LAPTOP-9"].owner is None


def test_a_mapping_of_hostname_to_fields_is_accepted(tmp_path):
    body = "DC-01:\n  criticality: crown_jewel\nLAPTOP-9:\n  criticality: low\n"
    assets = load_inventory(_write(tmp_path, "a.yaml", body))
    assert assets["DC-01"].criticality is Criticality.CROWN_JEWEL


# --- failures are loud -------------------------------------------------------


def test_a_missing_file_raises(tmp_path):
    with pytest.raises(AssetInventoryError, match="not found"):
        load_inventory(tmp_path / "absent.yaml")


def test_an_invalid_criticality_names_the_host_and_the_valid_values(tmp_path):
    body = "- hostname: DC-01\n  criticality: extremely_important\n"
    with pytest.raises(AssetInventoryError) as exc:
        load_inventory(_write(tmp_path, "a.yaml", body))
    assert "DC-01" in str(exc.value)
    assert "crown_jewel" in str(exc.value)


def test_an_entry_without_a_hostname_raises(tmp_path):
    with pytest.raises(AssetInventoryError, match="hostname"):
        load_inventory(_write(tmp_path, "a.yaml", "- criticality: high\n"))


def test_one_bad_entry_rejects_the_file_rather_than_loading_partially(tmp_path):
    """A half-loaded inventory reports known hosts as unknown, and unknown
    ranks high enough to change decisions."""
    body = "- hostname: DC-01\n  criticality: crown_jewel\n- criticality: nonsense\n"
    with pytest.raises(AssetInventoryError):
        load_inventory(_write(tmp_path, "a.yaml", body))


def test_an_unsupported_extension_is_reported(tmp_path):
    with pytest.raises(AssetInventoryError, match="unsupported"):
        load_inventory(_write(tmp_path, "a.txt", "whatever"))


# --- live reload -------------------------------------------------------------


def test_an_unlisted_host_reads_as_unknown(tmp_path):
    inv = FileAssetInventory(_write(tmp_path, "a.yaml", YAML))
    asset = inv.lookup("NOT-LISTED")
    assert asset.criticality is Criticality.UNKNOWN
    assert asset.in_inventory is False


def test_edits_take_effect_without_a_restart(tmp_path):
    """An inventory that requires a restart to update stops being accurate."""
    path = _write(tmp_path, "a.yaml", YAML)
    inv = FileAssetInventory(path)
    assert inv.lookup("NEW-HOST").criticality is Criticality.UNKNOWN

    import os
    import time

    path.write_text(YAML + "- hostname: NEW-HOST\n  criticality: high\n")
    os.utime(path, (time.time() + 1, time.time() + 1))
    assert inv.lookup("NEW-HOST").criticality is Criticality.HIGH


def test_listing_is_ordered_by_criticality(tmp_path):
    inv = FileAssetInventory(_write(tmp_path, "a.yaml", YAML))
    assert [a.hostname for a in inv.list_assets()] == ["DC-01", "LAPTOP-9"]


def test_listing_can_be_filtered(tmp_path):
    inv = FileAssetInventory(_write(tmp_path, "a.yaml", YAML))
    assert [a.hostname for a in inv.list_assets(Criticality.HIGH)] == ["DC-01"]


# --- backend selection -------------------------------------------------------


def test_the_file_backend_is_selected_by_configuration(tmp_path, monkeypatch):
    from aegis.tools.assets import reset_asset_inventory, resolve_asset_inventory

    monkeypatch.setenv("ASSET_INVENTORY", "file")
    monkeypatch.setenv("ASSET_INVENTORY_PATH", str(_write(tmp_path, "a.yaml", YAML)))
    reset_asset_inventory()
    try:
        assert isinstance(resolve_asset_inventory(), FileAssetInventory)
    finally:
        reset_asset_inventory()


def test_an_unreadable_inventory_raises_rather_than_using_the_mock(tmp_path, monkeypatch):
    """Fabricated criticality feeding the auto-close gate is worse than an error."""
    from aegis.tools.assets import lookup_asset, reset_asset_inventory

    monkeypatch.setenv("ASSET_INVENTORY", "file")
    monkeypatch.setenv("ASSET_INVENTORY_PATH", str(tmp_path / "absent.yaml"))
    reset_asset_inventory()
    try:
        with pytest.raises(AssetInventoryError):
            lookup_asset("DC-01")
    finally:
        reset_asset_inventory()
