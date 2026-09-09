"""External MCP tools: filtering, capping, and failure isolation.

No MCP server is started. What matters is what gets past the filter, since a
server's tool descriptions reach the prompt and AWS servers can terminate
instances.
"""

from __future__ import annotations

from typing import Any

import pytest

from aegis.nodes.investigation_tools import INVESTIGATION_TOOLS, all_investigation_tools
from aegis.tools import mcp_tools
from aegis.tools.mcp_tools import MAX_MCP_TOOLS, is_read_only, reset_mcp_tools


@pytest.fixture(autouse=True)
def _clear_cache():
    reset_mcp_tools()
    yield
    reset_mcp_tools()


class FakeTool:
    def __init__(self, name: str) -> None:
        self.name = name


# --- the filter --------------------------------------------------------------


@pytest.mark.parametrize("name", [
    "describe_instances", "list_buckets", "get_caller_identity",
    "search_logs", "query_cloudwatch", "lookup_events", "check_security_groups",
])
def test_read_tools_are_allowed(name):
    assert is_read_only(name)


@pytest.mark.parametrize("name", [
    "terminate_instances", "delete_bucket", "create_user", "modify_instance",
    "put_object", "revoke_security_group_ingress", "run_instances",
    "stop_instances", "attach_role_policy", "execute_command", "update_stack",
])
def test_mutating_tools_are_rejected(name):
    """AWS servers expose destructive operations. A prompt asking a model not
    to call them is not a control."""
    assert not is_read_only(name)


def test_ambiguously_named_tools_are_rejected():
    """An allowlist as well as a denylist: a tool whose purpose is not clearly
    read-only is not something to hand a model mid-incident."""
    assert not is_read_only("do_the_thing")
    assert not is_read_only("aws_helper")


def test_a_read_prefix_does_not_rescue_a_mutating_verb():
    assert not is_read_only("get_and_delete_snapshot")
    assert not is_read_only("list_then_terminate")


# --- loading -----------------------------------------------------------------


def test_disabled_by_default():
    assert mcp_tools.load_mcp_tools() == ()
    assert all_investigation_tools() == INVESTIGATION_TOOLS


def test_mutating_tools_are_dropped_at_load(monkeypatch):
    monkeypatch.setenv("MCP_ENABLED", "true")
    monkeypatch.setattr(mcp_tools, "_load_raw_tools", lambda _: [
        FakeTool("describe_instances"),
        FakeTool("terminate_instances"),
        FakeTool("list_security_groups"),
    ])
    names = [t.name for t in mcp_tools.load_mcp_tools()]
    assert names == ["describe_instances", "list_security_groups"]


def test_tool_count_is_capped(monkeypatch):
    """Schemas are resent every loop iteration, and too many choices degrade
    selection."""
    monkeypatch.setenv("MCP_ENABLED", "true")
    monkeypatch.setattr(mcp_tools, "_load_raw_tools",
                        lambda _: [FakeTool(f"describe_thing_{i}") for i in range(40)])
    assert len(mcp_tools.load_mcp_tools()) == MAX_MCP_TOOLS


def test_an_unreachable_server_degrades_to_the_builtin_tools(monkeypatch):
    """A misconfigured server must not stop investigations."""
    monkeypatch.setenv("MCP_ENABLED", "true")

    def boom(_: Any) -> Any:
        raise RuntimeError("uvx: command not found")

    monkeypatch.setattr(mcp_tools, "_load_raw_tools", boom)
    assert mcp_tools.load_mcp_tools() == ()
    assert all_investigation_tools() == INVESTIGATION_TOOLS


def test_builtin_tools_come_first(monkeypatch):
    monkeypatch.setenv("MCP_ENABLED", "true")
    monkeypatch.setattr(mcp_tools, "_load_raw_tools",
                        lambda _: [FakeTool("describe_instances")])
    tools = all_investigation_tools()
    assert tools[: len(INVESTIGATION_TOOLS)] == INVESTIGATION_TOOLS
    assert tools[-1].name == "describe_instances"
