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


# --- schema conversion and result flattening ---------------------------------


def test_tool_parameters_survive_the_schema_conversion():
    """mcp 2.x exposes `input_schema`; reading the `inputSchema` alias yields
    nothing and the tool looks argument-less to the model."""
    from aegis.tools.mcp_client import MCPToolSpec
    from aegis.tools.mcp_tools import _args_model

    spec = MCPToolSpec(
        server="aws", name="describe_instances",
        input_schema={
            "type": "object",
            "properties": {
                "instance_id": {"type": "string", "description": "The instance"},
                "max_results": {"type": "integer"},
            },
            "required": ["instance_id"],
        },
    )
    model = _args_model(spec)
    assert set(model.model_fields) == {"instance_id", "max_results"}
    assert model.model_fields["instance_id"].is_required()
    assert not model.model_fields["max_results"].is_required()


def test_a_tool_with_no_parameters_converts_cleanly():
    from aegis.tools.mcp_client import MCPToolSpec
    from aegis.tools.mcp_tools import _args_model

    assert _args_model(MCPToolSpec(server="s", name="list_things")).model_fields == {}


def test_unknown_parameter_types_are_kept_rather_than_dropped():
    """A type the converter does not recognise should still be passable."""
    from aegis.tools.mcp_client import MCPToolSpec
    from aegis.tools.mcp_tools import _args_model

    spec = MCPToolSpec(server="s", name="t", input_schema={
        "properties": {"weird": {"type": "some-future-type"}}})
    assert "weird" in _args_model(spec).model_fields


def test_text_content_is_flattened_for_the_model():
    from aegis.tools.mcp_client import flatten_content

    class Item:
        def __init__(self, text): self.text = text

    class Result:
        content = [Item("first line"), Item("second line")]
        isError = False

    assert flatten_content(Result()) == "first line\nsecond line"


def test_an_empty_result_says_so_rather_than_returning_blank():
    """A blank string reads to the model as a successful lookup that found
    nothing."""
    from aegis.tools.mcp_client import flatten_content

    class Result:
        content: list = []
        isError = False

    assert "no content" in flatten_content(Result())


def test_a_tool_error_is_reported_as_an_error():
    from aegis.tools.mcp_client import flatten_content

    class Item:
        text = "access denied"

    class Result:
        content = [Item()]
        isError = True

    assert flatten_content(Result()).startswith("Tool reported an error")


def test_calling_an_unconnected_server_is_reported_not_raised():
    from aegis.tools.mcp_client import MCPClient

    client = MCPClient({})
    assert "not connected" in client.call("nope", "tool", {})
