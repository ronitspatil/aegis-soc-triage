"""External investigation tools loaded over MCP.

Used for context Aegis has no client of its own for. The first is AWS: knowing
that an IP belongs to your own NAT gateway turns a suspicious egress alert into
a non-event, and no threat intel feed can tell you that.

The client is written directly against the mcp 2.x API rather than using
langchain-mcp-adapters, which requires mcp<2 and cannot coexist with the MCP
server this project exposes.

Two properties of MCP make this different from writing a client:

  * A server's tool DESCRIPTIONS enter the prompt. They are text supplied by
    third-party code, read by a model that then chooses what to call, so adding
    a server is a supply-chain decision rather than a convenience.
  * Servers commonly expose write operations. AWS servers can terminate
    instances. Filtering happens here, at load time, because a prompt asking a
    model not to call something is not a control.

Everything loaded is subject to the same rails as the built-in tools: the step
budget, the audit trail, and running only after an alert is already escalated.
"""

from __future__ import annotations

import json
import logging
import re
from functools import lru_cache
from typing import Any

from langchain_core.tools import BaseTool, StructuredTool
from pydantic import BaseModel, Field, create_model

from aegis.llm.config import get_settings
from aegis.tools.mcp_client import MCPClient, MCPToolSpec

logger = logging.getLogger(__name__)

# Verbs that indicate a tool changes something. Matched against the tool name;
# anything hitting this list is dropped regardless of what its description says.
MUTATING_VERBS: frozenset[str] = frozenset({
    "create", "delete", "put", "post", "update", "modify", "terminate", "stop",
    "start", "reboot", "attach", "detach", "run", "execute", "invoke", "write",
    "remove", "revoke", "authorize", "associate", "disassociate", "enable",
    "disable", "apply", "deploy", "restore", "import", "register", "tag",
})

# Read verbs an investigation tool is expected to begin with. An allowlist as
# well as a denylist: a tool whose purpose is not obviously read-only is not
# something to hand a model mid-incident.
READ_PREFIXES: tuple[str, ...] = (
    "describe", "list", "get", "search", "query", "lookup", "read", "check",
    "find", "resolve", "analyze", "count",
)

# Too many tools degrades selection quality and inflates every prompt in the
# loop, since schemas are resent each turn.
MAX_MCP_TOOLS = 12

# Sessions must outlive the load call; stdio servers are subprocesses.
_client: MCPClient | None = None


def is_read_only(tool_name: str) -> bool:
    """Whether a tool may be exposed to the investigation agent."""
    name = tool_name.lower()
    parts = set(name.replace("-", "_").split("_"))
    if parts & MUTATING_VERBS:
        return False
    return name.startswith(READ_PREFIXES)


def _server_config() -> dict[str, Any]:
    """Server definitions, from a JSON file or the built-in AWS default.

    Pinning is deliberate: an unpinned server is arbitrary code whose tool
    descriptions reach your prompt on the next release.
    """
    settings = get_settings()
    if settings.mcp_config_path:
        with open(settings.mcp_config_path) as fh:
            return json.load(fh)

    if not settings.mcp_aws_enabled:
        return {}

    env: dict[str, str] = {"AWS_REGION": settings.aws_region}
    if settings.aws_profile:
        env["AWS_PROFILE"] = settings.aws_profile
    return {
        "aws": {
            "command": "uvx",
            "args": [f"awslabs.aws-api-mcp-server@{settings.mcp_aws_version}"],
            "transport": "stdio",
            "env": env,
        }
    }


_JSON_TYPES: dict[str, Any] = {
    "string": str, "integer": int, "number": float,
    "boolean": bool, "array": list, "object": dict,
}


def _args_model(spec: MCPToolSpec) -> type[BaseModel]:
    """Build a pydantic model from a tool's JSON input schema.

    Unknown types fall back to `Any` rather than being dropped: a parameter the
    converter does not recognise should still be passable, not silently
    unavailable.
    """
    properties = (spec.input_schema or {}).get("properties") or {}
    required = set((spec.input_schema or {}).get("required") or [])

    fields: dict[str, Any] = {}
    for key, prop in properties.items():
        annotation = _JSON_TYPES.get((prop or {}).get("type"), Any)
        description = (prop or {}).get("description", "")
        if key in required:
            fields[key] = (annotation, Field(..., description=description))
        else:
            fields[key] = (annotation | None if annotation is not Any else Any,
                           Field(default=None, description=description))

    safe_name = re.sub(r"\W", "_", f"{spec.server}_{spec.name}_args")
    return create_model(safe_name, **fields)


def _as_langchain_tool(client: MCPClient, spec: MCPToolSpec) -> BaseTool:
    """Wrap one MCP tool so the agent calls it like any other."""

    def _call(**kwargs: Any) -> str:
        # Drop unset optionals: servers often reject explicit nulls.
        arguments = {k: v for k, v in kwargs.items() if v is not None}
        return client.call(spec.server, spec.name, arguments)

    return StructuredTool.from_function(
        func=_call,
        name=spec.name,
        description=spec.description or f"{spec.name} from the {spec.server} server",
        args_schema=_args_model(spec),
    )


def _load_raw_tools(config: dict[str, Any]) -> list[BaseTool]:
    """Connect to the configured servers and wrap what they offer."""
    global _client

    client = MCPClient(config)
    client.start()
    _client = client  # kept alive: the sessions must outlive this call
    return [_as_langchain_tool(client, spec) for spec in client.list_tools()]


@lru_cache(maxsize=1)
def load_mcp_tools() -> tuple[BaseTool, ...]:
    """Load, filter and cap external tools. Never raises.

    A misconfigured or unreachable server must not stop investigations: the
    built-in tools are the ones that matter, and these are additive.
    """
    settings = get_settings()
    if not settings.mcp_enabled:
        return ()

    config = _server_config()
    if not config:
        return ()

    try:
        tools = _load_raw_tools(config)
    except Exception as exc:  # noqa: BLE001 - external process, many failure modes
        # Enabled but unusable is worth an error, not a quiet fallback: the
        # usual cause is a missing server command rather than a transient fault.
        logger.error(
            "MCP_ENABLED is set but no tools could be loaded (%s). "
            "Check that the server command is installed and runnable. "
            "Continuing with built-in tools only.", exc,
        )
        return ()

    kept: list[BaseTool] = []
    for tool in tools:
        if not is_read_only(tool.name):
            logger.info("MCP tool %s rejected: not read-only", tool.name)
            continue
        kept.append(tool)
        if len(kept) >= MAX_MCP_TOOLS:
            logger.info("MCP tool limit reached at %d", MAX_MCP_TOOLS)
            break

    logger.info("loaded %d MCP tool(s) of %d offered: %s",
                len(kept), len(tools), [t.name for t in kept])
    return tuple(kept)


def reset_mcp_tools() -> None:
    """Drop the cache and close any sessions."""
    global _client
    load_mcp_tools.cache_clear()
    if _client is not None:
        _client.stop()
        _client = None
