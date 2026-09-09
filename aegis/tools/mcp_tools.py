"""External investigation tools loaded over MCP.

Used for context Aegis has no client of its own for. The first is AWS: knowing
that an IP belongs to your own NAT gateway turns a suspicious egress alert into
a non-event, and no threat intel feed can tell you that.

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

import asyncio
import json
import logging
from functools import lru_cache
from typing import Any

from langchain_core.tools import BaseTool

from aegis.llm.config import get_settings

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


async def _fetch_tools(config: dict[str, Any]) -> list[BaseTool]:
    from langchain_mcp_adapters.client import MultiServerMCPClient

    client = MultiServerMCPClient(config)
    return await client.get_tools()


def _load_raw_tools(config: dict[str, Any]) -> list[BaseTool]:
    """Synchronous seam over the async client, so callers and tests stay sync."""
    return asyncio.run(_fetch_tools(config))


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
    except ImportError as exc:
        # Enabled but unusable is a configuration error, not a quiet fallback.
        # langchain-mcp-adapters requires mcp<2, while the MCP server in this
        # project uses the 2.x API, so the two cannot be installed together.
        logger.error(
            "MCP_ENABLED is set but the client could not be imported (%s). "
            "Install the mcp-client extra in a separate environment, or drop "
            "MCP_ENABLED. Continuing with built-in tools only.", exc,
        )
        return ()
    except Exception as exc:  # noqa: BLE001 - external process, many failure modes
        logger.warning("MCP tools unavailable, continuing without them: %s", exc)
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
    """Drop the cache. Tests and configuration changes need this."""
    load_mcp_tools.cache_clear()
