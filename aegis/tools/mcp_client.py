"""Minimal MCP client, built on the mcp 2.x API.

Written directly rather than via langchain-mcp-adapters, which requires mcp<2
and so cannot coexist with the MCP server this project exposes. One protocol
version, one dependency.

A stdio MCP server is a subprocess with a session that must stay open between
listing tools and calling them, and the protocol is async while the rest of
this codebase is not. So the session lives in a background event loop and the
public surface here is synchronous.
"""

from __future__ import annotations

import asyncio
import logging
import threading
from contextlib import AsyncExitStack
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)

DEFAULT_CALL_TIMEOUT = 30.0
STARTUP_TIMEOUT = 30.0


@dataclass
class MCPToolSpec:
    """A tool a server offers."""

    server: str
    name: str
    description: str = ""
    input_schema: dict[str, Any] = field(default_factory=dict)


class MCPClient:
    """Holds stdio sessions open in a background loop.

    Failures are reported rather than raised: an unreachable server should cost
    the tools it would have provided, not the investigation.
    """

    def __init__(self, servers: dict[str, dict[str, Any]]) -> None:
        self._servers = servers
        self._loop: asyncio.AbstractEventLoop | None = None
        self._thread: threading.Thread | None = None
        self._sessions: dict[str, Any] = {}
        self._stack: AsyncExitStack | None = None
        self._ready = threading.Event()
        self._error: Exception | None = None

    # --- lifecycle -----------------------------------------------------------

    def start(self) -> None:
        if self._thread is not None:
            return
        self._thread = threading.Thread(target=self._run, daemon=True,
                                        name="mcp-client")
        self._thread.start()
        if not self._ready.wait(timeout=STARTUP_TIMEOUT):
            raise TimeoutError("MCP servers did not start within the timeout")
        if self._error is not None:
            raise self._error

    def _run(self) -> None:
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        try:
            self._loop.run_until_complete(self._open())
        except Exception as exc:  # noqa: BLE001
            self._error = exc
            self._ready.set()
            return
        self._ready.set()
        self._loop.run_forever()

    async def _open(self) -> None:
        from mcp import ClientSession
        from mcp.client.stdio import StdioServerParameters, stdio_client

        self._stack = AsyncExitStack()
        for name, cfg in self._servers.items():
            if cfg.get("transport", "stdio") != "stdio":
                logger.warning("MCP server %s: only stdio transport is supported", name)
                continue
            params = StdioServerParameters(
                command=cfg["command"], args=cfg.get("args", []),
                env=cfg.get("env"), cwd=cfg.get("cwd"),
            )
            read, write = await self._stack.enter_async_context(stdio_client(params))
            session = await self._stack.enter_async_context(ClientSession(read, write))
            await session.initialize()
            self._sessions[name] = session
            logger.info("MCP server %s connected", name)

    def stop(self) -> None:
        if self._loop is None:
            return
        self._loop.call_soon_threadsafe(self._loop.stop)
        self._thread = None

    # --- operations ----------------------------------------------------------

    def _submit(self, coro: Any, timeout: float) -> Any:
        if self._loop is None:
            raise RuntimeError("MCP client is not started")
        return asyncio.run_coroutine_threadsafe(coro, self._loop).result(timeout)

    def list_tools(self) -> list[MCPToolSpec]:
        specs: list[MCPToolSpec] = []
        for server, session in self._sessions.items():
            try:
                listing = self._submit(session.list_tools(), DEFAULT_CALL_TIMEOUT)
            except Exception as exc:  # noqa: BLE001
                logger.warning("MCP server %s: listing tools failed: %s", server, exc)
                continue
            for tool in listing.tools:
                specs.append(MCPToolSpec(
                    server=server,
                    name=tool.name,
                    description=tool.description or "",
                    # mcp 2.x exposes `input_schema`; `inputSchema` is only
                    # the serialisation alias. Reading the alias silently
                    # yields no parameters, so the tool looks argument-less.
                    input_schema=(getattr(tool, "input_schema", None)
                                  or getattr(tool, "inputSchema", None) or {}),
                ))
        return specs

    def call(self, server: str, name: str, arguments: dict[str, Any],
             timeout: float = DEFAULT_CALL_TIMEOUT) -> str:
        """Invoke a tool and flatten the result to text for the model."""
        session = self._sessions.get(server)
        if session is None:
            return f"MCP server '{server}' is not connected."
        try:
            result = self._submit(session.call_tool(name, arguments), timeout)
        except Exception as exc:  # noqa: BLE001 - one dead tool is not fatal
            logger.warning("MCP call %s.%s failed: %s", server, name, exc)
            return f"Tool {name} failed: {exc}"
        return flatten_content(result)


def flatten_content(result: Any) -> str:
    """Turn a CallToolResult into plain text.

    Servers may return text, structured content, or images. Only text is useful
    to the model here, and an empty result is stated rather than returned blank
    so it does not read as a successful lookup that found nothing.
    """
    parts: list[str] = []
    for item in getattr(result, "content", None) or []:
        text = getattr(item, "text", None)
        if text:
            parts.append(str(text))
    if not parts:
        structured = getattr(result, "structuredContent", None)
        if structured:
            parts.append(str(structured))
    if getattr(result, "isError", False):
        return "Tool reported an error: " + (" ".join(parts) or "no detail given")
    return "\n".join(parts) if parts else "The tool returned no content."
